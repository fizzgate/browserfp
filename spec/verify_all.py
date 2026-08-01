"""一条命令跑完所有验证，给出项目当前的真实状态。

**为什么需要它**：验证入口散在 20 多个门禁 + covscan + live_handshake 里，谁想
知道"现在到底什么状态"都得自己拼一遍，而拼漏一项就会得出过于乐观的结论。

分三层报告，越往下越接近真实网络：
  1. 静态门禁    —— 数据自洽、三方语义一致、文档不僵尸（不联网，快）
  2. 覆盖度      —— 生产 UA 口径与全版本口径分别缺多少（不联网）
  3. 端到端与生产形态 —— 参考实现能否握手、**C 构造的伪装字节能否被服务端接受**、
     C 模块在真实 OpenResty worker 里是否与 Python 一致（联网/需容器，默认跳过）

**默认不跑第 3 层**：它对外发真实请求（profile 数 × 站点数），不该在每次改动
后无脑跑。加 --live 才跑。

跑：python -m spec.verify_all           # 前两层
    python -m spec.verify_all --live    # 含端到端
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = os.path.join(ROOT, ".venv", "bin", "python")

# 联网 / 需要容器的门禁单列，默认不跑。test_openresty 要拉镜像、编译、起容器，
# 耗时以分钟计，不适合每次改动都跑；但它是唯一验证"生产形态"的一环。
NETWORK_GATES = {"test_live_handshake", "test_cf_discrimination", "test_openresty",
                 "test_build_live"}


# 各门禁真正的结论行长什么样 —— 取末行常常抓到的是附注而非结论。实测
# test_live_handshake 的末行是"跳过的纯 TLS1.2 profile…"，把最关键的
# "130/130 组合可用"淹没了。
VERDICT_HINTS = ("组合可用", "一致", "通过", "OK", "成立", "印证", "可信",
                 "未倒退", "合规", "无跨品牌")


def _pick_verdict(lines):
    """从输出里挑出真正的结论行：优先含结论词的最后一条，否则退回末行。"""
    for line in reversed(lines):
        if any(h in line for h in VERDICT_HINTS):
            return line.strip()
    return lines[-1].strip() if lines else "无输出"


def _run(mod, timeout=300):
    """跑一个模块，返回 (成功?, 结论摘要)。"""
    env = dict(os.environ)
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        env.pop(k, None)
    try:
        out = subprocess.run([PY, "-m", mod], capture_output=True, text=True,
                             timeout=timeout, cwd=ROOT, env=env)
    except subprocess.TimeoutExpired:
        return False, f"超时（{timeout}s）"
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    return out.returncode == 0, _pick_verdict(lines)


def gates(include_network):
    names = sorted(f[:-3] for f in os.listdir(HERE)
                   if f.startswith("test_") and f.endswith(".py"))
    if not include_network:
        names = [n for n in names if n not in NETWORK_GATES]
    return names


def main(argv):
    live = "--live" in argv
    print("=" * 62)
    print("第 1 层：静态门禁（数据自洽 / 三方一致 / 文档不僵尸）")
    print("=" * 62)
    ok_n = bad = 0
    failed = []
    for name in gates(include_network=False):
        ok, tail = _run(f"spec.{name}")
        if ok:
            ok_n += 1
        else:
            bad += 1
            failed.append((name, tail))
        print(f"  {'✅' if ok else '❌'} {name:26s} {tail[:60]}")
    print(f"\n  通过 {ok_n} / 失败 {bad}")

    print("\n" + "=" * 62)
    print("第 2 层：覆盖度")
    print("=" * 62)
    _, cov = _run("oracle.uamap")
    print(f"  生产 UA 口径（60 种 / 14026 次请求）")
    env = dict(os.environ)
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        env.pop(k, None)
    out = subprocess.run([PY, "-m", "oracle.uamap"], capture_output=True,
                         text=True, timeout=180, cwd=ROOT, env=env)
    for line in out.stdout.splitlines():
        if any(k in line for k in ("exact", "same-seg", "fallback", "unparsed")):
            print(f"    {line.strip()}")
    out = subprocess.run([PY, "-m", "oracle.covscan"], capture_output=True,
                         text=True, timeout=300, cwd=ROOT, env=env)
    print("  全版本口径")
    for line in out.stdout.splitlines():
        if "缺 " in line and "扫描" in line:
            print(f"    {line.strip()}")
        elif line.startswith("合计"):
            print(f"    {line.strip()}")

    if live:
        print("\n" + "=" * 62)
        print("第 3 层：端到端与生产形态")
        print("=" * 62)
        # 结果必须并进 failed —— 只往 bad 计数会让返回码对、结尾却打印
        # "所有已跑的验证均通过"。撞过一次：第 3 层红着，总览是绿的。
        for mod, label, tmo in (
                ("spec.test_live_handshake", "对真实站点逐 profile 握手", 1800),
                ("spec.test_build_live", "C 构造的伪装握手", 900),
                ("spec.test_openresty", "真实 OpenResty worker", 1800)):
            ok, tail = _run(mod, timeout=tmo)
            print(f"  {'✅' if ok else '❌'} {label}：{tail}")
            if not ok:
                bad += 1
                failed.append((mod.split(".")[-1], tail))
    else:
        print("\n（未跑端到端验证；加 --live 才跑，它对外发真实请求）")

    print("\n" + "=" * 62)
    if failed:
        print(f"有 {len(failed)} 项未通过：")
        for name, tail in failed:
            print(f"  ✗ {name}: {tail[:70]}")
    else:
        print("所有已跑的验证均通过")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
