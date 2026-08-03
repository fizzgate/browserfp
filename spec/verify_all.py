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
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = os.environ.get("BROWSERFP_PY") or os.path.join(ROOT, ".venv", "bin", "python")
if not os.path.exists(PY): PY = sys.executable

# 联网 / 需要容器的门禁单列，默认不跑。test_openresty 要拉镜像、编译、起容器，
# 耗时以分钟计，不适合每次改动都跑；但它是唯一验证"生产形态"的一环。
NETWORK_GATES = {"test_live_handshake", "test_cf_discrimination", "test_openresty",
                 "test_echo_fingerprint",
                 "test_build_live", "test_h2_live", "test_masquerade_live", "test_version_ceiling",
                 "test_chromium_h2", "test_gecko_h2",
                 "test_clean_clone", "test_trivial_pass"}


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


# 每轮用一个全新的字节码缓存目录，杜绝"跑的是旧代码"这类假绿。
#
# **macOS 系统 Python 把缓存放在源码之外**：sys.pycache_prefix 默认是
# ~/Library/Caches/com.apple.python/<源码绝对路径>/，源码旁边根本不会出现
# __pycache__ —— 删本地 __pycache__ 等于什么都没做。而 Python 判缓存是否
# 有效只看 (mtime, size) 两个数：变异测试里"改一个数字再 cp 还原"既不改
# 大小、又常落在同一秒，缓存就被判定有效，执行的是变异版本、inspect 读到
# 的却是还原后的源码。实测因此追查了很久：门禁坚持报 chrome 上限是 150，
# 而文件里、git 里、getsource 里全是 153。
_PYCACHE = tempfile.mkdtemp(prefix="browserfp-pyc-")


def _run(mod, timeout=300):
    """跑一个模块，返回 (成功?, 结论摘要)。"""
    env = dict(os.environ)
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        env.pop(k, None)
    env["PYTHONPYCACHEPREFIX"] = _PYCACHE
    try:
        out = subprocess.run([PY, "-m", mod], capture_output=True, text=True,
                             timeout=timeout, cwd=ROOT, env=env)
    except subprocess.TimeoutExpired:
        return False, f"超时（{timeout}s）"
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    return out.returncode == 0, _pick_verdict(lines)


# 第 1 层是自动发现的，默认 300s 够用；这几个要在临时副本里反复起子进程，
# 单独放宽。超时会被算成失败 —— 那是对的（挂死不是通过），但不能因为
# 默认值太紧而误报。
SLOW_GATES = {
    "test_mutation": 1800,
    # 实测单独跑 92s / 168s 两次 —— **波动很大**，168s 已经用掉 300s 预算的一大
    # 半，机器上有别的负载时必然超。它超时过两次，两次都被当成"环境占用"解释
    # 掉了；量下来是这条门禁本身就贴着上限，属于假红发生器。
    "test_h2_table": 900,
}


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
        ok, tail = _run(f"spec.{name}", timeout=SLOW_GATES.get(name, 300))
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

    # QUIC / h3 按引擎报 —— 这两层没有版本表，藏起来就等于没人看着它退化
    out = subprocess.run(
        [PY, "-c",
         "import sys;sys.path.insert(0,'.');"
         "from oracle.covscan import quic_coverage;"
         "c=quic_coverage();"
         "print('  QUIC/h3（按引擎，无版本表）');"
         "print('    QUIC ' + '  '.join(f'{e}:{\",\".join(v)}' "
         "for e,v in sorted(c['quic'].items())));"
         "print('    h3   ' + '  '.join(f'{e}:{\",\".join(v)}' "
         "for e,v in sorted(c['h3'].items())));"
         "print('    缺 webkit（Safari）—— 证书信任已解决，实测它根本不发 QUIC')"],
        capture_output=True, text=True, timeout=120, cwd=ROOT, env=env)
    print(out.stdout.rstrip() or "  （QUIC 覆盖度取不到）")

    if live:
        print("\n" + "=" * 62)
        print("第 3 层：端到端与生产形态")
        print("=" * 62)
        # 结果必须并进 failed —— 只往 bad 计数会让返回码对、结尾却打印
        # "所有已跑的验证均通过"。撞过一次：第 3 层红着，总览是绿的。
        # 第 3 层的网络门禁**共用同几个上游站点**：test_live_handshake 先打
        # 132 次握手，紧接着 build_live 又上，容易把对方的限速窗口撞满 ——
        # 实测出现过 build_live 报 2 个组合网络失败、单独重跑却 12/12。
        # 这不是掩盖问题：分档判据已经能把"服务端拒绝"和"这一跳没走通"分开，
        # 冷却只是让测量落在对方不丢包的区间里，与 build_live 内部的 PACE 同理。
        COOLDOWN = 15

        for mod, label, tmo in (
                ("spec.test_live_handshake", "对真实站点逐 profile 握手", 1800),
                ("spec.test_build_live", "C 构造的伪装握手", 900),
                ("spec.test_h2_live", "C 构造的 h2 开场被服务端接受", 900),
                ("spec.test_echo_fingerprint",
                 "对端看到的指纹 = 我们想冒充的指纹", 900),
                ("spec.test_openresty", "真实 OpenResty worker", 1800),
                ("spec.test_version_ceiling", "扫描上限 vs 上游最新版", 300),
                ("spec.test_chromium_h2", "Chromium h2 推导 vs 实采", 900),
                ("spec.test_gecko_h2", "Gecko h2 推导 vs 实采", 900),
                ("spec.test_trivial_pass", "每个数据源都有门禁把守", 900),
                ("spec.test_clean_clone", "干净克隆能不能跑", 900)):
            ok, tail = _run(mod, timeout=tmo)
            print(f"  {'✅' if ok else '❌'} {label}：{tail}")
            time.sleep(COOLDOWN)
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
