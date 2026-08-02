"""干净克隆能不能跑 —— 只用 git 跟踪的文件，不带缓存与本地产物。

本项目要能开源发布，而开发机上攒了两类东西是**不进版本控制**的：
`spec/cache/`（40MB 源码缓存）与 `csrc/` 下的编译产物。它们让本机看起来一切正常，
新克隆的人却会撞墙。实测第一次跑这条检查，三个门禁在干净副本上失败：

```
test_build_parity   缺 csrc/snitest —— Makefile 里**根本没有它的构建规则**，
                    本机那个是早年手工编的，所以一直没人发现
test_h2_table       冷缓存下要为 650 个版本逐个取源，**超时挂死**（退出码 124）
                    而不是优雅跳过 —— try/except 拦得住异常，拦不住慢
test_match          缺 hrrserver（Go 二进制），判失败而不是跳过
```

三种都不是"数据不对"，是**打包与降级路径**的问题，只有换个干净环境才看得见。

做法：`git ls-files` 出一份纯净副本到临时目录，在里面跑不联网的门禁。
排除自己与 `test_trivial_pass`（它俩都会再复制一份，套娃没意义），也排除联网/
起容器的那些 —— 那些的环境依赖另有各自的跳过逻辑。

**跳过必须显示出来**。`test_match` 现在缺 Go 时报"跳过"而不是失败，但会打印
原因并计入"N 项跳过"；全跳过则判失败 —— 那说明这台机器什么都没验到。

跑：python -m spec.test_clean_clone
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 不在干净副本里跑的：自己（套娃）、另一个也复制副本的元门禁、
# 以及联网/起容器的那些（它们各有自己的跳过逻辑，放这里只会拖时间）
EXCLUDE = {"test_clean_clone", "test_trivial_pass",
           "test_live_handshake", "test_build_live", "test_h2_live",
           "test_masquerade_live", "test_openresty", "test_cf_discrimination",
           "test_version_ceiling", "test_chromium_h2", "test_gecko_h2",
           "test_robustness"}


def _export(dest):
    """把**已提交**的树导出到 dest —— 干净克隆里有什么，这里就有什么。

    用 `git archive HEAD` 而不是 `git ls-files | tar`：后者要边写文件名边读
    tar 输出，两个管道互等会死锁（第一版就是这么挂的，tar 报 Write error）。
    `git archive` 直接把 tar 打到 stdout，一次读完即可。
    语义上也更对 —— 它取的是提交树，不受工作区未提交改动影响。
    """
    ar = subprocess.run(["git", "archive", "HEAD"], cwd=ROOT,
                        capture_output=True, timeout=300)
    if ar.returncode != 0 or not ar.stdout:
        raise RuntimeError(f"git archive 失败：{ar.stderr[:200]!r}")
    subprocess.run(["tar", "-xf", "-"], cwd=dest, input=ar.stdout, timeout=300,
                   check=True)


def main():
    gates = sorted(f[:-3] for f in os.listdir(HERE)
                   if f.startswith("test_") and f.endswith(".py")
                   and f[:-3] not in EXCLUDE)
    work = tempfile.mkdtemp(prefix="tlsfp-clean-")
    try:
        _export(work)
        # 导出的可能是仓库根下的子目录结构，找到 spec/ 在哪
        base = work
        if not os.path.isdir(os.path.join(base, "spec")):
            subs = [d for d in os.listdir(base)
                    if os.path.isdir(os.path.join(base, d, "spec"))]
            if not subs:
                print("导出的副本里找不到 spec/ —— 导出方式要改", file=sys.stderr)
                return 1
            base = os.path.join(base, subs[0])

        n_files = sum(len(f) for _, _, f in os.walk(base))
        print(f"干净副本 {n_files} 个文件（只含 git 跟踪的）\n")

        env = dict(os.environ)
        env["PYTHONPYCACHEPREFIX"] = os.path.join(work, ".pyc")
        for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
            env.pop(k, None)

        bad, ok = [], 0
        for g in gates:
            try:
                r = subprocess.run([sys.executable, "-m", f"spec.{g}"], cwd=base,
                                   capture_output=True, text=True, timeout=240,
                                   env=env)
                rc, tail = r.returncode, (r.stdout.strip().splitlines()
                                          or ["（无输出）"])[-1]
            except subprocess.TimeoutExpired:
                rc, tail = -1, "超时 —— 冷环境下挂死了，该有跳过路径"
            if rc == 0:
                ok += 1
            else:
                bad.append(f"{g}: {tail[:70]}")
                print(f"  ✗ {g:26s} {tail[:60]}")

        print(f"\n干净副本上 {ok}/{len(gates)} 个门禁通过")
        if ok == 0:
            bad.append("一个都没通过 —— 导出或运行方式本身有问题")
        print(f"\n{'干净克隆可用' if not bad else f'{len(bad)} 个门禁在干净克隆上跑不起来'}")
        return 1 if bad else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
