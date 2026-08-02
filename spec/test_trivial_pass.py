"""每个数据源被清空时，至少有一个门禁必须变红。

**一个不会红的门禁比没有门禁更糟** —— 它让人以为验过了。这条元门禁把"清空数据
源再跑一遍"这件事固化下来，因为光读代码看不出平凡通过：实测清空
`spec/profiles.json` 后，三方一致性与重建这四个骨干门禁全部照样绿，打印的是
"0 一致，0 不符"。

做法上有两条硬要求：

  1. **在临时副本里改，不碰工作区**。曾经在工作区里清空 profiles.json，恰好
     有一次后台 `--live` 在跑，它读到中间状态、整轮结论作废（所幸也因此撞出
     `test_live_handshake` 的 0/0 绿勾）。
  2. **只断言"有门禁会红"，不断言"哪个会红"**。哪个门禁负责哪个数据源会随
     重构变化，钉死具体名字就是给自己找僵尸断言。真正要守的是"没有哪个数据源
     是无人看管的"。

`test_ua_mapping` 在段表全空时仍绿，那是**合理**的：它问的是"库对生产流量够不够
用"（覆盖率 92.2%→84.8%，仍高于 80% 阈值），不是"段表在不在"。段表缺失由另外
三个门禁抓。所以本门禁只要求"至少一个"，不要求"全部"。

跑：python -m spec.test_trivial_pass
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 数据源 → 清空方式，以及跑哪些门禁去探。门禁子集是为了控制耗时；选的都是
# 直接吃那个数据源的，联网/起容器的一律不选。
SOURCES = {
    "spec/profiles.json": ("json-list-empty",
                           ["test_c_parity", "test_lua_parity", "test_rebuild",
                            "test_build_parity"]),
    "spec/h2table.json": ("json-empty",
                          ["test_h2_build", "test_h2_table", "test_h2_identify",
                           "test_coherence"]),
    "spec/uach.json": ("json-empty", ["test_uach"]),
    "spec/golden/headers_real.json": ("json-empty",
                                      ["test_header_order", "test_uach_platform"]),
    "spec/golden/h2_real_browsers.json": ("json-empty",
                                          ["test_header_order", "test_coherence"]),
    "spec/segments": ("dir-empty",
                      ["test_segments", "test_coverage_ratchet",
                       "test_c_ua_parity"]),
    "spec/fixtures/prod_user_agents.json": ("json-list-empty",
                                            ["test_ua_mapping", "test_strict_ua"]),
    "spec/golden/uach_real.json": ("json-empty", ["test_uach"]),
    "spec/golden/h2_wreq.json": ("json-empty", ["test_header_order"]),
    "spec/golden/real_browsers.json": ("json-empty", ["test_registry_fresh"]),
    "spec/golden/quic_real_browsers.json": ("json-empty", ["test_registry_fresh"]),
    "spec/golden/h3_real_browsers.json": ("json-empty", ["test_registry_fresh"]),
}

# 不是"数据源"的数据文件，要写明理由 —— 否则新增一个源没人扫，就成了
# Edge/Opera 那种"扫描器漏掉一个轴，那个轴上的缺陷就不存在"。
# **这张表写错过**：h3/quic 那两份曾被我声明成"无人读"，实际上 registry.py
# 一直在读（h3 装到 profile 的 h3 字段、quic 建 real_quic:* 那几条）。判据不能
# 靠印象，要实测"清空之后有没有门禁变红" —— 那次实测同时暴露了 test_registry_fresh
# 只比 TLS 字段、不比 h2/h3 载荷的问题。
NOT_A_SOURCE = {
    "golden/curl_cffi.json":
        "带 SNI 的采集，只用于与 nosni 版对比确认 SNI 在扩展序列里的位置；"
        "注册表统一用 nosni 版",
}

# 多家库互为冗余的那些，单独清空任何一家都不该让门禁变红（其余几家还在），
# 所以不逐个登记 —— 但至少要有一家被扫到，h2_wreq.json 就是那一家。
REDUNDANT_PREFIX = ("golden/h2_", "golden/tls_client", "golden/utls_",
                    "golden/wreq_", "golden/curl_cffi_", "golden/linux_",
                    "golden/real_browsers_psk", "golden/derived_")


def _snapshot(dest):
    """把跑门禁需要的东西复制到临时目录。**排除 spec/cache**（40MB 的源码
    缓存，与本门禁无关），也排除 .git 与字节码缓存。"""
    def ignore(d, names):
        skip = {"__pycache__", ".git", "cache", ".venv"}
        return [n for n in names if n in skip]
    for sub in ("spec", "oracle", "csrc", "lua"):
        shutil.copytree(os.path.join(ROOT, sub), os.path.join(dest, sub),
                        ignore=ignore, symlinks=True)


def _empty(path, how):
    if how == "json-empty":
        with open(path, "w") as f:
            f.write("{}")
    elif how == "json-list-empty":
        with open(path, "w") as f:
            f.write("[]")
    elif how == "json-array-empty":
        with open(path, "w") as f:
            f.write("[]")
    else:
        shutil.rmtree(path)
        os.makedirs(path)


def _run(workdir, gate, timeout=200):
    """在临时副本里跑一个门禁，返回退出码。

    **必须给独立的字节码缓存目录**：本机 python 把缓存放在源码之外
    （~/Library/Caches/com.apple.python/<绝对路径>/），临时目录路径每次不同，
    本来就不会撞；显式指定是为了跑完即弃、不留垃圾。
    """
    env = dict(os.environ)
    env["PYTHONPYCACHEPREFIX"] = os.path.join(workdir, ".pyc")
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        env.pop(k, None)
    try:
        r = subprocess.run([sys.executable, "-m", f"spec.{gate}"], cwd=workdir,
                           capture_output=True, text=True, timeout=timeout,
                           env=env)
        return r.returncode
    except subprocess.TimeoutExpired:
        return -1


def main():
    bad, checked = [], 0
    for rel, (how, gates) in SOURCES.items():
        work = tempfile.mkdtemp(prefix="tlsfp-tp-")
        try:
            _snapshot(work)
            target = os.path.join(work, rel)
            if not os.path.exists(target):
                bad.append(f"{rel}: 临时副本里没有这个源，扫描无效")
                continue

            # 先确认原样能跑绿 —— 否则"清空后变红"证明不了任何事
            base = {g: _run(work, g) for g in gates}
            green0 = [g for g, c in base.items() if c == 0]
            if not green0:
                bad.append(f"{rel}: 原样副本里这些门禁一个都不绿"
                           f"（{base}）—— 扫描环境本身有问题")
                continue

            _empty(target, how)
            after = {g: _run(work, g) for g in green0}
            red = [g for g, c in after.items() if c != 0]
            checked += 1
            mark = "✅" if red else "✗"
            print(f"  {mark} 清空 {rel:34s} → 变红 {red or '（一个都没有）'}")
            if not red:
                bad.append(f"{rel} 被清空后没有任何门禁变红 —— "
                           f"这个数据源无人看管，坏掉了也不会有人知道")
        finally:
            shutil.rmtree(work, ignore_errors=True)

    # 登记完整性：spec/ 下的数据文件要么被扫、要么写明为什么不是源。
    # 少了这一条，新增一个数据源就会静悄悄地无人看管。
    listed = {x[len("spec/"):] for x in SOURCES}
    undeclared = []
    for root, dirs, files in os.walk(os.path.join(ROOT, "spec")):
        dirs[:] = [d for d in dirs if d not in ("cache", "__pycache__")]
        for fn in files:
            if not fn.endswith((".json", ".txt")):
                continue
            rel = os.path.relpath(os.path.join(root, fn),
                                  os.path.join(ROOT, "spec"))
            if (rel in listed or rel in NOT_A_SOURCE
                    or rel.startswith("segments/")
                    or rel.startswith(REDUNDANT_PREFIX)):
                continue
            undeclared.append(rel)
    if undeclared:
        bad.append(f"这些数据文件既没被扫、也没写明为什么不是源：{undeclared} —— "
                   "新增数据源却不登记，等于给自己留一个无人看管的轴")
    print(f"  登记完整性  spec/ 下无未声明的数据文件"
          if not undeclared else f"  ✗ 未声明 {len(undeclared)} 个")

    print(f"\n扫描 {checked}/{len(SOURCES)} 个数据源")
    for b in bad:
        print(f"  ✗ {b}")
    if checked < len(SOURCES):
        bad.append(f"只扫到 {checked} 个数据源，少于登记的 {len(SOURCES)} 个")
    print(f"\n{'每个数据源都有门禁把守' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
