"""门禁：golden 目录里不得有"采了却没人读"的孤儿文件。

quic_real_browsers.json 与 h3_real_browsers.json 曾经采完之后一直没并入注册表。
这种遗漏**不报错**：门禁全绿、数字照常，只是那批数据永远用不上，而且越晚发现
越容易被当成"本来就没采"。

判据：spec/golden/ 下每个 .json 要么被 registry.py 引用，要么在 EXPECTED_UNUSED
里显式声明理由。新增 golden 文件时若忘了接进注册表，本门禁会失败。

跑：python -m spec.test_golden_orphans
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GOLDEN = os.path.join(HERE, "golden")
REGISTRY_SRC = os.path.join(ROOT, "oracle", "registry.py")

# 故意不入注册表的文件 → 理由。加入这里必须写清为什么。
EXPECTED_UNUSED = {
    "uach_real.json":
        "sec-ch-ua 的真机实采（本机 Chrome 151 / Chromium 142 / Edge 151），"
        "不进指纹注册表 —— 它验的是 oracle/uach.py 的源码推导对不对，"
        "由 spec/test_uach.py 读取",
    "curl_cffi.json":
        "带 SNI 采集，仅用于与 nosni 版对比确认 SNI 在扩展序列中的位置规律；"
        "注册表统一使用 nosni 版，以便与真机采集（无法带域名 SNI）逐字段可比",
}


def main():
    src = open(REGISTRY_SRC).read()
    files = sorted(f for f in os.listdir(GOLDEN) if f.endswith(".json"))
    orphans, declared = [], []
    for fn in files:
        if f'"{fn}"' in src:
            continue
        if fn in EXPECTED_UNUSED:
            declared.append(fn)
        else:
            orphans.append(fn)

    print(f"golden 文件 {len(files)} 个：入注册表 "
          f"{len(files) - len(declared) - len(orphans)}，"
          f"声明不用 {len(declared)}，孤儿 {len(orphans)}")
    for fn in declared:
        print(f"  · {fn}（已声明）：{EXPECTED_UNUSED[fn][:60]}…")
    for fn in orphans:
        print(f"  ✗ {fn}: 未被 registry.py 引用，也未在 EXPECTED_UNUSED 声明"
              f" —— 采了却没人读")
    return 1 if orphans else 0


if __name__ == "__main__":
    raise SystemExit(main())
