"""重建闭环验证：profile → ClientHello 字节 → 解析 → 与 golden 逐字段比。

这是写 C 模块前的**证伪实验**。全绿说明 golden 里的数据足以重建每一个 target
的 ClientHello，C 模块照着同一份数据做就能得到同样的指纹；有红说明 profile
数据不完备，得先补采集，不然 C 写完了也对不上。

跑：python -m spec.test_rebuild
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chbuild import build_client_hello                 # noqa: E402
from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.coverage import FIELDS, SET_FIELDS                # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "golden", "curl_cffi_nosni.json")
REAL = os.path.join(HERE, "golden", "real_browsers.json")


def check(name, profile):
    """重建后解析，返回差异列表。空 = 该 profile 可被完整重建。"""
    record = build_client_hello(profile, sni=None)
    rebuilt = fingerprint(record)
    diffs = []
    for f in FIELDS:
        a, b = rebuilt.get(f), profile.get(f)
        if f in SET_FIELDS:
            a, b = sorted(a or []), sorted(b or [])
        if a != b:
            diffs.append((f, b, a))
    return diffs


def main():
    cases = []
    with open(GOLDEN) as f:
        for t, p in json.load(f).items():
            cases.append((f"curl_cffi:{t}", p))
    if os.path.exists(REAL):
        with open(REAL) as f:
            for n, e in json.load(f).items():
                cases.append((f"real:{n}", e["fingerprint"]))

    failed = []
    for name, profile in cases:
        try:
            diffs = check(name, profile)
        except Exception as e:
            failed.append((name, [("<exception>", "", repr(e))]))
            continue
        if diffs:
            failed.append((name, diffs))

    print(f"重建 {len(cases)} 个 profile：{len(cases) - len(failed)} 通过，"
          f"{len(failed)} 失败")
    for name, diffs in failed:
        print(f"\n  ✗ {name}")
        for field, want, got in diffs:
            print(f"      {field}\n        golden : {str(want)[:110]}"
                  f"\n        重建后 : {str(got)[:110]}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
