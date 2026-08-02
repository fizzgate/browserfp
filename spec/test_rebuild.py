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
    # **verbatim**：本门禁验的是"能不能照采集那条重建回去"。出网口径下 ECH 长度
    # 与 padding 都随连接变，拿它比 golden 等于比两条本来就不同的报文。
    record = build_client_hello(profile, sni=None, verbatim=True)
    rebuilt = fingerprint(record)
    diffs = []
    for f in FIELDS:
        a, b = rebuilt.get(f), profile.get(f)
        if f in SET_FIELDS:
            a, b = sorted(a or []), sorted(b or [])
        if a != b:
            diffs.append((f, b, a))
    return diffs


REGISTRY = os.path.join(HERE, "profiles.json")

# 防平凡通过：注册表被截断或读空时，"0 一致，0 不符"看着是绿的 —— 实测过，
# 清空 profiles.json 后本门禁照样退出码 0。下限**不是棘轮**，它只回答
# "比对集是不是还在"，所以取一个远低于真实值（81）又远高于零的数。
MIN_PROFILES = 50



def main():
    # 优先验注册表——它才是交付给 C 模块的东西；单个 golden 文件只是它的原料。
    if os.path.exists(REGISTRY):
        with open(REGISTRY) as f:
            cases = [(rec["id"], rec["tls"]) for rec in json.load(f)]
    else:
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

    _n_compared = len(cases)
    print(f"重建 {len(cases)} 个 profile：{len(cases) - len(failed)} 通过，"
          f"{len(failed)} 失败")
    for name, diffs in failed:
        print(f"\n  ✗ {name}")
        for field, want, got in diffs:
            print(f"      {field}\n        golden : {str(want)[:110]}"
                  f"\n        重建后 : {str(got)[:110]}")
    # 比对集为空时上面每一项都会"通过" —— 实测过：清空
    # profiles.json 后本门禁照样退出码 0，打印"0 一致，0 不符"。
    if _n_compared < MIN_PROFILES:
        print(f"  ✗ 只比对了 {_n_compared} 条（下限 "
              f"{MIN_PROFILES}）—— 注册表被截断或读空了？")
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
