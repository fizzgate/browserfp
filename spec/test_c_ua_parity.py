"""C 侧 UA 映射与 Python 的差分门禁：生产 UA + 全版本 × 全品牌两个口径都比。

生产跑的是 C/Lua，Python 只是权威参照。UA 映射的语义（三档判定、同段需同库、
跨品牌拒绝）比纯解析复杂得多，C 版极易在边界上偏离而不报错，故必须逐条比。

**只比生产 UA 是不够的**。那批样本 60 种、解析出来 48 条，覆盖不到移动端品牌、
桌面等价回落、派生 profile 这些后加的路径 —— 实测把口径扩到全版本（334 个查询）
后一次暴露 11 处分歧，其中一处是派生的移动端 profile 被注册进了桌面表，桌面查询
会命中一份少了 SCT 的指纹。生产口径下那条路径根本走不到。

两个口径分开计数并分别报告：生产口径是"今天就在用的"，全版本口径是"改坏了会
不会被发现"。

跑：python -m spec.test_c_ua_parity
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.covscan import NEVER_RELEASED, TARGETS            # noqa: E402
from oracle.uamap import UAMapper, parse_ua                   # noqa: E402

# 全版本口径当前的分歧数。生产口径必须 0 分歧（那是今天就在用的路径），全版本
# 口径用棘轮。
#
# 剩下 5 处的成因已查明但未修：两侧"取最近版本"的范围不同。
#   Python  移动端表没有该版本时，回落到**桌面段表**内取最近
#   C       只在 <移动端段 ∩ 桌面段可替代> 的交集里补条目，补不出来就靠查表时
#           的 same-seg 推断，而那条要求 lo 与 hi 都存在、同组同库
# 那批 firefox-mobile 的分歧已随实采补齐而消失（108-111 与 119-123 两段拿到
# 实采锚之后，两侧都能在段内取到同一个最近版本）。现在只剩 chrome 151 一处：
# 它是 confidence 归类差异（Python 报 same-seg、C 报 exact），profile 本身一致，
# 不会让任何一侧发出对方拒绝的指纹。
FULL_RANGE_BASELINE = 0


def _full_range_diff(mapper):
    """全版本 × 全品牌差分，返回 (不符列表, 总数)。"""
    cases, expected = [], []
    for brand, (tpl, lo, hi) in TARGETS.items():
        skip = NEVER_RELEASED.get(brand, set())
        for v in range(lo, hi + 1):
            if v in skip:
                continue
            r = mapper.lookup(tpl.format(v=v))
            cases.append(f"{brand} {v}")
            expected.append((r.get("profile") or "-", r["confidence"]))
    out = subprocess.run([CLI], input="\n".join(cases),
                         capture_output=True, text=True, timeout=120)
    got = [tuple(l.split("\t")) for l in out.stdout.splitlines() if l.strip()]
    if len(got) != len(expected):
        return [("条数不符", len(expected), len(got))], len(cases)
    return ([(c, e, g) for c, e, g in zip(cases, expected, got) if e != g],
            len(cases))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLI = os.path.join(ROOT, "csrc", "uacli")
FIXTURES = os.path.join(HERE, "fixtures", "prod_user_agents.json")


def main():
    if not os.path.exists(CLI):
        print(f"缺 {CLI}；先在 csrc 下 make uacli", file=sys.stderr)
        return 2
    if not os.path.exists(FIXTURES):
        print("缺真实 UA 测试集，跳过", file=sys.stderr)
        return 0

    with open(FIXTURES) as f:
        rows = json.load(f)

    mapper = UAMapper()
    cases, expected = [], []
    for row in rows:
        brand, ver = parse_ua(row["ua"])
        if not brand:
            continue                      # 非浏览器 UA，C 侧不处理
        r = mapper.lookup(row["ua"])
        cases.append(f"{brand} {ver}")
        expected.append((r.get("profile") or "-", r["confidence"]))

    out = subprocess.run([CLI], input="\n".join(cases), capture_output=True,
                         text=True, timeout=60)
    got = [tuple(l.split("\t")) for l in out.stdout.splitlines() if l.strip()]

    if len(got) != len(expected):
        print(f"条数不符：C {len(got)} vs Python {len(expected)}", file=sys.stderr)
        return 1

    bad = [(c, e, g) for c, e, g in zip(cases, expected, got) if e != g]
    print(f"生产 UA 口径   {len(cases)} 条：{len(cases) - len(bad)} 一致，"
          f"{len(bad)} 不符")
    for c, e, g in bad[:10]:
        print(f"  ✗ {c}\n      Python {e}\n      C      {g}")

    full_bad, n_full = _full_range_diff(mapper)
    print(f"全版本口径     {n_full} 条：{n_full - len(full_bad)} 一致，"
          f"{len(full_bad)} 不符")
    for c, e, g in full_bad[:10]:
        print(f"  ✗ {c}\n      Python {e}\n      C      {g}")
    if len(full_bad) > FULL_RANGE_BASELINE:
        print(f"\n全版本差分 {len(full_bad)} 处，超过水位 {FULL_RANGE_BASELINE}")
    elif len(full_bad) < FULL_RANGE_BASELINE:
        print(f"\n全版本差分降到 {len(full_bad)}（水位 {FULL_RANGE_BASELINE}），"
              "确认无误后把 FULL_RANGE_BASELINE 改小")

    failed = bool(bad) or len(full_bad) > FULL_RANGE_BASELINE
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
