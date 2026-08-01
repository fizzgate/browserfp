"""C 侧 UA 映射与 Python 的差分门禁，输入取自真实生产 UA。

生产跑的是 C/Lua，Python 只是权威参照。UA 映射的语义（三档判定、同段需同库、
跨品牌拒绝）比纯解析复杂得多，C 版极易在边界上偏离而不报错，故必须逐条比。

跑：python -m spec.test_c_ua_parity
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.uamap import UAMapper, parse_ua                   # noqa: E402

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
    print(f"UA 映射差分 {len(cases)} 条：{len(cases) - len(bad)} 一致，{len(bad)} 不符")
    for c, e, g in bad[:10]:
        print(f"  ✗ {c}\n      Python {e}\n      C      {g}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
