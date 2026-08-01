"""严格模式门禁：没有精确指纹时，绝不返回"最接近的那个"。

**为什么这是硬约束**：拿相邻版本的指纹去伪装另一个版本，制造的是 split-brain
——UA 自称 Chrome 78，TLS 却是 Chrome 83 的形态。这比完全不伪装更容易被判，
因为"UA 与 TLS 形态互相矛盾"本身就是个强信号，而不伪装至少是自洽的。

所以三档里只有前两档可用：
    exact     该主版本有直接对应的 profile
    same-seg  两端指纹相同**且**出自同一来源库 —— 段内可安全替代
    fallback  只有跨段的最近版本 —— 必须返回 None/NULL

**同时验负向证据**：判成 fallback 的版本，其上下两端必须**确实**指纹不同。
否则说明 same-seg 的判定漏了本该可用的情况，是在白白丢覆盖率。这条断言让
"拒绝"与"该拒绝"两个方向都被钉住——只查一个方向的话，一个永远返回 None 的
实现也能全绿。

跑：python -m spec.test_strict_ua
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.coverage import FIELDS, SET_FIELDS                 # noqa: E402
from oracle.uamap import UAMapper                              # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "prod_user_agents.json")


def _norm(tls, field):
    v = tls.get(field)
    return sorted(v) if field in SET_FIELDS and v else v


def check_strict_returns_none(mapper, rows):
    """fallback 档必须 profile=None。"""
    bad = []
    for row in rows:
        r = mapper.lookup(row["ua"])
        if r["confidence"] == "fallback" and r["profile"] is not None:
            bad.append(f"{r['brand']} {r['version']} → {r['profile']}")
    return bad


def check_relaxed_still_works(mapper, rows):
    """strict=False 仍应给出最近者 —— 否则这个开关是死的，负向断言就成了空转。"""
    seen = 0
    for row in rows:
        r = mapper.lookup(row["ua"], strict=False)
        if r["confidence"] == "fallback":
            seen += 1
            if r["profile"] is None:
                return [f"{r['brand']} {r['version']} 在 relaxed 下仍为 None"], seen
    return [], seen


def check_gaps_are_real(mapper, rows):
    """每个被拒的版本，其上下两端必须确实指纹不同（否则 same-seg 判漏了）。"""
    bad, evidence = [], []
    checked = set()
    for row in rows:
        r = mapper.lookup(row["ua"])
        if r["confidence"] != "fallback":
            continue
        brand, ver = r["brand"], r["version"]
        if (brand, ver) in checked:
            continue
        checked.add((brand, ver))

        table = mapper.by_brand.get(brand, {})
        lo = max((v for v in table if v < ver), default=None)
        hi = min((v for v in table if v > ver), default=None)
        if lo is None or hi is None:
            evidence.append(f"{brand} {ver}: 单侧（lo={lo} hi={hi}），无从判段")
            continue

        rlo, rhi = table[lo][0], table[hi][0]
        diff = [f for f in FIELDS
                if _norm(rlo["tls"], f) != _norm(rhi["tls"], f)]
        srcs_lo = {a.split(":", 1)[0] for a in [rlo["id"]] + rlo.get("aliases", [])}
        srcs_hi = {a.split(":", 1)[0] for a in [rhi["id"]] + rhi.get("aliases", [])}
        shared = srcs_lo & srcs_hi

        if not diff and shared:
            bad.append(f"{brand} {ver}: {lo}↔{hi} 指纹相同且同库({sorted(shared)})，"
                       f"本该判 same-seg 却判了 fallback")
        else:
            why = "、".join(diff) if diff else f"跨库（{sorted(srcs_lo)} vs {sorted(srcs_hi)}）"
            evidence.append(f"{brand} {ver}: {lo}↔{hi} 差 {why}")
    return bad, evidence, checked


def main():
    if not os.path.exists(FIXTURES):
        print("缺 spec/fixtures/prod_user_agents.json", file=sys.stderr)
        return 2
    with open(FIXTURES) as f:
        rows = json.load(f)

    mapper = UAMapper()
    leaked = check_strict_returns_none(mapper, rows)
    dead, n_fb = check_relaxed_still_works(mapper, rows)
    misjudged, evidence, gaps = check_gaps_are_real(mapper, rows)

    total = sum(r["count"] for r in rows)
    usable = sum(r["count"] for r in rows
                 if mapper.lookup(r["ua"])["profile"] is not None)

    print(f"真实 UA {len(rows)} 种 / {total} 次请求")
    print(f"严格模式可精确伪装：{usable} 次（{usable * 100 / total:.1f}%）")
    print(f"被拒的版本 {len(gaps)} 个，覆盖 fallback 档 {n_fb} 种 UA\n")

    print(f"严格返回 None   {'OK' if not leaked else '失败'}")
    for b in leaked:
        print(f"  ✗ 泄漏了不精确的 profile：{b}")
    print(f"relaxed 开关活   {'OK' if not dead else '失败'}")
    for b in dead:
        print(f"  ✗ {b}")
    print(f"拒绝有据         {'OK' if not misjudged else '失败'}")
    for b in misjudged:
        print(f"  ✗ {b}")

    print("\n每个缺口的两端差异（这是必须实采的依据）：")
    for e in sorted(evidence):
        print(f"  {e}")

    failed = len(leaked) + len(dead) + len(misjudged)
    print(f"\n{'严格模式成立' if not failed else f'{failed} 处问题'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
