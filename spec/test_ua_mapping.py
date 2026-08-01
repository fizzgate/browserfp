"""UA → profile 映射门禁，测试集取自真实生产流量。

此前所有验证都跑在自造样本上。本门禁用生产 access.log 里的真实 UA 分布
（spec/fixtures/prod_user_agents.json）衡量映射质量，这是唯一能回答
"我们的库够不够用"的口径。

三条判据：
  1. exact + same-seg 覆盖率不低于阈值 —— 这两档是可安全伪装的
  2. **不得跨品牌套用**：曾出现 firefox→tor145、edge→chrome124，比没有指纹更糟
  3. **移动端与桌面不得互相套用**（指纹实测不同）。uamap 把移动端 UA 的品牌
     标成 "<brand>-mobile"，所以这里两个方向都要查：桌面 UA 不得命中纯移动端
     profile，移动端 UA 也必须命中带移动端别名的 profile。

跑：python -m spec.test_ua_mapping
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.uamap import (MOBILE_ALIAS, UAMapper,               # noqa: E402
                          load_desktop_equivalent)
from oracle.match import Matcher                              # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "prod_user_agents.json")

MIN_SAFE_RATIO = 0.80          # exact + same-seg 占浏览器请求的比例下限
DERIVED = ("tor", "android", "ios", "ipad", "mobile", "private", "okhttp")


def mobile_equivalence_evidence(reg):
    """找出同时含移动端与桌面别名的 profile —— 移动端映射规则的证据基础。

    规则是"移动端 UA 可以命中带移动端别名的 profile"，依据是注册表按指纹去重后
    这类条目里两边并存，说明该指纹**同时**被移动端与桌面观测到。实测有 6 条，
    其中 Safari 占 4 条（iOS ≡ macOS，覆盖 153/155/180/26）。

    这是推断而非实测每个版本，所以要盯住证据本身：哪天这类条目消失了，说明
    "移动端与桌面可能同指纹"不再有观测支持，规则必须重新评估而不是继续用。
    """
    out = []
    for rec in reg.values():
        if rec.get("mode") != "initial":
            continue
        names = [rec["id"]] + rec.get("aliases", [])
        short = [n.split(":", 1)[1].lower() for n in names]
        mob = [n for n in short if MOBILE_ALIAS.search(n)]
        desk = [n for n in short
                if not any(t in n for t in DERIVED) and not MOBILE_ALIAS.search(n)]
        if mob and desk:
            out.append((rec["id"], mob[:2], desk[:2]))
    return out


def main():
    if not os.path.exists(FIXTURES):
        print("缺真实 UA 测试集，跳过", file=sys.stderr)
        return 0
    with open(FIXTURES) as f:
        rows = json.load(f)

    mapper = UAMapper()
    # 判"是否跨品牌"要看该条目的**全部 aliases**，不能只看 id：注册表按指纹
    # 去重，Chrome151 与 Edge151 同指纹被并成一条、id 恰为 real:edge，
    # 它服务 Chrome UA 是正确的。只看 id 会把这种正常映射误报成跨品牌。
    reg = {r["id"]: r for r in Matcher().registry}
    desktop_equiv = load_desktop_equivalent()
    stats, total, violations = {}, 0, []
    for row in rows:
        r = mapper.lookup(row["ua"])
        stats[r["confidence"]] = stats.get(r["confidence"], 0) + row["count"]
        total += row["count"]
        pid = r.get("profile")
        if pid and r["brand"]:
            rec = reg.get(pid, {})
            alias_names = [a.split(":", 1)[1].lower()
                           for a in [pid] + rec.get("aliases", [])]
            names = " ".join(alias_names)
            # 品牌名可能带 -mobile 后缀，比对时要剥掉——别名里写的是
            # chrome99_android 而非 chrome-mobile99
            is_mobile_ua = r["brand"].endswith("-mobile")
            base_brand = r["brand"].replace("-mobile", "")
            brand_ok = (base_brand in names
                        or (base_brand == "chrome" and "chromium" in names))
            has_mobile_alias = any(MOBILE_ALIAS.search(a) for a in alias_names)
            all_derived = all(any(t in a for t in DERIVED) for a in alias_names)
            if not brand_ok:
                violations.append(("跨品牌", row["ua"][:60], pid))
            elif is_mobile_ua and not has_mobile_alias:
                # 移动端 UA 命中纯桌面 profile —— 默认是 split-brain，**除非**
                # 源码证明该版本区间里移动端与桌面同形态（平台分支在那些版本
                # 上不产生差异）。豁免要有据可查，所以判据取自段表产物的
                # same_as_desktop 字段，而不是在这里放宽成"移动端随便命中"。
                spans = desktop_equiv.get(r["brand"], [])
                if not any(lo <= r["version"] <= hi for lo, hi in spans):
                    violations.append(("移动端→桌面", row["ua"][:60], pid))
            elif not is_mobile_ua and all_derived:
                violations.append(("桌面→衍生/移动端", row["ua"][:60], pid))

    safe = stats.get("exact", 0) + stats.get("same-seg", 0)
    ratio = safe / total if total else 0

    print(f"真实 UA {len(rows)} 种 / {total} 次请求")
    for k in ("exact", "same-seg", "fallback", "no-version", "no-brand", "unparsed"):
        if stats.get(k):
            print(f"  {k:12s} {stats[k]:>6}  {stats[k]*100/total:5.1f}%")
    print(f"\n可安全伪装(exact+same-seg): {ratio*100:.1f}%  阈值 {MIN_SAFE_RATIO*100:.0f}%")

    # 移动端映射规则的证据。定 3 是下限：当前 6 条，掉到 3 条以下说明观测基础
    # 明显削弱，该重新评估这条规则而不是接着用。
    evidence = mobile_equivalence_evidence(reg)
    ev_ok = len(evidence) >= 3
    print(f"\n移动端↔桌面同指纹证据 {len(evidence)} 条"
          f"（规则依据，下限 3）{'' if ev_ok else '  ✗ 不足'}")
    for pid, mob, desk in evidence[:6]:
        print(f"    {pid:24s} 移动端{mob} ≡ 桌面{desk}")

    ok = ratio >= MIN_SAFE_RATIO and not violations and ev_ok
    for kind, ua, pid in violations[:6]:
        print(f"  ✗ {kind}: {ua} → {pid}")
    if not violations:
        print("  无跨品牌 / 衍生 profile 误用")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
