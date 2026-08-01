"""UA → profile 映射门禁，测试集取自真实生产流量。

此前所有验证都跑在自造样本上。本门禁用生产 access.log 里的真实 UA 分布
（spec/fixtures/prod_user_agents.json）衡量映射质量，这是唯一能回答
"我们的库够不够用"的口径。

三条判据：
  1. exact + same-seg 覆盖率不低于阈值 —— 这两档是可安全伪装的
  2. **不得跨品牌套用**：曾出现 firefox→tor145、edge→chrome124，比没有指纹更糟
  3. **不得使用移动端/衍生浏览器 profile 服务桌面 UA**（指纹实测不同）

跑：python -m spec.test_ua_mapping
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.uamap import UAMapper                             # noqa: E402
from oracle.match import Matcher                              # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "prod_user_agents.json")

MIN_SAFE_RATIO = 0.80          # exact + same-seg 占浏览器请求的比例下限
DERIVED = ("tor", "android", "ios", "ipad", "mobile", "private", "okhttp")


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
    stats, total, violations = {}, 0, []
    for row in rows:
        r = mapper.lookup(row["ua"])
        stats[r["confidence"]] = stats.get(r["confidence"], 0) + row["count"]
        total += row["count"]
        pid = r.get("profile")
        if pid and r["brand"]:
            rec = reg.get(pid, {})
            names = " ".join(a.split(":", 1)[1].lower()
                             for a in [pid] + rec.get("aliases", []))
            brand_ok = (r["brand"] in names
                        or (r["brand"] == "chrome" and "chromium" in names))
            if not brand_ok:
                violations.append(("跨品牌", row["ua"][:60], pid))
            elif all(any(t in a.split(":", 1)[1].lower() for t in DERIVED)
                     for a in [pid] + rec.get("aliases", [])):
                violations.append(("衍生/移动端", row["ua"][:60], pid))

    safe = stats.get("exact", 0) + stats.get("same-seg", 0)
    ratio = safe / total if total else 0

    print(f"真实 UA {len(rows)} 种 / {total} 次请求")
    for k in ("exact", "same-seg", "fallback", "no-version", "no-brand", "unparsed"):
        if stats.get(k):
            print(f"  {k:12s} {stats[k]:>6}  {stats[k]*100/total:5.1f}%")
    print(f"\n可安全伪装(exact+same-seg): {ratio*100:.1f}%  阈值 {MIN_SAFE_RATIO*100:.0f}%")

    ok = ratio >= MIN_SAFE_RATIO and not violations
    for kind, ua, pid in violations[:6]:
        print(f"  ✗ {kind}: {ua} → {pid}")
    if not violations:
        print("  无跨品牌 / 衍生 profile 误用")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
