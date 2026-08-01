"""全版本覆盖扫描：逐版本构造 UA 走一遍映射，找出真实的覆盖边界。

**为什么不能只看生产 UA 的口径**：`spec/fixtures/prod_user_agents.json` 只有
60 种 UA，`fallback=0` 只说明**那批样本**没缺口。真实用户的版本分布远比样本宽，
今天没出现的版本明天就可能出现。要知道边界在哪，得对每个品牌逐版本问一遍。

**扫描用的 UA 是构造的**，与真实 UA 的差别只在版本号——模板取自生产样本里
该品牌最典型的那一条，这样解析路径与生产一致（Chromium 系取 `Chrome/` 而非
`Edg/`、移动端带平台标记）。

缺漏成因分两类，报告时分开列：
  · 段内没有任何实采 golden —— 源码能定段边界，定不出段内该用哪份指纹
  · 段内实采数据互相矛盾 —— 不是判段维度不足，是数据本身有问题

跑：python -m oracle.covscan            # 全品牌
    python -m oracle.covscan firefox    # 单品牌
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.uamap import UAMapper                              # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SEGMENTS_DIR = os.path.join(HERE, "..", "spec", "segments")

# 每个品牌的 UA 模板与扫描范围。范围上界取该品牌**已发布**的最高版本 ——
# 扫到不存在的版本只会得到一串无意义的"缺漏"。
TARGETS = {
    "chrome": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36", 70, 153),
    "chrome-mobile": (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/{v}.0.0.0 Mobile Safari/537.36", 70, 153),
    "firefox": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) "
        "Gecko/20100101 Firefox/{v}.0", 78, 153),
    "firefox-mobile": (
        "Mozilla/5.0 (Android 14; Mobile; rv:{v}.0) "
        "Gecko/{v}.0 Firefox/{v}.0", 78, 153),
    # Edge / Opera：用户点名的主流品牌，此前**一个版本都没扫过** —— uamap
    # 认得它们不等于覆盖到了。加进来后立刻暴露两个真问题：Android 版全部
    # no-brand（-mobile 后缀让 CHROMIUM_DERIVED 成员判断永远不命中），
    # 桌面侧缺 14/18 个版本（段表只按内核品牌建，衍生品牌查不到）。
    # 版本号一律用 UA 里的 **Chrome/** 内核号，与 uamap 的解析口径一致。
    "edge": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36 Edg/{v}.0.0.0",
        79, 153),          # Chromium 版 Edge 从 79 起
    "edge-mobile": (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/{v}.0.0.0 Mobile Safari/537.36 "
        "EdgA/{v}.0.0.0", 79, 153),
    "opera": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36 OPR/117.0.0.0",
        70, 153),
    "opera-mobile": (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/{v}.0.0.0 Mobile Safari/537.36 "
        "OPR/91.0.0.0", 70, 153),
    "safari": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/{v}.0 Safari/605.1.15", 12, 27),
    "safari-mobile": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS {v}_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{v}.0 "
        "Mobile/15E148 Safari/604.1", 12, 27),
}

# 从未发布的版本，不计入缺漏。
#   Chrome 82  —— 2020 年疫情期间从 81 直接跳到 83
#   Safari 19-25 —— 2025 年 Safari 从 18 直接跳到 26（跟随 OS 版本号），
#                   中间这些主版本号根本不存在
# 扫描上界要跟着已发布版本走：本机 Safari 已是 27.0，上界停在 26 就扫不到它，
# 那个区间出问题也发现不了。
NEVER_RELEASED = {
    # Chrome 82 因疫情取消发布，所有 Chromium 系品牌同样跳过这一号
    "chrome": {82}, "chrome-mobile": {82},
    "edge": {82}, "edge-mobile": {82},
    "opera": {82}, "opera-mobile": {82},
    "safari": set(range(19, 26)), "safari-mobile": set(range(19, 26)),
}


def _ranges(xs):
    if not xs:
        return "无"
    out, start, end = [], xs[0], xs[0]
    for x in xs[1:]:
        if x == end + 1:
            end = x
        else:
            out.append(str(start) if start == end else f"{start}-{end}")
            start = end = x
    out.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(out)


def _segment_reason(brand, ver):
    """该版本落在哪个段、那个段为什么不可替代。"""
    path = os.path.join(SEGMENTS_DIR, f"{brand}.json")
    if not os.path.exists(path):
        return "无该品牌段表"
    with open(path) as f:
        data = json.load(f)
    for seg in data["segments"]:
        if seg["from"] <= ver <= seg["to"]:
            return f"段 {seg['from']}-{seg['to']}：{seg.get('substitution_reason', '?')}"
    return "落在段表范围之外"


def scan(brand, mapper):
    tpl, lo, hi = TARGETS[brand]
    skip = NEVER_RELEASED.get(brand, set())
    missing = []
    for v in range(lo, hi + 1):
        if v in skip:
            continue
        if not mapper.lookup(tpl.format(v=v))["profile"]:
            missing.append(v)
    return missing, lo, hi


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    mapper = UAMapper()
    brands = [only] if only else list(TARGETS)
    total_missing = 0

    for brand in brands:
        if brand not in TARGETS:
            print(f"未知品牌 {brand}；可选 {sorted(TARGETS)}", file=sys.stderr)
            return 2
        missing, lo, hi = scan(brand, mapper)
        total_missing += len(missing)
        span = hi - lo + 1 - len(NEVER_RELEASED.get(brand, set()))
        print(f"\n{brand}  扫描 {lo}-{hi}（{span} 个已发布版本）"
              f"  缺 {len(missing)}：{_ranges(missing)}")
        # 按所属段归并，避免逐版本重复打印同一个理由
        seen = set()
        for v in missing:
            why = _segment_reason(brand, v)
            if why in seen:
                continue
            seen.add(why)
            print(f"    {why}")

    print(f"\n合计缺 {total_missing} 个版本。"
          "\n缺漏成因分两类：段内没有任何实采 golden（补齐靠实采），"
          "或段内实采数据互相矛盾（数据问题，非判段维度不足）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
