"""真实生产 UA 里，有多少条我们**真的能出指纹**。

覆盖面此前只有一个数：644/650 个 (品牌, 版本)。那是我们**自己枚举出来的**目标集，
它回答不了「线上进来的流量有多少能被伪装」—— 用户不发版本号给我们挑，用户发的是
一条 UA 字符串。中间隔着 parse_ua 这一步，而它才是最容易漏的地方。

判据分两类，**不能混成一个百分比**：

    非浏览器认不出   是对的。扫描器、健康检查、裸 Mozilla/5.0 —— 给它们套浏览器
                     指纹才是错的（那是给爬虫伪造身份，不是我们的活）。
    浏览器认不出     是真缺口。UA 明确说了是某个浏览器，我们却出不了指纹，
                     web-relay 那条会直接 502。

跑：python -m spec.test_prod_ua_coverage
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.uamap import UAMapper, parse_ua                      # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURE = os.path.join(HERE, "fixtures", "prod_user_agents.json")

# 「是不是浏览器」用一条**规则**判，不靠列名单：真浏览器一定会发一个产品版本
# 标记。一条 UA 里连这些标记一个都没有，就是有人自己拼的字符串（扫描器、健康
# 检查、被截断的 UA），给它套浏览器指纹才是错的 —— 那是给爬虫伪造身份。
PRODUCT_TOKENS = ("Chrome/", "Firefox/", "Version/", "Edg", "OPR/",
                  "CriOS/", "FxiOS/", "UCBrowser/")


def looks_like_browser(ua):
    return any(t in ua for t in PRODUCT_TOKENS)


# 浏览器、但我们出不了指纹。**这份名单要能一条条说出理由**，不能当垃圾桶用。
KNOWN_BROWSER_GAPS = {
    "UCBrowser/": "UC Browser（安卓）自带内核，UA 里没有 Chrome/ 版本可依，"
                  "指纹库里也没有它的 profile。认不出 ⇒ 退回/拒绝，"
                  "**不拿 Chrome 顶替** —— 那正是 split-brain。",
}

# 必须映射成这个结果的几条。**壳不等于内核**：iOS 上所有浏览器都是系统 WebKit，
# Edge-on-iOS 要出 Safari 的指纹而不是 Edge 的；判错就是现实中不存在的组合。
MUST_MAP = [
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Version/15.0 EdgiOS/120.0.2210.56 Mobile/15E148 "
     "Safari/537.36", "safari-mobile", "iOS 上的 Edge：壳是 Edge，内核是系统 WebKit"),
]

# 覆盖率下限。**这是个棘轮**：parse_ua 被改坏、profile 被删，这个数就会掉。
MIN_BROWSER_COVERAGE = 1.0      # 浏览器类必须 100%（已知缺口另计，见下）
MAX_KNOWN_GAP_RATIO = 0.05      # 已知缺口最多占语料的 5%


def main():
    with open(FIXTURE) as f:
        uas = [row["ua"] for row in json.load(f)]
    mapper = UAMapper()

    ok, not_browser, known_gap, real_gap = [], [], [], []
    for ua in uas:
        brand, ver = parse_ua(ua)
        why = None
        if brand is None:
            why = "认不出 UA"
        else:
            # 与网关同一口径：TLS profile 与 h2 指纹缺任一都出不了指纹
            prof = mapper.lookup(ua).get("profile")
            if not prof:
                why = f"无 TLS profile（{brand} {ver}）"
        if not why:
            ok.append(ua)
            continue
        if not looks_like_browser(ua):
            not_browser.append(ua)
        elif any(m in ua for m in KNOWN_BROWSER_GAPS):
            known_gap.append(ua)
        else:
            real_gap.append((ua, why))

    bad = []
    n = len(uas)

    # 壳不等于内核：判错等于发一个现实中不存在的组合
    for ua, want_brand, why in MUST_MAP:
        got, gv = parse_ua(ua)
        if got != want_brand:
            bad.append(f"{why} —— 应判成 {want_brand}，实得 {got} {gv}")
    # 分母**不含已知缺口**（它们单独受下面两条约束），否则名单一长这个数就永远
    # 到不了 100%，下限也就形同虚设。
    browsers = len(ok) + len(real_gap)
    cov = len(ok) / browsers if browsers else 0.0

    for ua, why in real_gap:
        bad.append(f"{why}：{ua[:96]}\n        —— 这是个浏览器却出不了指纹，"
                   "web-relay 那条会直接 502。要么补 profile，要么写进 "
                   "KNOWN_BROWSER_GAPS 并说明理由")
    if cov < MIN_BROWSER_COVERAGE:
        bad.append(f"浏览器类覆盖率 {cov:.1%}，低于下限 {MIN_BROWSER_COVERAGE:.0%}")

    # ⚠ 已知缺口名单**不能当垃圾桶**：把浏览器往里一塞，覆盖率就永远 100%。
    # 两条约束把它钉住 —— 占比有上限，且名单里的每一条都必须真的在语料里出现
    # （出现不了说明它已经被修好或改名了，是残留，留着会把"已知"撑虚）。
    gap_ratio = len(known_gap) / n if n else 0.0
    if gap_ratio > MAX_KNOWN_GAP_RATIO:
        bad.append(f"已知缺口占了 {gap_ratio:.1%} 的流量（上限 {MAX_KNOWN_GAP_RATIO:.0%}）"
                   " —— 这不是「已知缺口」了，是真该补 profile")
    for m in KNOWN_BROWSER_GAPS:
        if not any(m in u for u in known_gap):
            bad.append(f"KNOWN_BROWSER_GAPS 里的 {m} 在语料里一条都没命中 —— "
                       "要么它已经被修好了，要么语料换了；残留会把「已知」撑虚")

    # 防平凡通过：语料读空 / 全被判成非浏览器时，上面两条都不会红
    if n < 40:
        bad.append(f"语料只有 {n} 条，远少于预期（60）—— 是不是读错文件了？")
    if len(ok) < 30:
        bad.append(f"只有 {len(ok)} 条能出指纹 —— 太少了，parse_ua 或注册表是不是坏了？")

    print(f"  生产 UA {n} 条：能出指纹 {len(ok)}，非浏览器（应认不出）{len(not_browser)}，"
          f"已知浏览器缺口 {len(known_gap)}，未知缺口 {len(real_gap)}")
    print(f"  浏览器类覆盖率 {cov:.1%}（{len(ok)}/{browsers}，已知缺口 "
          f"{len(known_gap)} 条 = {gap_ratio:.1%} 另计）")
    for m, why in KNOWN_BROWSER_GAPS.items():
        hit = sum(1 for u in known_gap if m in u)
        print(f"    已知缺口 {m} × {hit}：{why.splitlines()[0]}")

    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'真实 UA 覆盖面达标' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
