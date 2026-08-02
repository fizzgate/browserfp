"""扫描上限是否已经落后于**真实发布的**最新版本。

`test_coverage_ratchet` 里的 `check_scan_range` 查的是"上限 >= 库里已有数据"，
那是自洽性 —— 它管不了"浏览器发新版了、而我们的上限还停在旧号"。那种情况下
覆盖度报告会说"全覆盖"，但覆盖的是一个已经过时的版本区间，**新版本压根不在
统计口径里**。这正是上一轮 Edge/Opera 那类盲区的时间维度。

判据只能来自上游发布源，所以这条归第 3 层（联网）。

**取不到的源按"跳过"处理，不算失败**。本机实测：Mozilla 的 product-details
可达，而 Google 的几个版本源（versionhistory.googleapis.com、
chromiumdash.appspot.com、googlechromelabs.github.io）DNS 能解析但连不上
（chromiumdash 解析到 104.244.46.165，不是 Google 网段）。把"取不到"判成
失败，这条门禁在这台机器上就永远是红的，很快会被无视 —— 那比没有门禁更糟。
所以取不到就明说"没查到"，取得到的才断言。

跑：python -m spec.test_version_ceiling
"""

import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.covscan import TARGETS                              # noqa: E402

# 每个品牌一组候选源，逐个试，第一个取到的算数。
# 值是 (url, 从 JSON 里取版本号的函数)。
FEEDS = {
    "firefox": [
        ("https://product-details.mozilla.org/1.0/firefox_versions.json",
         lambda d: d.get("LATEST_FIREFOX_VERSION")),
    ],
    "chrome": [
        ("https://versionhistory.googleapis.com/v1/chrome/platforms/win/"
         "channels/stable/versions",
         lambda d: d["versions"][0]["version"] if d.get("versions") else None),
        ("https://chromiumdash.appspot.com/fetch_releases"
         "?channel=Stable&platform=Windows&num=1",
         lambda d: d[0]["version"] if d else None),
        ("https://googlechromelabs.github.io/chrome-for-testing/"
         "last-known-good-versions.json",
         lambda d: d["channels"]["Stable"]["version"]),
    ],
}


def fetch_latest(brand, timeout=20):
    """返回 (主版本号, 源 url)；全部取不到返回 (None, 说明)。"""
    tried = []
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for url, pick in FEEDS.get(brand, []):
        try:
            raw = opener.open(url, timeout=timeout).read()
            ver = pick(json.loads(raw))
            if ver:
                return int(str(ver).split(".")[0]), url
            tried.append(f"{url.split('/')[2]}: 响应里没有版本号")
        except Exception as e:
            tried.append(f"{url.split('/')[2]}: {type(e).__name__}")
    return None, "；".join(tried) if tried else "没有配置版本源"


def local_versions():
    """本机已装浏览器的版本 —— **上游源被挡时唯一可达的判据**。

    它不是"上游最新"，是一个**下界**：本机那台浏览器是真实发布过的，所以扫描
    上限至少不能低于它。用途很实际 —— 用户的 Chrome 自动更新到了我们表外的版本，
    这条会先发现。

    Google 的三个版本源在本机全部连不上（curl 也取不到，不是我们的装置问题），
    于是**最重要的那个品牌永远查不到**。有一个可达的下界，比完全没有强。
    """
    from oracle.capture_browser import BROWSERS, browser_version
    out = {}
    for brand, path in BROWSERS.items():
        if not os.path.exists(path):
            continue
        v = browser_version(path)
        m = re.search(r"(\d+)\.", str(v or ""))
        if m:
            out[brand] = (int(m.group(1)), str(v).strip())
    return out


def main():
    print("扫描上限 vs 上游最新稳定版\n")
    stale, skipped = [], []
    local = local_versions()
    for brand in sorted(FEEDS):
        if brand not in TARGETS:
            continue
        hi = TARGETS[brand][2]
        latest, info = fetch_latest(brand)
        if latest is None:
            # 上游取不到时退到**本机已装版本**这个下界。它回答不了"上游最新是
            # 多少"，但能回答"有没有落后于一台真实存在的浏览器"。
            lv = local.get(brand)
            if lv and hi < lv[0]:
                stale.append((brand, hi, lv[0], f"本机已装：{lv[1]}"))
                print(f"  ❌ {brand:16s} 上限 {hi:>3}   本机已装 {lv[0]}（上游取不到）")
            else:
                skipped.append((brand, info))
                extra = f"，本机已装 {lv[0]}（未超上限）" if lv else ""
                print(f"  ？ {brand:16s} 上限 {hi:>3}   取不到上游版本{extra}")
            continue
        mark = "✅" if hi >= latest else "❌"
        print(f"  {mark} {brand:16s} 上限 {hi:>3}   上游最新 {latest}")
        if hi < latest:
            stale.append((brand, hi, latest, info))

    for brand, hi, latest, url in stale:
        print(f"\n✗ {brand} 已发布到 {latest}，而扫描上限还是 {hi} —— "
              f"{hi + 1}..{latest} 完全不在覆盖统计口径里。")
        print(f"   把 oracle/covscan.py 的 TARGETS['{brand}'] 上限抬到 {latest}，"
              f"再看棘轮报多少缺漏。（来源 {url}）")
    for brand, info in skipped:
        print(f"\n？ {brand}: {info}")
        print("   取不到不算失败，但也不构成'上限没落后'的证据。")

    ok = not stale
    print(f"\n{'扫描上限未落后于上游' if ok else f'{len(stale)} 个品牌的扫描上限已过时'}"
          f"{'（其中 %d 个品牌没查到）' % len(skipped) if skipped else ''}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
