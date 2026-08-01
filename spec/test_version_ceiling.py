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


def main():
    print("扫描上限 vs 上游最新稳定版\n")
    stale, skipped = [], []
    for brand in sorted(FEEDS):
        if brand not in TARGETS:
            continue
        hi = TARGETS[brand][2]
        latest, info = fetch_latest(brand)
        if latest is None:
            skipped.append((brand, info))
            print(f"  ？ {brand:16s} 上限 {hi:>3}   取不到上游版本")
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
