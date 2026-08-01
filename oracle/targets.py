"""curl_cffi 可用的 impersonate target 清单（本机实测，非文档抄录）。

**为什么不直接用 requests.BrowserType**：该枚举含别名——safari153 与 safari15_3
是同一个指纹的两种写法，直接遍历会把同一份 golden 采两遍，让"覆盖 N 个浏览器"
的计数虚高。ALIASES 显式列出别名对，UNIQUE 才是真实覆盖面。

版本敏感：curl_cffi 0.13.0（本机 pip 可见的最新发布版）。官方文档 latest 页面
还列了 chrome142/145/146、firefox144/147，但这些在 0.13.0 里不存在——文档领先
于 release。升级 curl_cffi 后必须重跑 verify_enum() 而不是照抄这里的常量。
"""

# 别名 → 规范名。两边指向同一份 curl-impersonate 配置。
ALIASES = {
    "safari15_3": "safari153",
    "safari15_5": "safari155",
    "safari17_0": "safari170",
    "safari17_2_ios": "safari172_ios",
    "safari18_0": "safari180",
    "safari18_0_ios": "safari180_ios",
}

# 按浏览器家族分组的唯一 target（31 个）。
FAMILIES = {
    "chrome": [
        "chrome99", "chrome100", "chrome101", "chrome104", "chrome107",
        "chrome110", "chrome116", "chrome119", "chrome120", "chrome123",
        "chrome124", "chrome131", "chrome133a", "chrome136",
    ],
    "chrome_android": ["chrome99_android", "chrome131_android"],
    "edge": ["edge99", "edge101"],
    "firefox": ["firefox133", "firefox135"],
    "safari": ["safari153", "safari155", "safari170", "safari180", "safari184", "safari260"],
    "safari_ios": ["safari172_ios", "safari180_ios", "safari184_ios", "safari260_ios"],
    "tor": ["tor145"],
}

UNIQUE = [t for family in FAMILIES.values() for t in family]


def verify_enum():
    """比对本模块的常量与实际安装的 curl_cffi 枚举。

    返回 (missing, extra)：missing = 枚举有而我们没列（新版本加了 target，
    覆盖面出现缺口）；extra = 我们列了而枚举没有（降级或写错）。
    两者都空才说明 UNIQUE 确实等于本机可用的全集。
    """
    from curl_cffi import requests

    enum_names = {n for n in dir(requests.BrowserType) if not n.startswith("_")}
    canonical = {ALIASES.get(n, n) for n in enum_names}
    ours = set(UNIQUE)
    return sorted(canonical - ours), sorted(ours - canonical)


if __name__ == "__main__":
    missing, extra = verify_enum()
    print(f"unique targets: {len(UNIQUE)}")
    for family, targets in FAMILIES.items():
        print(f"  {family:16s} {len(targets):2d}  {' '.join(targets)}")
    print(f"missing (enum has, we don't): {missing}")
    print(f"extra   (we have, enum doesn't): {extra}")
    raise SystemExit(1 if (missing or extra) else 0)
