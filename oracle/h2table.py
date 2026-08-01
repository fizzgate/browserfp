"""按 (品牌, 版本) 解析 h2 指纹 —— 独立于 TLS 的去重。

**为什么必须独立**：注册表按 **TLS 指纹**去重，h2 只是搭在合并后的那条记录上。
两个版本 TLS 完全相同、h2 却不同，是很常见的事 —— Chrome 的 h2 参数改在
`net/http/http_network_session.cc`，与 BoringSSL 那边的 ClientHello 各改各的。
实测后果：

    curl_cffi:chrome100 这一条 profile 的 36 个别名带着**三种** h2 指纹
    全库 8/81 条 profile 有这个问题，53 个别名拿到的 h2 不是自己那份
    UA 口径下，chrome 106-117 共 9 个版本拿到的 h2，**没有任何一个库**
    把它归给这些版本

TLS 对、h2 不对，是一个现实中不存在的组合，比不伪装更容易被判。所以 h2 要有
自己的按版本解析，不能继承 TLS 去重的结果。

判据优先级：

  1. **该版本自己的库条目**。多个库都收录时要求一致；不一致则记为冲突，
     由第 2 条裁决 —— 实测 wreq 把 Chrome110 记成了旧形态，而 curl_cffi 与
     tls_client 都是新形态，源码也站新形态这边。
  2. **源码推导**（Chromium 系，见 oracle/chromiumh2.py）。它同时用来补缺口：
     库里没收录的版本，只要源码取得到就能推出来。

源码推导本身已在 spec/test_chromium_h2.py 里用实采验过 —— 先验证再使用。

跑：python -m oracle.h2table [品牌]
"""

import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "..", "spec", "golden")

# 库文件里的条目名 → (品牌, 版本)。三家命名各不相同，统一在这里认。
#   curl_cffi   chrome100 / edge101 / safari155 / chrome99_android
#   tls_client  chrome_103 / firefox_110 / safari_ios_15_5
#   wreq        Chrome100 / Edge101 / SafariIPad18 / FirefoxAndroid135
NAME = re.compile(r"^(chrome|chromium|edge|opera|firefox|safari)"
                  r"[-_]?(\d{2,3})(?!\d)", re.I)
MOBILE = re.compile(r"android|_ios|ios_|ipad|mobile", re.I)


def _load_sources():
    out = {}
    for f in sorted(glob.glob(os.path.join(GOLDEN, "h2_*.json"))):
        lib = os.path.basename(f)[3:-5]
        with open(f) as fh:
            out[lib] = json.load(fh)
    return out


def _parse_name(name):
    """条目名 → (品牌, 版本)；认不出返回 None。

    **移动端要带 -mobile 后缀**，不能与桌面混：Chrome 在 Android 上的网络栈
    参数有平台分支，混进来会让桌面的判据把移动端也一起裁了。
    """
    m = NAME.match(name)
    if not m:
        return None
    brand = m.group(1).lower()
    if brand == "chromium":
        brand = "chrome"
    ver = int(m.group(2))
    # safari 的三位数写法（155 = 15.5）折回主版本
    if brand == "safari" and ver >= 100:
        ver //= 10
    if MOBILE.search(name):
        brand += "-mobile"
    return brand, ver


def observed(sources=None):
    """{(brand, ver): {lib: akamai}} —— 各库对每个版本自报的 h2。"""
    sources = sources or _load_sources()
    out = {}
    for lib, entries in sources.items():
        for name, val in entries.items():
            if not isinstance(val, dict) or not val.get("akamai_fingerprint"):
                continue
            key = _parse_name(name)
            if not key:
                continue
            out.setdefault(key, {})[f"{lib}:{name}"] = val
    return out


def resolve(brand, ver, obs=None, allow_source=True):
    """返回 (h2记录, 依据说明)；无法确定时返回 (None, 原因)。"""
    obs = observed() if obs is None else obs
    hits = obs.get((brand, ver), {})
    fps = {}
    for who, val in hits.items():
        fps.setdefault(val["akamai_fingerprint"], []).append((who, val))

    if len(fps) == 1:
        fp, rows = next(iter(fps.items()))
        return rows[0][1], f"{len(rows)} 个库一致"

    derived = None
    if allow_source and brand in ("chrome", "edge", "opera"):
        try:
            from oracle.chromiumh2 import akamai, chrome_h2
            rec = chrome_h2(ver)
            derived = (akamai(rec), rec)
        except Exception:
            derived = None

    if len(fps) > 1:
        # 库之间冲突：交给源码裁决。裁决不了就弃权 —— 猜一个等于随机挑一个
        # 浏览器的 h2 配上另一个浏览器的 TLS。
        if derived and derived[0] in fps:
            rows = fps[derived[0]]
            return rows[0][1], f"库间冲突（{len(fps)} 种），源码裁定"
        return None, (f"库间冲突（{len(fps)} 种）且源码"
                      f"{'给出第三种' if derived else '取不到'}，弃权")

    if derived:
        fp, rec = derived
        return {
            "akamai_fingerprint": fp,
            "settings": [list(x) for x in rec["settings"]],
            "window_update": rec["window_update"],
            "priorities": [],
            "pseudo_header_order": rec["pseudo_header_order"],
        }, "源码推导"
    return None, "无库条目且源码取不到"


def main(argv):
    obs = observed()
    only = argv[1] if len(argv) > 1 else None
    brands = sorted({b for b, _ in obs}) if not only else [only]
    for b in brands:
        vers = sorted(v for bb, v in obs if bb == b)
        conflict = sum(1 for v in vers
                       if len({x["akamai_fingerprint"]
                               for x in obs[(b, v)].values()}) > 1)
        print(f"  {b:16s} 收录 {len(vers):>3} 个版本"
              f"（{min(vers)}..{max(vers)}），库间冲突 {conflict} 个")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
