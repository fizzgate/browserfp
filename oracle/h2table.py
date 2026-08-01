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
  3. **跨平台/跨品牌归一**，每条都有实证，且 `check_premises()` 会重验：

       Chromium 系（chrome/edge/opera，含 -mobile）→ 用桌面 Chrome 的推导
         依据：curl_cffi 的 chrome99_android ≡ chrome99、chrome131_android ≡
               chrome131；h2 的那几个常量在 http_network_session 里没有平台分支
       safari-mobile → 同版本 safari
         依据：wreq 的 SafariIos26 ≡ Safari26、SafariIPad18 ≡ Safari18

     **firefox-mobile 没有这条规则**：wreq 的 FirefoxAndroid135 与 Firefox135
     实测不同（HEADER_TABLE_SIZE 4096 vs 65536、INITIAL_WINDOW_SIZE 32768 vs
     131072）。一条规则在 Chromium 上成立不代表在 Gecko 上也成立。

源码推导本身已在 spec/test_chromium_h2.py 里用实采验过 —— 先验证再使用。

跑：python -m oracle.h2table [品牌]
"""

import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.uamap import MOBILE_ALIAS                            # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "..", "spec", "golden")

# 库文件里的条目名 → (品牌, 版本)。三家命名各不相同，统一在这里认。
#   curl_cffi   chrome100 / edge101 / safari155 / chrome99_android
#   tls_client  chrome_103 / firefox_110 / safari_ios_15_5
#   wreq        Chrome100 / Edge101 / SafariIPad18 / FirefoxAndroid135
# 命名形态与 uamap 完全一致，**平台词要先剥掉再匹配品牌+数字**：
#   safari_ios_15_5     品牌_平台_数字
#   safari172_ios       品牌数字_平台
#   FirefoxAndroid135   品牌平台数字   ← 不剥就永远匹配不上
# 第一版漏了第三种，firefox-mobile 因此算出 0 条，而 wreq:FirefoxAndroid135
# 明明就在库里。移动端判定直接复用 uamap.MOBILE_ALIAS，不另写一份。
NAME = re.compile(r"^(chrome|chromium|edge|opera|firefox|safari)"
                  r"[-_]*(\d{2,3})(?!\d)", re.I)


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
    is_mobile = bool(MOBILE_ALIAS.search(name))
    m = NAME.match(MOBILE_ALIAS.sub("", name) if is_mobile else name)
    if not m:
        return None
    brand = m.group(1).lower()
    if brand == "chromium":
        brand = "chrome"
    ver = int(m.group(2))
    # safari 的三位数写法（155 = 15.5）折回主版本
    if brand == "safari" and ver >= 100:
        ver //= 10
    if is_mobile:
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

    # 跨平台归一：safari-mobile 取同版本桌面 safari。
    if brand == "safari-mobile" and not fps:
        rec, why = resolve("safari", ver, obs, allow_source)
        if rec:
            return rec, f"移动端取同版本桌面（{why}）"

    # Chromium 系（含 -mobile）统一走桌面 Chrome 的源码推导
    engine = brand
    if brand.endswith("-mobile"):
        engine = brand[: -len("-mobile")]
    derived = None
    if allow_source and engine in ("chrome", "edge", "opera"):
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


def check_premises(obs=None):
    """重验上面那几条归一规则的前提，返回不成立的清单。

    规则写进代码就会一直用下去，而它依赖的实证是可能过期的 —— 新采一批数据
    发现 Chrome Android 的 h2 与桌面分叉了，规则却还在照常归一，就会静默产出
    错的 h2。所以每次建表都重验一遍，前提没了就该让门禁红。
    """
    obs = observed() if obs is None else obs

    def fp(brand, ver):
        hits = obs.get((brand, ver), {})
        s = {v["akamai_fingerprint"] for v in hits.values()}
        return next(iter(s)) if len(s) == 1 else None

    bad = []
    for ver in (99, 131):
        a, b = fp("chrome-mobile", ver), fp("chrome", ver)
        if a and b and a != b:
            bad.append(f"Chrome Android {ver} 的 h2 已与桌面分叉 —— "
                       "「Chromium 系统一用桌面推导」这条规则的前提没了")
    for ver in (18, 26):
        a, b = fp("safari-mobile", ver), fp("safari", ver)
        if a and b and a != b:
            bad.append(f"Safari iOS {ver} 的 h2 已与桌面分叉 —— "
                       "「safari-mobile 取桌面」这条规则的前提没了")
    # 反向断言：firefox 两端**必须**仍然不同。哪天它们一样了，说明数据或解析
    # 变了，那条"Gecko 不适用归一"的注释就该重新审，而不是继续躺在那里。
    a, b = fp("firefox-mobile", 135), fp("firefox", 135)
    if a and b and a == b:
        bad.append("Firefox Android 135 的 h2 现在与桌面相同了 —— "
                   "「Gecko 不适用跨平台归一」这条判断要重新审")
    return bad


def build(dest=None):
    """把整张表算出来写成 JSON，供 C 生成器与门禁共用。

    落成文件而不是每次现算，有两个理由：一是源码推导要联网取 Chromium 源码，
    C 的构建流程不该依赖网络；二是这张表值得被 diff —— 改一次判据就能看清
    到底动了哪些版本。
    """
    from oracle.covscan import NEVER_RELEASED, TARGETS
    obs = observed()
    bad = check_premises(obs)
    if bad:
        raise RuntimeError("归一规则的前提已失效，拒绝建表：" + "；".join(bad))

    out = {}
    for brand, (_tpl, lo, hi) in TARGETS.items():
        skip = NEVER_RELEASED.get(brand, set())
        rows = {}
        for v in range(lo, hi + 1):
            if v in skip:
                continue
            rec, why = resolve(brand, v, obs)
            if rec:
                rows[str(v)] = {
                    "akamai_fingerprint": rec["akamai_fingerprint"],
                    "settings": [list(x) for x in rec.get("settings") or []],
                    "window_update": rec.get("window_update") or 0,
                    "priorities": [list(x) for x in rec.get("priorities") or []],
                    "pseudo_header_order": rec.get("pseudo_header_order") or [],
                    "why": why,
                }
        out[brand] = rows
    if dest:
        with open(dest, "w") as f:
            json.dump(out, f, indent=1, ensure_ascii=False, sort_keys=True)
            f.write("\n")
    return out


def main(argv):
    obs = observed()
    pb = check_premises(obs)
    for b in pb:
        print(f"  ✗ 前提失效：{b}")
    # 位置参数才是品牌名；以 - 开头的一律当开关，否则 `--build` 会被当成
    # 品牌去查表，算出空集合再在 min() 上炸掉。
    pos = [a for a in argv[1:] if not a.startswith("-")]
    only = pos[0] if pos else None
    brands = sorted({b for b, _ in obs}) if not only else [only]
    for b in brands:
        vers = sorted(v for bb, v in obs if bb == b)
        conflict = sum(1 for v in vers
                       if len({x["akamai_fingerprint"]
                               for x in obs[(b, v)].values()}) > 1)
        print(f"  {b:16s} 收录 {len(vers):>3} 个版本"
              f"（{min(vers)}..{max(vers)}），库间冲突 {conflict} 个")
    if "--build" in argv:
        dest = os.path.join(HERE, "..", "spec", "h2table.json")
        t = build(dest)
        print(f"\n  已写出 {dest}："
              + "  ".join(f"{b}={len(v)}" for b, v in sorted(t.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
