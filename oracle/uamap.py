"""UA → profile 映射：按客户端声称的 User-Agent 选出该用的 TLS 指纹。

**用途来自真实架构**：网关在 CDN 之后，拿不到客户端原始 ClientHello，只能看到
UA。出站代理浏览器流量时，需要按 UA 挑一个匹配的指纹去伪装——挑错就成了
"UA 说是 Chrome 150、TLS 却是别的形态"的 split-brain，比不伪装更容易被判。

**版本相近 ≠ 指纹相同**，所以不能简单取最近版本。实测同一品牌的版本会被压缩成
若干「指纹段」，段内任意版本指纹一致、跨段则不同。

**判"同段"必须在同一个来源库内比**。实测同一版本在不同库里的指纹就不一致：
    Firefox133  wreq vs tls_client   差 2 项
    Firefox135  wreq vs curl_cffi    差 1 项
    Firefox120  tls_client vs utls   差 2 项
各库抓包的环境、时间、feature 配置不同，跨库比出来的"相同/不同"没有意义。
映射因此分三档，并且**永远显式告知用的是哪一档**：

    exact     该主版本有直接对应的 profile
    same-seg  落在同一指纹段内（可安全替代）。两种证据都算：
                a) 同一来源库内两端指纹一致
                b) **源码段表**（spec/segments/*.json）证明同段——这条更强，
                   它读的是产生 ClientHello 的源码本身，不受"两端分属不同
                   来源库因而不可比"的限制
    fallback  只能跨段取最近 —— **默认不返回 profile**

**默认严格模式**：fallback 档一律返回 profile=None。拿最近版本的指纹去冒充另一个
版本，正是 split-brain 的来源——UA 说 Chrome 78、TLS 却是 Chrome 83 的形态，比
完全不伪装更容易被判。要伪装就必须精确。

调用方拿到 profile=None 时应放弃伪装（或走其他策略），并记录 nearest 以便补录。
`strict=False` 仅供覆盖率分析使用，不要在生产开启。

真实流量验证见 spec/test_ua_mapping.py，测试集取自生产 access.log。
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.coverage import FIELDS, SET_FIELDS                # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "..", "spec", "profiles.json")
SEGMENTS_DIR = os.path.join(HERE, "..", "spec", "segments")


def load_segments():
    """加载源码段表，**逐段**筛选，只收 substitutable=true 的段。

    早先是品牌级开关（firefox 整体可用、chrome 整体不可用），太粗：Firefox
    也有 4 个段的实采 golden 在同一来源库内就不一致（段划粗了），拿它们做替代
    同样会发错指纹。逐段判之后 firefox 5/9、chrome 1/8 段可用。

    每段的 substitutable 由 oracle/segments.py 落盘时算出：该段内实采 golden
    在**同一来源库内**是否一致。跨库差异是采集环境噪声（29 个多库收录版本中
    17 个有分歧），不能当作段划粗的证据。
    """
    out = {}
    if not os.path.isdir(SEGMENTS_DIR):
        return out
    for name in sorted(os.listdir(SEGMENTS_DIR)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(SEGMENTS_DIR, name)) as f:
            data = json.load(f)
        usable = [s for s in data["segments"] if s.get("substitutable")]
        if usable:
            out[data["brand"]] = usable
    return out


def load_desktop_equivalent():
    """{移动端品牌: [(from, to), ...]} —— 该区间的移动端形态与桌面完全相同。

    平台差异全部来自源码里的 ANDROID / IS_ANDROID 分支，而那些分支在某些版本
    区间根本不产生差异：Firefox 115 时 SCT 与 MLKEM 都还没启用，Chrome 134 时
    kPostQuantumKyber 在两个平台都是 True。这类区间可以直接用桌面 profile。

    **这不是合成样本**：派生规则在有 golden 的版本上验证过 —— 桌面 Firefox 135
    减去 SCT 与 MLKEM 后，与实采的 wreq:FirefoxAndroid135 逐字段一致。这里用的
    是同一条规则的退化情形（差异为空）。
    """
    out = {}
    if not os.path.isdir(SEGMENTS_DIR):
        return out
    for name in sorted(os.listdir(SEGMENTS_DIR)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(SEGMENTS_DIR, name)) as f:
            data = json.load(f)
        if not data["brand"].endswith("-mobile"):
            continue
        spans = [(s["from"], s["to"]) for s in data["segments"]
                 if s.get("same_as_desktop")]
        if spans:
            out[data["brand"]] = spans
    return out

# iOS 上**所有**浏览器都被 App Store 政策强制使用系统 WKWebView，自己不带
# TLS 栈。所以 FxiOS(Firefox)、EdgiOS(Edge)、CriOS(Chrome)、OPiOS(Opera) 发出的
# ClientHello 就是 iOS Safari 的，版本也该按 **iOS 版本**取而不是它们自己的版本
# 号——UA 里 FxiOS/128.4 跑在 iOS 15 上，用 128 去查 safari 表只会张冠李戴。
IOS_THIRD_PARTY = re.compile(r"\b(?:CriOS|FxiOS|EdgiOS|OPiOS|YaBrowser)/")
IOS_VERSION = re.compile(r"CPU (?:iPhone )?OS (\d+)[_.]")

# 顺序有意义：Edge/Opera 的 UA 里也含 "Chrome/"，必须先匹配更具体的标记。
UA_RULES = [
    ("edge",    re.compile(r"Edg(?:e|A|iOS)?/(\d+)")),
    ("opera",   re.compile(r"OPR/(\d+)")),
    ("firefox", re.compile(r"Firefox/(\d+)")),
    ("safari",  re.compile(r"Version/(\d+)[\d.]*\s+(?:Mobile/\S+\s+)?Safari/")),
    ("chrome",  re.compile(r"Chrome/(\d+)")),
]


# Chromium 系衍生浏览器：UA 里同时写着自己的版本号与内核的 Chrome 版本号。
# **内核版本才是决定 TLS 指纹的那个**，所以取 Chrome/ 而不是 OPR//Edg/。
# 实证（生产 UA）：
#   Opera 110 的 UA 里是 Chrome/125 —— OPR 版本与内核版本差了 15，按 OPR
#     版本号去查 chrome 表会张冠李戴
#   Edge 的 Edg/ 与 Chrome/ 完全一致（150/148/125/126 四种都对得上），所以
#     此前基于 alias 推断的 Edge↔Chromium 映射在 UA 层面也成立
CHROMIUM_DERIVED = {"edge", "opera"}
CHROME_VER = re.compile(r"Chrome/(\d+)")

# 移动端与同名桌面版是**两种指纹**，必须分开。品牌名加 -mobile 后缀，这样
# C 侧只按 brand 字符串匹配就能区分，不必改 API 传平台。
#
# 不这么做的后果是实测出来的：生产 569 次移动端请求全部命中了桌面 profile，
# 其中 287 次命中的 profile 连一个移动端别名都没有 —— UA 说 Android Firefox
# 115、TLS 却是桌面 Firefox 102 的形态，正是本项目一直在防的 split-brain。
# 另外 282 次是**对的**：注册表按指纹去重后，curl_cffi:safari155 的别名里同时
# 含桌面与 safari_ios_15_5，说明这两者指纹本就相同，那种命中有据可依。
MOBILE_UA = re.compile(r"Android|iPhone|iPad|iPod|; Mobile|Mobile Safari")
MOBILE_ALIAS = re.compile(r"android|ios|ipad|iphone|mobile", re.I)


def parse_ua(ua):
    """返回 (brand, major_version)；识别不了返回 (None, None)。

    对 Chromium 系衍生浏览器，version 返回的是**内核 Chrome 版本**——指纹由
    内核决定，用衍生版本号查表会错位。brand 仍保留原样，便于统计与排错。
    """
    if not ua or not ua.startswith("Mozilla/"):
        return None, None
    mobile = bool(MOBILE_UA.search(ua))
    # iOS 第三方浏览器：壳不同、TLS 栈同为系统 WebKit，一律按 iOS Safari 处理
    if IOS_THIRD_PARTY.search(ua):
        m = IOS_VERSION.search(ua)
        if m:
            return "safari-mobile", int(m.group(1))
        return None, None
    for brand, pat in UA_RULES:
        m = pat.search(ua)
        if m:
            ver = int(m.group(1))
            if brand in CHROMIUM_DERIVED:
                core = CHROME_VER.search(ua)
                if core:
                    ver = int(core.group(1))
            return (brand + "-mobile" if mobile else brand), ver
    return None, None


def _norm(fp):
    return json.dumps(
        {f: (sorted(fp.get(f) or []) if f in SET_FIELDS else fp.get(f))
         for f in FIELDS}, sort_keys=True)


class UAMapper:
    def __init__(self, registry_path=REGISTRY):
        with open(registry_path) as f:
            registry = json.load(f)
        self.segments = load_segments()
        self.desktop_equiv = load_desktop_equivalent()

        # 只用默认配置的首连形态：需 feature flag 才出现的变体不是正常用户行为，
        # 会话恢复/QUIC 形态由连接阶段决定，不该按 UA 选。
        self.by_brand = {}
        for rec in registry:
            if not rec.get("default_config", True) or rec.get("mode") != "initial":
                continue
            key = _norm(rec["tls"])
            for alias in [rec["id"]] + rec.get("aliases", []):
                name = alias.split(":", 1)[1].lower()
                # 排除移动端/衍生浏览器：它们的指纹与同名桌面版不同（实测
                # Firefox 桌面 vs Android 在 TLS 与 h2 两层都有差异），
                # 而 UA 里的版本号是按桌面品牌解析的，混进来会张冠李戴。
                # tor 尤其危险：Tor Browser 基于 Firefox，名字里的数字曾被
                # 当成 Firefox 版本，导致 "firefox 126 → tor145"。
                # 移动端别名单独建表（品牌名加 -mobile），不能与桌面混为一谈：
                # 两者指纹不同，而 UA 里的版本号解析方式相同，混进来会张冠李戴。
                # tor 尤其危险：Tor Browser 基于 Firefox，名字里的数字曾被当成
                # Firefox 版本，导致 "firefox 126 → tor145"。
                is_mobile = bool(MOBILE_ALIAS.search(name))
                if any(t in name for t in ("tor", "private")):
                    continue
                if is_mobile:
                    # 移动端别名有三种命名形态，都要认，否则表会稀疏得没用：
                    #   safari_ios_15_5    品牌_平台_数字
                    #   safari172_ios      品牌数字_平台
                    #   FirefoxAndroid135  品牌平台数字
                    # 先把平台词剥掉再匹配"品牌+数字"，三种就统一了。
                    # utls 用 IOS_11_1 / IOS_13 这种命名，别名里根本不出现
                    # "safari" —— 但 iOS 上所有浏览器都是系统 WebKit，这就是
                    # iOS Safari 的指纹。不认这个形态，safari-mobile 表就凭空
                    # 少掉 11-14 四个版本。
                    mi = re.match(r"^ios[_-]?(\d{1,2})", name)
                    if mi:
                        self.by_brand.setdefault("safari-mobile", {}).setdefault(
                            int(mi.group(1)), (rec, key))
                        continue
                    base = MOBILE_ALIAS.sub("", name)
                    mm = re.match(r"^(chrome|chromium|firefox|safari|edge|opera)"
                                  r"[-_]*(\d{1,3})", base)
                    if mm:
                        b = "chrome" if mm.group(1) == "chromium" else mm.group(1)
                        v = int(mm.group(2))
                        if b == "safari" and v >= 100:
                            v //= 10
                        self.by_brand.setdefault(b + "-mobile", {}).setdefault(
                            v, (rec, key))
                    continue
                m = re.match(r"^(chrome|chromium|firefox|safari|edge|opera)"
                             r"[-_]?(\d{2,3})(?!\d)", name)
                if not m:
                    continue
                brand = "chrome" if m.group(1) == "chromium" else m.group(1)
                ver = int(m.group(2))
                if brand == "safari" and ver >= 100:
                    ver //= 10
                self.by_brand.setdefault(brand, {}).setdefault(ver, (rec, key))
            # covers_versions：该实采指纹经验证同时适用的其他主版本（见
            # registry.COVERS）。这样既能命中生产 UA，又不必往库里塞推导样本。
            # 品牌要从**所有 aliases** 推断，不能只看 id：注册表按指纹去重，
            # Chrome151 与 Edge151 指纹相同被并成一条、id 恰好是 real:edge，
            # 只看 id 就会漏掉它同样服务 chrome 的事实（生产第一大 UA
            # Chrome 150 因此命不中）。
            brands = set()
            for alias in [rec["id"]] + rec.get("aliases", []):
                head = alias.split(":", 1)[1].split("-")[0].lower()
                b = {"chrome": "chrome", "chromium": "chrome", "edge": "edge",
                     "firefox": "firefox", "safari": "safari"}.get(head)
                if b:
                    brands.add(b)
            for cv in (rec.get("covers_versions") or []):
                for b in brands:
                    self.by_brand.setdefault(b, {}).setdefault(cv, (rec, key))

            # **Edge 与 Chromium 版本号对齐**（Edge 126 就是 Chromium 126），
            # 所以一条同时服务 chrome 与 edge 的 profile，它覆盖的 chrome 版本
            # 也适用于 edge。实证：注册表里有 6 条这样的 profile，跨 chrome
            # 83-149、跨多个来源库，其中 real:chromium 一条就同时是
            # chrome 132-149 与 edge 135-148。
            #
            # **Opera 不能这么做**：它的版本号与 Chromium 不对齐（Opera 110
            # 约等于 Chromium 124），curl_cffi:chrome131 一条就覆盖了
            # opera 116-131。按版本号套会张冠李戴。
            names = [rec["id"]] + rec.get("aliases", [])
            has_chrome = any(re.match(r"^\w+:(?:chrome|chromium)", n.lower())
                             for n in names)
            has_edge = any(re.match(r"^\w+:edge", n.lower()) for n in names)
            if has_chrome and has_edge:
                for v in list(self.by_brand.get("chrome", {})):
                    if self.by_brand["chrome"][v][0] is rec:
                        self.by_brand.setdefault("edge", {}).setdefault(v, (rec, key))

            # 真机条目的版本号在 versions 里，alias 里没有
            for vs in (rec.get("versions") or []):
                mm = re.match(r"^(?:\D*?)(\d+)", str(vs))
                brand = {"chrome": "chrome", "chromium": "chrome", "edge": "edge",
                         "firefox": "firefox", "safari": "safari"}.get(
                             rec["id"].split(":", 1)[1].split("-")[0])
                if mm and brand:
                    self.by_brand.setdefault(brand, {}).setdefault(
                        int(mm.group(1)), (rec, key))

    def lookup(self, ua, strict=True):
        """返回 {profile, confidence, brand, version, note}；无法映射时 profile=None。

        strict=True（默认）时 fallback 档不返回 profile，只在 nearest 里给出
        最接近者供补录参考。
        """
        brand, ver = parse_ua(ua)
        if not brand:
            return {"profile": None, "confidence": "unparsed", "brand": None,
                    "version": None, "note": "非浏览器 UA 或无法解析"}

        table = self.by_brand.get(brand)
        # Chromium 系衍生浏览器：version 已经是内核 Chrome 版本，直接查 chrome
        # 表最准。仍先看自家表——若某个衍生版本被实采过，那份数据优先于内核推断。
        # 移动端：自家表没有该版本时，若源码证明该区间与桌面无差异，就用桌面表
        if brand.endswith("-mobile") and ver not in (table or {}):
            base = brand[: -len("-mobile")]
            for lo, hi in self.desktop_equiv.get(brand, []):
                if lo <= ver <= hi:
                    dtbl = self.by_brand.get(base) or {}
                    if ver in dtbl:
                        rec, _ = dtbl[ver]
                        return {"profile": rec["id"], "confidence": "exact",
                                "brand": brand, "version": ver,
                                "note": f"源码证明 {lo}-{hi} 段移动端与桌面同形态"}
                    # 桌面表本身也常常不含该版本号 —— 桌面那边同样靠段表覆盖
                    # （firefox 表里只有 108/109/110/117/120/123，115 是段
                    # 112-118 给覆盖的）。所以回落必须连桌面段表一起走，只查
                    # 桌面表会白白落空。
                    for seg in self.segments.get(base, []):
                        if not (seg["from"] <= ver <= seg["to"]):
                            continue
                        near = sorted((v for v in dtbl
                                       if seg["from"] <= v <= seg["to"]),
                                      key=lambda x: abs(x - ver))
                        if near:
                            rec = dtbl[near[0]][0]
                            return {"profile": rec["id"], "confidence": "same-seg",
                                    "brand": brand, "version": ver,
                                    "note": f"源码证明 {lo}-{hi} 段移动端与桌面"
                                            f"同形态，取桌面段 {seg['from']}-"
                                            f"{seg['to']} 内的 {near[0]}"}
                        break
                    table = {**dtbl, **(table or {})}
                    break

        if brand in CHROMIUM_DERIVED:
            own = table or {}
            if ver not in own:
                chrome_tbl = self.by_brand.get("chrome") or {}
                if ver in chrome_tbl:
                    rec, _ = chrome_tbl[ver]
                    return {"profile": rec["id"], "confidence": "exact",
                            "brand": brand, "version": ver,
                            "note": f"按 UA 内核版本 Chrome/{ver} 取指纹"}
                table = {**chrome_tbl, **own} if own else chrome_tbl
        if not table:
            return {"profile": None, "confidence": "no-brand", "brand": brand,
                    "version": ver, "note": f"没有 {brand} 的任何 profile"}

        if ver in table:
            rec, _ = table[ver]
            return {"profile": rec["id"], "confidence": "exact",
                    "brand": brand, "version": ver, "note": ""}

        # 先问源码段表：它直接读产生 ClientHello 的源码，能回答"这两个版本
        # 是否同段"，不受两端分属不同来源库的限制（Firefox 126 此前就卡在
        # 123 与 128 跨库不可比上，只能弃权）。
        for seg in self.segments.get(brand, []):
            if not (seg["from"] <= ver <= seg["to"]):
                continue
            same = sorted((v for v in table if seg["from"] <= v <= seg["to"]),
                          key=lambda x: abs(x - ver))
            if same:
                rec = table[same[0]][0]
                return {"profile": rec["id"], "confidence": "same-seg",
                        "brand": brand, "version": ver,
                        "note": f"源码段 {seg['from']}-{seg['to']} 内，"
                                f"与 {same[0]} 同指纹"}
            break        # 落在段内但该段没有已采 profile，继续走下面的判据

        # 找上下最近的两个已知版本。判"落在同一指纹段内"有两个条件，缺一不可：
        #   1. 两端指纹相同
        #   2. **两端出自同一个来源库** —— 跨库的"相同"是巧合，跨库的"不同"
        #      也可能只是库间建模差异，都不能作为版本演进的证据
        lower = max((v for v in table if v < ver), default=None)
        upper = min((v for v in table if v > ver), default=None)
        if lower is not None and upper is not None:
            klo, khi = table[lower][1], table[upper][1]
            rlo, rhi = table[lower][0], table[upper][0]
            srcs_lo = {a.split(":", 1)[0] for a in [rlo["id"]] + rlo.get("aliases", [])}
            srcs_hi = {a.split(":", 1)[0] for a in [rhi["id"]] + rhi.get("aliases", [])}
            if klo == khi and (srcs_lo & srcs_hi):
                return {"profile": rhi["id"], "confidence": "same-seg",
                        "brand": brand, "version": ver,
                        "note": f"{lower}..{upper} 同库同指纹段，可安全替代"}

        near = upper if upper is not None else lower
        if near is None:
            return {"profile": None, "confidence": "no-version", "brand": brand,
                    "version": ver, "note": "该品牌无任何可用版本"}
        rec = table[near][0]
        # 跨段回退必须有**同品牌依据**，但判据要看该条目的全部 aliases 而非 id。
        # 注册表按指纹去重，id 只是众多别名中的一个：curl_cffi:tor145 的 aliases
        # 里含 wreq:Firefox128（Tor 基于 Firefox ESR，指纹本就相同），
        # curl_cffi:chrome119 含 wreq:Edge122。只看 id 会把这些**正确**的映射
        # 判成跨品牌而拒绝——构建版本表时按 aliases、检查时按 id，判据不一致是 bug。
        names = " ".join(a.split(":", 1)[1].lower()
                         for a in [rec["id"]] + rec.get("aliases", []))
        # 用基础品牌名比对：品牌加了 -mobile 后缀后，直接拿它去匹配别名字符串
        # 永远匹配不上（别名里写的是 chrome99_android 而非 chrome-mobile99），
        # 结果所有移动端版本都被判成"条目不含该品牌别名"而拒绝，掩盖了真正的
        # 判定结果。
        base_brand = brand.replace("-mobile", "")
        if base_brand not in names and not (base_brand == "chrome"
                                            and "chromium" in names):
            return {"profile": None, "confidence": "no-version", "brand": brand,
                    "version": ver,
                    "note": f"最近版本 {near} 的条目不含 {brand} 别名，拒绝套用"}
        return {"profile": None if strict else rec["id"],
                "confidence": "fallback",
                "brand": brand, "version": ver, "nearest": rec["id"],
                "note": f"无 {brand} {ver} 的精确指纹；最近版本 {near}"
                        f"（{rec['id']}）跨指纹段，严格模式下不使用"}


def main(argv):
    mapper = UAMapper()
    fixtures = os.path.join(HERE, "..", "spec", "fixtures", "prod_user_agents.json")
    if not os.path.exists(fixtures):
        print("缺 spec/fixtures/prod_user_agents.json", file=sys.stderr)
        return 2
    with open(fixtures) as f:
        rows = json.load(f)

    stats, total = {}, 0
    detail = []
    for row in rows:
        r = mapper.lookup(row["ua"])          # 默认严格：fallback 不给 profile
        stats[r["confidence"]] = stats.get(r["confidence"], 0) + row["count"]
        total += row["count"]
        detail.append((row["count"], r, row["ua"]))

    print(f"真实 UA 测试集：{len(rows)} 种，{total} 次请求\n")
    for conf in ("exact", "same-seg", "fallback", "no-version", "no-brand", "unparsed"):
        n = stats.get(conf, 0)
        if n:
            print(f"  {conf:12s} {n:>6} 次  {n * 100 / total:5.1f}%")

    gaps = {}
    for c, r, u in detail:
        if r["confidence"] in ("fallback", "no-version", "no-brand"):
            gaps[(r["brand"], r["version"])] = gaps.get((r["brand"], r["version"]), 0) + c
    if gaps:
        print("\n严格模式下无法伪装的版本（补齐这些即可全精确，按请求数排序）：")
        for (b, v), c in sorted(gaps.items(), key=lambda x: -x[1]):
            print(f"  {c:>5} 次  {b} {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
