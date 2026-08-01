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
    same-seg  落在同一指纹段内的相邻版本（段内指纹一致，可安全替代）
    fallback  只能跨段取最近 —— 有 split-brain 风险，调用方应记录并考虑放弃伪装

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

# 顺序有意义：Edge/Opera 的 UA 里也含 "Chrome/"，必须先匹配更具体的标记。
UA_RULES = [
    ("edge",    re.compile(r"Edg(?:e|A|iOS)?/(\d+)")),
    ("opera",   re.compile(r"OPR/(\d+)")),
    ("firefox", re.compile(r"Firefox/(\d+)")),
    ("safari",  re.compile(r"Version/(\d+)[\d.]*\s+(?:Mobile/\S+\s+)?Safari/")),
    ("chrome",  re.compile(r"Chrome/(\d+)")),
]


def parse_ua(ua):
    """返回 (brand, major_version)；识别不了返回 (None, None)。"""
    if not ua or not ua.startswith("Mozilla/"):
        return None, None
    for brand, pat in UA_RULES:
        m = pat.search(ua)
        if m:
            return brand, int(m.group(1))
    return None, None


def _norm(fp):
    return json.dumps(
        {f: (sorted(fp.get(f) or []) if f in SET_FIELDS else fp.get(f))
         for f in FIELDS}, sort_keys=True)


class UAMapper:
    def __init__(self, registry_path=REGISTRY):
        with open(registry_path) as f:
            registry = json.load(f)

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
                if any(t in name for t in ("android", "ios", "ipad", "mobile",
                                           "tor", "private", "okhttp")):
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

            # 真机条目的版本号在 versions 里，alias 里没有
            for vs in (rec.get("versions") or []):
                mm = re.match(r"^(?:\D*?)(\d+)", str(vs))
                brand = {"chrome": "chrome", "chromium": "chrome", "edge": "edge",
                         "firefox": "firefox", "safari": "safari"}.get(
                             rec["id"].split(":", 1)[1].split("-")[0])
                if mm and brand:
                    self.by_brand.setdefault(brand, {}).setdefault(
                        int(mm.group(1)), (rec, key))

    def lookup(self, ua):
        """返回 {profile, confidence, brand, version, note}；无法映射时 profile=None。"""
        brand, ver = parse_ua(ua)
        if not brand:
            return {"profile": None, "confidence": "unparsed", "brand": None,
                    "version": None, "note": "非浏览器 UA 或无法解析"}

        table = self.by_brand.get(brand)
        if not table:
            return {"profile": None, "confidence": "no-brand", "brand": brand,
                    "version": ver, "note": f"没有 {brand} 的任何 profile"}

        if ver in table:
            rec, _ = table[ver]
            return {"profile": rec["id"], "confidence": "exact",
                    "brand": brand, "version": ver, "note": ""}

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
        if brand not in names and not (brand == "chrome" and "chromium" in names):
            return {"profile": None, "confidence": "no-version", "brand": brand,
                    "version": ver,
                    "note": f"最近版本 {near} 的条目不含 {brand} 别名，拒绝套用"}
        return {"profile": rec["id"], "confidence": "fallback",
                "brand": brand, "version": ver,
                "note": f"跨指纹段取最近版本 {near}，有 split-brain 风险"}


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
        r = mapper.lookup(row["ua"])
        stats[r["confidence"]] = stats.get(r["confidence"], 0) + row["count"]
        total += row["count"]
        detail.append((row["count"], r, row["ua"]))

    print(f"真实 UA 测试集：{len(rows)} 种，{total} 次请求\n")
    for conf in ("exact", "same-seg", "fallback", "no-version", "no-brand", "unparsed"):
        n = stats.get(conf, 0)
        if n:
            print(f"  {conf:12s} {n:>6} 次  {n * 100 / total:5.1f}%")

    risky = [(c, r, u) for c, r, u in detail
             if r["confidence"] in ("fallback", "no-version", "no-brand")]
    if risky:
        print("\n有 split-brain 风险的（按请求数排序）：")
        for c, r, u in sorted(risky, key=lambda x: -x[0])[:8]:
            print(f"  {c:>5} 次  {r['brand']} {r['version']}  → {r['profile']}"
                  f"  {r['note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
