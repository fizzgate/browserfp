"""把 profiles.json 编译成 C 静态数组 —— 避免运行时解析 JSON。

为什么不在 C 里读 JSON：
  · 这个库要跑在 nginx worker 里，启动期与请求期都不该做文件 I/O 与动态分配；
  · profile 数据是构建期就确定的常量，编译进只读段既快又省心；
  · 少一个 JSON 解析器就少一类解析漏洞。

生成的 profiles.inc 由 tlsfp.c 直接 #include。

跑：python csrc/gen_profiles.py > csrc/profiles.inc
"""

import json
import re
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "..", "spec", "profiles.json")
SEGMENTS_DIR = os.path.join(HERE, "..", "spec", "segments")


def load_segments():
    """加载源码段表，**逐段**筛选，只收 substitutable=true 的段。

    早先按品牌整体开关，太粗——Firefox 也有 4 个段的实采 golden 在同一来源库
    内就不一致（段划粗了），拿它们替代同样会发错指纹。

    与 oracle/uamap.py 用同一份数据、同一条判据——两边算法不一致的话，
    spec/test_c_ua_parity.py 会立刻抓到，但那时已经浪费一轮排查了。
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


def _h2_tables():
    """从 spec/h2table.json 生成独立的 h2 记录表与 (品牌,版本) 索引。

    **不从 profiles.json 取**：那里的 h2 挂在按 TLS 指纹去重后的记录上，两个
    版本 TLS 相同而 h2 不同时就会发错（实测 chrome 106-117 共 9 个版本中招）。
    h2table.json 是按版本解析的产物，判据见 oracle/h2table.py。

    相同的 h2 记录很多（一整段版本共用一份），所以按 akamai 去重成记录表，
    索引只存下标 —— 514 条索引实际只对应十几份记录。
    """
    path = os.path.join(os.path.dirname(HERE), "spec", "h2table.json")
    if not os.path.exists(path):
        raise SystemExit(f"缺 {path}；先跑 python -m oracle.h2table --build")
    with open(path) as f:
        table = json.load(f)

    def engine_of(brand):
        base = brand.split("-")[0]
        return ("chromium" if base in ("chrome", "chromium", "edge", "opera")
                else "gecko" if base == "firefox" else "webkit")

    recs, index = {}, []
    span = {}                       # akamai → (引擎集合, 最小版本, 最大版本)
    for brand in sorted(table):
        for ver in sorted(table[brand], key=int):
            r = table[brand][ver]
            key = r["akamai_fingerprint"]
            if key not in recs:
                recs[key] = (len(recs), r)
            index.append((brand, int(ver), recs[key][0]))
            engs, lo, hi = span.get(key, (set(), 9999, 0))
            engs.add(engine_of(brand))
            span[key] = (engs, min(lo, int(ver)), max(hi, int(ver)))

    # **每个 akamai 只对应一个引擎** —— 这是反查有意义的前提。实测 644 个
    # 组合归成 19 个指纹，没有一个跨引擎。哪天跨了，反查就只能报"不确定"，
    # 而不是继续给一个引擎名。
    mixed = {k: sorted(v[0]) for k, v in span.items() if len(v[0]) > 1}
    if mixed:
        raise SystemExit(f"有 akamai 跨引擎，反查不成立：{list(mixed.items())[:2]}")

    lines = []
    for key, (i, r) in sorted(recs.items(), key=lambda kv: kv[1][0]):
        st = [x for pair in (r.get("settings") or []) for x in pair]
        pr = [x for q in (r.get("priorities") or [])
              for x in (list(q) + [0, 0, 0, 0])[:4]]
        lines.append(c_u32_array(f"h2r{i}_set", st))
        lines.append(c_u32_array(f"h2r{i}_prio", pr))
    lines.append("")
    lines.append("static const tlsfp_h2 tlsfp_h2_records[] = {")
    for key, (i, r) in sorted(recs.items(), key=lambda kv: kv[1][0]):
        pseudo = ",".join(k[1] for k in (r.get("pseudo_header_order") or []))
        engs, lo, hi = span[key]
        lines.append(
            f'    {{h2r{i}_set, {len(r.get("settings") or [])}, '
            f'{r.get("window_update") or 0}, '
            f'h2r{i}_prio, {len(r.get("priorities") or [])}, '
            f'"{pseudo}", "{key}", "{next(iter(engs))}", {lo}, {hi}}},')
    lines.append("};")
    lines.append(f"#define TLSFP_H2_RECORD_COUNT {len(recs)}")
    lines.append("")
    lines.append("typedef struct { const char *brand; uint16_t version;"
                 " uint16_t rec; } tlsfp_h2_entry;")
    lines.append("static const tlsfp_h2_entry tlsfp_h2_table[] = {")
    for brand, ver, ri in index:
        lines.append(f'    {{"{brand}", {ver}, {ri}}},')
    lines.append("};")
    lines.append(f"#define TLSFP_H2_COUNT {len(index)}")
    return lines


def _header_value_table():
    """(品牌, 头名) → 由**浏览器**决定的取值。

    只收 accept / accept-encoding / upgrade-insecure-requests。
    accept-language 不在其中 —— 它取决于系统 locale 与用户设置，把采集环境的
    值抄进去等于把本机 locale 泄漏出去。sec-fetch-* 取决于请求类型，调用方
    比我们清楚。判据全来自真机实采，见 oracle/headerorder.py。
    """
    sys.path.insert(0, os.path.dirname(HERE))
    from oracle.headerorder import BRAND_ENGINE, values_for

    lines = ["typedef struct { const char *brand; const char *name;"
             " const char *value; } tlsfp_hv_entry;",
             "static const tlsfp_hv_entry tlsfp_hv_table[] = {"]
    n = 0
    for brand in sorted(BRAND_ENGINE):
        for name, val in sorted(values_for(brand).items()):
            v = val.replace('"', '\\"')
            lines.append(f'    {{"{brand}", "{name}", "{v}"}},')
            n += 1
    lines.append("};")
    lines.append(f"#define TLSFP_HV_COUNT {n}")
    return lines


def _uach_table():
    """(品牌, 版本) → sec-ch-ua。

    这一项手写必然错：里面的 GREASE 品牌是按主版本号确定性生成的
    （"Not" + chars[v%11] + "A" + chars[(v+1)%11] + "Brand"，版本取
    ["8","99","24"][v%3]），既非固定串也非随机串。推导见 oracle/uach.py，
    已用本机 Chrome 151 / Chromium 142 / Edge 151 三份实采验过。
    Opera 不在表里 —— 它的嵌入层会再加自己的品牌项，而本项目没有 Opera 实采。
    """
    path = os.path.join(os.path.dirname(HERE), "spec", "uach.json")
    if not os.path.exists(path):
        raise SystemExit(f"缺 {path}；先跑 python -m oracle.uach --build")
    with open(path) as f:
        table = json.load(f)
    lines = ["typedef struct { const char *brand; uint16_t version;"
             " const char *value; } tlsfp_uach_entry;",
             "static const tlsfp_uach_entry tlsfp_uach_table[] = {"]
    n = 0
    for brand in sorted(table):
        for ver in sorted(table[brand], key=int):
            v = table[brand][ver].replace('"', '\\"')
            lines.append(f'    {{"{brand}", {ver}, "{v}"}},')
            n += 1
    lines.append("};")
    lines.append(f"#define TLSFP_UACH_COUNT {n}")
    return lines


def _header_order_table():
    """品牌 → 请求头相对顺序（逗号分隔）。

    **只从真机实采推**，不碰库里那 240 条 header_order —— 那些是各库自己的
    发头顺序，互相矛盾（chrome 一项就 398 处），详见 oracle/headerorder.py。
    按引擎建模：Chromium 系共用一份，Gecko 与 WebKit 各一份。
    """
    sys.path.insert(0, os.path.dirname(HERE))
    from oracle.headerorder import BRAND_ENGINE, order_for

    lines = ["typedef struct { const char *brand; const char *order;"
             " int attested; const char *engine; } tlsfp_hdr_entry;",
             "static const tlsfp_hdr_entry tlsfp_hdr_table[] = {"]
    n = 0
    for brand in sorted(BRAND_ENGINE):
        order, attested = order_for(brand)
        if not order:
            continue
        eng = ("chromium" if brand.split("-")[0] in ("chrome", "edge", "opera")
               else "gecko" if brand.startswith("firefox") else "webkit")
        lines.append(f'    {{"{brand}", "{",".join(order)}", '
                     f'{1 if attested else 0}, "{eng}"}},')
        n += 1
    lines.append("};")
    lines.append(f"#define TLSFP_HDR_COUNT {n}")
    return lines


def c_u32_array(name, vals):
    """h2 的 SETTINGS 值与 window_update 都可能超过 16 位，必须用 u32。"""
    if not vals:
        return f"static const uint32_t {name}[1] = {{0}};"
    body = ", ".join(str(v) for v in vals)
    return f"static const uint32_t {name}[{len(vals)}] = {{{body}}};"


def c_u16_array(name, values):
    if not values:
        return f"static const uint16_t {name}[1] = {{0}};"
    body = ", ".join(f"0x{v:04x}" for v in values)
    return f"static const uint16_t {name}[{len(values)}] = {{{body}}};"


MOBILE_ALIAS = re.compile(r"android|ios|ipad|iphone|mobile", re.I)


# 与 oracle/uamap.py 的 ALIAS_BRANDS 必须一致：**不含 opera**。
# 库里的 opera 别名用的是 OPR 发行号（wreq:Opera116），而查表用的是 UA 里的
# 内核号（Chrome/），两套编号差十几位；按 OPR 号建表再拿内核号去查，会以
# exact 置信度返回错版本的指纹。Opera 统一走内核表。
# 这条规则两侧都要写，因为 C 表由本脚本独立生成 —— 只改 Python 会让三方
# 一致性门禁立刻报 opera 不符（实测就是这么被抓到的）。
ALIAS_BRANDS = r"^(chrome|chromium|firefox|safari|edge)"
ALIAS_BRANDS_T = r"^(chrome|chromium|firefox|safari|edge|tor)"


def brand_versions(rec):
    """从 aliases + versions + covers_versions 提取 (brand, version) 对。

    移动端别名归到 "<brand>-mobile" 品牌下，与桌面分开——两者指纹不同，混为
    一谈就成了 split-brain（实测生产 569 次移动端请求全命中桌面 profile，其中
    287 次连一个移动端别名都没有）。与 oracle/uamap.py 同一条判据。

    必须遍历**全部 aliases**：注册表按指纹去重，id 只是众多别名之一
    （Chrome151 与 Edge151 同指纹被并成一条、id 恰为 real:edge），
    只看 id 会漏掉这条同样服务 chrome 的事实。
    """
    out = set()
    brands = set()
    for alias in [rec["id"]] + rec.get("aliases", []):
        name = alias.split(":", 1)[1].lower()
        if "private" in name:
            continue
        if MOBILE_ALIAS.search(name):
            # utls 的 IOS_11_1 / IOS_13 命名里根本不出现品牌名，但 iOS 上所有
            # 浏览器都是系统 WebKit，那就是 iOS Safari 的指纹。与 uamap 同一条
            # 判据 —— 少了它 safari-mobile 表会缺 11-14 四个版本。
            mi = re.match(r"^ios[_-]?(\d{1,2})", name)
            if mi:
                out.add(("safari-mobile", int(mi.group(1))))
                continue
            # 三种命名形态（safari_ios_15_5 / safari172_ios / FirefoxAndroid135）
            # 先剥平台词再匹配品牌+数字，否则表会稀疏得没用
            base = MOBILE_ALIAS.sub("", name)
            mm = re.match(ALIAS_BRANDS + r"[-_]*(\d{1,3})", base)
            if mm:
                b = "chrome" if mm.group(1) == "chromium" else mm.group(1)
                v = int(mm.group(2))
                if b == "safari" and v >= 100:
                    v //= 10
                out.add((b + "-mobile", v))
            continue
        m = re.match(ALIAS_BRANDS_T + r"[-_]?(\d{2,3})(?!\d)", name)
        if m:
            b = "chrome" if m.group(1) == "chromium" else m.group(1)
            v = int(m.group(2))
            if b == "safari" and v >= 100:
                v //= 10
            out.add((b, v))
            brands.add(b)
        else:
            head = name.split("-")[0]
            b = {"chrome": "chrome", "chromium": "chrome", "edge": "edge",
                 "firefox": "firefox", "safari": "safari"}.get(head)
            if b:
                brands.add(b)
    # 条目若同时带移动端别名，说明这一份指纹在两个平台都被观测到，桌面
    # versions 里的版本号也该注册给移动端 —— 与 oracle/uamap.py 同一条判据。
    # 实测 real:safari 是本机 Safari 27 的实采、iOS 别名只到 26，不补这条会
    # 出现"同一份指纹，桌面有 27 而 safari-mobile 说没有"。
    has_mobile_alias = any(
        MOBILE_ALIAS.search(a.split(":", 1)[1])
        for a in [rec["id"]] + rec.get("aliases", []))
    for vs in (rec.get("versions") or []):
        mm = re.match(r"^(?:\D*?)(\d+)", str(vs))
        if mm:
            for b in brands:
                out.add((b, int(mm.group(1))))
                if has_mobile_alias:
                    out.add((b + "-mobile", int(mm.group(1))))
    for cv in (rec.get("covers_versions") or []):
        for b in brands:
            out.add((b, cv))
    return sorted(out)


def main():
    with open(REGISTRY) as f:
        registry = json.load(f)

    # 只导出默认配置形态：需显式 feature flag 才出现的变体不是正常用户行为，
    # 编进库里只会增大体积并稀释匹配结果。
    profiles = [r for r in registry if r.get("default_config", True)]

    out = ["/* 由 csrc/gen_profiles.py 从 spec/profiles.json 生成，请勿手改。 */",
           "/* 仅含默认配置形态；需 feature flag 才出现的变体不编入。 */", ""]

    # UA 映射表：(brand, version) → profile 下标。生产在 CDN 之后拿不到
    # ClientHello，只能按 UA 选指纹，故这张表是 C 侧的主入口。
    # 指纹分组号：同组即指纹相同。判 same-seg 时两端必须同组**且**同来源库。
    fp_group, groups = {}, {}
    for i, rec in enumerate(profiles):
        key = json.dumps(rec["tls"].get("ja4", "") , sort_keys=True)
        fp_group[i] = groups.setdefault(key, len(groups))
    # 来源库位掩码：跨库的"指纹相同"是巧合，不能据以替代
    SRC_BIT = {"curl_cffi": 1, "tls_client": 2, "wreq": 4, "utls": 8,
               "real": 16, "real_psk": 16, "curl_cffi_psk": 1,
               "real_quic": 16, "linux": 32}
    src_mask = {}
    for i, rec in enumerate(profiles):
        m = 0
        for a in [rec["id"]] + rec.get("aliases", []):
            m |= SRC_BIT.get(a.split(":", 1)[0], 0)
        src_mask[i] = m

    ua_rows = []
    direct = {}               # (brand, ver) → profile 下标，供段表补齐时找最近者
    for i, rec in enumerate(profiles):
        if rec.get("mode") != "initial":
            continue          # 会话恢复/QUIC 形态由连接阶段决定，不按 UA 选
        for brand, ver in brand_versions(rec):
            ua_rows.append((brand, ver, i, fp_group[i], src_mask[i], 0))
            direct.setdefault((brand, ver), i)

    # Edge 与 Chromium 版本号对齐（Edge 126 就是 Chromium 126），所以一条同时
    # 服务 chrome 与 edge 的 profile，它覆盖的 chrome 版本也适用于 edge。
    # Opera 不能这么做——版本号不对齐（Opera 110 约等于 Chromium 124）。
    # 与 oracle/uamap.py 同一条判据、同样的先到先得语义，两边不一致会被
    # test_c_ua_parity 抓到。
    for i, rec in enumerate(profiles):
        if rec.get("mode") != "initial":
            continue
        names = [rec["id"]] + rec.get("aliases", [])
        has_chrome = any(re.match(r"^\w+:(?:chrome|chromium)", n.lower())
                         for n in names)
        has_edge = any(re.match(r"^\w+:edge", n.lower()) for n in names)
        if not (has_chrome and has_edge):
            continue
        for (b, v), idx in list(direct.items()):
            if b == "chrome" and idx == i and ("edge", v) not in direct:
                direct[("edge", v)] = i
                ua_rows.append(("edge", v, i, fp_group[i], src_mask[i], 0))

    # 移动端与桌面同形态的段：直接把桌面条目也注册给移动端品牌。源码证明这些
    # 区间里平台分支不产生差异（Firefox 115 时 SCT 与 MLKEM 都还没启用、
    # Chrome 134 时 kPostQuantumKyber 两平台都是 True）。与 oracle/uamap.py 的
    # load_desktop_equivalent 同一份数据、同一条判据。
    for name in sorted(os.listdir(SEGMENTS_DIR)) if os.path.isdir(SEGMENTS_DIR) else []:
        if not name.endswith(".json"):
            continue
        with open(os.path.join(SEGMENTS_DIR, name)) as f:
            data = json.load(f)
        mb = data["brand"]
        if not mb.endswith("-mobile"):
            continue
        base = mb[: -len("-mobile")]
        # 桌面段表：same_as_desktop 只说明"两平台同形态"，还得那个桌面段本身
        # 可替代才能用。Python 侧回落时走的是桌面段表（只认 substitutable 的
        # 段），C 侧若只看 same_as_desktop 就会比 Python 宽松 —— 实测
        # firefox-mobile 111/119/121/122 上 C 给出了 profile 而 Python 拒绝，
        # 那几个版本所在的桌面段是 1:1 平局、本就不该用。
        desk_ok = set()
        desk_path = os.path.join(SEGMENTS_DIR, f"{base}.json")
        if os.path.exists(desk_path):
            with open(desk_path) as df:
                for ds in json.load(df)["segments"]:
                    if ds.get("substitutable"):
                        desk_ok.update(range(ds["from"], ds["to"] + 1))

        for seg in data["segments"]:
            if not seg.get("same_as_desktop"):
                continue
            have = sorted(v for (b, v) in direct
                          if b == base and seg["from"] <= v <= seg["to"]
                          and v in desk_ok)
            if not have:
                continue
            for ver in range(seg["from"], seg["to"] + 1):
                if (mb, ver) in direct or ver not in desk_ok:
                    continue
                near = min(have, key=lambda x: abs(x - ver))
                i = direct[(base, near)]
                direct[(mb, ver)] = i
                # 跨平台替代一律标 from_seg=1 —— 即便桌面表里正好有同号版本，
                # 那也是桌面采到的指纹，不是这个移动端版本被观测过。
                ua_rows.append((mb, ver, i, fp_group[i], src_mask[i], 1))

    # 按源码段表补齐：段内没有直接 profile 的版本，用同段最近者。第 6 列标 1
    # 表示"来自段表"，C 侧据此报 same-seg 而不是 exact——这个区分必须保留，
    # 调用方有权知道用的是直接采到的还是段内替代的。
    for brand, segs in load_segments().items():
        for seg in segs:
            have = sorted(v for (b, v) in direct if b == brand
                          and seg["from"] <= v <= seg["to"])
            if not have:
                continue      # 该段没有任何已采 profile，补不了
            for ver in range(seg["from"], seg["to"] + 1):
                if (brand, ver) in direct:
                    continue
                near = min(have, key=lambda x: abs(x - ver))
                i = direct[(brand, near)]
                ua_rows.append((brand, ver, i, fp_group[i], src_mask[i], 1))
    ua_rows.sort()

    # 重建 ClientHello 所需的原始字节：raw_* 保序且含 GREASE，extension_bodies
    # 是每个扩展的原始体。**比对用的字段不够重建** —— 比对剔了 GREASE、丢了
    # 每个扩展的具体内容，拿它拼出来的握手与真实浏览器不是一回事。
    # 全库 bodies 合计约 62KB，编进只读段完全可接受。
    for i, rec in enumerate(profiles):
        tls = rec["tls"]
        raw_ext = tls.get("raw_extensions") or []
        out.append(c_u16_array(f"p{i}_rawciph", tls.get("raw_ciphers") or []))
        out.append(c_u16_array(f"p{i}_rawext", raw_ext))
        bodies = tls.get("extension_bodies") or {}
        # 扩展体按 raw_extensions 的顺序平铺，另存每段的偏移与长度
        blob, offs, lens = [], [], []
        for e in raw_ext:
            hexs = bodies.get(str(e)) or bodies.get(e) or ""
            b = bytes.fromhex(hexs) if hexs else b""
            offs.append(len(blob))
            lens.append(len(b))
            blob.extend(b)
        if blob:
            body = ", ".join(f"0x{b:02x}" for b in blob)
            out.append(f"static const uint8_t p{i}_extblob[{len(blob)}] = {{{body}}};")
        else:
            out.append(f"static const uint8_t p{i}_extblob[1] = {{0}};")
        out.append(c_u16_array(f"p{i}_extoff", offs))
        out.append(c_u16_array(f"p{i}_extlen", lens))

    for i, rec in enumerate(profiles):
        tls = rec["tls"]
        out.append(c_u16_array(f"p{i}_ciphers", tls.get("ciphers") or []))
        out.append(c_u16_array(f"p{i}_exts", tls.get("extensions_ordered") or []))
        out.append(c_u16_array(f"p{i}_curves", tls.get("curves") or []))
        out.append(c_u16_array(f"p{i}_sigalgs", tls.get("sig_algs") or []))


    out.append("")
    def _prof_engine(rec):
        """profile 的引擎，从别名推。**实测 0/81 跨引擎**，所以这是良定义的；
        跨了就直接构建失败 —— 那时三层一致性检查的前提没了。"""
        es = set()
        for a in [rec["id"]] + rec.get("aliases", []):
            n = a.split(":", 1)[1].lower()
            if any(k in n for k in ("firefox", "tor", "gecko")):
                es.add("gecko")
            elif any(k in n for k in ("safari", "ios", "ipad")):
                es.add("webkit")
            elif any(k in n for k in ("chrome", "chromium", "edge", "opera")):
                es.add("chromium")
        if len(es) > 1:
            raise SystemExit(f"{rec['id']} 跨引擎 {sorted(es)}，"
                             "三层一致性检查的前提不成立")
        return next(iter(es)) if es else ""

    out.append("static const tlsfp_profile tlsfp_profiles[] = {")
    for i, rec in enumerate(profiles):
        tls = rec["tls"]
        h2 = (rec.get("h2") or {}).get("akamai_fingerprint") or ""
        out.append(
            f'    {{"{rec["id"]}", "{tls.get("ja4","")}", "{h2}", '
            f'"{rec.get("mode","initial")}", '
            f'p{i}_ciphers, {len(tls.get("ciphers") or [])}, '
            f'p{i}_exts, {len(tls.get("extensions_ordered") or [])}, '
            f'p{i}_curves, {len(tls.get("curves") or [])}, '
            f'p{i}_sigalgs, {len(tls.get("sig_algs") or [])}, '
            f'p{i}_rawciph, {len(tls.get("raw_ciphers") or [])}, '
            f'p{i}_rawext, {len(tls.get("raw_extensions") or [])}, '
            f'p{i}_extblob, p{i}_extoff, p{i}_extlen, '
            f'{tls.get("client_version") or 0x0303}, '
            f'{tls.get("session_id_len") or 32}, '
            f'"{_prof_engine(rec)}"}},')
    out.append("};")
    out.append(f"#define TLSFP_PROFILE_COUNT {len(profiles)}")
    out.append("")
    out.append("static const tlsfp_ua_entry tlsfp_ua_table[] = {")
    for brand, ver, idx, grp, mask, from_seg in ua_rows:
        out.append(f'    {{"{brand}", {ver}, {idx}, {grp}, {mask}, {from_seg}}},')
    out.append("};")
    out.append(f"#define TLSFP_UA_COUNT {len(ua_rows)}")
    out.append("")
    out.extend(_h2_tables())
    out.append("")
    out.extend(_header_order_table())
    out.append("")
    out.extend(_uach_table())
    out.append("")
    out.extend(_header_value_table())

    print("\n".join(out))
    print(f"/* 共 {len(profiles)} 条（注册表 {len(registry)} 条，"
          f"排除 {len(registry) - len(profiles)} 条非默认配置） */")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
