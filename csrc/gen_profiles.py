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
    """加载源码段表，只收标了 usable_for_substitution 的品牌。

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
        if data.get("usable_for_substitution"):
            out[data["brand"]] = data["segments"]
    return out


def c_u16_array(name, values):
    if not values:
        return f"static const uint16_t {name}[1] = {{0}};"
    body = ", ".join(f"0x{v:04x}" for v in values)
    return f"static const uint16_t {name}[{len(values)}] = {{{body}}};"


def brand_versions(rec):
    """从 aliases + versions + covers_versions 提取 (brand, version) 对。

    必须遍历**全部 aliases**：注册表按指纹去重，id 只是众多别名之一
    （Chrome151 与 Edge151 同指纹被并成一条、id 恰为 real:edge），
    只看 id 会漏掉这条同样服务 chrome 的事实。
    """
    out = set()
    brands = set()
    for alias in [rec["id"]] + rec.get("aliases", []):
        name = alias.split(":", 1)[1].lower()
        # 移动端/衍生浏览器的指纹与同名桌面版不同，不参与按 UA 的桌面映射
        if any(t in name for t in ("android", "ios", "ipad", "mobile",
                                   "private", "okhttp")):
            continue
        m = re.match(r"^(chrome|chromium|firefox|safari|edge|opera|tor)"
                     r"[-_]?(\d{2,3})(?!\d)", name)
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
    for vs in (rec.get("versions") or []):
        mm = re.match(r"^(?:\D*?)(\d+)", str(vs))
        if mm:
            for b in brands:
                out.add((b, int(mm.group(1))))
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

    for i, rec in enumerate(profiles):
        tls = rec["tls"]
        out.append(c_u16_array(f"p{i}_ciphers", tls.get("ciphers") or []))
        out.append(c_u16_array(f"p{i}_exts", tls.get("extensions_ordered") or []))
        out.append(c_u16_array(f"p{i}_curves", tls.get("curves") or []))
        out.append(c_u16_array(f"p{i}_sigalgs", tls.get("sig_algs") or []))

    out.append("")
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
            f'p{i}_sigalgs, {len(tls.get("sig_algs") or [])}}},')
    out.append("};")
    out.append(f"#define TLSFP_PROFILE_COUNT {len(profiles)}")
    out.append("")
    out.append("static const tlsfp_ua_entry tlsfp_ua_table[] = {")
    for brand, ver, idx, grp, mask, from_seg in ua_rows:
        out.append(f'    {{"{brand}", {ver}, {idx}, {grp}, {mask}, {from_seg}}},')
    out.append("};")
    out.append(f"#define TLSFP_UA_COUNT {len(ua_rows)}")

    print("\n".join(out))
    print(f"/* 共 {len(profiles)} 条（注册表 {len(registry)} 条，"
          f"排除 {len(registry) - len(profiles)} 条非默认配置） */")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
