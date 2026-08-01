"""ClientHello 原始字节 → 结构化指纹（JA3 / JA4 / 逐扩展明细）。

**为什么自己算而不打 tls.peet.ws**：远端只给 hash，两个 target 不一致时只知道
"不一样"，定位不到是哪个扩展错了。本模块保留扩展的原始顺序和内容，比对失败能
直接指出"第 7 个扩展应为 0x0017 实际 0x002b"。附带好处是零外网依赖——31 个
target × 每次回归打远端会被限流，本地跑毫秒级。

JA4 规范：https://github.com/FoxIO-LLC/ja4 (ja4_a_ja4_b_ja4_c)
"""

import hashlib
import struct


def is_grease(v: int) -> bool:
    """GREASE 值（RFC 8701）：0x0a0a, 0x1a1a … 0xfafa，高低字节相同且低半字节为 a。

    JA3/JA4 都必须先剔除 GREASE，否则 Chrome 每连接随机换 GREASE 值会让
    指纹每次都变。
    """
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


class ParseError(ValueError):
    pass


def _u8(b, o):
    return b[o], o + 1


def _u16(b, o):
    return struct.unpack_from(">H", b, o)[0], o + 2


def _u24(b, o):
    return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2], o + 3


def parse_client_hello(record: bytes) -> dict:
    """解析一条 TLS record（含 5 字节 record 头）里的 ClientHello。

    返回 dict：tls_record_version / client_version / ciphers / extensions
    （[(id, body_bytes)] 保序）/ curves / sig_algs / alpn / supported_versions /
    sni。GREASE 一律保留在 raw_* 字段、剔除后放在主字段——两者都要，因为
    "有没有发 GREASE"本身是指纹的一部分（Node.js 不发，Chrome 发）。
    """
    if len(record) < 5:
        raise ParseError("record too short")
    if record[0] != 0x16:
        raise ParseError(f"not a handshake record: type=0x{record[0]:02x}")
    rec_ver, _ = _u16(record, 1)
    rec_len, _ = _u16(record, 3)
    body = record[5:5 + rec_len]
    if len(body) < rec_len:
        raise ParseError(f"truncated record: want {rec_len} got {len(body)}")

    o = 0
    hs_type, o = _u8(body, o)
    if hs_type != 0x01:
        raise ParseError(f"not a ClientHello: handshake_type={hs_type}")
    hs_len, o = _u24(body, o)
    client_ver, o = _u16(body, o)
    random_bytes = body[o:o + 32]
    o += 32
    sid_len, o = _u8(body, o)
    session_id = body[o:o + sid_len]
    o += sid_len

    cs_len, o = _u16(body, o)
    raw_ciphers = list(struct.unpack_from(f">{cs_len // 2}H", body, o))
    o += cs_len

    comp_len, o = _u8(body, o)
    compression = list(body[o:o + comp_len])
    o += comp_len

    extensions = []
    if o < len(body):
        ext_total, o = _u16(body, o)
        end = o + ext_total
        while o < end:
            ext_id, o = _u16(body, o)
            ext_len, o = _u16(body, o)
            extensions.append((ext_id, body[o:o + ext_len]))
            o += ext_len

    out = {
        "tls_record_version": rec_ver,
        "client_version": client_ver,
        "session_id_len": sid_len,
        "random_hex": random_bytes.hex(),
        "compression": compression,
        "raw_ciphers": raw_ciphers,
        "ciphers": [c for c in raw_ciphers if not is_grease(c)],
        "raw_extensions": [e for e, _ in extensions],
        "extensions": [e for e, _ in extensions if not is_grease(e)],
        "extension_bodies": {e: b.hex() for e, b in extensions},
        "has_grease": any(is_grease(c) for c in raw_ciphers)
        or any(is_grease(e) for e, _ in extensions),
    }
    out.update(_parse_known_extensions(extensions))
    return out


def _parse_known_extensions(extensions) -> dict:
    """展开指纹相关的扩展内容。未出现的扩展留空，不用 None——下游按空列表比对。"""
    res = {"sni": None, "curves": [], "sig_algs": [], "alpn": [],
           "supported_versions": [], "point_formats": [], "psk_modes": [],
           "cert_compression": [], "record_size_limit": None,
           "app_settings": [], "ech": False}
    for ext_id, body in extensions:
        if ext_id == 0x0000 and len(body) >= 5:          # server_name
            name_len = struct.unpack_from(">H", body, 3)[0]
            res["sni"] = body[5:5 + name_len].decode("ascii", "replace")
        elif ext_id == 0x000A and len(body) >= 2:        # supported_groups
            n = struct.unpack_from(">H", body, 0)[0] // 2
            res["curves"] = [g for g in struct.unpack_from(f">{n}H", body, 2)
                             if not is_grease(g)]
        elif ext_id == 0x000B and len(body) >= 1:        # ec_point_formats
            res["point_formats"] = list(body[1:1 + body[0]])
        elif ext_id == 0x000D and len(body) >= 2:        # signature_algorithms
            n = struct.unpack_from(">H", body, 0)[0] // 2
            res["sig_algs"] = list(struct.unpack_from(f">{n}H", body, 2))
        elif ext_id == 0x0010 and len(body) >= 2:        # ALPN
            o, end = 2, 2 + struct.unpack_from(">H", body, 0)[0]
            while o < end:
                ln = body[o]
                res["alpn"].append(body[o + 1:o + 1 + ln].decode("ascii", "replace"))
                o += 1 + ln
        elif ext_id == 0x002B and len(body) >= 1:        # supported_versions
            n = body[0] // 2
            res["supported_versions"] = [
                v for v in struct.unpack_from(f">{n}H", body, 1) if not is_grease(v)]
        elif ext_id == 0x002D and len(body) >= 1:        # psk_key_exchange_modes
            res["psk_modes"] = list(body[1:1 + body[0]])
        elif ext_id == 0x001B and len(body) >= 1:        # compress_certificate
            n = body[0] // 2
            res["cert_compression"] = list(struct.unpack_from(f">{n}H", body, 1))
        elif ext_id == 0x001C and len(body) >= 2:        # record_size_limit
            res["record_size_limit"] = struct.unpack_from(">H", body, 0)[0]
        elif ext_id == 0x4469 and len(body) >= 2:        # application_settings (ALPS)
            o, end = 2, 2 + struct.unpack_from(">H", body, 0)[0]
            while o < end:
                ln = body[o]
                res["app_settings"].append(body[o + 1:o + 1 + ln].decode("ascii", "replace"))
                o += 1 + ln
        elif ext_id == 0xFE0D:                            # encrypted_client_hello
            res["ech"] = True
    return res


def ja3(ch: dict) -> tuple:
    """JA3 字符串与 md5。

    注意 JA3 对扩展**顺序敏感**，而 Chrome 自 110 起每连接随机打乱扩展顺序
    (RFC 8701 permutation)，所以 Chrome 的 JA3 每次都不同——不能拿来做断言，
    只用于跟历史抓包对照。稳定的判据用 ja4()。
    """
    curves = "-".join(str(c) for c in ch["curves"])
    fmts = "-".join(str(p) for p in ch["point_formats"])
    s = "{},{},{},{},{}".format(
        ch["client_version"],
        "-".join(str(c) for c in ch["ciphers"]),
        "-".join(str(e) for e in ch["extensions"]),
        curves, fmts)
    return s, hashlib.md5(s.encode()).hexdigest()


def ja4(ch: dict) -> str:
    """JA4 指纹（顺序无关，Chrome 的扩展乱序不影响取值）。"""
    versions = ch["supported_versions"] or [ch["client_version"]]
    ver_map = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}
    ja4_ver = ver_map.get(max(versions), "00")

    sni_flag = "d" if ch["sni"] else "i"
    n_ciphers = min(len(ch["ciphers"]), 99)
    # 扩展计数含 SNI 与 ALPN（JA4 规范：计数含、but 排序哈希时排除）
    n_exts = min(len(ch["extensions"]), 99)
    alpn = ch["alpn"][0] if ch["alpn"] else ""
    alpn_code = (alpn[0] + alpn[-1]) if alpn else "00"

    ja4_a = f"t{ja4_ver}{sni_flag}{n_ciphers:02d}{n_exts:02d}{alpn_code}"

    cipher_str = ",".join(f"{c:04x}" for c in sorted(ch["ciphers"]))
    ja4_b = hashlib.sha256(cipher_str.encode()).hexdigest()[:12] if cipher_str else "0" * 12

    ext_sorted = sorted(e for e in ch["extensions"] if e not in (0x0000, 0x0010))
    ext_str = ",".join(f"{e:04x}" for e in ext_sorted)
    sig_str = ",".join(f"{s:04x}" for s in ch["sig_algs"])
    ja4_c_input = f"{ext_str}_{sig_str}" if sig_str else ext_str
    ja4_c = hashlib.sha256(ja4_c_input.encode()).hexdigest()[:12] if ext_str else "0" * 12

    return f"{ja4_a}_{ja4_b}_{ja4_c}"


def fingerprint(record: bytes, drop_sni: bool = False) -> dict:
    """一步到位：raw record → 可直接落 golden 的比对结构。

    drop_sni=True 时把带 SNI 的握手归一化成无 SNI 形态。**与库里的 golden 比对
    前必须这么做**：库里的 profile 全部采自无 SNI 场景（ja4 首段 t13i），而真机
    经代理采到的是真实形态（t13d），直接比会得出"库里没有这个指纹"的错误结论。
    实测 Firefox 149：
        真机          t13d1717h2_5b57614c22b0_3cbfd9057e0d
        real:firefox  t13i1716h2_5b57614c22b0_3cbfd9057e0d
    后两段本来就一致——ja4 的扩展哈希在计算时就排除了 server_name 与 ALPN，
    差异只在首段的 SNI 标志与扩展计数。

    raw_extensions / raw_ciphers / extension_bodies 三个字段带 GREASE 且保序，
    比对时用不到（比对用剔除 GREASE 的版本），但**重建 ClientHello 时必需**：
    GREASE 插在哪个位置、每个扩展的 body 长什么样，只有原始形态才有。少了它们
    golden 只能验证、不能当 profile 用。
    """
    ch = parse_client_hello(record)
    if drop_sni:
        ch["sni"] = None
        ch["extensions"] = [e for e in ch["extensions"] if e != 0x0000]
        ch["raw_extensions"] = [e for e in ch["raw_extensions"] if e != 0x0000]
        ch["extension_bodies"] = {k: v for k, v in ch["extension_bodies"].items()
                                  if k != 0x0000}
    ja3_str, ja3_hash = ja3(ch)
    return {
        "ja4": ja4(ch),
        "ja3": ja3_str,
        "ja3_hash": ja3_hash,
        "raw_ciphers": ch["raw_ciphers"],
        "raw_extensions": ch["raw_extensions"],
        "extension_bodies": ch["extension_bodies"],
        "compression": ch["compression"],
        "client_version": ch["client_version"],
        "ciphers": ch["ciphers"],
        "extensions_ordered": ch["extensions"],
        "curves": ch["curves"],
        "sig_algs": ch["sig_algs"],
        "alpn": ch["alpn"],
        "supported_versions": ch["supported_versions"],
        "psk_modes": ch["psk_modes"],
        "cert_compression": ch["cert_compression"],
        "record_size_limit": ch["record_size_limit"],
        "app_settings": ch["app_settings"],
        "point_formats": ch["point_formats"],
        "ech": ch["ech"],
        "has_grease": ch["has_grease"],
        "session_id_len": ch["session_id_len"],
    }
