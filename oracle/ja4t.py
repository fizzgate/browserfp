"""TCP 层指纹 JA4T：从 SYN 包算出 window_size_options_MSS_windowscale。

**为什么本地采不了，只能在生产入口采**：

1. ja4t 的四项里，只有 MSS 能通过 socket API（TCP_MAXSEG）拿到；options 顺序与
   window scale **只存在于 SYN 包**，socket API 完全看不到，必须抓包。
2. macOS 上 /dev/bpf 是 `crw------- root:wheel`，抓包必须 root。
3. **即使有 root，在 127.0.0.1 上采到的也是失真值**：实测回环接口
   TCP_MAXSEG=4024（loopback MTU 16384），真实网卡是 1460。TCP 指纹取决于
   客户端 OS 栈**加网络路径**（MTU、中间设备的 MSS clamping），本地造不出来。

所以本模块只提供**解析**：输入一个 SYN 包（链路层或 IP 层起始），输出 JA4T。
真实数据须在生产入口用 tcpdump/pcap 采集后喂进来。解析逻辑本身用构造向量验证
（见 spec/test_ja4t.py），不依赖抓包权限。

JA4T 规范：https://github.com/FoxIO-LLC/ja4
    格式  <window_size>_<option kinds 按序用-连接>_<MSS>_<window scale>
    例    64240_2-4-8-1-3_1460_7
"""

import struct

# TCP option kind
OPT_EOL, OPT_NOP, OPT_MSS, OPT_WSCALE, OPT_SACKOK, OPT_TIMESTAMP = 0, 1, 2, 3, 4, 8


class ParseError(ValueError):
    pass


def parse_tcp_options(raw):
    """按线上顺序返回 [(kind, value_bytes)]。

    NOP(1) **保留**且计入顺序——它是填充，但不同 OS 的填充位置不同，正是 JA4T
    的区分点之一。EOL(0) 终止解析。
    """
    out, i = [], 0
    while i < len(raw):
        kind = raw[i]
        if kind == OPT_EOL:
            break
        if kind == OPT_NOP:
            out.append((kind, b""))
            i += 1
            continue
        if i + 1 >= len(raw):
            break
        length = raw[i + 1]
        if length < 2 or i + length > len(raw):
            break
        out.append((kind, raw[i + 2:i + length]))
        i += length
    return out


def parse_syn(packet, link_offset=None):
    """从一个 SYN 包解析出 JA4T 所需字段。

    link_offset=None 时自动判断：以太网帧 14 字节、回环(NULL/Loopback) 4 字节，
    或直接从 IP 头开始（0）。判据是该偏移处高 4 位是否为 IP 版本号 4/6。
    """
    offsets = [link_offset] if link_offset is not None else [0, 4, 14]
    for off in offsets:
        if off + 20 > len(packet):
            continue
        ver = packet[off] >> 4
        if ver == 4:
            ihl = (packet[off] & 0x0F) * 4
            if packet[off + 9] != 6:            # protocol != TCP
                continue
            return _parse_tcp(packet, off + ihl)
        if ver == 6:
            if packet[off + 6] != 6:            # next header != TCP
                continue
            return _parse_tcp(packet, off + 40)
    raise ParseError("未能定位 IP 头；请显式给出 link_offset")


def _parse_tcp(packet, o):
    if o + 20 > len(packet):
        raise ParseError("TCP 头截断")
    window = struct.unpack_from(">H", packet, o + 14)[0]
    data_off = (packet[o + 12] >> 4) * 4
    flags = packet[o + 13]
    if not (flags & 0x02):
        raise ParseError(f"不是 SYN 包（flags=0x{flags:02x}）")
    opts = parse_tcp_options(packet[o + 20:o + data_off])

    mss = wscale = None
    for kind, val in opts:
        if kind == OPT_MSS and len(val) == 2:
            mss = struct.unpack(">H", val)[0]
        elif kind == OPT_WSCALE and len(val) == 1:
            wscale = val[0]
    return {
        "window_size": window,
        "options": [k for k, _ in opts],
        "mss": mss,
        "window_scale": wscale,
        "is_syn_ack": bool(flags & 0x10),
    }


def ja4t(parsed):
    """按 FoxIO 规范拼 JA4T 串。

    三处占位规则与参考实现（0x676e67/pingly src/tcp/fingerprint.rs）对齐，初版
    曾全部写错，会产出与其他工具对不上的 JA4T：
      · 空 options   → "00"（不是 "0"）
      · MSS 缺失     → "00"
      · window scale 缺失**或等于 0** → "00"
        —— pingly 用 `.filter(|value| *value != 0)`，即 wscale=0 与缺失同等对待。
           这条最隐蔽：SYN 里确实带 WS 选项但值为 0 时，仍记 "00"。
    EOL 不计入 options（NOP 计入，它是区分点）。
    """
    ids = [k for k in parsed["options"] if k != OPT_EOL]
    opts = "-".join(str(k) for k in ids) if ids else "00"
    mss = parsed["mss"]
    ws = parsed["window_scale"]
    return (f'{parsed["window_size"]}_{opts}_'
            f'{mss if mss is not None else "00"}_'
            f'{ws if ws else "00"}')


def from_syn(packet, link_offset=None):
    """便捷入口：SYN 包字节 → JA4T 串。"""
    return ja4t(parse_syn(packet, link_offset))
