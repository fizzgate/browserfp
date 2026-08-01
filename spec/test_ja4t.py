"""JA4T 解析器门禁 —— 用构造的 SYN 包验证，不依赖抓包权限。

TCP 层数据只能在生产入口采（见 oracle/ja4t.py 的说明），但**解析逻辑现在就能
验证**：手工构造已知 OS 特征的 SYN 包，断言算出的 JA4T 与预期一致。这样等真实
pcap 到位时，解析这一环是已经验过的。

向量取自各 OS 典型 SYN（FoxIO JA4T 文档中的常见形态）：
    Linux    window 64240, options MSS,SACKOK,TS,NOP,WS, MSS 1460, wscale 7
    Windows  window 64240, options MSS,NOP,WS,NOP,NOP,SACKOK, MSS 1460, wscale 8

占位规则与参考实现 0x676e67/pingly (src/tcp/fingerprint.rs) 逐条核对过：
空 options / MSS 缺失 / window scale 缺失或为 0，一律记 "00" 而非 "0"。

跑：python -m spec.test_ja4t
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.ja4t import ParseError, from_syn, parse_syn                # noqa: E402


def build_syn(window, options_bytes, src_ip="1.2.3.4", dst_ip="5.6.7.8",
              link="ethernet"):
    """构造一个 IPv4 SYN 包。options_bytes 必须已按 4 字节对齐。"""
    assert len(options_bytes) % 4 == 0, "TCP 选项区需 4 字节对齐"
    data_off = (20 + len(options_bytes)) // 4
    tcp = struct.pack(">HHIIBBHHH", 12345, 443, 0, 0,
                      data_off << 4, 0x02, window, 0, 0) + options_bytes
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     bytes(int(x) for x in src_ip.split(".")),
                     bytes(int(x) for x in dst_ip.split(".")))
    if link == "ethernet":
        return b"\x00" * 12 + b"\x08\x00" + ip + tcp
    if link == "loopback":
        return struct.pack("<I", 2) + ip + tcp
    return ip + tcp


def opt_mss(v):
    return bytes([2, 4]) + struct.pack(">H", v)


def opt_ws(v):
    return bytes([3, 3, v])


SACKOK, NOP, EOL = bytes([4, 2]), bytes([1]), bytes([0])
TS = bytes([8, 10]) + b"\x00" * 8


CASES = [
    ("Linux 典型", 64240, opt_mss(1460) + SACKOK + TS + NOP + opt_ws(7),
     "64240_2-4-8-1-3_1460_7"),
    ("Windows 典型", 64240, opt_mss(1460) + NOP + opt_ws(8) + NOP + NOP + SACKOK,
     "64240_2-1-3-1-1-4_1460_8"),
    ("无 MSS 无 WS", 65535, SACKOK + NOP + NOP, "65535_4-1-1_00_00"),
    # wscale=0 必须记 00 而不是 0 —— 与 pingly 的 filter(|v| *v != 0) 对齐
    ("WS 值为 0", 64240, opt_mss(1460) + opt_ws(0) + NOP, "64240_2-3-1_1460_00"),
]


def t_vectors():
    bad = []
    for name, window, opts, expect in CASES:
        pad = (-len(opts)) % 4
        got = from_syn(build_syn(window, opts + NOP * pad))
        # 末尾补的 NOP 会进 options 序列，断言时按实际补位数扩展预期
        exp = expect if pad == 0 else expect.split("_")[0] + "_" + \
            "-".join(expect.split("_")[1].split("-") + ["1"] * pad) + "_" + \
            "_".join(expect.split("_")[2:])
        if got != exp:
            bad.append(f"{name}: 期望 {exp} 得到 {got}")
    return not bad, (f"{len(CASES) - len(bad)}/{len(CASES)} 向量通过"
                     + ("；" + " | ".join(bad) if bad else ""))


def t_link_layers():
    """同一个包在以太网/回环/裸 IP 三种封装下必须解出相同 JA4T。"""
    opts = opt_mss(1460) + SACKOK + TS + NOP + opt_ws(7)
    results = {lk: from_syn(build_syn(64240, opts, link=lk))
               for lk in ("ethernet", "loopback", "raw")}
    ok = len(set(results.values())) == 1
    return ok, f"三种封装结果{'一致' if ok else '不一致'}: {set(results.values())}"


def t_rejects_non_syn():
    """非 SYN 包必须报错而不是返回一个看似合理的值。"""
    pkt = bytearray(build_syn(64240, opt_mss(1460)))
    # 以太网(14) + IP(20) 后的 TCP flags 在偏移 13
    pkt[14 + 20 + 13] = 0x10          # 只置 ACK
    try:
        parse_syn(bytes(pkt))
        return False, "非 SYN 包被接受了——会把普通数据包算成指纹"
    except ParseError:
        return True, "非 SYN 包被正确拒绝"


def main():
    tests = [("已知向量", t_vectors), ("链路层无关", t_link_layers),
             ("拒绝非 SYN", t_rejects_non_syn)]
    failed = 0
    for name, fn in tests:
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        print(f"  {'✅' if ok else '❌'} {name:14s} {detail}")
        failed += 0 if ok else 1
    print(f"\n{len(tests) - failed}/{len(tests)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
