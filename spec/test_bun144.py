"""bun 1.4.4 指纹锁:pq2 profile 的 sigalgs / JA4 必须钉死在实采值上。

背景:bun 1.4.4 起 us_ssl_ctx_set_verify_signature_algorithms() 把客户端 sigalgs 从 9 条扩成 11 条
(+ed25519 0x0807 +ecdsa_secp521r1_sha512 0x0603),其余(cipher/groups/扩展)全同 1.4.3。
实采自 CC 2.1.302(bun 1.4.4+0049fd75e)。这一档是 bun:*-tls13-pq2。

本测用 csrc/buildcli(从 profile 造 ClientHello)+ csrc/ja4cli(算 JA4)锁三件事:
  1. pq2 的 signature_algorithms 扩展 == 实采的 11 条(逐字节)。
  2. pq2 的 JA4 == 实采值 t13d1713h1_5b57614c22b0_7f527383e249(cipher 段同 pq,尾段变)。
  3. pq2 相对 pq **只差 sigalgs**:cipher 列表、groups、其余扩展体逐字节相同。

跑:python -m spec.test_bun144   (需先 make -C csrc)
"""

import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CSRC = os.path.join(HERE, "..", "csrc")

EXP_SIGALGS_PQ2 = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
                   0x0806, 0x0601, 0x0807, 0x0603, 0x0201]   # 11 条,bun 1.4.4 实采
EXP_SIGALGS_PQ = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
                  0x0806, 0x0601, 0x0201]                     # 9 条,bun 1.4.1-1.4.3
EXP_JA4_PQ2 = "t13d1713h1_5b57614c22b0_7f527383e249"
EXP_JA4_PQ = "t13d1713h1_5b57614c22b0_6a3d802a7139"
# axios(node:https)那条:bun 的 sigalg 改动对 fetch/node:https 一视同仁,故 sigalgs 同为 11 条;
# cipher/扩展是 axios 自己那套,JA4 cipher 段不同(5d04281c6031),尾段同样因 sigalgs 而变。
EXP_JA4_AXIOS_PQ2 = "t13d181000_5d04281c6031_25d8bb11352d"
EXP_JA4_AXIOS_PQ = "t13d181000_5d04281c6031_78e6aca7449b"

fails = 0


def ok(name, cond, got=None, want=None):
    global fails
    if cond:
        print("  ✓ " + name)
    else:
        fails += 1
        print("  ✗ %s\n      got=%s\n      want=%s" % (name, got, want))


def build(profile_id, egress=True):
    prefix = "=" if egress else ""
    out = subprocess.run([os.path.join(CSRC, "buildcli")], input=(prefix + profile_id + "\n"),
                         capture_output=True, text=True).stdout.strip()
    if not out or out == "-":
        raise SystemExit("buildcli 造不出 %s —— 先 make -C csrc" % profile_id)
    return bytes.fromhex(out)


def ja4(ch_bytes):
    out = subprocess.run([os.path.join(CSRC, "ja4cli")], input=ch_bytes.hex() + "\n",
                         capture_output=True, text=True).stdout.strip()
    return out.split()[0] if out else ""


def parse(rec):
    b = rec[5:]  # strip TLS record header
    assert b[0] == 0x01
    i = 4 + 2 + 32
    sidlen = b[i]; i += 1 + sidlen
    cslen = struct.unpack_from(">H", b, i)[0]; cs = b[i + 2:i + 2 + cslen]; i += 2 + cslen
    cl = b[i]; i += 1 + cl
    extot = struct.unpack_from(">H", b, i)[0]; i += 2; end = i + extot
    exts = {}
    while i < end:
        et = struct.unpack_from(">H", b, i)[0]; el = struct.unpack_from(">H", b, i + 2)[0]
        exts[et] = b[i + 4:i + 4 + el]; i += 4 + el
    return cs, exts


def sigalgs(ext13):
    ln = struct.unpack_from(">H", ext13, 0)[0]
    return [struct.unpack_from(">H", ext13, 2 + k)[0] for k in range(0, ln, 2)]


def main():
    for pid, exp_sa, exp_ja4 in (
        ("bun:sdk-tls13-pq2", EXP_SIGALGS_PQ2, EXP_JA4_PQ2),
        ("bun:sdk-tls13-pq", EXP_SIGALGS_PQ, EXP_JA4_PQ),
        ("bun:nhttps-tls13-pq2", EXP_SIGALGS_PQ2, EXP_JA4_AXIOS_PQ2),
        ("bun:nhttps-tls13-pq", EXP_SIGALGS_PQ, EXP_JA4_AXIOS_PQ),
    ):
        ch = build(pid)
        _, exts = parse(ch)
        got_sa = sigalgs(exts[13])
        ok("%s sigalgs == 实采" % pid, got_sa == exp_sa,
           [hex(x) for x in got_sa], [hex(x) for x in exp_sa])
        got_ja4 = ja4(ch)
        ok("%s JA4 == 实采" % pid, got_ja4 == exp_ja4, got_ja4, exp_ja4)

    # pq2 相对 pq:只差 sigalgs
    cs2, e2 = parse(build("bun:sdk-tls13-pq2"))
    csp, ep = parse(build("bun:sdk-tls13-pq"))
    ok("pq2 cipher 列表 == pq", cs2 == csp, cs2.hex(), csp.hex())
    ok("pq2 groups(0x0a) == pq", e2.get(0x0a) == ep.get(0x0a))
    other_diffs = [hex(k) for k in e2 if k != 0x0d and k in ep and e2[k] != ep[k]]
    ok("pq2 除 sigalgs 外的扩展体 == pq", not other_diffs, other_diffs, "[]")
    ok("pq2 sigalgs 扩展 != pq(确有变)", e2.get(0x0d) != ep.get(0x0d))

    print("\nbun144 golden: %s" % ("ALL PASS" if fails == 0 else ("%d FAILED" % fails)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
