"""密钥交换：C 侧算出的共享密钥必须与**另一份独立实现**逐字节相同。

`tlsfp.client_hello()` 现在要求调用方把每一组的公钥交进来，于是调用方得先能
产出这些密钥。生产 UA 里 64.9% 落在需要 X25519MLKEM768 的 profile 上，这不是
可选项。

**判据不是"能跑通"，是"两份实现算出同一个 32/64 字节"。** 密钥交换错了不会
报错：本地照样算得出一个共享密钥，只是与服务端算的不同，症状是握手在
Finished 阶段失败、报"解密失败"——与真因隔着两层。所以每一组都拿
`cryptography`（独立实现，走的是它自己链接的 OpenSSL）当对端，比最终字节。

一处曾经量错层的地方记在这里：容器里 `openssl version` 报 3.0.20，据此得出过
"ML-KEM 得自己写"的结论。**那是 Debian 的系统二进制**，OpenResty 链的是
`/usr/local/openresty/openssl3/`，实测是 3.5.7，ML-KEM-768 就在里面。所以本
门禁把解析到的版本打出来并断言 ML-KEM 可用 —— 版本不够时要**当场红**，不是
悄悄跳过：跳过等于把"生产上这条根本不能用"藏起来。

X25519MLKEM768 的拼接顺序（ML-KEM 在前）单独做了阴性对照：把两段对调后必须
对不上。顺序错是这一族里最容易犯又最难查的 —— 长度完全正确。

跑：python -m spec.test_kx
"""

import glob
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KXCLI = os.path.join(ROOT, "csrc", "kxcli")

ROUNDS = 3           # 每组跑几轮 —— 一轮碰巧对上也可能是常数，多轮才看得出新鲜度

GROUPS = [(0x001D, "X25519", 32, 32),
          (0x0017, "secp256r1", 65, 32),
          (0x0018, "secp384r1", 97, 48),
          (0x11EC, "X25519MLKEM768", 1216, 64)]

MLKEM_EK, MLKEM_CT, X_LEN = 1184, 1088, 32


def find_libcrypto():
    """挑一份带 ML-KEM 的 libcrypto。

    **优先 OpenResty 自带那份** —— 生产上加载的就是它，拿别的版本验等于验了
    一个生产上不存在的东西。
    """
    pats = ["/usr/local/openresty/openssl3/lib/libcrypto.so*",
            "/opt/homebrew/Cellar/openresty-openssl3/*/lib/libcrypto.dylib",
            "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"]
    for p in pats:
        hits = sorted(glob.glob(p))
        if hits:
            return hits[-1]
    return None


class Cli:
    """一个长驻进程 —— 私钥句柄只在进程内有效，gen 与 derive 必须同进程。"""

    def __init__(self, lib):
        self.p = subprocess.Popen([KXCLI, lib], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True, bufsize=1)

    def cmd(self, s):
        self.p.stdin.write(s + "\n")
        self.p.stdin.flush()
        return self.p.stdout.readline().strip()

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


def peer_side(group, pub):
    """用 cryptography 当对端：返回 (服务端那一段, 它算出的共享密钥)。"""
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDH, SECP256R1, SECP384R1, EllipticCurvePublicKey, generate_private_key)
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    if group == 0x001D:
        k = X25519PrivateKey.generate()
        return (k.public_key().public_bytes_raw(),
                k.exchange(X25519PublicKey.from_public_bytes(pub)))
    if group in (0x0017, 0x0018):
        curve = SECP256R1() if group == 0x0017 else SECP384R1()
        k = generate_private_key(curve)
        return (k.public_key().public_bytes(Encoding.X962,
                                            PublicFormat.UncompressedPoint),
                k.exchange(ECDH(),
                           EllipticCurvePublicKey.from_encoded_point(curve, pub)))
    ek, xp = pub[:MLKEM_EK], pub[MLKEM_EK:]
    ss, ct = MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
    k = X25519PrivateKey.generate()
    return (ct + k.public_key().public_bytes_raw(),
            ss + k.exchange(X25519PublicKey.from_public_bytes(xp)))


def main():
    lib = find_libcrypto()
    if not lib:
        print("找不到 libcrypto —— 不能当作通过", file=sys.stderr)
        return 1
    # **先删产物再 make**。不能指望 mtime：变异测试是"改一行再 cp 还原"，
    # 还原后的 .c 常与上一次编出的 .o 落在同一秒，make 认为不用重编，于是门禁
    # 跑的是变异版二进制 —— 实测已经因此误报过一次（源码里 grep 不到变异，
    # 门禁却按变异的行为报错）。仓里 test_mutation 的 _force_rebuild 记的是
    # 同一个坑。
    csrc = os.path.join(ROOT, "csrc")
    for f in ("kxcli", "tlsfp_kx.o"):
        try:
            os.unlink(os.path.join(csrc, f))
        except FileNotFoundError:
            pass
    r = subprocess.run(["make", "-s", "kxcli"], cwd=csrc,
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"make 失败：{(r.stderr or r.stdout)[-300:]}")
        return 1

    cli = Cli(lib)
    bad, checked = [], 0
    try:
        ver = cli.cmd("version")
        print(f"  libcrypto  {lib}")
        print(f"  版本       {ver}")
        # OpenSSL 3.5 起才有 ML-KEM。**版本不够要红** —— 生产上这条不能用，
        # 悄悄跳过等于把缺陷藏起来。
        try:
            major, minor = (int(x) for x in ver.split()[1].split(".")[:2])
        except Exception:
            bad.append(f"版本串读不出来：{ver!r}")
            major = minor = 0
        if (major, minor) < (3, 5):
            bad.append(f"OpenSSL {major}.{minor} 没有 ML-KEM（要 ≥3.5）—— "
                       "64.9% 的生产 UA 会因此伪装不了")

        for group, name, publen, seclen in GROUPS:
            pubs = set()
            before = len(bad)
            for _ in range(ROUNDS):
                out = cli.cmd(f"gen 0x{group:04x}")
                if out == "ERR" or " " not in out:
                    bad.append(f"{name}: keygen 失败（{out}）")
                    break
                hexpub, handle = out.split()
                pub = bytes.fromhex(hexpub)
                if len(pub) != publen:
                    bad.append(f"{name}: 公钥 {len(pub)} 字节，应为 {publen}")
                    break
                pubs.add(pub)
                # **对端算不出来也要当成发现记下来，不能让异常打死整条门禁**。
                # 实测：把混合组两段对调后，cryptography 直接抛
                # "ML-KEM-768 public key is 1184 bytes"，后面三条阴性对照
                # 一条都没跑到 —— 崩掉时只看得到 traceback，看不到"哪几处不符"。
                try:
                    share, want = peer_side(group, pub)
                except Exception as e:
                    bad.append(f"{name}: 对端拿我们的公钥算不下去 —— "
                               f"{type(e).__name__}: {str(e)[:70]}")
                    break
                got = cli.cmd(f"derive {handle} {share.hex()}")
                if got == "ERR":
                    bad.append(f"{name}: derive 失败")
                    break
                got = bytes.fromhex(got)
                if len(got) != seclen:
                    bad.append(f"{name}: 共享密钥 {len(got)} 字节，应为 {seclen}")
                if got != want:
                    bad.append(f"{name}: 与 cryptography 算出的共享密钥不同 —— "
                               f"我们 {got[:8].hex()}… 对方 {want[:8].hex()}…")
                checked += 1
            if len(pubs) < ROUNDS:
                bad.append(f"{name}: {ROUNDS} 轮只产出 {len(pubs)} 个不同公钥 —— "
                           "密钥必须每次新生成，复用等于一把固定公钥反复上线")
            # **有发现就不能打勾**。首版无条件打勾，变异跑出来的画面是
            # "四组全 ✅" 底下跟着一堆 ✗ —— 读的人第一眼会以为主体是好的。
            if len(bad) == before:
                print(f"  ✅ {name:16s} pub={publen:4d} secret={seclen:2d} "
                      f"×{ROUNDS} 轮与 cryptography 一致")
            else:
                print(f"  ✗ {name:16s} {bad[before][:80]}")

        # —— 阴性对照 1：混合组把两段对调，必须对不上 ——
        try:
            hexpub, handle = cli.cmd("gen 0x11ec").split()
            pub = bytes.fromhex(hexpub)
            share, want = peer_side(0x11EC, pub)
            swapped = share[MLKEM_CT:] + share[:MLKEM_CT]
            got = cli.cmd(f"derive {handle} {swapped.hex()}")
        except Exception as e:
            bad.append(f"对调用例本身没跑起来：{type(e).__name__}: {str(e)[:60]}")
            got, want = "ERR", b""
        if got != "ERR" and bytes.fromhex(got) == want:
            bad.append("把 ML-KEM 密文与 X25519 公钥对调后仍算出同一个共享密钥 —— "
                       "说明拼接顺序根本没被用上，这条断言是空的")
        else:
            print("  ✅ 对照：混合组两段对调后确实对不上")

        # —— 阴性对照 2：截短的对端 share 必须被拒，不能算出个东西来 ——
        out = cli.cmd("gen 0x001d")
        hexpub, handle = out.split()
        short = bytes.fromhex(hexpub)[:31]
        if cli.cmd(f"derive {handle} {short.hex()}") != "ERR":
            bad.append("X25519 收到 31 字节的对端公钥仍算出了共享密钥 —— "
                       "长度不合法必须拒绝")
        else:
            print("  ✅ 对照：长度不合法的对端 share 被拒绝")

        # —— 阴性对照 3：不认识的组必须拒绝，不能给个空结果 ——
        if cli.cmd("gen 0x6399") != "ERR":
            bad.append("Kyber768Draft00(0x6399) 我们做不了，却没有拒绝 —— "
                       "静默产出一把无效公钥比报错难查得多")
        else:
            print("  ✅ 对照：做不了的组（0x6399）当场拒绝")
    finally:
        cli.close()

    want_checks = ROUNDS * len(GROUPS)
    if checked < want_checks:
        bad.append(f"只比了 {checked}/{want_checks} 次 —— 有组没跑完，"
                   "剩下的断言等于没验")

    print(f"\n密钥交换差分 {checked}/{want_checks} 次")
    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'四组密钥交换与独立实现一致' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
