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

**X25519Kyber768Draft00（0x6399）的顺序正好相反：X25519 在前、Kyber 在后。**
两份独立实现印证：Go 标准库 handshake_client.go 与 utls 的
handshake_client_tls13.go。它也不需要另一份密码学实现 —— ML-KEM 相对 Kyber
第三轮只去掉了最后一步哈希，补回 SHAKE-256(K || SHA3-256(ct), 32) 就是
Kyber v3（Go 与 utls 都这么做）。这条不是"看着像"：本门禁拿 CIRCL 的真·第三轮
实现对我们生成的公钥做封装，两边的共享密钥必须逐字节相同。

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
          (0x11EC, "X25519MLKEM768", 1216, 64),
          (0x6399, "X25519Kyber768Draft00", 1216, 64)]

# 0x6399 的对端要一份**真·第三轮 Kyber** 实现 —— OpenSSL 只有最终版 ML-KEM。
# CIRCL 的 kem/kyber/kyber768 文档明确写着 "as submitted to round 3"，与它自己的
# kem/mlkem 是两个包。拿它当判据，不是拿我们的实现跟我们自己比。
KYBERCLI = os.path.join(ROOT, "oracle", "gotls", "kybercli", "kybercli")

MLKEM_EK, MLKEM_CT, X_LEN = 1184, 1088, 32


def have_kybercli():
    if os.path.exists(KYBERCLI):
        return True
    import shutil as _sh
    if not _sh.which("go"):
        return False
    subprocess.run(["go", "build", "-o", "kybercli/kybercli", "./kybercli"],
                   cwd=os.path.join(ROOT, "oracle", "gotls"),
                   env={**os.environ, "GOFLAGS": "-mod=mod"}, timeout=300)
    return os.path.exists(KYBERCLI)


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
    if group == 0x6399:
        # **顺序与 0x11ec 相反**：X25519 在前、Kyber 在后
        xp, ek = pub[:X_LEN], pub[X_LEN:]
        r = subprocess.run([KYBERCLI, "encap", ek.hex()],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError("CIRCL 拒绝了这把 ek：" + r.stderr.strip()[:80])
        ct_hex, ss_hex = r.stdout.strip().split("\t")
        k = X25519PrivateKey.generate()
        return (k.public_key().public_bytes_raw() + bytes.fromhex(ct_hex),
                k.exchange(X25519PublicKey.from_public_bytes(xp))
                + bytes.fromhex(ss_hex))
    ek, xp = pub[:MLKEM_EK], pub[MLKEM_EK:]
    ss, ct = MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
    k = X25519PrivateKey.generate()
    return (ct + k.public_key().public_bytes_raw(),
            ss + k.exchange(X25519PublicKey.from_public_bytes(xp)))


LUA_REPL = r"""
package.path = "%s/lua/?.lua;" .. package.path
local tlsfp = require "tlsfp"
assert(tlsfp.load("%s"))
local function hex(s)
    return (s:gsub(".", function(c) return string.format("%%02x", c:byte()) end))
end
local keys
for line in io.lines() do
    local brand, ver = line:match("^gen (%%S+) (%%d+)$")
    if brand then
        if keys then keys:free() end
        local k, e = tlsfp.gen_key_shares(brand, tonumber(ver))
        if not k then print("ERR " .. tostring(e)) else
            keys = k
            -- 顺带确认这些密钥真能被 client_hello 收下
            local rec, prof = tlsfp.client_hello(brand, tonumber(ver), "example.com",
                                                 k.shares)
            if not rec then print("ERR client_hello: " .. tostring(prof)) else
                local out = {}
                for g, pub in pairs(k.shares) do
                    out[#out + 1] = string.format("%%d:%%s", g, hex(pub))
                end
                table.sort(out)
                print(prof.id .. " " .. table.concat(out, ","))
            end
        end
    else
        local g, peer = line:match("^derive (%%d+) (%%x+)$")
        if g then
            local raw = peer:gsub("%%x%%x", function(h)
                return string.char(tonumber(h, 16)) end)
            local sec, e = keys:derive(tonumber(g), raw)
            print(sec and hex(sec) or ("ERR " .. tostring(e)))
        else
            print("ERR 不认识的指令")
        end
    end
    io.flush()
end
"""


def lua_arm(bad):
    """第二段：从**生产入口**（Lua）过一遍。

    第一段验的是 C 那一层。但生产上调用它的是 `tlsfp.gen_key_shares()`，中间
    隔着 FFI 的输出缓冲、句柄所有权与 ffi.gc —— 这些都能在不崩溃的情况下给出
    错误结果（比如私钥被 GC 掉后 derive 出一段垃圾）。这一段的判据仍然是
    "与 cryptography 算出同一个共享密钥"，只是密钥这次由 Lua 产。
    """
    lua = None
    for c in ("luajit", "resty"):
        r = subprocess.run(["which", c], capture_output=True, text=True)
        if r.returncode == 0:
            lua = r.stdout.strip()
            break
    if not lua:
        bad.append("缺 luajit/resty —— 生产入口这一段没验到，不能算通过")
        return 0

    script = LUA_REPL % (ROOT, os.path.join(ROOT, "csrc", "libtlsfp.so"))
    # 写临时文件而不是 spec/cache —— 变异测试里那个目录是软链回真仓的。
    import tempfile
    fd, src = tempfile.mkstemp(prefix="kx_repl_", suffix=".lua")
    with os.fdopen(fd, "w") as f:
        f.write(script)
    p = subprocess.Popen([lua, src], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, text=True, bufsize=1)

    def cmd(s):
        p.stdin.write(s + "\n")
        p.stdin.flush()
        return p.stdout.readline().strip()

    n = 0
    try:
        for brand, ver in (("chrome", 151), ("firefox", 153), ("safari-mobile", 27)):
            line = cmd(f"gen {brand} {ver}")
            if line.startswith("ERR") or " " not in line:
                bad.append(f"Lua {brand} {ver}: {line[:90]}")
                continue
            pid, rest = line.split(" ", 1)
            for item in rest.split(","):
                g, hexpub = item.split(":")
                group, pub = int(g), bytes.fromhex(hexpub)
                try:
                    share, want = peer_side(group, pub)
                except Exception as e:
                    bad.append(f"Lua {brand} {ver} 组 0x{group:04x}: 对端算不下去 "
                               f"{type(e).__name__}: {str(e)[:60]}")
                    continue
                got = cmd(f"derive {group} {share.hex()}")
                if got.startswith("ERR"):
                    bad.append(f"Lua {brand} {ver} 组 0x{group:04x}: derive 失败 "
                               f"{got[:70]}")
                    continue
                if bytes.fromhex(got) != want:
                    bad.append(f"Lua {brand} {ver} 组 0x{group:04x}: 共享密钥与 "
                               "cryptography 不同 —— 生产入口产的密钥握不上手")
                n += 1
            print(f"  ✅ Lua {brand} {ver} → {pid}，"
                  f"{len(rest.split(','))} 组各自与 cryptography 一致")
    finally:
        p.stdin.close()
        p.wait(timeout=10)
        os.unlink(src)
    return n


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

        kyber_ok = have_kybercli()
        groups = GROUPS
        if not kyber_ok:
            print("  --  0x6399 没验到：缺 kybercli 且没有 go 工具链 —— "
                  "这一组的正确性当前无人看管")
            groups = [g for g in GROUPS if g[0] != 0x6399]
        for group, name, publen, seclen in groups:
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
        if cli.cmd("gen 0x001e") != "ERR":
            bad.append("不支持的组（0x001e）没有被拒绝 —— "
                       "静默产出一把无效公钥比报错难查得多")
        else:
            print("  ✅ 对照：不支持的组（0x001e）当场拒绝")
    finally:
        cli.close()

    print("\n生产入口（Lua）这一段：")
    lua_n = lua_arm(bad)
    if lua_n < 7:      # chrome 2 组 + firefox 3 组 + safari 2 组
        bad.append(f"Lua 侧只验到 {lua_n} 组 —— 应为 7（chrome 2 + firefox 3 "
                   "+ safari 2），少了说明有组没走到")

    want_checks = ROUNDS * (len(GROUPS) if kyber_ok else len(GROUPS) - 1)
    if checked < want_checks:
        bad.append(f"只比了 {checked}/{want_checks} 次 —— 有组没跑完，"
                   "剩下的断言等于没验")

    print(f"\n密钥交换差分 {checked}/{want_checks} 次")
    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'五组密钥交换与独立实现一致' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
