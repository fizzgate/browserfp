"""从 profile 定义重建 ClientHello 字节 —— C 模块的 Python 参考实现。

**这个模块存在的意义是先证伪**：在动手写 BoringSSL C 模块之前，先确认采到的
golden 是否**足够重建**一个 ClientHello。如果 Python 拿这份数据重建出的
ClientHello 解析回来与 golden 逐字段相同，说明 profile 数据是完备的，C 模块
照着做就行；如果不够，现在发现比写完 C 再发现便宜得多。

**不追求逐字节相同**：random / session_id / key_share 公钥每次连接都不同，
逐字节比对必然失败且没有意义。判据是 clienthello.fingerprint() 的那些确定性
字段——它们才是"指纹"，也正是上游用来判别的东西。
"""

import os
import secrets
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.clienthello import is_grease                      # noqa: E402

# 内容随连接变化的扩展：重建时必须重新生成，不能照搬 golden 里那份。
VOLATILE_EXTENSIONS = {
    0x0033,   # key_share —— 含真实 ECDH 公钥
    0x0029,   # pre_shared_key —— 含会话票据
    0xFE0D,   # encrypted_client_hello —— 含新鲜的 GREASE ECH payload
}


def _u16(v):
    return struct.pack(">H", v)


def _vec(body, len_bytes):
    """长度前缀向量。TLS 里到处都是，长度字段宽度各不相同。"""
    if len_bytes == 1:
        return bytes([len(body)]) + body
    if len_bytes == 2:
        return _u16(len(body)) + body
    if len_bytes == 3:
        n = len(body)
        return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]) + body
    raise ValueError(len_bytes)


def grease_ech(golden_body, rnd=None):
    """按 draft-ietf-tls-esni 的 outer 形态**新鲜生成** GREASE ECH。

        type(1)=0 | kdf(2) | aead(2) | config_id(1) | enc<2> | payload<2>

    **不能照抄 golden 的 body**：config_id 只有 1 字节，固定值一旦撞上服务端
    真实的 ECH 配置，服务端会拿自己的私钥去解 payload、失败，回
    handshake_failure(40)。这条是参考实现 `oracle/tls13.py` 实测出来的，而发货
    的构造器（本模块与 C）一直在照抄 golden —— 34/81 条默认 profile 带 0xFE0D，
    也就是绝大多数 Chrome 形态都埋着这个雷。`test_build_live` 只打三个站点，
    撞不上就一直是绿的。

    **形状必须照抄**：payload 长度决定 ClientHello 总长度，属于该 profile 指纹
    的一部分；kdf/aead 也照 golden（实测三个 Chrome profile 都是 0x0001/0x0001）。
    只有 config_id / enc / payload 的**内容**是新鲜的。

    rnd: 取随机字节的函数，默认 secrets.token_bytes。C 侧没有内部 RNG（库是
    内存进内存出的），那边从调用方给的 random32 派生。
    """
    if not golden_body or len(golden_body) < 8:
        return b""
    rnd = rnd or secrets.token_bytes
    kdf, aead = struct.unpack_from(">HH", golden_body, 1)
    enc_len = struct.unpack_from(">H", golden_body, 6)[0]
    payload_len = struct.unpack_from(">H", golden_body, 8 + enc_len)[0]
    return (bytes([0]) + struct.pack(">HH", kdf, aead)
            + rnd(1)
            + _vec(rnd(enc_len), 2)
            + _vec(rnd(payload_len), 2))


def _parse_key_share(body):
    """golden 的 key_share 体 → [(group, pub_len)]，顺序照原样。"""
    out, i = [], 2                       # 跳过 client_shares 的 2 字节长度
    while i + 4 <= len(body):
        g = int.from_bytes(body[i:i + 2], "big")
        n = int.from_bytes(body[i + 2:i + 4], "big")
        out.append((g, n))
        i += 4 + n
    return out


def _build_key_share(golden_body, key_shares=None):
    """**按 golden 的形状**重建 key_share：分组、顺序、每条的长度全部照抄，
    只换公钥内容。

    这里原来写的是"给 curves[0] 发一个占位公钥"，实测后果是重建出来的
    key_share 与真机**形状完全不同**：

        chrome131   真机 GREASE(1) + X25519MLKEM768(1216) + X25519(32)
                    重建 只有 X25519MLKEM768
        safari-ios  真机 GREASE(1) + X25519(32)
                    重建 只有 X25519

    JA4 不哈希 key_share 的内容，所以三方差分、重建闭环、真机握手全部照样绿 ——
    而 **Chrome 恒发一个 GREASE key_share，丢掉它本身就是破绽**，少发一组
    也与它自己的 supported_groups 对不上。C 侧一直是照抄 golden 的，于是
    C 与 Python 产出的字节形状长期不同，同样没人发现。

    key_shares: {group: pubkey_bytes}，真出网**必须**由调用方给 —— golden 里
    那把公钥是采集当时的，我们没有对应私钥，拿它握手算不出共享密钥。
    没给的组用随机字节占位：那只能用于指纹验证，绝不能拿去真握手。
    长度与 golden 不符时**报错而不是接受** —— 长度一变形状就变了。
    """
    shape = _parse_key_share(golden_body)
    if not shape:
        return golden_body
    # **给进来的分组必须在 profile 里存在**。调用方以为注入了、实际被忽略，
    # 是最难查的一类错：握手会拿 golden 里那把旧公钥去算共享密钥，而那把私钥
    # 不在我们手里 —— 症状是"握手莫名其妙失败"，与 key_share 毫无表面关联。
    for g in (key_shares or {}):
        if not any(g == gg for gg, _ in shape):
            raise ValueError(
                f"key_share 组 0x{g:04x} 不在该 profile 的 key_share 里 "
                f"（有的是 {[hex(gg) for gg, _ in shape]}）—— "
                "静默忽略会让调用方以为注入成功了")
    out = b""
    for group, plen in shape:
        if key_shares and group in key_shares:
            pub = key_shares[group]
            if len(pub) != plen:
                raise ValueError(
                    f"key_share 组 0x{group:04x} 的公钥长度 {len(pub)} 与 golden "
                    f"的 {plen} 不符 —— 长度一变 ClientHello 的形状就变了")
        elif is_grease(group):
            # GREASE 条目照抄 golden（内容按 RFC 8701 是 1 字节 0x00）
            pub = golden_body[
                golden_body.index(_u16(group) + _u16(plen)) + 4:][:plen]
        else:
            pub = secrets.token_bytes(plen)
        out += _u16(group) + _vec(pub, 2)
    return _vec(out, 2)


def build_client_hello(profile, sni=None, key_shares=None):
    """按 profile 组装一条完整的 TLS record（含 5 字节 record 头）。

    profile 用的是 oracle.clienthello.fingerprint() 的输出结构，也就是 golden
    里存的那份——采集与重建共用同一个数据形态，中间没有翻译层可以出错。
    """
    raw_ciphers = profile["raw_ciphers"]
    raw_extensions = profile["raw_extensions"]
    bodies = {int(k): bytes.fromhex(v) for k, v in profile["extension_bodies"].items()}

    ext_bytes = b""
    for ext_id in raw_extensions:
        if is_grease(ext_id):
            # GREASE 扩展体：位置照抄 golden，内容按 RFC 8701 留空
            # （唯一例外是 Chrome 末尾那个 GREASE 会带 1 字节 0x00）。
            ext_bytes += _u16(ext_id) + _vec(bodies.get(ext_id, b""), 2)
            continue
        if ext_id == 0x0000 and sni is not None:
            name = sni.encode()
            entry = bytes([0]) + _vec(name, 2)
            body = _vec(entry, 2)
        elif ext_id == 0x0033:
            body = _build_key_share(bodies.get(ext_id, b""), key_shares)
        elif ext_id == 0xFE0D:
            body = grease_ech(bodies.get(ext_id, b""))
        elif ext_id in VOLATILE_EXTENSIONS:
            body = bodies.get(ext_id, b"")
        else:
            body = bodies.get(ext_id, b"")
        ext_bytes += _u16(ext_id) + _vec(body, 2)

    hello = b""
    hello += _u16(profile.get("client_version", 0x0303))
    hello += secrets.token_bytes(32)                       # random
    hello += _vec(secrets.token_bytes(profile.get("session_id_len", 32)), 1)
    hello += _vec(b"".join(_u16(c) for c in raw_ciphers), 2)
    hello += _vec(bytes(profile.get("compression", [0])), 1)
    hello += _vec(ext_bytes, 2)

    handshake = bytes([0x01]) + _vec(hello, 3)
    return bytes([0x16]) + _u16(0x0301) + _vec(handshake, 2)
