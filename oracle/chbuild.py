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


def _build_key_share(curves):
    """按 profile 的曲线顺序造 key_share。

    真实客户端只为**前若干条**曲线发公钥（Chrome 发 X25519MLKEM768 + X25519
    两条），不是每条都发。这里照抄 golden 的 key_share 结构由调用方给出；
    没有 golden body 时退化为给第一条非 GREASE 曲线发一个占位公钥。
    """
    sizes = {0x001D: 32, 0x0017: 65, 0x0018: 97, 0x0019: 133, 0x11EC: 1216}
    entries = b""
    for c in curves[:1]:
        if is_grease(c):
            continue
        entries += _u16(c) + _vec(secrets.token_bytes(sizes.get(c, 32)), 2)
    return _vec(entries, 2)


def build_client_hello(profile, sni=None):
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
            body = _build_key_share(profile.get("curves", []))
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
