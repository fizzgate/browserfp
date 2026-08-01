"""QUIC Initial 包解密与 ClientHello 提取。

**为什么不需要服务端私钥**：QUIC Initial 包的加密密钥由**公开的 salt + 客户端
选的 DCID** 经 HKDF 派生（RFC 9001 §5.2）。这层加密的目的是防中间设备篡改
（ossification），不是保密。所以任何观察者都能解，我们的 UDP 观测点也能。

链路与 TLS 那侧一致，只是多两层剥离：
    UDP 包 → 去 header protection → 解 AEAD → CRYPTO 帧重组 → ClientHello
拿到 ClientHello 后直接复用 oracle.clienthello 的解析与 JA4 计算，**JA4 只需把
首字符从 t 换成 q**（RFC/FoxIO 规范：t=TCP、q=QUIC，其余算法完全相同）。

参考实现 0x676e67/pingly 的 src/quic/ 只有 parameter.rs 与 varint.rs，没有解密
代码——因为它作为服务端天然能解。我们是旁路观测，得自己做这一步。
"""

import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# RFC 9001 §5.2：QUIC v1 的 initial salt。v2 另有一个值。
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cad ccbb7f0a".replace(" ", ""))
INITIAL_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
VERSION_V1, VERSION_V2 = 0x00000001, 0x6B3343CF


class QuicError(ValueError):
    pass


def _hkdf_extract(salt, ikm):
    import hmac
    return hmac.new(salt, ikm, "sha256").digest()


def _expand_label(secret, label, length):
    """TLS 1.3 的 HKDF-Expand-Label，QUIC 复用它（前缀同样是 "tls13 "）。"""
    info = (struct.pack(">H", length)
            + bytes([len(b"tls13 " + label)]) + b"tls13 " + label
            + b"\x00")
    return HKDFExpand(algorithm=hashes.SHA256(), length=length,
                      info=info).derive(secret)


def initial_secrets(dcid, version=VERSION_V1):
    """由 DCID 派生 client initial 的 key / iv / header-protection key。"""
    salt = INITIAL_SALT_V2 if version == VERSION_V2 else INITIAL_SALT_V1
    initial = _hkdf_extract(salt, dcid)
    client = _expand_label(initial, b"client in", 32)
    return (_expand_label(client, b"quic key", 16),
            _expand_label(client, b"quic iv", 12),
            _expand_label(client, b"quic hp", 16))


def _parse_varint(buf, i):
    """QUIC 变长整数（RFC 9000 §16）：前两位决定长度 1/2/4/8 字节。"""
    if i >= len(buf):
        raise QuicError("varint 越界")
    prefix = buf[i] >> 6
    length = 1 << prefix
    if i + length > len(buf):
        raise QuicError("varint 截断")
    value = buf[i] & 0x3F
    for k in range(1, length):
        value = (value << 8) | buf[i + k]
    return value, i + length


def parse_initial(datagram):
    """解一个 QUIC Initial 数据报，返回 {version, dcid, scid, crypto}。

    crypto 是该包内 CRYPTO 帧的 [(offset, data)]，需跨包重组后才是完整
    ClientHello（大的 ClientHello 会分片到多个 Initial 包）。
    """
    if not datagram or not (datagram[0] & 0x80):
        raise QuicError("不是长包头（Initial 必为长包头）")
    version = struct.unpack_from(">I", datagram, 1)[0]
    o = 5
    dcid_len = datagram[o]
    o += 1
    dcid = datagram[o:o + dcid_len]
    o += dcid_len
    scid_len = datagram[o]
    o += 1
    scid = datagram[o:o + scid_len]
    o += scid_len

    packet_type = (datagram[0] & 0x30) >> 4
    if packet_type != 0:
        raise QuicError(f"不是 Initial 包（type={packet_type}）")

    token_len, o = _parse_varint(datagram, o)
    o += token_len
    length, o = _parse_varint(datagram, o)
    pn_offset = o

    key, iv, hp = initial_secrets(dcid, version)

    # 去 header protection：用密文采样算掩码（RFC 9001 §5.4）
    sample = datagram[pn_offset + 4:pn_offset + 20]
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()

    first = datagram[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(datagram[pn_offset + k] ^ mask[1 + k] for k in range(pn_len))
    pn = int.from_bytes(pn_bytes, "big")

    header = bytearray(datagram[:pn_offset + pn_len])
    header[0] = first
    for k in range(pn_len):
        header[pn_offset + k] = pn_bytes[k]

    payload = datagram[pn_offset + pn_len:pn_offset + length]
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    plain = AESGCM(key).decrypt(nonce, payload, bytes(header))

    return {"version": version, "dcid": dcid, "scid": scid,
            "packet_number": pn, "crypto": _crypto_frames(plain)}


def _crypto_frames(plain):
    """从解密后的 payload 里挑出 CRYPTO 帧，忽略 PADDING/PING/ACK。"""
    out, i = [], 0
    while i < len(plain):
        ftype = plain[i]
        if ftype == 0x00:                     # PADDING，可能一大片
            i += 1
            continue
        if ftype == 0x01:                     # PING
            i += 1
            continue
        if ftype == 0x06:                     # CRYPTO
            i += 1
            offset, i = _parse_varint(plain, i)
            ln, i = _parse_varint(plain, i)
            out.append((offset, plain[i:i + ln]))
            i += ln
            continue
        if ftype == 0x02 or ftype == 0x03:    # ACK
            i += 1
            for _ in range(4):
                _, i = _parse_varint(plain, i)
            break                             # ACK 之后通常只剩 padding
        break                                 # 其余帧类型：Initial 里少见，停止
    return out


def reassemble_client_hello(crypto_chunks):
    """把多个 Initial 包的 CRYPTO 片段按 offset 拼成 TLS 握手消息。

    返回可直接喂给 oracle.clienthello 的 **TLS record**（补上 5 字节 record 头）
    —— QUIC 里没有 TLS record 层，握手消息裸放在 CRYPTO 帧里。
    """
    if not crypto_chunks:
        raise QuicError("没有 CRYPTO 帧")
    total = max(off + len(data) for off, data in crypto_chunks)
    buf = bytearray(total)
    seen = bytearray(total)
    for off, data in crypto_chunks:
        buf[off:off + len(data)] = data
        for k in range(off, off + len(data)):
            seen[k] = 1
    if not all(seen):
        raise QuicError(f"CRYPTO 有空洞，收到 {sum(seen)}/{total} 字节")
    if not buf or buf[0] != 0x01:
        raise QuicError(f"不是 ClientHello（handshake type={buf[0] if buf else None}）")
    return bytes([0x16, 0x03, 0x01]) + struct.pack(">H", len(buf)) + bytes(buf)


def ja4q(fingerprint_dict):
    """QUIC 的 JA4：算法与 TLS 完全相同，仅首字符 t→q。"""
    ja4 = fingerprint_dict["ja4"]
    return "q" + ja4[1:] if ja4.startswith("t") else ja4
