"""TLS 1.3 客户端握手（RFC 8446）—— 按 profile 发指纹化 ClientHello。

**定位**：C 模块的 Python 参考实现。用它验证"从 golden 重建的 ClientHello 能
真的完成握手并跑 h2"，而不是拿来跑生产——生产走 BoringSSL C 模块。

对外暴露 send/read/settimeout/close 四方法，与 fizz-node-resty 的
tls13_client.lua、proxy_endpoint.lua:_browser_tls() 同一个契约，将来换引擎
下游不用改。

**密钥交换支持**：X25519 与 X25519MLKEM768（0x11ec，后量子混合）。后者靠
cryptography 50 的 MLKEM768PrivateKey——本机这版链接 OpenSSL 4.0.1，原生带
ML-KEM，不需要 ctypes 绑定，也不需要为此上 BoringSSL。含 0x11ec 的 profile
（chrome131/133a/136、firefox133/135、safari260）实测均可对真实 CF 完成
TLS1.3 握手并跑 h2 拿到 200。

**已知局限**：不支持 X25519Kyber768Draft00（0x6399）——那是被 ML-KEM 取代的
过时草案，cryptography 未实现。仅影响 chrome124 一个 profile。
"""

import hashlib
import hmac
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.mlkem import (       # noqa: E402
    MLKEM768PrivateKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (      # noqa: E402
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import (           # noqa: E402
    AESGCM, ChaCha20Poly1305)

from oracle.chbuild import _u16, _vec                               # noqa: E402
from oracle.clienthello import is_grease                            # noqa: E402

X25519_GROUP = 0x001D
X25519MLKEM768_GROUP = 0x11EC

# X25519MLKEM768 的线上布局（draft-ietf-tls-ecdhe-mlkem）：
#   client_share = ML-KEM-768 封装密钥(1184) || X25519 公钥(32)      = 1216
#   server_share = ML-KEM-768 密文(1088)     || X25519 公钥(32)      = 1120
#   shared       = ML-KEM 共享密钥(32)       || X25519 共享密钥(32)  = 64
# 1216 这个数与 golden 里 chrome136/firefox135 的 key_share 实测长度吻合，
# 不是按规范猜的。
MLKEM_EK_LEN, MLKEM_CT_LEN, X25519_LEN = 1184, 1088, 32

CIPHER_PARAMS = {
    0x1301: ("sha256", AESGCM, 16),      # TLS_AES_128_GCM_SHA256
    0x1302: ("sha384", AESGCM, 32),      # TLS_AES_256_GCM_SHA384
    0x1303: ("sha256", ChaCha20Poly1305, 32),  # TLS_CHACHA20_POLY1305_SHA256
}

HS_SERVER_HELLO = 2
HS_ENCRYPTED_EXTENSIONS = 8
HS_CERTIFICATE = 11
HS_CERTIFICATE_VERIFY = 15
HS_FINISHED = 20
HS_NEW_SESSION_TICKET = 4


class TLSError(Exception):
    pass


def hkdf_extract(salt, ikm, hashname):
    return hmac.new(salt, ikm, hashname).digest()


def hkdf_expand(prk, info, length, hashname):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashname).digest()
        out += t
        i += 1
    return out[:length]


def hkdf_expand_label(secret, label, context, length, hashname):
    info = _u16(length) + _vec(b"tls13 " + label, 1) + _vec(context, 1)
    return hkdf_expand(secret, info, length, hashname)


def derive_secret(secret, label, messages, hashname):
    digest = hashlib.new(hashname, messages).digest()
    return hkdf_expand_label(secret, label, digest, len(digest), hashname)


class _Keys:
    """一个方向的 AEAD 上下文：key + iv + 序号。"""

    def __init__(self, secret, aead_cls, key_len, hashname):
        self.key = hkdf_expand_label(secret, b"key", b"", key_len, hashname)
        self.iv = hkdf_expand_label(secret, b"iv", b"", 12, hashname)
        self.aead = aead_cls(self.key)
        self.seq = 0

    def nonce(self):
        n = bytearray(self.iv)
        seq = struct.pack(">Q", self.seq)
        for i in range(8):
            n[4 + i] ^= seq[i]
        self.seq += 1
        return bytes(n)


class TLS13Client:
    """在已连接的 socket 上跑 TLS 1.3 握手，之后当加密管道用。

    verify=False 时跳过证书校验——参考实现只用于指纹验证与本地联调，生产由
    C 模块承担，那里必须开校验（server Finished 的 HMAC 只保握手完整性、
    不绑证书，缺了链校验一样能被 MITM）。
    """

    def __init__(self, sock, profile, sni, verify=False):
        self.sock = sock
        self.profile = profile
        self.sni = sni
        self.verify = verify
        self.transcript = b""
        self._inbuf = b""
        self._plainbuf = b""
        self.negotiated_alpn = None
        self.cipher_suite = None
        self._negotiated_group = None
        self._use_mlkem = False
        self._closed = False

    # ---- 网络原语 -------------------------------------------------------
    def _recv_exact(self, n):
        while len(self._inbuf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise TLSError(f"connection closed ({len(self._inbuf)}/{n})")
            self._inbuf += chunk
        out, self._inbuf = self._inbuf[:n], self._inbuf[n:]
        return out

    def _read_record(self):
        head = self._recv_exact(5)
        length = struct.unpack_from(">H", head, 3)[0]
        return head[0], head, self._recv_exact(length)

    # ---- 握手 -----------------------------------------------------------
    def handshake(self):
        # 按 profile 的首选曲线决定 key_share 形态：含 0x11ec 就发后量子混合，
        # 否则退到纯 X25519。发什么必须跟 supported_groups 的首项一致，否则
        # 服务端会发 HelloRetryRequest。
        self._use_mlkem = X25519MLKEM768_GROUP in (self.profile.get("curves") or [])
        x_priv = X25519PrivateKey.generate()
        x_pub = x_priv.public_key().public_bytes_raw()
        mlkem_priv = MLKEM768PrivateKey.generate() if self._use_mlkem else None

        record = self._build_hello(x_pub, mlkem_priv)
        # transcript 只含 handshake 消息体，不含 record 头
        self.transcript += record[5:]
        self.sock.sendall(record)

        server_pub, self.cipher_suite = self._read_server_hello()
        hashname, aead_cls, key_len = CIPHER_PARAMS[self.cipher_suite]
        hlen = hashlib.new(hashname).digest_size

        if self._negotiated_group == X25519MLKEM768_GROUP:
            if len(server_pub) != MLKEM_CT_LEN + X25519_LEN:
                raise TLSError(f"bad X25519MLKEM768 server share: {len(server_pub)}")
            ct, srv_x = server_pub[:MLKEM_CT_LEN], server_pub[MLKEM_CT_LEN:]
            shared = (mlkem_priv.decapsulate(ct)
                      + x_priv.exchange(X25519PublicKey.from_public_bytes(srv_x)))
        else:
            shared = x_priv.exchange(X25519PublicKey.from_public_bytes(server_pub))

        early = hkdf_extract(b"\x00" * hlen, b"\x00" * hlen, hashname)
        derived = derive_secret(early, b"derived", b"", hashname)
        hs_secret = hkdf_extract(derived, shared, hashname)

        c_hs = derive_secret(hs_secret, b"c hs traffic", self.transcript, hashname)
        s_hs = derive_secret(hs_secret, b"s hs traffic", self.transcript, hashname)
        self._rx = _Keys(s_hs, aead_cls, key_len, hashname)
        self._tx = _Keys(c_hs, aead_cls, key_len, hashname)

        self._read_server_flight(hashname)

        # server Finished 已进 transcript，此处的摘要用于导出 application 密钥
        after_server = self.transcript
        finished_key = hkdf_expand_label(c_hs, b"finished", b"", hlen, hashname)
        verify_data = hmac.new(
            finished_key, hashlib.new(hashname, after_server).digest(), hashname).digest()
        fin = bytes([HS_FINISHED]) + _vec(verify_data, 3)
        self._send_encrypted(fin, 0x16)
        self.transcript += fin

        derived2 = derive_secret(hs_secret, b"derived", b"", hashname)
        master = hkdf_extract(derived2, b"\x00" * hlen, hashname)
        c_ap = derive_secret(master, b"c ap traffic", after_server, hashname)
        s_ap = derive_secret(master, b"s ap traffic", after_server, hashname)
        self._tx = _Keys(c_ap, aead_cls, key_len, hashname)
        self._rx = _Keys(s_ap, aead_cls, key_len, hashname)
        return self

    def _build_hello(self, x_pub, mlkem_priv=None):
        """按 profile 组装 ClientHello，但用真实 key_share 与真实 SNI 覆写。"""
        p = self.profile
        bodies = {int(k): bytes.fromhex(v)
                  for k, v in p["extension_bodies"].items()}

        # profile 可能来自 no-SNI 采集（真机浏览器只能这么采，见 browsers.py），
        # 那样 raw_extensions 里没有 0x0000，遍历它永远发不出 SNI —— 打
        # cloudflare.com 不报错（有默认证书），打 claude.ai 这类多租户站点则
        # 直接 handshake_failure(40)。这里按实测规律补：SNI 紧跟开头的 GREASE，
        # 无 GREASE 时排第一（31 个 curl_cffi profile 全部符合，tor145 是唯一
        # 无 GREASE 的，其 SNI 就在第 0 位）。
        ext_order = list(p["raw_extensions"])
        if self.sni and 0x0000 not in ext_order:
            pos = 1 if ext_order and is_grease(ext_order[0]) else 0
            ext_order.insert(pos, 0x0000)

        ext_bytes = b""
        for ext_id in ext_order:
            if is_grease(ext_id):
                ext_bytes += _u16(ext_id) + _vec(bodies.get(ext_id, b""), 2)
                continue
            if ext_id == 0x0000:
                entry = bytes([0]) + _vec(self.sni.encode(), 2)
                body = _vec(entry, 2)
            elif ext_id == 0x0033:
                body = _vec(self._key_share_entries(x_pub, mlkem_priv), 2)
            elif ext_id == 0x0029:
                continue          # pre_shared_key：无票据可用，整个扩展不发
            elif ext_id == 0xFE0D:
                # GREASE ECH：Chrome 恒发。**不能跳过**——claude.ai 缺了它直接
                # 回 handshake_failure(40)，而 cloudflare.com 不要求，只打后者
                # 会漏掉这个缺陷。也**不能照搬 golden 的 body**：config_id 只有
                # 1 字节，固定值一旦撞上服务端真实 ECH 配置，它会拿自己的私钥去
                # 解 payload 并失败，同样是 handshake_failure。必须每次新鲜生成。
                body = self._grease_ech(bodies.get(ext_id, b""))
                if not body:
                    continue
            else:
                body = bodies.get(ext_id, b"")
            ext_bytes += _u16(ext_id) + _vec(body, 2)

        hello = _u16(p.get("client_version", 0x0303))
        hello += os.urandom(32)
        hello += _vec(os.urandom(p.get("session_id_len", 32) or 32), 1)
        hello += _vec(b"".join(_u16(c) for c in p["raw_ciphers"]), 2)
        hello += _vec(bytes(p.get("compression", [0])), 1)
        hello += _vec(ext_bytes, 2)

        handshake = bytes([0x01]) + _vec(hello, 3)
        return bytes([0x16]) + _u16(0x0301) + _vec(handshake, 2)

    @staticmethod
    def _grease_ech(golden_body):
        """按 draft-ietf-tls-esni 的 outer 形态生成 GREASE ECH。

            type(1)=0 | kdf(2) | aead(2) | config_id(1) | enc<2> | payload<2>

        config_id / enc / payload 内容全部新鲜随机；**payload 长度沿用 golden**
        —— 它决定 ClientHello 总长度，属于该 profile 指纹的一部分，随意改会让
        我们发出的 CH 与真实浏览器长度对不上。kdf/aead 也照 golden（实测三个
        Chrome profile 都是 0x0001/0x0001）。

        服务端遇到不认识的 config_id 应按规范忽略 ECH 并正常握手，所以这里
        不需要任何服务端配合。
        """
        if not golden_body or len(golden_body) < 8:
            return b""
        kdf, aead = struct.unpack_from(">HH", golden_body, 1)
        enc_len = struct.unpack_from(">H", golden_body, 6)[0]
        payload_len = struct.unpack_from(">H", golden_body, 8 + enc_len)[0]
        return (bytes([0]) + struct.pack(">HH", kdf, aead)
                + os.urandom(1)                       # config_id
                + _vec(os.urandom(enc_len), 2)        # enc（HPKE 公钥）
                + _vec(os.urandom(payload_len), 2))   # payload（伪密文）

    def _key_share_entries(self, x_pub, mlkem_priv):
        """按 profile 首选曲线产出 key_share 条目。

        只发首选那一条（外加后量子混合时它本身就含 X25519）——真实浏览器也只为
        前一两条曲线发公钥，不是每条都发；发多了反而与 golden 的 key_share 长度
        对不上。
        """
        if mlkem_priv is not None:
            share = mlkem_priv.public_key().public_bytes_raw() + x_pub
            return _u16(X25519MLKEM768_GROUP) + _vec(share, 2)
        return _u16(X25519_GROUP) + _vec(x_pub, 2)

    def _read_server_hello(self):
        ctype, head, body = self._read_record()
        if ctype != 0x16:
            raise TLSError(f"expected handshake, got content type {ctype}")
        if body[0] != HS_SERVER_HELLO:
            raise TLSError(f"expected ServerHello, got handshake type {body[0]}")
        self.transcript += body

        o = 4 + 2 + 32                       # type/len + version + random
        sid_len = body[o]
        o += 1 + sid_len
        cipher = struct.unpack_from(">H", body, o)[0]
        o += 2 + 1                            # cipher + compression
        ext_total = struct.unpack_from(">H", body, o)[0]
        o += 2
        end = o + ext_total

        server_pub = None
        while o < end:
            eid, elen = struct.unpack_from(">HH", body, o)
            ebody = body[o + 4:o + 4 + elen]
            o += 4 + elen
            if eid == 0x0033:                 # key_share
                group = struct.unpack_from(">H", ebody, 0)[0]
                if group not in (X25519_GROUP, X25519MLKEM768_GROUP):
                    raise TLSError(
                        f"server chose group 0x{group:04x}; "
                        f"参考实现支持 X25519 / X25519MLKEM768")
                self._negotiated_group = group
                klen = struct.unpack_from(">H", ebody, 2)[0]
                server_pub = ebody[4:4 + klen]

        if server_pub is None:
            raise TLSError("ServerHello 无 key_share（可能回落到 TLS 1.2）")
        if cipher not in CIPHER_PARAMS:
            raise TLSError(f"unsupported cipher 0x{cipher:04x}")
        return server_pub, cipher

    def _decrypt_record(self, head, payload):
        plain = self._rx.aead.decrypt(self._rx.nonce(), payload, head)
        # 去掉尾部 padding，最后一个非零字节是真实 content type
        i = len(plain) - 1
        while i >= 0 and plain[i] == 0:
            i -= 1
        if i < 0:
            raise TLSError("decrypted record is all padding")
        return plain[i], plain[:i]

    def _read_server_flight(self, hashname):
        """读 EncryptedExtensions..Finished，沿途累积 transcript。"""
        pending = b""
        while True:
            ctype, head, payload = self._read_record()
            if ctype == 0x14:                 # ChangeCipherSpec：middlebox 兼容，忽略
                continue
            if ctype != 0x17:
                raise TLSError(f"unexpected content type {ctype} during flight")
            inner_type, plain = self._decrypt_record(head, payload)
            if inner_type != 0x16:
                raise TLSError(f"expected handshake, got inner type {inner_type}")
            pending += plain

            while len(pending) >= 4:
                htype = pending[0]
                hlen = (pending[1] << 16) | (pending[2] << 8) | pending[3]
                if len(pending) < 4 + hlen:
                    break
                msg, pending = pending[:4 + hlen], pending[4 + hlen:]
                if htype == HS_ENCRYPTED_EXTENSIONS:
                    self._parse_encrypted_extensions(msg)
                self.transcript += msg
                if htype == HS_FINISHED:
                    return

    def _parse_encrypted_extensions(self, msg):
        o, total = 4, struct.unpack_from(">H", msg, 4)[0]
        o += 2
        end = o + total
        while o < end:
            eid, elen = struct.unpack_from(">HH", msg, o)
            ebody = msg[o + 4:o + 4 + elen]
            o += 4 + elen
            if eid == 0x0010 and len(ebody) >= 3:      # ALPN
                self.negotiated_alpn = ebody[3:3 + ebody[2]].decode()

    # ---- 应用数据 -------------------------------------------------------
    def _send_encrypted(self, data, inner_type):
        plain = data + bytes([inner_type])
        head = bytes([0x17]) + _u16(0x0303) + _u16(len(plain) + 16)
        self.sock.sendall(head + self._tx.aead.encrypt(self._tx.nonce(), plain, head))

    def send(self, data):
        self._send_encrypted(data, 0x17)
        return len(data)

    def read(self):
        """返回一段应用数据（语义同 tls13_client.lua:read —— 有多少给多少）。"""
        while not self._plainbuf:
            ctype, head, payload = self._read_record()
            if ctype == 0x14:
                continue
            inner_type, plain = self._decrypt_record(head, payload)
            if inner_type == 0x16:
                continue                       # NewSessionTicket 等，忽略
            if inner_type == 0x15:             # alert
                if len(plain) >= 2 and plain[1] == 0:
                    return b""                 # close_notify
                raise TLSError(f"alert level={plain[0]} desc={plain[1]}")
            self._plainbuf += plain
        out, self._plainbuf = self._plainbuf, b""
        return out

    def settimeout(self, seconds):
        self.sock.settimeout(seconds)

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                self.sock.close()
            except OSError:
                pass
