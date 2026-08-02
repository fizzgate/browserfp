"""TLS 1.3 客户端握手（RFC 8446）—— 按 profile 发指纹化 ClientHello。

**定位**：C 模块的 Python 参考实现。用它验证"从 golden 重建的 ClientHello 能
真的完成握手并跑 h2"，而不是拿来跑生产——生产走 BoringSSL C 模块。

对外暴露 send/read/settimeout/close 四方法，与宿主 Lua 侧的 TLS 客户端抽象同一个契约，将来换引擎
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

from cryptography.hazmat.primitives.serialization import (          # noqa: E402
    Encoding, PublicFormat)
from oracle.chbuild import (_parse_key_share, _u16, _vec,           # noqa: E402
                            build_client_hello, grease_ech)
from oracle.clienthello import is_grease                            # noqa: E402

X25519_GROUP = 0x001D
SECP256R1_GROUP, SECP384R1_GROUP = 0x0017, 0x0018

# HelloRetryRequest 的标志：ServerHello 的 random 恒等于 SHA-256("HelloRetryRequest")
# （RFC 8446 §4.1.3）。它长得跟 ServerHello 一模一样，只有这 32 字节能区分 ——
# 不认它就会把"请你换个组重发"当成"这是服务端的公钥"，然后在算共享密钥时
# 报一个与真因毫无关系的错。
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
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

    def __init__(self, sock, profile, sni, verify=False, hello=None, privs=None):
        """hello/privs 非空时，**用调用方给的 ClientHello 字节上线**。

        这是为了验"生产真正发的那份字节"：C 构造器出的 hello 由本类完成握手，
        Python 侧只负责密钥调度。不这么做的话，回显门禁验的永远是参考实现那份，
        而生产发的是 C 那份 —— 本项目已经栽过五次"两份实现悄悄分叉"。

        privs 必须与 hello 里 key_share 的公钥对应，否则算不出共享密钥。
        """
        self._hello_override = hello
        self._privs_override = privs
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
        # **按 profile 的 key_share 形状逐组生成真密钥**，而不是只发首选那条。
        # 真机会同时发 GREASE + 后量子混合 + X25519（chrome131 是三条），只发一条
        # 与它自己的 supported_groups 对不上。GREASE 那条由构造器照抄 profile。
        if self._hello_override is not None:
            record = self._hello_override
            self._privs = self._privs_override or {}
        else:
            self._shares, self._privs = self._gen_shares()
            record = self._build_hello(self._shares)
        self._use_mlkem = X25519MLKEM768_GROUP in self._privs
        # 留一份**实际发出去的字节**。要回答"对端看到的指纹是不是我们想要的"，
        # 就得拿这份去算，而不是拿 profile 里存的值 —— 后者是采集时的，
        # 与本次真正上线的字节之间隔着构造器。
        self.client_hello = record
        # transcript 只含 handshake 消息体，不含 record 头
        self.transcript += record[5:]
        self.sock.sendall(record)

        server_pub, self.cipher_suite, is_hrr = self._read_server_hello()
        if is_hrr:
            # **HelloRetryRequest**：服务端要一个我们没在 key_share 里发过的组。
            # 真浏览器都会补发，我们不补的话表现是"某些站点连不上"，而错误信息
            # 会指向共享密钥算错 —— 与真因毫无关系。
            g = self._negotiated_group
            pub, priv = self._gen_one_share(g)
            if pub is None:
                raise TLSError(
                    f"HelloRetryRequest 要 0x{g:04x}，参考实现产不出这条曲线的"
                    "密钥 —— 这是实现能力不足，不是 profile 不可用")
            self._privs[g] = priv
            # 第二个 ClientHello **只改 key_share**，其余照旧（RFC 8446 §4.1.2）
            record = self._build_hello(None, hrr=(g, pub))
            self.transcript += record[5:]
            self.sock.sendall(record)
            server_pub, self.cipher_suite, again = self._read_server_hello()
            if again:
                raise TLSError("连续两次 HelloRetryRequest —— 协议不允许")
        hashname, aead_cls, key_len = CIPHER_PARAMS[self.cipher_suite]
        hlen = hashlib.new(hashname).digest_size

        if self._negotiated_group == X25519MLKEM768_GROUP:
            if len(server_pub) != MLKEM_CT_LEN + X25519_LEN:
                raise TLSError(f"bad X25519MLKEM768 server share: {len(server_pub)}")
            ct, srv_x = server_pub[:MLKEM_CT_LEN], server_pub[MLKEM_CT_LEN:]
            mk, xk = self._privs[X25519MLKEM768_GROUP]
            shared = (mk.decapsulate(ct)
                      + xk.exchange(X25519PublicKey.from_public_bytes(srv_x)))
        elif self._negotiated_group in (SECP256R1_GROUP, SECP384R1_GROUP):
            from cryptography.hazmat.primitives.asymmetric.ec import (
                ECDH, SECP256R1, SECP384R1, EllipticCurvePublicKey)
            curve = (SECP256R1() if self._negotiated_group == SECP256R1_GROUP
                     else SECP384R1())
            peer = EllipticCurvePublicKey.from_encoded_point(curve, server_pub)
            shared = self._privs[self._negotiated_group].exchange(ECDH(), peer)
        else:
            if X25519_GROUP not in self._privs:
                raise TLSError(
                    f"服务端选了 0x{self._negotiated_group:04x}，而参考实现只做 "
                    "X25519 与 X25519MLKEM768 —— 这是实现能力不足，不是 profile 不可用")
            shared = self._privs[X25519_GROUP].exchange(
                X25519PublicKey.from_public_bytes(server_pub))

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

    def _gen_one_share(self, group):
        """为 HRR 指定的那一个组生成密钥。产不出就返回 (None, None)。"""
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1, SECP384R1, generate_private_key)

        if group == X25519_GROUP:
            pk = X25519PrivateKey.generate()
            return pk.public_key().public_bytes_raw(), pk
        if group == X25519MLKEM768_GROUP:
            mk, xk = MLKEM768PrivateKey.generate(), X25519PrivateKey.generate()
            return (mk.public_key().public_bytes_raw()
                    + xk.public_key().public_bytes_raw()), (mk, xk)
        curve = {SECP256R1_GROUP: SECP256R1, SECP384R1_GROUP: SECP384R1}.get(group)
        if curve is None:
            return None, None
        ek = generate_private_key(curve())
        return ek.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint), ek

    def _gen_shares(self):
        """按 profile 的 key_share 形状逐组生成**真**密钥。

        返回 ({group: pub_bytes}, {group: 私钥})。GREASE 那条不生成 —— 构造器
        会照抄 profile（RFC 8701 规定内容固定）。

        0x6399（Kyber768Draft00）我们生成不了（cryptography 只有 ML-KEM）——
        那 3 条 profile 上留给构造器填随机字节；**服务端真选中它时握手会失败**，
        那是实现能力不足，会明确报出来而不是悄悄发一把假公钥当成功。
        """
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1, generate_private_key)

        eb = self.profile.get("extension_bodies") or {}
        k = [x for x in eb if int(x) == 0x0033]
        shape = _parse_key_share(bytes.fromhex(eb[k[0]])) if k else []
        pubs, privs = {}, {}
        for group, plen in shape:
            if is_grease(group):
                continue
            if group == X25519_GROUP:
                pk = X25519PrivateKey.generate()
                pubs[group] = pk.public_key().public_bytes_raw()
                privs[group] = pk
            elif group == X25519MLKEM768_GROUP:
                mk = MLKEM768PrivateKey.generate()
                xk = X25519PrivateKey.generate()
                pubs[group] = (mk.public_key().public_bytes_raw()
                               + xk.public_key().public_bytes_raw())
                privs[group] = (mk, xk)
            elif group == 0x0017 and plen == 65:
                ek = generate_private_key(SECP256R1())
                pubs[group] = ek.public_key().public_bytes(
                    Encoding.X962, PublicFormat.UncompressedPoint)
                privs[group] = ek
        return pubs, privs

    def _build_hello(self, shares, hrr=None):
        """走**发货那份构造器**，只把真密钥注进去。

        这里原来是自造的一份组装逻辑，于是与 chbuild / C 那两份长期分叉，而且
        分叉的方向恰好让端到端测试**看起来更好**：它补 SNI、新鲜生成 GREASE ECH、
        跳过 pre_shared_key，发货那两份一度三样都不做。"端到端全绿"证明的是
        测试用的构造器能用，不是我们发货的能用 —— 三处缺陷都是这么藏住的。

        反过来它自己也藏着一个：key_share **只发首选那一条**，把 GREASE 条目与
        其余分组全丢了（真机 chrome131 发三条）。`test_builder_parity` 就是抓
        这一类的。现在统一走 `build_client_hello`，形状由 profile 决定。
        """
        if hrr is not None:
            # 沿用第一次的 GREASE / random / session_id：CH2 是 CH1 的修改版，
            # 不是新的一条。random 与 session_id 从 CH1 的字节里取回来。
            ch1 = self.client_hello
            rnd = ch1[11:43]
            sid_len = ch1[43]
            sid = ch1[44:44 + sid_len]
            from oracle.clienthello import parse_client_hello as _p
            eb = _p(ch1)["extension_bodies"]
            k = [x for x in eb if int(x) == 0xFE0D]
            return build_client_hello(self.profile, sni=self.sni,
                                      hrr_group=hrr, grease=self._grease,
                                      random32=rnd, session_id=sid,
                                      ech_body=bytes.fromhex(eb[k[0]]) if k else None,
                                      record_version=0x0303)
        from oracle.chbuild import pick_grease
        self._grease = pick_grease()
        return build_client_hello(self.profile, sni=self.sni, key_shares=shares,
                                  grease=self._grease)

    def _read_server_hello(self):
        # **HRR 之后服务端会先发一条 ChangeCipherSpec**（中间盒兼容用，
        # RFC 8446 附录 D.4），必须跳过。不跳的表现是
        # "expected handshake, got content type 20" —— 看着像协议错，
        # 其实是我们少读了一条无关紧要的记录。
        while True:
            ctype, head, body = self._read_record()
            if ctype != 0x14:                 # 0x14 = ChangeCipherSpec
                break
        if ctype != 0x16:
            raise TLSError(f"expected handshake, got content type {ctype}")
        if body[0] != HS_SERVER_HELLO:
            raise TLSError(f"expected ServerHello, got handshake type {body[0]}")
        if body[6:38] == HRR_RANDOM:
            # **transcript 要先把 CH1 换成 message_hash**（RFC 8446 §4.4.1）：
            #   Transcript-Hash(ClientHello1, HRR, ...) =
            #       Hash(message_hash || 00 00 Hash.length || Hash(CH1)) || HRR || ...
            # 不做这一步，后面所有密钥都会算错，而症状是 Finished 校验失败 ——
            # 又是一个"错在 A、报在 B"的地方。
            hn = "sha256"
            digest = hashlib.new(hn, self.transcript).digest()
            self.transcript = (bytes([254, 0, 0, len(digest)]) + digest)
        self.transcript += body

        is_hrr = body[6:38] == HRR_RANDOM
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
                self._negotiated_group = group
                if is_hrr:
                    # HRR 的 key_share 里**只有组号，没有公钥**
                    server_pub = b""
                else:
                    klen = struct.unpack_from(">H", ebody, 2)[0]
                    server_pub = ebody[4:4 + klen]

        if server_pub is None:
            raise TLSError("ServerHello 无 key_share（可能回落到 TLS 1.2）")
        if cipher not in CIPHER_PARAMS:
            raise TLSError(f"unsupported cipher 0x{cipher:04x}")
        return server_pub, cipher, is_hrr

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
