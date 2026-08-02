"""HTTP/2 客户端 —— 按 profile 复刻 SETTINGS / WINDOW_UPDATE / 伪头顺序。

**为什么不用现成的 h2 库**：hyper-h2 会按自己的规则发 SETTINGS，参数取值和
顺序都是库定的，那正是指纹的一部分。要冒充某个浏览器，SETTINGS 必须逐项照
profile 发（连顺序都要——safari172_ios 是 2,4,3 而其余 safari 是 2,3,4）。
HPACK 编解码没有指纹含义，仍用 hpack 库。

配合 tls13.TLS13Client 使用：它只提供 send/read，本模块在其上做帧层。
"""

import struct

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_DATA, FRAME_HEADERS, FRAME_SETTINGS = 0x0, 0x1, 0x4
FRAME_PRIORITY = 0x2
FRAME_WINDOW_UPDATE, FRAME_GOAWAY, FRAME_RST = 0x8, 0x7, 0x3

FLAG_END_STREAM, FLAG_END_HEADERS = 0x1, 0x4


def _frame(ftype, flags, stream_id, payload=b""):
    n = len(payload)
    return (bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF, ftype, flags])
            + struct.pack(">I", stream_id) + payload)


class H2Client:
    """在一条已完成 TLS 握手（ALPN=h2）的连接上跑 HTTP/2。

    profile 取 h2_curl_cffi.json / h2_real_browsers.json 里那份结构：
    settings=[(id,value)] 保序、window_update=int、pseudo_header_order=[":method",…]
    """

    def __init__(self, conn, h2_profile):
        self.conn = conn
        self.profile = h2_profile
        self._buf = b""
        self._next_stream = 1

    def connect(self):
        """发 preface + SETTINGS + WINDOW_UPDATE，顺序与真实浏览器一致。"""
        out = PREFACE
        settings = b"".join(struct.pack(">HI", k, v)
                            for k, v in self.profile["settings"])
        out += _frame(FRAME_SETTINGS, 0, 0, settings)
        wu = self.profile.get("window_update")
        if wu:
            out += _frame(FRAME_WINDOW_UPDATE, 0, 0, struct.pack(">I", wu))
        # **PRIORITY 帧也要发**。Firefox 开场发 6 条分组帧，它们进 akamai 指纹的
        # 第三段；本客户端此前一条都不发，于是对端看到的是 `…|0|…` 而 profile 里
        # 写着 `…|3:0:0:201|5:0:0:101|…` —— 端到端一直是绿的，因为那些门禁只看
        # ServerHello 与 :status，没有一条去问"对端看到的 h2 指纹是什么"。
        # C 侧的 tlsfp_build_h2_preface 一直在发，又是一处两份实现的分叉。
        for pr in (self.profile.get("priorities") or []):
            sid, dep, excl, weight = pr
            out += _frame(FRAME_PRIORITY, 0, sid,
                          struct.pack(">IB", (dep | (0x80000000 if excl else 0)),
                                      weight))
        self.conn.send(out)
        return self

    def request(self, method, path, authority, scheme="https", headers=None):
        """发一个请求，返回 stream_id。伪头顺序照 profile，不用字典序。"""
        from hpack import Encoder

        pseudo = {":method": method, ":authority": authority,
                  ":scheme": scheme, ":path": path}
        ordered = [(k, pseudo[k]) for k in self.profile["pseudo_header_order"]
                   if k in pseudo]
        ordered += list(headers or [])

        block = Encoder().encode(ordered)
        sid = self._next_stream
        self._next_stream += 2
        self.conn.send(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM,
                              sid, block))
        return sid

    def read_response(self, stream_id, max_frames=200):
        """读到该 stream 的 END_STREAM 为止，返回 (headers, body)。"""
        from hpack import Decoder

        decoder = Decoder()
        headers, body = [], b""
        for _ in range(max_frames):
            ftype, flags, sid, payload = self._next_frame()
            if ftype == FRAME_SETTINGS and not (flags & 0x1):
                self.conn.send(_frame(FRAME_SETTINGS, 0x1, 0))   # ACK
            elif ftype == FRAME_GOAWAY:
                code = struct.unpack_from(">I", payload, 4)[0] if len(payload) >= 8 else -1
                raise OSError(f"GOAWAY error_code={code}")
            elif ftype == FRAME_RST and sid == stream_id:
                code = struct.unpack_from(">I", payload, 0)[0]
                raise OSError(f"RST_STREAM error_code={code}")
            elif sid == stream_id and ftype == FRAME_HEADERS:
                headers += decoder.decode(self._strip_headers_padding(payload, flags))
            elif sid == stream_id and ftype == FRAME_DATA:
                body += payload
            if sid == stream_id and (flags & FLAG_END_STREAM):
                return headers, body
        raise OSError("response did not end within frame budget")

    @staticmethod
    def _strip_headers_padding(payload, flags):
        o = 0
        pad = payload[0] if flags & 0x8 else 0
        if flags & 0x8:
            o += 1
        if flags & 0x20:
            o += 5
        return payload[o:len(payload) - pad]

    def _next_frame(self):
        while len(self._buf) < 9:
            self._fill()
        head = self._buf[:9]
        length = (head[0] << 16) | (head[1] << 8) | head[2]
        while len(self._buf) < 9 + length:
            self._fill()
        payload = self._buf[9:9 + length]
        self._buf = self._buf[9 + length:]
        sid = struct.unpack_from(">I", head, 5)[0] & 0x7FFFFFFF
        return head[3], head[4], sid, payload

    def _fill(self):
        chunk = self.conn.read()
        if not chunk:
            raise OSError("connection closed mid-frame")
        self._buf += chunk
