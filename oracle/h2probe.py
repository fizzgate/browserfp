"""L2 观测点：真 TLS 握手 + ALPN h2，抓 HTTP/2 层指纹。

**为什么必须有这一层**：curl_cffi 的"一个指纹"是三层——ClientHello、HTTP/2
SETTINGS、头序。L1(sniffer.py) 只覆盖第一层。只对 TLS 不对 h2，得到的是
"ClientHello 像 Chrome、协议栈像 curl"的 split-brain，比不伪装更容易被判。

输出 Akamai HTTP/2 fingerprint 格式：
    SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
例  1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p

与 L1 不同，这里必须完成真握手才能拿到 h2 帧，所以需要自签证书，客户端也必须
信任它。三种客户端三条路径，都已打通：
  · curl_cffi  SSL_VERIFYPEER=0
  · Chromium   --ignore-certificate-errors（151 起还须 -spki-list）
  · Firefox    certutil 往临时 profile 的 cert9.db 注入 CA
  · Safari     注入用户钥匙串，采完即删（h2collect.py:_capture_safari）
"""

import os
import socket
import ssl
import struct
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
# 发**完整链**（leaf + CA）而不是只发 leaf：Firefox 库里有 CA 能自己补全，
# Safari 严格要求服务端把中间证书一并发出，只发 leaf 会回
# SSLV3_ALERT_CERTIFICATE_UNKNOWN。Chrome 的 SPKI pin 仍指 leaf，不受影响。
CERT = os.path.join(HERE, "..", "spec", "certs", "fullchain.pem")
CA_CERT = os.path.join(HERE, "..", "spec", "certs", "ca.pem")
KEY = os.path.join(HERE, "..", "spec", "certs", "key.pem")

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_NAMES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
               4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY",
               8: "WINDOW_UPDATE", 9: "CONTINUATION"}


class H2Probe:
    """TLS+h2 观测点。收到客户端第一个 HEADERS 帧即算采集完成。"""

    def __init__(self, host="127.0.0.1", port=0, alpn=("h2", "http/1.1")):
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(CERT, KEY)
        self._ctx.set_alpn_protocols(list(alpn))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(8)
        self.host, self.port = self._sock.getsockname()
        self._results = []
        self._errors = []
        self._cv = threading.Condition()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        tls = None
        try:
            conn.settimeout(20)
            tls = self._ctx.wrap_socket(conn, server_side=True)
            alpn = tls.selected_alpn_protocol()
            if alpn != "h2":
                self._push_error(f"client negotiated {alpn!r}, not h2")
                return
            self._push(self._read_h2(tls, alpn))
        except (OSError, ssl.SSLError) as e:
            self._push_error(f"{type(e).__name__}: {e}")
        finally:
            for s in (tls, conn):
                try:
                    if s:
                        s.close()
                except OSError:
                    pass

    def _read_h2(self, tls, alpn):
        """读到第一个 HEADERS（END_HEADERS）为止，沿途记录所有帧。"""
        buf = self._recv_exact(tls, len(PREFACE))
        if buf != PREFACE:
            raise OSError(f"bad h2 preface: {buf[:24]!r}")

        settings, window_update, priorities, frame_seq = [], None, [], []
        header_block = b""

        while True:
            head = self._recv_exact(tls, 9)
            length, ftype, flags, sid = self._parse_frame_header(head)
            payload = self._recv_exact(tls, length) if length else b""
            frame_seq.append(FRAME_NAMES.get(ftype, str(ftype)))

            if ftype == 4 and not (flags & 0x1):           # SETTINGS (非 ACK)
                for i in range(0, len(payload), 6):
                    sid_, val = struct.unpack_from(">HI", payload, i)
                    settings.append((sid_, val))
            elif ftype == 8:                                # WINDOW_UPDATE
                window_update = struct.unpack_from(">I", payload, 0)[0] & 0x7FFFFFFF
            elif ftype == 2:                                # PRIORITY
                dep, weight = struct.unpack_from(">IB", payload, 0)
                priorities.append((sid, dep & 0x7FFFFFFF, (dep >> 31) & 1, weight + 1))
            elif ftype == 1:                                # HEADERS
                header_block += self._headers_payload(payload, flags)
                if flags & 0x4:                             # END_HEADERS
                    break
            elif ftype == 9:                                # CONTINUATION
                header_block += payload
                if flags & 0x4:
                    break

        pseudo, regular, values = self._decode_headers(header_block)
        return {
            "alpn": alpn,
            "settings": settings,
            "window_update": window_update,
            "priorities": priorities,
            "pseudo_header_order": pseudo,
            "header_order": regular,
            # 取值和顺序一样是指纹（accept / sec-ch-ua 都是版本相关的）。
            # 之前这里把解出来的值直接丢了 —— 解码本来就产出 (k, v) 对，
            # 只返回键名等于白采一遍。
            "header_values": values,
            "frame_sequence": frame_seq,
            "akamai_fingerprint": self._akamai(settings, window_update, priorities, pseudo),
        }

    @staticmethod
    def _parse_frame_header(head):
        length = (head[0] << 16) | (head[1] << 8) | head[2]
        ftype, flags = head[3], head[4]
        sid = struct.unpack_from(">I", head, 5)[0] & 0x7FFFFFFF
        return length, ftype, flags, sid

    @staticmethod
    def _headers_payload(payload, flags):
        """剥掉 HEADERS 帧的 padding 与 priority 字段，留纯 HPACK 块。"""
        o = 0
        pad = payload[0] if flags & 0x8 else 0
        if flags & 0x8:
            o += 1
        if flags & 0x20:          # PRIORITY
            o += 5
        return payload[o:len(payload) - pad]

    @staticmethod
    def _decode_headers(block):
        from hpack import Decoder

        decoded = Decoder().decode(block, raw=False)
        pseudo = [k for k, _ in decoded if k.startswith(":")]
        regular = [k for k, _ in decoded if not k.startswith(":")]
        values = {k: v for k, v in decoded if not k.startswith(":")}
        return pseudo, regular, values

    @staticmethod
    def _akamai(settings, window_update, priorities, pseudo):
        """Akamai h2 fingerprint。伪头用首字母缩写：m=method a=authority s=scheme p=path。"""
        s = ",".join(f"{k}:{v}" for k, v in settings) or "0"
        w = str(window_update) if window_update is not None else "0"
        # PRIORITY 各条之间是逗号，不是 "|" —— 用 "|" 会把整串切成 9 段
        p = ",".join(f"{sid}:{excl}:{dep}:{wt}"
                     for sid, dep, excl, wt in priorities) or "0"
        h = ",".join(k[1] for k in pseudo) or "0"
        return f"{s}|{w}|{p}|{h}"

    @staticmethod
    def _recv_exact(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError(f"closed after {len(buf)}/{n} bytes")
            buf += chunk
        return buf

    def _push(self, result):
        with self._cv:
            self._results.append(result)
            self._cv.notify_all()

    def _push_error(self, msg):
        with self._cv:
            self._errors.append(msg)
            self._cv.notify_all()

    def pop(self, timeout=20):
        with self._cv:
            if not self._cv.wait_for(lambda: self._results or self._errors, timeout):
                raise TimeoutError(f"no h2 request within {timeout}s")
            if self._results:
                return self._results.pop(0)
            raise OSError(self._errors.pop(0))
