"""QUIC 观测点：收 UDP 上的 Initial 包，解出 ClientHello。

与 TLS 侧的 sniffer 对应，但多两步：QUIC 的 ClientHello 藏在 Initial 包的 CRYPTO
帧里，且整个包做了 header protection + AEAD。所幸这层密钥由**公开 salt + 客户端
自选的 DCID** 派生（RFC 9001 §5.2），旁路观测也能解——见 oracle/quic.py。

大的 ClientHello 会分片到多个 Initial 包（Chrome 的通常 2 个），所以要按 DCID
聚合 CRYPTO 片段，凑齐无空洞才能重组。

不回任何包：客户端会重传几次然后放弃，那时 ClientHello 早已到手。
"""

import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.quic import QuicError, parse_initial, reassemble_client_hello  # noqa: E402


class QuicProbe:
    """监听 UDP，聚合 Initial 包并重组 ClientHello。"""

    def __init__(self, host="127.0.0.1", port=0):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self.host, self.port = self._sock.getsockname()
        self._chunks = {}          # dcid -> [(offset, data)]
        self._records = []
        self._errors = []
        self._cv = threading.Condition()
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def __enter__(self):
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
                data, _ = self._sock.recvfrom(65535)
            except OSError:
                return
            try:
                info = parse_initial(data)
            except QuicError:
                continue          # 非 Initial（Handshake/0-RTT/短包头）忽略
            except Exception as e:
                self._push_error(f"{type(e).__name__}: {e}")
                continue

            key = info["dcid"]
            chunks = self._chunks.setdefault(key, [])
            chunks.extend(info["crypto"])
            try:
                record = reassemble_client_hello(chunks)
            except QuicError:
                continue          # 还差片段，等后续包
            with self._cv:
                self._records.append(record)
                self._cv.notify_all()
            self._chunks.pop(key, None)

    def _push_error(self, msg):
        with self._cv:
            self._errors.append(msg)
            self._cv.notify_all()

    def pop(self, timeout=30):
        with self._cv:
            if not self._cv.wait_for(lambda: self._records or self._errors, timeout):
                raise TimeoutError(f"{timeout}s 内没有收到完整的 QUIC ClientHello")
            if self._records:
                return self._records.pop(0)
            raise OSError(self._errors.pop(0))
