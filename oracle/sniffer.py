"""本地 ClientHello 观测点：裸 TCP 收第一条 record 就够，不做握手。

**为什么不真握手**：我们只要 ClientHello。不握手就不需要证书、不需要 CA 信任、
不会因为客户端校验失败而拿不到数据——curl_cffi 那边会报 SSL 错误，那是预期的，
ClientHello 在报错前已经完整送达。要采 HTTP/2 SETTINGS 时才需要真握手（见
docs/verification-plan.md 的 L2），那是另一个观测点。
"""

import socket
import struct
import threading


class ClientHelloSniffer:
    """起一个本地监听，把每条连接的第一个 TLS record 原样收下。

    用法：
        with ClientHelloSniffer() as s:
            ...  # 让客户端连 s.host, s.port
            record = s.pop(timeout=10)
    """

    def __init__(self, host="127.0.0.1", port=0, backlog=16):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(backlog)
        self.host, self.port = self._sock.getsockname()
        self._records = []
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
        try:
            conn.settimeout(10)
            head = self._recv_exact(conn, 5)
            if head is None:
                self._push_error("connection closed before record header")
                return
            length = struct.unpack_from(">H", head, 3)[0]
            body = self._recv_exact(conn, length)
            if body is None:
                self._push_error(f"connection closed mid-record (want {length})")
                return
            self._push_record(head + body)
        except OSError as e:
            self._push_error(f"socket error: {e}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _push_record(self, record):
        with self._cv:
            self._records.append(record)
            self._cv.notify_all()

    def _push_error(self, msg):
        with self._cv:
            self._errors.append(msg)
            self._cv.notify_all()

    def pop(self, timeout=10):
        """取一条 ClientHello。超时或对端异常都抛，不返回 None——静默的空值会让
        采集脚本把"没连上"记成"指纹为空"。"""
        with self._cv:
            ok = self._cv.wait_for(
                lambda: self._records or self._errors, timeout=timeout)
            if not ok:
                raise TimeoutError(f"no ClientHello within {timeout}s")
            if self._records:
                return self._records.pop(0)
            raise OSError(self._errors.pop(0))
