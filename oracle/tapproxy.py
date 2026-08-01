"""透明 TCP 转发代理，途中记录客户端发的第一个 TLS record。

**为什么需要它**：对着本地观测点采到的 golden，是客户端"打本地"时发的
ClientHello。要诊断"为什么同一 profile 打 A 站通、打 B 站不通"，必须拿到它
**打真实站点**时发的那一份——两者可能不同（例如真 ECH 会先查 DNS 的 HTTPS RR
拿 ECHConfig，只有对真实域名才会触发）。

只做字节转发，不解密、不改写：TLS 在隧道内端到端，上游看到的握手与直连一致。
"""

import os
import socket
import struct
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TapProxy:
    """监听本地端口，把连接转发到 upstream，并留存第一个 TLS record。"""

    def __init__(self, upstream_host, upstream_port=443, host="127.0.0.1", port=0):
        self.upstream = (upstream_host, upstream_port)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(8)
        self.host, self.port = self._sock.getsockname()
        self.records = []
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
                client, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client):
        server = None
        try:
            client.settimeout(20)
            head = self._recv_exact(client, 5)
            if not head:
                return
            length = struct.unpack_from(">H", head, 3)[0]
            body = self._recv_exact(client, length)
            if body is None:
                return
            record = head + body
            with self._cv:
                self.records.append(record)
                self._cv.notify_all()

            server = socket.create_connection(self.upstream, timeout=20)
            server.settimeout(20)
            server.sendall(record)
            self._pump(client, server)
        except OSError:
            pass
        finally:
            for s in (client, server):
                try:
                    if s:
                        s.close()
                except OSError:
                    pass

    @staticmethod
    def _pump(a, b):
        def one(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=one, args=(b, a), daemon=True)
        t.start()
        one(a, b)
        t.join(timeout=5)

    @staticmethod
    def _recv_exact(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def pop(self, timeout=20):
        with self._cv:
            if not self._cv.wait_for(lambda: self.records, timeout):
                raise TimeoutError("no ClientHello captured")
            return self.records.pop(0)
