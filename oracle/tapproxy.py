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
            # 首个 record 已在上面记过，_pump 只负责后续（HRR 的第二个 CH）
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

    def _pump(self, a, b):
        """双向转发。client→server 方向持续解析 TLS record，把后续出现的
        ClientHello 也记下来。

        **不能只记第一个 record**：HelloRetryRequest 是在**同一条 TCP 连接内**
        完成的——服务端回 HRR 后，客户端在同一连接上重发第二个 ClientHello
        （带服务端要求的 key_share，可能还有 cookie）。只记首个 record 会把
        HRR 形态整个漏掉，且表现为"只捕获到 1 个 ClientHello"，很容易被误读成
        HRR 没被触发。
        """
        def upstream(src, dst):
            buf = b""
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
                    buf += data
                    buf = self._scan_records(buf)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        def downstream(src, dst):
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

        t = threading.Thread(target=downstream, args=(b, a), daemon=True)
        t.start()
        upstream(a, b)
        t.join(timeout=5)

    def _scan_records(self, buf):
        """从缓冲里切出完整 TLS record，遇到 ClientHello 就记录；返回剩余字节。

        握手一旦进入加密阶段（type 0x17），后续 record 无法解析，直接丢弃缓冲
        以免无限增长。
        """
        while len(buf) >= 5:
            ctype = buf[0]
            length = struct.unpack_from(">H", buf, 3)[0]
            if len(buf) < 5 + length:
                return buf
            record, buf = buf[:5 + length], buf[5 + length:]
            if ctype == 0x17:
                return b""
            if ctype == 0x16 and length >= 4 and record[5] == 0x01:
                with self._cv:
                    self.records.append(record)
                    self._cv.notify_all()
        return buf

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
