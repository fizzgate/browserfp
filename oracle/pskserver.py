"""TLS 1.3 观测服务端：完成真握手并下发 NewSessionTicket，好让客户端二次连接
带 PSK。

**必须用 anaconda 的 python 跑**（OpenSSL 3.4.1），不能用 venv 里那个：
macOS 系统 Python 3.9 链接 LibreSSL 2.8.3，`ssl.HAS_TLSv1_3` 为 False，
根本发不出 TLS 1.3 的 NewSessionTicket，也就采不到 PSK 形态。

本进程只负责"握手 + 发票据"，不负责记录 ClientHello —— Python 的 ssl 模块
拿不到原始 ClientHello 字节（只给解析后的 ClientHelloInfo，没有扩展顺序）。
原始字节由前置的 tapproxy 记录，本进程是它的 upstream。

用法（被 psk_capture.py 拉起，一般不手工跑）：
    /opt/anaconda3/bin/python3 -m oracle.pskserver <port> <certfile> <keyfile>
"""

import os
import socket
import ssl
import sys
import threading


def serve(port, certfile, keyfile, alpn=("h2", "http/1.1")):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    ctx.set_alpn_protocols(list(alpn))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    # 票据数量：默认 2。给足，确保客户端一定拿到可用票据。
    if hasattr(ctx, "num_tickets"):
        ctx.num_tickets = 4

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    sys.stderr.write(f"pskserver ready on {srv.getsockname()[1]} "
                     f"({ssl.OPENSSL_VERSION})\n")
    sys.stderr.flush()

    def handle(conn):
        try:
            conn.settimeout(20)
            tls = ctx.wrap_socket(conn, server_side=True)
            try:
                # 读一点请求就回最简响应；重点是让握手完成、票据发出。
                tls.settimeout(5)
                try:
                    tls.recv(65536)
                except (OSError, ssl.SSLError):
                    pass
                body = b"ok"
                if tls.selected_alpn_protocol() == "h2":
                    # h2 客户端不会理会 HTTP/1.1 响应，直接关；握手已完成，
                    # 票据在握手末尾已随 NewSessionTicket 发出。
                    pass
                else:
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                b"Connection: close\r\n\r\n" + body)
            finally:
                try:
                    tls.close()
                except OSError:
                    pass
        except (OSError, ssl.SSLError):
            pass

    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.stderr.write(__doc__)
        raise SystemExit(2)
    serve(int(sys.argv[1]), sys.argv[2], sys.argv[3])
