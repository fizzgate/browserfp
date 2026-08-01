"""对照实验：Cloudflare 到底认不认 TLS 指纹？

**为什么必须做这个**：web_proxy.lua:6-10 记着一条结论——"CF managed challenge
与 TLS 指纹无关（cf_clearance 只绑 UA + 出口 IP，不绑指纹；Go+utls 四种
ALPN/指纹组合全部 403）"，据此整条 uTLS 链路被删除。C 模块要不要开工，取决于
这条结论是否成立。

**怀疑点**：当年那四种组合可能都是"半吊子伪装"——TLS 像浏览器、协议栈却不像
（ALPN 给了 h2 却仍用 HTTP/1.1 发，或根本没发 h2 SETTINGS）。那样上游看到的是
split-brain，比不伪装更可疑。"四种全 403"可能证明的是"半吊子无效"，而不是
"指纹无关"。

**本实验的干净之处**：三个臂同一 URL、同一时刻、同一出口 IP，唯一变量是 TLS/h2
指纹。不带任何凭据（无 cookie、无 Authorization），只看状态码。

臂 A  裸 Python ssl   —— LibreSSL 指纹，完全不伪装（阴性对照）
臂 B  本项目参考实现  —— TLS 指纹 + h2 SETTINGS + 伪头顺序三层齐全
臂 C  curl_cffi      —— 权威实现（阳性对照/上界）

跑：python -m spec.test_cf_discrimination [host]
"""

import json
import os
import socket
import ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.h2client import H2Client                          # noqa: E402
from oracle.tls13 import TLS13Client                          # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
TLS_GOLDEN = os.path.join(HERE, "golden", "curl_cffi_nosni.json")
H2_GOLDEN = os.path.join(HERE, "golden", "h2_curl_cffi.json")

# 参考实现打不通含后量子组的 profile（Python 无 MLKEM/Kyber 实现），
# safari184 是可用集里最新的桌面 Safari。
PROFILE = "safari184"

PATH = "/"
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Version/18.4 Safari/605.1.15")


def arm_plain_ssl(host):
    """阴性对照：系统 ssl，指纹是 LibreSSL，与任何浏览器都不像。"""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    with socket.create_connection((host, 443), timeout=20) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.sendall(f"GET {PATH} HTTP/1.1\r\nHost: {host}\r\n"
                      f"User-Agent: {UA}\r\nAccept: text/html\r\n"
                      f"Connection: close\r\n\r\n".encode())
            head = s.recv(4096)
    line = head.split(b"\r\n", 1)[0].decode("latin1")
    return line.split(" ")[1] if " " in line else "?", s.version()


def arm_reference(host):
    """本项目实现：指纹化 ClientHello + 按 profile 的 h2。"""
    with open(TLS_GOLDEN) as f:
        tls_profile = json.load(f)[PROFILE]
    with open(H2_GOLDEN) as f:
        h2_profile = json.load(f)[PROFILE]

    raw = socket.create_connection((host, 443), timeout=20)
    raw.settimeout(20)
    conn = TLS13Client(raw, tls_profile, sni=host)
    try:
        conn.handshake()
        if conn.negotiated_alpn != "h2":
            return f"ALPN={conn.negotiated_alpn}", None
        h2 = H2Client(conn, h2_profile).connect()
        sid = h2.request("GET", PATH, host, headers=[
            ("user-agent", UA),
            ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("accept-language", "en-US,en;q=0.9"),
            ("accept-encoding", "gzip, deflate, br"),
        ])
        headers, _ = h2.read_response(sid)
        return dict(headers).get(":status", "?"), "TLSv1.3/h2"
    finally:
        conn.close()


def arm_curl_cffi(host):
    """阳性对照：权威实现，三层齐全。"""
    from curl_cffi import requests

    r = requests.get(f"https://{host}{PATH}", impersonate=PROFILE,
                     timeout=20, headers={"User-Agent": UA})
    return str(r.status_code), r.http_version


def main(argv):
    host = argv[1] if len(argv) > 1 else "claude.ai"
    print(f"目标: https://{host}{PATH}   profile={PROFILE}   无凭据\n")
    print(f"{'臂':<28} {'状态':<10} {'协议'}")
    print("-" * 60)

    results = {}
    for label, fn in [("A 裸 Python ssl (无伪装)", arm_plain_ssl),
                      ("B 本项目参考实现", arm_reference),
                      ("C curl_cffi (权威)", arm_curl_cffi)]:
        try:
            status, proto = fn(host)
            results[label] = status
            print(f"{label:<28} {str(status):<10} {proto}")
        except Exception as e:
            results[label] = f"ERR"
            print(f"{label:<28} {'ERR':<10} {type(e).__name__}: {str(e)[:60]}")

    print()
    vals = list(results.values())
    if len(set(vals)) == 1:
        print(f"三臂结果相同（{vals[0]}）→ 该 URL 上 TLS 指纹不构成判据。")
        print("  注意：这不等于'CF 从不看指纹'，只说明此端点当前未按指纹区别对待。")
    else:
        print("三臂结果不同 → TLS/h2 指纹在该端点上构成判据。")
        print("  web_proxy.lua:6-10 那条'指纹无关'的结论需要重新评估。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
