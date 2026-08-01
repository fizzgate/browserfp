"""对真实服务器逐 profile 跑 TLS1.3 + h2，验证注册表里每条都能真正用。

重建闭环（test_rebuild）只证明 profile 数据自洽——字节能拼出来、解析回去
字段一致。但自洽不等于可用：服务端可能因为某个扩展组合拒绝握手、或选一个
我们处理不了的密钥交换组。本测试是端到端的可用性门禁。

默认打 cloudflare.com（claude.ai 的前置，与目标同一套边缘），一 profile 一
连接，串行。这会对外发真实请求，别在 CI 里高频跑。

跑：python -m spec.test_live_handshake [host]
"""

import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.h2client import H2Client                          # noqa: E402
from oracle.tls13 import TLS13Client, TLSError                # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "profiles.json")


def try_profile(rec, host, timeout=15):
    """返回 (ok, detail)。h2 缺失的 profile 只验到 TLS 层。"""
    raw = socket.create_connection((host, 443), timeout=timeout)
    raw.settimeout(timeout)
    conn = TLS13Client(raw, rec["tls"], sni=host)
    try:
        conn.handshake()
        group = f"0x{conn._negotiated_group:04x}"
        if conn.negotiated_alpn != "h2":
            return True, f"TLS1.3 group={group} alpn={conn.negotiated_alpn}"
        if not rec.get("h2"):
            return True, f"TLS1.3 group={group} (无 h2 profile，未验 h2 层)"
        h2 = H2Client(conn, rec["h2"]).connect()
        sid = h2.request("GET", "/cdn-cgi/trace", host,
                         headers=[("user-agent", "fizztls-ref"), ("accept", "*/*")])
        headers, _ = h2.read_response(sid)
        return True, f"TLS1.3 group={group} h2 HTTP {dict(headers).get(':status')}"
    finally:
        conn.close()


def main(argv):
    host = argv[1] if len(argv) > 1 else "cloudflare.com"
    with open(REGISTRY) as f:
        registry = json.load(f)

    # 纯 TLS 1.2 的 profile（无 supported_versions 扩展，JA4 首段 t12）超出
    # 参考实现范围——它只做 TLS 1.3。把这些算作失败会让口径失真：它们不是
    # 握手失败，是压根不该用 TLS 1.3 客户端去跑。C 模块若要覆盖需另接 1.2 栈。
    tls12 = [r for r in registry if not r["tls"].get("supported_versions")]
    tls13 = [r for r in registry if r["tls"].get("supported_versions")]

    print(f"注册表 {len(registry)} 条：TLS1.3 {len(tls13)} 条待验，"
          f"纯 TLS1.2 {len(tls12)} 条跳过（超出参考实现范围）\n")

    ok, failed = [], []
    for rec in tls13:
        try:
            good, detail = try_profile(rec, host)
        except TLSError as e:
            good, detail = False, f"TLSError: {e}"
        except Exception as e:
            good, detail = False, f"{type(e).__name__}: {str(e)[:60]}"
        (ok if good else failed).append((rec["id"], detail))
        print(f"  {'✅' if good else '❌'} {rec['id']:34s} {detail}")
        time.sleep(0.2)

    print(f"\nTLS1.3: {len(ok)}/{len(tls13)} 可用")
    if failed:
        print("\n不可用：")
        for name, detail in failed:
            print(f"  {name:34s} {detail}")
    if tls12:
        print(f"\n跳过的纯 TLS1.2 profile（{len(tls12)}）：")
        print("  " + " ".join(r["id"] for r in tls12))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
