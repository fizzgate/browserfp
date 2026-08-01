"""对真实服务器逐 profile 跑 TLS1.3 + h2，验证注册表里每条都能真正用。

重建闭环（test_rebuild）只证明 profile 数据自洽——字节能拼出来、解析回去
字段一致。但自洽不等于可用：服务端可能因为某个扩展组合拒绝握手、或选一个
我们处理不了的密钥交换组。本测试是端到端的可用性门禁。

**必须打多个站点**。曾经只打 cloudflare.com，34 条全绿，却掩盖了"根本没发
SNI"这个致命缺陷——cloudflare.com 有默认证书所以不介意，多租户站点 是多租户
站点直接 handshake_failure。单站点门禁给出的绿是假绿。选站原则：
  · 至少一个多租户/严格 SNI 的站点（多租户站点 —— 也是本项目真实目标）
  · 至少一个宽松站点作对照，好把"站点特有策略"与"我们的实现缺陷"分开

这会对外发真实请求（profile 数 × 站点数），别在 CI 里高频跑。

跑：python -m spec.test_live_handshake [host1,host2,...]
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

DEFAULT_HOSTS = ["cloudflare.com", "example.com"]


def try_profile(rec, host, timeout=15):
    """返回 (ok, detail)。h2 缺失的 profile 只验到 TLS 层。"""
    raw = socket.create_connection((host, 443), timeout=timeout)
    raw.settimeout(timeout)
    conn = TLS13Client(raw, rec["tls"], sni=host)
    try:
        conn.handshake()
        group = f"0x{conn._negotiated_group:04x}"
        if conn.negotiated_alpn != "h2":
            return True, f"TLS1.3 {group} alpn={conn.negotiated_alpn}"
        if not rec.get("h2"):
            return True, f"TLS1.3 {group} (无 h2 profile)"
        h2 = H2Client(conn, rec["h2"]).connect()
        sid = h2.request("GET", "/", host,
                         headers=[("user-agent", "tlsfp-ref"), ("accept", "*/*")])
        headers, _ = h2.read_response(sid)
        return True, f"TLS1.3 {group} h2 {dict(headers).get(':status')}"
    finally:
        conn.close()


# 只有这些才重试：纯网络层抖动，与 profile 是否正确无关。
# TLSError 一律不重试 —— 那是协议层拒绝（扩展组合不被接受、密钥交换组不支持），
# 重试只会把稳定缺陷洗成偶发绿，正是门禁最该避免的事。
TRANSIENT = (socket.timeout, TimeoutError, ConnectionResetError,
             ConnectionAbortedError, BrokenPipeError)


def attempt(rec, host, retries=1):
    """跑一次；网络类失败最多重试 retries 次，协议类失败立即判负。"""
    last = None
    for i in range(retries + 1):
        try:
            return try_profile(rec, host)
        except TLSError as e:
            return False, f"TLSError: {e}"
        except TRANSIENT as e:
            last = f"{type(e).__name__}: {str(e)[:40]}"
            if i < retries:
                time.sleep(1.0)
        except Exception as e:
            return False, f"{type(e).__name__}: {str(e)[:50]}"
    return False, f"{last} (重试 {retries} 次仍失败)"


def main(argv):
    hosts = argv[1].split(",") if len(argv) > 1 else DEFAULT_HOSTS
    with open(REGISTRY) as f:
        registry = json.load(f)

    # 纯 TLS 1.2 的 profile（无 supported_versions 扩展，JA4 首段 t12）超出
    # 参考实现范围——它只做 TLS 1.3。把这些算作失败会让口径失真。
    tls12 = [r for r in registry if not r["tls"].get("supported_versions")]
    tls13 = [r for r in registry if r["tls"].get("supported_versions")]

    print(f"注册表 {len(registry)} 条：TLS1.3 {len(tls13)} 条 × {len(hosts)} 站点"
          f"；纯 TLS1.2 {len(tls12)} 条跳过\n")

    failures = []
    for rec in tls13:
        cells = []
        for host in hosts:
            good, detail = attempt(rec, host)
            cells.append((host, good, detail))
            if not good:
                failures.append((rec["id"], host, detail))
            time.sleep(0.15)
        mark = "".join("✅" if g else "❌" for _, g, _ in cells)
        detail = " | ".join(f"{h}:{d}" for h, g, d in cells)
        print(f"  {mark} {rec['id']:32s} {detail}")

    total = len(tls13) * len(hosts)
    print(f"\n{total - len(failures)}/{total} 组合可用"
          f"（{len(tls13)} profile × {len(hosts)} 站点）")
    if failures:
        print("\n失败：")
        for pid, host, detail in failures:
            print(f"  {pid:32s} @{host:18s} {detail}")
    if tls12:
        print(f"\n跳过的纯 TLS1.2 profile（{len(tls12)}）："
              + " ".join(r["id"] for r in tls12))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
