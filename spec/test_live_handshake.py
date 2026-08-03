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


# 防平凡通过：注册表被截断或读空时，"0/0 组合可用"是打绿勾的 —— 这条是实测
# 撞出来的：一次后台 --live 恰好跑在把 profiles.json 清空的时段，报了
# "0/0 组合可用" 并判通过。下限不是棘轮，只回答"比对集是不是还在"。
MIN_COMBOS = 40



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
                         headers=[("user-agent", "browserfp-ref"), ("accept", "*/*")])
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
    rest = [r for r in registry if r["tls"].get("supported_versions")]

    # QUIC 形态不能拿去做 TCP 握手：它的 ClientHello 走 QUIC 传输参数那一套，
    # 送进 TCP 只会换回一个 alert（实测 real_quic:edge 报 content type 21）。
    # 这是形态不匹配，不是 profile 有问题。
    quic = [r for r in rest if "quic" in (r.get("mode") or "").lower()
            or "quic" in r["id"].lower()]
    rest = [r for r in rest if r not in quic]

    # 参考实现只做 X25519 与 X25519MLKEM768（见 oracle/tls13.py 顶部）。含
    # Kyber768Draft00(0x6399) 而不含 MLKEM 的 profile，服务器会选 0x6399，
    # 我们算不出共享密钥。这是**参考实现能力不足**，与"该 profile 不可用"
    # 是两回事，混报会让口径失真——但也不能静默跳过，否则这一类会无声增长。
    # **会话恢复态按它自己的形态验不了**：里面那张 pre_shared_key 是采集当时的
    # 票据，我们既没有有效票据、也算不出 binder（它是对整段 transcript 的 HMAC）。
    #
    # 旧行为是"把 PSK 扩展整个丢掉再握手"，于是这 15 条一直是绿的 —— 但那验的
    # 不是这条 profile，是一个被改过的形态。构造器现在会明确拒绝（注入了
    # key_share = 真要握手），所以这里改成显式跳过并说明理由，而不是让它抛错。
    psk = [r for r in rest if 0x0029 in (r["tls"].get("raw_extensions") or [])]
    rest = [r for r in rest if r not in psk]

    KYBER, MLKEM = 0x6399, 0x11EC
    unsupported_kx = [r for r in rest
                      if KYBER in (r["tls"].get("curves") or [])
                      and MLKEM not in (r["tls"].get("curves") or [])]
    tls13 = [r for r in rest if r not in unsupported_kx]

    print(f"注册表 {len(registry)} 条：实测 {len(tls13)} 条 × {len(hosts)} 站点"
          f"；跳过 纯TLS1.2 {len(tls12)} / QUIC形态 {len(quic)} / "
          f"会话恢复态 {len(psk)} / 参考实现缺密钥交换 {len(unsupported_kx)}\n")

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
    if psk:
        print(f"\n跳过的会话恢复态（{len(psk)}）—— 没有有效票据，按它自己的形态"
              "验不了；旧行为是丢掉 PSK 扩展再握手，那验的不是这条 profile：")
        print("  " + " ".join(r["id"] for r in psk))
    if quic:
        print(f"\n跳过的 QUIC 形态（{len(quic)}，TCP 测试不适用）："
              + " ".join(r["id"] for r in quic))
    if unsupported_kx:
        print(f"\n参考实现未实现其密钥交换（{len(unsupported_kx)}）—— 含 "
              "Kyber768Draft00(0x6399) 而无 MLKEM。**这是我们的能力缺口，不是 "
              "profile 不可用**，所以改用 curl_cffi 补验：它自己能完成这类握手，"
              "只要它打得通，就说明该 profile 在真实网络上可用。")
        for r in unsupported_kx:
            # 补验有两个前提，缺一不可，报告时要分辨清楚是哪一个不满足：
            #   1. 得是 curl_cffi 自家的 target —— utls 的 PQ 变体它跑不了
            #   2. 得是首连形态 —— PSK（会话恢复）要先建会话再复用，单次
            #      请求根本走不到那条路径
            if (r.get("mode") or "") == "resumed":
                print(f"  {r['id']:28s} PSK 会话恢复形态，单次请求验不了")
                continue
            target = None
            for alias in [r["id"]] + r.get("aliases", []):
                if alias.startswith("curl_cffi:"):
                    target = alias.split(":", 1)[1]
                    break
            if not target:
                print(f"  {r['id']:28s} 非 curl_cffi 变体，它跑不了这个 target")
                continue
            marks = []
            for host in hosts:
                try:
                    from curl_cffi import requests as creq
                    resp = creq.get(f"https://{host}/", impersonate=target,
                                    timeout=20, allow_redirects=False)
                    marks.append(f"{host}:{resp.status_code}")
                except Exception as e:
                    marks.append(f"{host}:{type(e).__name__}")
            print(f"  {r['id']:28s} curl_cffi[{target}] → {' | '.join(marks)}")
    if tls12:
        print(f"\n跳过的纯 TLS1.2 profile（{len(tls12)}）："
              + " ".join(r["id"] for r in tls12))
    if total < MIN_COMBOS:
        print(f"  ✗ 只跑了 {total} 个组合（下限 {MIN_COMBOS}）"
              f" —— 注册表被截断或读空了？0/0 也是绿的")
        return 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
