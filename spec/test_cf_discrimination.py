"""对照实验：Cloudflare 到底认不认 TLS/h2 指纹？

**要验的结论**：宿主项目此前记录过"CF managed challenge 与 TLS 指纹无关
（cf_clearance 只绑 UA + 出口 IP）；Go+utls 四种 ALPN/指纹组合全部 403"，据此
整条 uTLS 链路被删。C 模块要不要开工取决于它是否成立。

**v1 的设计缺陷（本文件是 v2，已修）**：v1 三个臂的变量不止一个——阴性对照走
HTTP/1.1 而两个伪装臂走 h2，且阴性对照用 Safari UA 配 LibreSSL 指纹，本身就是
split-brain。三臂结果不同只能说明"某处不同"，无法归因到指纹。

**v2 的控制**：
  · 全部走 h2（ALPN 都给 h2,http/1.1），HTTP 版本不再是变量
  · UA 与指纹配套（Chrome 指纹配 Chrome UA），不制造 split-brain
  · 每臂重复 REPEATS 次，区分稳定判据与偶发
  · 记录 cf-ray / server / cf-mitigated 等头，而不是只看状态码——CF 的挑战
    与业务重定向都可能是 3xx，只看数字会误判
  · 不带任何凭据（无 cookie、无 Authorization）

臂：
  ref:<profile>   本项目参考实现，TLS + h2 三层齐全
  curl:<profile>  curl_cffi 权威实现（阳性对照/上界）
  plain           裸 Python ssl（LibreSSL/TLS1.2，阴性对照——注意它只能 TLS1.2，
                  这是该臂固有的第二变量，解读时须计入）

跑：python -m spec.test_cf_discrimination [host]
"""

import json
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.h2client import H2Client                          # noqa: E402
from oracle.tls13 import TLS13Client                          # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "profiles.json")

REPEATS = 2          # 每臂重复次数；刻意压低，这是对外真实请求

UA = {
    "chrome136": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"),
    "safari184": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
                  "(KHTML, like Gecko) Version/18.4 Safari/605.1.15"),
    "firefox135": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:135.0) "
                   "Gecko/20100101 Firefox/135.0"),
}

# CF 用来标记自己介入的头。cf-mitigated=challenge 是"确实下了挑战"的硬证据，
# 比状态码可靠——挑战页也可能是 403 或 503。
INTERESTING = ("cf-ray", "cf-mitigated", "server", "location", "cf-cache-status")


def _registry():
    """按 id 和 aliases 双向建索引。

    注册表按指纹去重，同指纹的多个名字并成 aliases，保留下来的 id 可能是任意
    一个别名——只查 id 会对 chrome136 这类被合并掉的名字报 KeyError，而那会被
    误读成"该指纹打不通"。"""
    with open(REGISTRY) as f:
        records = json.load(f)
    index = {}
    for rec in records:
        for key in [rec["id"]] + rec.get("aliases", []):
            index.setdefault(key, rec)
    return index


def _pick(reg, profile):
    for key in (f"curl_cffi:{profile}", f"tls_client:{profile}", profile):
        if key in reg:
            return reg[key]
    raise KeyError(f"{profile} 不在注册表（含 aliases）中")


def arm_reference(host, profile, reg):
    rec = _pick(reg, profile)
    raw = socket.create_connection((host, 443), timeout=20)
    raw.settimeout(20)
    conn = TLS13Client(raw, rec["tls"], sni=host)
    try:
        conn.handshake()
        if conn.negotiated_alpn != "h2":
            return f"ALPN={conn.negotiated_alpn}", {}
        h2 = H2Client(conn, rec["h2"]).connect()
        sid = h2.request("GET", "/", host, headers=[
            ("user-agent", UA[profile]),
            ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("accept-language", "en-US,en;q=0.9"),
            ("accept-encoding", "gzip, deflate, br"),
        ])
        headers, _ = h2.read_response(sid)
        d = dict(headers)
        return d.get(":status", "?"), {k: v for k, v in d.items() if k in INTERESTING}
    finally:
        conn.close()


def arm_curl_cffi(host, profile, _reg):
    from curl_cffi import requests

    r = requests.get(f"https://{host}/", impersonate=profile, timeout=20,
                     headers={"User-Agent": UA[profile]}, allow_redirects=False)
    return str(r.status_code), {k.lower(): v for k, v in r.headers.items()
                                if k.lower() in INTERESTING}


def arm_plain(host, _profile, _reg):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, 443), timeout=20) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            alpn = s.selected_alpn_protocol()
            if alpn == "h2":
                # LibreSSL 能协商 h2，但本臂没有 h2 帧层实现；如实报告而不是
                # 悄悄退回 HTTP/1.1——那会让"协议版本"重新变成隐藏变量。
                return f"h2-negotiated(no-impl)", {"tls": s.version()}
            s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                      f"User-Agent: {UA['chrome136']}\r\n"
                      f"Accept: text/html\r\nConnection: close\r\n\r\n".encode())
            raw_resp = s.recv(8192).decode("latin1")
    line = raw_resp.split("\r\n", 1)[0]
    status = line.split(" ")[1] if " " in line else "?"
    hdrs = {}
    for h in raw_resp.split("\r\n")[1:]:
        if ":" in h:
            k, v = h.split(":", 1)
            if k.lower() in INTERESTING:
                hdrs[k.lower()] = v.strip()
    return status, hdrs


def main(argv):
    host = argv[1] if len(argv) > 1 else "example.com"
    reg = _registry()

    arms = [("plain", arm_plain, "chrome136")]
    for profile in ("chrome136", "safari184", "firefox135"):
        arms.append((f"ref:{profile}", arm_reference, profile))
        arms.append((f"curl:{profile}", arm_curl_cffi, profile))

    print(f"目标 https://{host}/   无凭据   每臂 {REPEATS} 次   全部 ALPN h2\n")
    results = {}
    for label, fn, profile in arms:
        obs = []
        for _ in range(REPEATS):
            try:
                status, hdrs = fn(host, profile, reg)
                obs.append((str(status), hdrs))
            except Exception as e:
                obs.append((f"ERR:{type(e).__name__}", {}))
            time.sleep(0.5)
        statuses = [o[0] for o in obs]
        results[label] = statuses
        hdr_note = " ".join(f"{k}={v[:22]}" for k, v in obs[-1][1].items()) or "-"
        stable = "" if len(set(statuses)) == 1 else "  ⚠不稳定"
        print(f"  {label:18s} {'/'.join(statuses):26s} {hdr_note}{stable}")

    print()
    ref = {k: v for k, v in results.items() if k.startswith("ref:")}
    curl = {k: v for k, v in results.items() if k.startswith("curl:")}
    same = {tuple(v) for v in list(ref.values()) + list(curl.values())}
    if len(same) == 1:
        print("全部伪装臂结果一致 → 该端点未按浏览器指纹区别对待各 profile。")
    else:
        print("不同 profile 得到不同结果 → 指纹在该端点构成判据。")
    print("注意 plain 臂固有第二变量（LibreSSL 只能 TLS1.2），不可单独据其归因。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
