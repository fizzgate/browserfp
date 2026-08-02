"""对端**实际看到的**指纹，是不是我们想冒充的那个 —— 整条链的最终判据。

此前所有"端到端"验的都是**服务端接受了我们的握手**：`test_live_handshake` 看
ServerHello 与 `:status`，`test_build_live` 看回的是 ServerHello 还是 Alert。
接受 ≠ 认成那个浏览器 —— 一条把 GREASE 全丢掉、密码套件顺序打乱的 ClientHello
照样能握上手，只是任何指纹库都会把它归成"不是浏览器"。

而 JA4 一直是**我们自己算的**：Python 与 C 互校，golden 里的 `ja4` 字段也是采集
时由 `oracle/clienthello.py` 算的。`test_ja4_vectors` 用规范的官方向量补了算法这
一层，但那是一条合成的输入；**真实流量在真实对端眼里长什么样，从来没验过**。

这条门禁把回路闭上：用参考实现按某条 profile 出网，打一个会回显 TLS/h2 指纹的
服务，拿它回显的值与我们自己算的比。

```
我们发出的字节 ──→ 网络 ──→ 第三方指纹实现 ──→ 回显 JA4 / JA3 / akamai
      │                                              │
      └────────── 我们自己算的 JA4 ──── 必须相同 ──────┘
```

**分三档，与其它联网门禁同一口径**：对端回显与我们算的不符才是缺陷；连不上、
超时、回非 JSON 一律算"没验到"，不算失败也不冒充通过 —— 把网络问题报成字节
问题，会把排查引向根本不存在的 bug（本项目在 `test_build_live` 上栽过一次）。

**只打一个公开的指纹回显服务，不带任何凭据**，且逐条之间节流。

跑：python -m spec.test_echo_fingerprint [host]
"""

import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.clienthello import fingerprint                     # noqa: E402
from oracle.h2client import H2Client                           # noqa: E402
from oracle.tls13 import TLS13Client                           # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "profiles.json")

# 回显服务：返回 JSON，含 tls.ja3 / tls.ja4 与 http2.akamai_fingerprint。
# 换服务时只要它回同样的字段名即可 —— 判据是"第三方怎么算"，不绑定某一家。
ECHO_HOST = "tls.peet.ws"
ECHO_PATH = "/api/all"
PACE = 3.0

# 每个引擎挑一条有代表性的，全部是 initial 态（恢复态没有有效票据，验不了）
CASES = ("real:chromium", "real:firefox", "real:safari")

OK, MISMATCH, NET = "ok", "mismatch", "net"


def norm_akamai(fp):
    """akamai 指纹的 SETTINGS 段有两种记法，比之前必须归一。

    实测：`tls.peet.ws` 用分号 `2:0;3:100;4:2097152`，而本项目与语料里的三家库
    （curl_cffi / tls_client / wreq）都用逗号。**数值逐项相同**，只是记法不同 ——
    不归一就会把它报成"对端看到的与 profile 不同"，那是假警报，而且是最容易让人
    去改实现的那种假警报（明明是对的，看着像错的）。

    只归一分隔符，不动数值与顺序 —— 顺序是指纹的一部分，排序会把真差异抹掉。
    """
    return fp.replace(";", ",") if isinstance(fp, str) else fp


def fetch(profile, h2_profile, host):
    """按 profile 出网取回显 JSON。返回 (档位, 详情, 我们发的字节)。"""
    try:
        raw = socket.create_connection((host, 443), timeout=20)
        raw.settimeout(20)
    except Exception as e:
        return NET, f"连不上：{type(e).__name__}", None
    try:
        conn = TLS13Client(raw, profile, sni=host)
        conn.handshake()
        if conn.negotiated_alpn != "h2":
            return NET, f"没协商出 h2（{conn.negotiated_alpn}）", None
        h2 = H2Client(conn, h2_profile).connect()
        sid = h2.request("GET", ECHO_PATH, host,
                         headers=[("user-agent", "tlsfp-echo"),
                                  ("accept", "application/json")])
        headers, body = h2.read_response(sid)
        status = dict(headers).get(":status")
        if status != "200":
            return NET, f"回显服务返回 :status={status}", None
        return OK, json.loads(body.decode()), conn.client_hello
    except Exception as e:
        return NET, f"{type(e).__name__}: {str(e)[:70]}", None
    finally:
        try:
            raw.close()
        except Exception:
            pass


def main(argv):
    host = argv[1] if len(argv) > 1 else ECHO_HOST
    with open(REGISTRY) as f:
        registry = json.load(f)
    by_id = {r["id"]: r for r in registry}

    print(f"回显服务 {host}{ECHO_PATH}\n")
    bad, netbad, n = [], [], 0
    for pid in CASES:
        rec = by_id.get(pid)
        if not rec:
            bad.append(f"{pid}: 注册表里没有这条 profile")
            continue
        time.sleep(PACE)
        kind, data, sent = fetch(rec["tls"], rec.get("h2"), host)
        if kind is NET:
            # 只对网络类重试一次：协议级的不符重发无意义，还更像扫描。
            time.sleep(PACE)
            kind, data, sent = fetch(rec["tls"], rec.get("h2"), host)
        if kind is NET:
            netbad.append(f"{pid}: {data}")
            print(f"  ⚠️ {pid:16s} {data}")
            continue
        n += 1

        ours = fingerprint(sent)
        peer_ja4 = (data.get("tls") or {}).get("ja4")
        peer_ja3 = (data.get("tls") or {}).get("ja3_hash") \
            or (data.get("tls") or {}).get("ja3")
        peer_ak = (data.get("http2") or {}).get("akamai_fingerprint")

        line = []
        if peer_ja4 != ours["ja4"]:
            bad.append(f"{pid}: 对端看到的 JA4 与我们算的不同\n"
                       f"      我们 {ours['ja4']}\n      对端 {peer_ja4}")
            line.append("JA4✗")
        else:
            line.append("JA4✅")
        if peer_ja3 and peer_ja3 not in (ours["ja3"], ours["ja3_hash"]):
            bad.append(f"{pid}: 对端看到的 JA3 与我们算的不同\n"
                       f"      我们 {ours['ja3_hash']}\n      对端 {peer_ja3}")
            line.append("JA3✗")
        elif peer_ja3:
            line.append("JA3✅")
        want_ak = (rec.get("h2") or {}).get("akamai_fingerprint")
        if want_ak and peer_ak and norm_akamai(peer_ak) != norm_akamai(want_ak):
            bad.append(f"{pid}: 对端看到的 akamai 指纹与 profile 不同\n"
                       f"      profile {want_ak}\n      对端    {peer_ak}\n"
                       "      （已归一分隔符后仍不同）")
            line.append("h2✗")
        elif want_ak and peer_ak:
            line.append("h2✅")
        print(f"  {' '.join(line):18s} {pid:16s} {ours['ja4']}")

    print(f"\n{n}/{len(CASES)} 条完成回显比对")
    for b in bad:
        print(f"  ✗ {b}")
    for m in netbad:
        print(f"  ⚠️ {m}")

    if bad:
        print("\n对端看到的与我们算的不一致 —— 这是**最硬的一类失败**："
              "服务端接受了握手不代表把我们认成那个浏览器。")
        return 1
    if n == 0:
        print("\n一条都没验到（全是网络原因）。这不是通过，但也不是字节的证据。")
        return 1
    if netbad:
        print(f"\n{len(netbad)} 条因网络原因没验到。")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
