"""C 构造的 h2 开场能否真被服务器接受 —— h2 层的可用性验收。

TLS 层早就有这一环（`test_build_live`：字节真发出去，看回 ServerHello 还是
Alert），h2 层此前只有 `test_h2_build` 的自洽性检查 —— 构造出的帧解析回来与
golden 一致。**自洽不等于可用**：帧头长度写错一位、SETTINGS 项数与载荷长度对不
上、PRIORITY 依赖了一个不存在的流，解析器能忍、服务器会回 GOAWAY。

**TLS 那一跳故意用 Python 自己的 ssl，不用我们构造的 ClientHello**。这是分层：
TLS 层有它自己的实网门禁，两层混在一起的话，一次失败没法归因 —— 到底是握手被
拒还是 h2 被拒？分开之后这条门禁的红只可能来自 h2 层。

验到 HEADERS 才算通过，不是"没报错就算"：服务端回了响应头，说明它接受了我们的
SETTINGS、也接受了按 profile 伪头序发出去的请求。

**首个请求流的 ID 取决于有没有 PRIORITY 分组**：Firefox 的开场用 3..13 建六个
优先级节点，真实请求从 15 开始；Chrome 系没有分组，从 1 开始。发错会被服务端
按协议错误处理，而那是我们自己的问题不是服务端的。

跑：python -m spec.test_h2_live [host,host,...]
"""

import os
import socket
import ssl
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
H2CLI = os.path.join(ROOT, "csrc", "h2cli")

# 站点要**可达**且真的协商得出 h2。本机实测 Google 系域 DNS 能解析但连不上
# （chromiumdash.appspot.com 解析到 104.244.46.165，不是 Google 网段），
# 拿它当第二站点会让这条门禁恒红 —— 那比没有门禁更糟。
# 选两家不同实现作对照：cloudflare 与 fastly/nginx 系。
DEFAULT_HOSTS = ("cloudflare.com", "www.mozilla.org")

# 覆盖库里出现过的几种 SETTINGS 形态，而不是随便挑几个版本：
#   chrome 151   {1,2,4,6}      Chromium 新形态
#   chrome 106   {1,2,3,4,6}    推送移除过渡期，多一项 MAX_CONCURRENT
#   firefox 121  {1,4,5} + 六条 PRIORITY
#   firefox 135  {1,2,4,5}      Gecko 新形态，无 PRIORITY
#   safari 26    {2,3,4,9}      伪头序也不同（m,s,a,p）
TARGETS = (("chrome", 151), ("chrome", 106),
           ("firefox", 121), ("firefox", 135), ("safari", 26))

# 与 test_build_live 同样的理由：多个组合连打同一批站点会撞上限速，
# 那种失败与字节对错无关。
PACE = 2.0

OK, REJECT, NET = "ok", "reject", "net"

FRAME_NAMES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
               4: "SETTINGS", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE"}


def build(brand, ver):
    out = subprocess.run([H2CLI], input=f"{brand} {ver}\n",
                         capture_output=True, text=True, timeout=30).stdout
    hexs, _, pseudo = out.strip().partition("\t")
    if not hexs or hexs == "-":
        return None, None
    return bytes.fromhex(hexs), pseudo


def _frame(ftype, flags, sid, payload=b""):
    n = len(payload)
    return (bytes([n >> 16 & 255, n >> 8 & 255, n & 255, ftype, flags])
            + struct.pack(">I", sid) + payload)


def _has_priority(rec):
    """开场里有没有 PRIORITY 帧（类型 2、长度 5）。"""
    return b"\x00\x00\x05\x02" in rec


def attempt(brand, ver, host):
    from hpack import Decoder, Encoder

    rec, pseudo = build(brand, ver)
    if rec is None:
        return REJECT, "构造失败（该版本无 h2 数据）"

    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    try:
        raw = socket.create_connection((host, 443), timeout=20)
        s = ctx.wrap_socket(raw, server_hostname=host)
        s.settimeout(20)
    except Exception as e:
        return NET, f"{type(e).__name__}: {str(e)[:40]}"
    if s.selected_alpn_protocol() != "h2":
        s.close()
        return NET, f"服务端没协商出 h2（{s.selected_alpn_protocol()}）"

    sid = 15 if _has_priority(rec) else 1
    fields = {"m": (":method", "GET"), "s": (":scheme", "https"),
              "a": (":authority", host), "p": (":path", "/")}
    try:
        headers = [fields[c] for c in pseudo.split(",") if c]
    except KeyError as e:
        s.close()
        return REJECT, f"伪头序里有认不出的字段 {e}"

    try:
        s.sendall(rec)
        s.sendall(_frame(1, 0x5, sid,
                         Encoder().encode(headers + [("user-agent", "tlsfp")])))
        buf, seen, status = b"", [], None
        while True:
            d = s.recv(65535)
            if not d:
                break
            buf += d
            while len(buf) >= 9:
                ln = (buf[0] << 16) | (buf[1] << 8) | buf[2]
                if len(buf) < 9 + ln:
                    break
                ftype, payload = buf[3], buf[9:9 + ln]
                buf = buf[9 + ln:]
                seen.append(ftype)
                if ftype == 7:                       # GOAWAY
                    code = struct.unpack_from(">I", payload, 4)[0] if ln >= 8 else -1
                    s.close()
                    return REJECT, f"服务端 GOAWAY error_code={code}"
                if ftype == 1:                       # HEADERS
                    for k, v in Decoder().decode(payload, raw=False):
                        if k == ":status":
                            status = v
                    break
            if status is not None:
                break
    except Exception as e:
        s.close()
        return NET, f"{type(e).__name__}: {str(e)[:40]}"
    s.close()

    if status is None:
        return NET, f"没等到响应头（收到 {[FRAME_NAMES.get(t, t) for t in seen]}）"
    return OK, f":status={status}（流 {sid}，开场 {len(rec)}B）"


def main(argv):
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"make 失败：{(r.stderr or r.stdout)[-200:]}", file=sys.stderr)
        return 2
    if not os.path.exists(H2CLI):
        print(f"缺 {H2CLI}；先在 csrc 下 make", file=sys.stderr)
        return 2

    hosts = argv[1].split(",") if len(argv) > 1 else DEFAULT_HOSTS
    print(f"C 构造的 h2 开场 × {len(hosts)} 个真实站点\n")

    ok_n, rejected, netbad = 0, [], []
    prio_ok = 0
    for brand, ver in TARGETS:
        cells = []
        rec, _ = build(brand, ver)
        has_prio = rec is not None and _has_priority(rec)
        for host in hosts:
            time.sleep(PACE)
            kind, detail = attempt(brand, ver, host)
            cells.append({OK: "✅", REJECT: "❌", NET: "⚠️"}[kind])
            if kind is OK:
                ok_n += 1
                if has_prio:
                    prio_ok += 1
            elif kind is REJECT:
                rejected.append((brand, ver, host, detail))
            else:
                netbad.append((brand, ver, host, detail))
        print(f"  {''.join(cells)} {brand:10s} {ver:>3}"
              f"{'  含 PRIORITY' if has_prio else ''}")

    total = len(TARGETS) * len(hosts)
    print(f"\n{ok_n}/{total} 组合被服务端接受并返回响应头")
    for b, v, h, d in rejected:
        print(f"  ✗ {b} {v} @ {h}: {d}")
    for b, v, h, d in netbad:
        print(f"  ⚠️ {b} {v} @ {h}: {d}")

    if rejected:
        print("\n服务端拒绝了我们构造的 h2 开场 —— 自洽不等于可用，"
              "先查帧头长度、SETTINGS 项数与载荷长度是否一致。")
        return 1
    # 平凡通过防护：带 PRIORITY 的那种形态必须真的验到过。它是唯一会开
    # 额外流、也是最容易被服务端挑剔的形态，没验到就等于没覆盖到风险最大的一档。
    if ok_n and prio_ok == 0:
        print("\n✗ 没有一个带 PRIORITY 的组合通过 —— 那一档没被验证到")
        return 1
    if netbad:
        print(f"\n{len(netbad)} 个组合因网络原因没验到。这不是字节的证据。")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
