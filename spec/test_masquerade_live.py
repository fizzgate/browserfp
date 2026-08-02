"""四层拼在一起真发一次请求 —— 分层各自绿，不等于合起来能用。

本项目的伪装分四层，每层都有自己的门禁：

```
tlsfp_build_client_hello()   ClientHello 字节        test_build_live
tlsfp_build_h2_preface()     h2 开场                 test_h2_live
tlsfp_header_order()         请求头相对顺序           test_header_order（静态）
tlsfp_header_value()         accept / accept-encoding 同上
tlsfp_sec_ch_ua()            sec-ch-ua               test_uach（静态）
```

**但四层从没一起跑过。** 层与层之间有真实的耦合，分层测试恰好都测不到：

· 头顺序表里有 `sec-ch-ua`，取值得从 `tlsfp_sec_ch_ua()` 来，而后者按
  (品牌, 版本) 查、前者按品牌查 —— 两个口径不一致时，拼出来的请求会漏头或
  多头，两条静态门禁却都是绿的
· 伪头序来自 h2 层，普通头顺序来自头顺序层，HEADERS 帧里它们必须先伪后普
· UA-CH 只在安全上下文发，而这条链的出网恰好是 https —— 拼错了要么少发要么
  多发，静态门禁只知道"表里有什么"，不知道"实际发了什么"

这条门禁把四层的输出真的拼成一个请求发出去，看服务端回不回 200。

**TLS 那一跳仍用 Python 自己的 ssl**（同 test_h2_live 的理由：分层归因）。
所以它验的是"h2 开场 + 头顺序 + 头取值 + sec-ch-ua 四者拼起来能不能用"。

**"服务端收不收"验不了头顺序。** 变异测试实证：把顺序整个反排，三个站点
依然 3/3 全绿 —— HTTP/2 不在乎头的先后，顺序只影响"像不像浏览器"，不影响协议
合法性。所以这条性质另配一个**独立 oracle**：拼出来的顺序必须与
`spec/golden/headers_real.json` 里那台真浏览器的顺序一致（取交集比对）。
不能拿 `order_for()` 自比 —— compose() 本来就是按它排的，那是循环论证。

跑：python -m spec.test_masquerade_live [host,host,...]
"""

import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.covscan import TARGETS                               # noqa: E402
from oracle.headerorder import BRAND_ENGINE, CAPTURE_ENGINE      # noqa: E402
from oracle.headerorder import order_for, values_for             # noqa: E402
from oracle.uach import platform_hint                            # noqa: E402
from spec.test_h2_live import (NET, OK, REJECT, _frame,          # noqa: E402
                               _has_priority, build)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
UACHCLI = os.path.join(ROOT, "csrc", "uachcli")

DEFAULT_HOSTS = ("cloudflare.com", "www.mozilla.org")
PACE = 2.0

# 每个引擎一条，都取有实采背书的品牌
TARGETS_LIVE = (("chrome", 151), ("firefox", 135), ("safari", 26))


def sec_ch_ua(brand, ver):
    out = subprocess.run([UACHCLI], input=f"{brand} {ver}\n",
                         capture_output=True, text=True, timeout=30).stdout.strip()
    return None if out == "-" else out


def compose(brand, ver, host):
    """把四层的输出拼成一次请求该发的头。返回 (伪头, 普通头)。

    **顺序不是我们排的**，是 `tlsfp_header_order()` 给的；取值里能由库回答的
    都由库回答，不能回答的（sec-fetch-*、user-agent）才由调用方填 —— 这正是
    库与调用方的分工，拼错了这条门禁就会红。
    """
    order, _ = order_for(brand)
    vals = dict(values_for(brand))
    ua = TARGETS[brand][0].format(v=ver)

    # 调用方负责的部分：UA 与请求上下文相关的头
    supplied = {"user-agent": ua,
                "sec-fetch-site": "none", "sec-fetch-mode": "navigate",
                "sec-fetch-user": "?1", "sec-fetch-dest": "document",
                "accept-language": "en-US,en;q=0.9"}
    uach = sec_ch_ua(brand, ver)
    if uach:
        # **platform 与 mobile 也由库推，不能手填**：它们必须与 UA 里声明的
        # 系统同源。第一版这里硬编码 "Windows"/?0，UA 换成 Android 模板就会
        # 出现"UA 说 Android、platform 说 Windows"这种一眼假的组合。
        plat, mobile = platform_hint(ua)
        if not plat:
            return [], None          # 该 UA 的系统不发 UA-CH
        supplied["sec-ch-ua"] = uach
        supplied["sec-ch-ua-mobile"] = mobile
        supplied["sec-ch-ua-platform"] = plat

    have = {**supplied, **vals}
    # 按库给的顺序排，库不认识的（这里没有）留到最后
    ordered = [(h, have[h]) for h in order if h in have]
    ordered += [(h, v) for h, v in have.items() if h not in set(order)]
    return ordered, uach


def real_order(brand):
    """真机实采里该引擎的头顺序 —— compose() 的独立 oracle。"""
    with open(os.path.join(HERE, "golden", "headers_real.json")) as f:
        real = json.load(f)
    eng = BRAND_ENGINE.get(brand)
    for name, rec in real.items():
        if CAPTURE_ENGINE.get(name) == eng:
            return [h for h, _ in rec["headers"] if not h.startswith(":")]
    return None


def check_order_against_real(brand, composed):
    """拼出来的顺序与实采顺序在交集上必须一致。"""
    ref = real_order(brand)
    if not ref:
        return f"{brand}: 找不到该引擎的实采顺序，无法独立校验"
    pos = {h: i for i, h in enumerate(ref)}
    shared = [h for h in composed if h in pos]
    if shared != sorted(shared, key=lambda h: pos[h]):
        return (f"{brand}: 拼出的头序与真机实采不符\n"
                f"      拼出 {shared}\n"
                f"      实采 {[h for h in ref if h in set(shared)]}")
    if len(shared) < 5:
        return f"{brand}: 只有 {len(shared)} 个头能与实采比对，太少，等于没验"
    return None


def attempt(brand, ver, host):
    from hpack import Decoder, Encoder

    rec, pseudo = build(brand, ver)
    if rec is None:
        return REJECT, "h2 开场构造失败", None
    hdrs, uach = compose(brand, ver, host)

    # 该发 UA-CH 的品牌必须发到，不该发的必须没有 —— 这是安全上下文下的规则，
    # 静态门禁只知道表里有什么，这里查的是实际拼出来的请求。
    is_chromium = brand.split("-")[0] in ("chrome", "edge")
    has_uach = any(h.startswith("sec-ch-ua") for h, _ in hdrs)
    if is_chromium and not has_uach:
        return REJECT, "Chromium 系却没拼出 sec-ch-ua —— 少发即异常", None
    if not is_chromium and has_uach:
        return REJECT, f"{brand} 拼出了 sec-ch-ua —— 该引擎从不发这些头", None

    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    try:
        s = ctx.wrap_socket(socket.create_connection((host, 443), timeout=20),
                            server_hostname=host)
        s.settimeout(20)
    except Exception as e:
        return NET, f"{type(e).__name__}: {str(e)[:40]}", None
    if s.selected_alpn_protocol() != "h2":
        s.close()
        return NET, "服务端没协商出 h2", None

    sid = 15 if _has_priority(rec) else 1
    fields = {"m": (":method", "GET"), "s": (":scheme", "https"),
              "a": (":authority", host), "p": (":path", "/")}
    block = [fields[c] for c in pseudo.split(",") if c] + hdrs
    try:
        s.sendall(rec)
        s.sendall(_frame(1, 0x5, sid, Encoder().encode(block)))
        buf, status = b"", None
        while status is None:
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
                if ftype == 7:
                    code = struct.unpack_from(">I", payload, 4)[0] if ln >= 8 else -1
                    s.close()
                    return REJECT, f"服务端 GOAWAY error_code={code}", None
                if ftype == 1:
                    for k, v in Decoder().decode(payload, raw=False):
                        if k == ":status":
                            status = v
                    break
    except Exception as e:
        s.close()
        return NET, f"{type(e).__name__}: {str(e)[:40]}", None
    s.close()
    if status is None:
        return NET, "没等到响应头", None
    return OK, f":status={status}（{len(block)} 个头）", [h for h, _ in hdrs]


def main(argv):
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"make 失败：{(r.stderr or r.stdout)[-200:]}", file=sys.stderr)
        return 2

    hosts = argv[1].split(",") if len(argv) > 1 else DEFAULT_HOSTS
    print(f"四层合并伪装 × {len(hosts)} 个真实站点\n")

    # 顺序这条服务端验不了，先用实采做独立校验
    order_bad = []
    for brand, ver in TARGETS_LIVE:
        composed, _ = compose(brand, ver, "example.com")
        msg = check_order_against_real(brand, [h for h, _ in composed])
        if msg:
            order_bad.append(msg)
    print(f"  头序 vs 真机实采   {len(TARGETS_LIVE) - len(order_bad)}"
          f"/{len(TARGETS_LIVE)} 一致")
    for m in order_bad:
        print(f"    ✗ {m}")
    print()

    ok_n, rejected, netbad = 0, [], []
    seen_engines = set()
    for brand, ver in TARGETS_LIVE:
        cells, sample = [], None
        for host in hosts:
            time.sleep(PACE)
            kind, detail, order = attempt(brand, ver, host)
            cells.append({OK: "✅", REJECT: "❌", NET: "⚠️"}[kind])
            if kind is OK:
                ok_n += 1
                seen_engines.add(brand)
                sample = sample or order
            elif kind is REJECT:
                rejected.append((brand, ver, host, detail))
            else:
                netbad.append((brand, ver, host, detail))
        print(f"  {''.join(cells)} {brand:9s} {ver:>3}"
              + (f"  头序前三: {sample[:3]}" if sample else ""))

    total = len(TARGETS_LIVE) * len(hosts)
    print(f"\n{ok_n}/{total} 组合被服务端接受")
    for b, v, h, d in rejected:
        print(f"  ✗ {b} {v} @ {h}: {d}")
    for b, v, h, d in netbad:
        print(f"  ⚠️ {b} {v} @ {h}: {d}")

    if order_bad:
        print("\n拼出的头序与真机实采不符 —— 服务端不在乎顺序，"
              "但检测方在乎；这条只能靠实采校验。")
        return 1
    if rejected:
        print("\n四层拼起来被拒 —— 分层各自绿不代表合起来能用，"
              "先看是不是头序与取值的口径对不上。")
        return 1
    # 平凡通过防护：三个引擎都得跑到。只跑 Chromium 的话，"非 Chromium 不得
    # 发 UA-CH" 那条断言等于没执行。
    if ok_n and len(seen_engines) < len(TARGETS_LIVE):
        print(f"\n✗ 只跑通了 {sorted(seen_engines)} —— 三个引擎都要跑到，"
              "否则「该发/不该发 UA-CH」的两侧只验了一侧")
        return 1
    if netbad:
        print(f"\n{len(netbad)} 个组合因网络原因没验到。这不是字节的证据。")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
