"""HelloRetryRequest：服务端要一个我们没发过的组时，必须补发第二个 ClientHello。

参考实现原来不支持 HRR。表现不是"报错说不支持"，而是**在算共享密钥时报一个与
真因毫无关系的错** —— HRR 长得和 ServerHello 一模一样，只有 random 那 32 字节
（`SHA-256("HelloRetryRequest")`）能区分，不认它就会把"请换个组重发"当成
"这是服务端的公钥"。

真浏览器都会补发；我们不补的表现是"某些站点连不上"。判据现成：仓里的
`oracle/gotls/hrrserver` 只接受客户端不会首发的 P-384，必定触发 HRR。

CH2 的约束比想象中多。RFC 8446 §4.1.2 说它与 CH1 **只差指定的几处**，实测下来
每违反一条都会被拒，而告警**不会告诉你是哪一条**：

```
key_share       换成服务端选的那一个组                （允许改）
random          必须与 CH1 相同                       改了 → Alert
session_id      必须与 CH1 相同                       改了 → Alert
GREASE          必须沿用 CH1 抽到的那组               改了 → 两条 CH 对不上
GREASE ECH      必须原样带回                          改了 → Alert
记录层版本      **必须 0x0303**（首条才是 0x0301）    仍发 0x0301 → protocol_version
transcript      CH1 要先换成 message_hash（§4.4.1）   不换 → Finished 校验失败
```

最后那条记录层版本是我最后才想到的：告警说 `protocol_version`，而我先怀疑了三处
扩展 —— **告警码指向的是"哪一类"，不是"哪一处"**。定位靠的是把 CH1 与 CH2 逐字段
diff，而不是继续猜。

跑：python -m spec.test_hrr
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.h2probe import CERT                                # noqa: E402
from oracle.tls13 import TLS13Client                           # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HRRSERVER = os.path.join(ROOT, "oracle", "gotls", "hrrserver", "hrrserver")
KEY = CERT.replace("fullchain.pem", "key.pem")

# 每个引擎一条 —— 三个栈的扩展集合不同，CH2 的重建路径也就不同
CASES = ("curl_cffi:chrome119", "real:firefox", "real:safari")
WANT_GROUP = 0x0018        # hrrserver 只留 P-384


def start_server():
    if not os.path.exists(HRRSERVER):
        if not shutil.which("go"):
            return None, None
        subprocess.run(["go", "build", "-o", "hrrserver/hrrserver", "./hrrserver"],
                       cwd=os.path.join(ROOT, "oracle", "gotls"), timeout=300)
        if not os.path.exists(HRRSERVER):
            return None, None
    p = subprocess.Popen([HRRSERVER, "-addr", "127.0.0.1:0",
                          "-cert", CERT, "-key", KEY],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for _ in range(50):
        line = p.stderr.readline()
        if not line:
            break
        m = re.search(r"127\.0\.0\.1:(\d+)", line)
        if m:
            return p, int(m.group(1))
    p.terminate()
    return None, None


# —— 第一段（离线）：C 与 Lua 造出的 CH2 必须与参考实现逐字节相同 ——
#
# 参考实现（Python）能跟真服务端完成 HRR，所以它是判据。C 侧走的是另一条路：
# **在 CH1 的字节上就地改写**，而不是照 profile 重新造一条 —— 那样 random /
# session_id / GREASE / GREASE ECH 天然逐字节相同，不需要调用方存状态。两条
# 路殊途同归才说明改写没漏东西。
#
# 四个引擎各一条：扩展集合不同，CH2 的重建路径也不同；其中 safari 那条重建后
# 长度落进 [256,512)，padding 会被补上 —— 这一档只有它覆盖得到。
OFFLINE_CASES = ("curl_cffi:chrome119", "real:firefox153", "real:safari", "real:edge")
OFFLINE_GROUP = 0x0018        # P-384：四条 profile 都没首发它，正是 HRR 的场景


def offline_arm(registry):
    import secrets
    from oracle.chbuild import build_client_hello, pick_grease
    from oracle.clienthello import parse_client_hello

    bad, n = [], 0
    hrrcli = os.path.join(ROOT, "csrc", "hrrcli")
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        return [f"make 失败：{(r.stderr or r.stdout)[-200:]}"], 0
    p = subprocess.Popen([hrrcli], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         text=True, bufsize=1)
    padded_ch1 = 0        # 有多少次的 CH1 自己带 padding
    try:
        for pid in OFFLINE_CASES:
            rec = registry.get(pid)
            if not rec:
                bad.append(f"{pid}: 注册表里没有这条 profile")
                continue
            prof = rec["tls"]
            # **同一条 profile 要取多次样**。CH1 带不带 padding 取决于 GREASE ECH
            # 的体长（每连接在 {186,218,250,282} 里随机取），单次取样约 3/4 落在
            # "不带"那一档 —— 变异测试实测过：把"CH2 重算 padding"改坏，单次取样
            # 的版本照样全绿。这里按 (带不带 padding, ECH 体长) 去重后逐个比。
            seen, ok_here = set(), 0
            for _ in range(10):
                g = pick_grease()
                rnd, sid = secrets.token_bytes(32), secrets.token_bytes(32)
                pub = secrets.token_bytes(97)
                ch1 = build_client_hello(prof, sni="example.com", grease=g,
                                         random32=rnd, session_id=sid)
                a = parse_client_hello(ch1)
                eb = a["extension_bodies"].get(0xFE0D)
                has_pad = 0x0015 in a["raw_extensions"]
                key = (has_pad, len(eb or ""))
                if key in seen:
                    continue
                seen.add(key)
                if has_pad:
                    padded_ch1 += 1
                want = build_client_hello(prof, sni="example.com", grease=g,
                                          random32=rnd, session_id=sid,
                                          ech_body=bytes.fromhex(eb) if eb else None,
                                          hrr_group=(OFFLINE_GROUP, pub),
                                          record_version=0x0303)
                p.stdin.write(f"{ch1.hex()} {OFFLINE_GROUP} {pub.hex()}\n")
                p.stdin.flush()
                got = p.stdout.readline().strip()
                if got == "ERR":
                    bad.append(f"{pid}: C 侧重建 CH2 失败")
                    continue
                got = bytes.fromhex(got)
                n += 1
                if got != want:
                    where = next((i for i in range(min(len(got), len(want)))
                                  if got[i] != want[i]), min(len(got), len(want)))
                    bad.append(f"{pid}(CH1 带 padding={has_pad}): C 的 CH2 与参考"
                               f"实现不同（C {len(got)} / 参考 {len(want)}，"
                               f"首个不同字节在 {where}）")
                    continue
                ok_here += 1
                b = parse_client_hello(got)
                if ch1[11:43] != got[11:43]:
                    bad.append(f"{pid}: CH2 的 random 与 CH1 不同 —— RFC 8446 "
                               "§4.1.2 要求原样带回，改了会被 Alert")
                if got[1:3] != b"\x03\x03":
                    bad.append(f"{pid}: CH2 的记录层版本是 {got[1:3].hex()}，应为 0303")
                ks = b["extension_bodies"].get(0x0033)
                if not ks:
                    bad.append(f"{pid}: CH2 里没有 key_share")
                else:
                    body = bytes.fromhex(ks)
                    cnt, i2 = 0, 2
                    while i2 + 4 <= len(body):
                        gg = int.from_bytes(body[i2:i2 + 2], "big")
                        ln = int.from_bytes(body[i2 + 2:i2 + 4], "big")
                        cnt += 1
                        if gg != OFFLINE_GROUP:
                            bad.append(f"{pid}: CH2 的 key_share 里有组 "
                                       f"0x{gg:04x} —— RFC 规定只留服务端选的"
                                       "那一个，GREASE 那条也不留")
                        i2 += 4 + ln
                    if cnt != 1:
                        bad.append(f"{pid}: CH2 的 key_share 有 {cnt} 条，应为 1 条")
                if eb != b["extension_bodies"].get(0xFE0D):
                    bad.append(f"{pid}: CH2 的 GREASE ECH 体与 CH1 不同 —— "
                               "必须原样带回")
            print(f"  ✅ {pid:22s} {ok_here} 种 CH1 形态，CH2 均与参考实现逐字节相同")
    finally:
        p.stdin.close()
        p.wait(timeout=10)
    # **"CH1 自己带 padding"那一档必须真的验到**。它决定 CH2 要不要把旧 padding
    # 去掉重算；没取到样时，改坏这条逻辑的变异照样全绿 —— 实测过。
    if padded_ch1 == 0:
        bad.append("10 轮取样里一次都没遇到自带 padding 的 CH1 —— "
                   "CH2 去旧 padding 那条路径没被走到，等于没验")
    if n < len(OFFLINE_CASES):
        bad.append(f"只比了 {n} 次 —— 每个引擎的扩展集合不同，"
                   "差一条就是差一条重建路径没验")
    return bad, n


def main():
    with open(os.path.join(HERE, "profiles.json")) as f:
        reg0 = {r["id"]: r for r in json.load(f)}
    print("CH2 重建差分（C ←→ 参考实现）：")
    off_bad, off_n = offline_arm(reg0)
    for b in off_bad:
        print(f"  ✗ {b}")
    print()

    srv, port = start_server()
    if not srv:
        print("缺 hrrserver 且没有 go 工具链，跳过（非通过）", file=sys.stderr)
        return 0
    with open(os.path.join(HERE, "profiles.json")) as f:
        registry = {r["id"]: r for r in json.load(f)}

    bad, ok = [], 0
    try:
        for pid in CASES:
            rec = registry.get(pid)
            if not rec:
                bad.append(f"{pid}: 注册表里没有这条 profile")
                continue
            try:
                raw = socket.create_connection(("127.0.0.1", port), timeout=15)
                raw.settimeout(15)
                conn = TLS13Client(raw, rec["tls"], sni="localhost")
                conn.handshake()
            except Exception as e:
                bad.append(f"{pid}: {type(e).__name__}: {str(e)[:90]}")
                print(f"  ✗ {pid:22s} {type(e).__name__}")
                continue
            if conn._negotiated_group != WANT_GROUP:
                bad.append(f"{pid}: 协商组 0x{conn._negotiated_group:04x} != "
                           f"0x{WANT_GROUP:04x} —— 服务端只留了 P-384，"
                           "协商成别的说明 HRR 没真的走到")
            ok += 1
            print(f"  ✅ {pid:22s} 协商组=0x{conn._negotiated_group:04x}")
    finally:
        srv.terminate()

    print(f"\nHRR 端到端 {ok}/{len(CASES)}")
    if ok < len(CASES):
        bad.append(f"只有 {ok}/{len(CASES)} 条完成 —— 三个引擎的扩展集合不同，"
                   "CH2 的重建路径也不同，差一个不验就是差一条路径没验")
    for b in bad:
        print(f"  ✗ {b}")
    bad = off_bad + bad
    print(f"\n{'HelloRetryRequest 可用' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
