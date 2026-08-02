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


def main():
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
    print(f"\n{'HelloRetryRequest 可用' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
