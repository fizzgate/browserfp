"""采集会话恢复（PSK）形态的指纹 —— 补最严重的识别盲区。

**为什么是最严重的盲区**：此前 39 个指纹全部是首次连接形态，PSK 形态 0 覆盖。
浏览器打开一个站点后，后续请求基本都走会话复用，ClientHello 会多出
pre_shared_key（0x29，可能还有 early_data 0x2a），扩展集合与首连不同 —— 也就
是说，**所有浏览器、所有版本的会话恢复连接都识别不出**。这比"某个新版本没覆盖"
影响面大得多。

链路（三段，缺一不可）：
    curl_cffi Session ──> tapproxy(记原始字节) ──> pskserver(TLS1.3 发票据)

pskserver 必须用 anaconda 的 python 跑：venv 里那个是系统 Python 3.9，链接
LibreSSL 2.8.3，`HAS_TLSv1_3` 为 False，发不出 NewSessionTicket，也就永远采
不到 PSK 形态 —— gocollect 当初 9 个 _PSK profile 全部失败正是这个原因，当时
误判成"首连无票据、系统性可解释"就放过了。

每个 target 连两次：第一次拿票据，第二次带 PSK。取第二个 ClientHello。
"""

import json
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle import targets                                    # noqa: E402
from oracle.goldenio import write_golden              # noqa: E402
from oracle.clienthello import fingerprint, parse_client_hello  # noqa: E402
from oracle.tapproxy import TapProxy                          # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "..", "spec", "certs", "fullchain.pem")
KEY = os.path.join(HERE, "..", "spec", "certs", "key.pem")
OUT = os.path.join(HERE, "..", "spec", "golden", "curl_cffi_psk.json")
ANACONDA = "/opt/anaconda3/bin/python3"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_server():
    if not os.path.exists(ANACONDA):
        raise FileNotFoundError(
            f"{ANACONDA} 不存在；需要一个 ssl.HAS_TLSv1_3 为 True 的解释器")
    port = _free_port()
    proc = subprocess.Popen(
        [ANACONDA, "-m", "oracle.pskserver", str(port), CERT, KEY],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        cwd=os.path.dirname(HERE))
    time.sleep(2.5)
    if proc.poll() is not None:
        raise RuntimeError(f"pskserver 启动失败: {proc.stderr.read()[:200]}")
    return proc, port


def capture_psk(target, tap):
    """连两次，返回 (首连指纹, 恢复指纹)。恢复态取不到时第二项为 None。"""
    from curl_cffi import requests

    sess = requests.Session(impersonate=target, verify=False)
    for _ in range(2):
        try:
            sess.get(f"https://127.0.0.1:{tap.port}/", timeout=12)
        except Exception:
            pass
        time.sleep(0.4)
    try:
        sess.close()
    except Exception:
        pass

    hellos = []
    while True:
        try:
            hellos.append(tap.pop(timeout=2))
        except Exception:
            break
    if not hellos:
        raise OSError("未捕获到任何 ClientHello")
    first = fingerprint(hellos[0])
    resumed = None
    for raw in hellos[1:]:
        ch = parse_client_hello(raw)
        if 0x0029 in ch["raw_extensions"]:
            resumed = fingerprint(raw)
            break
    return first, resumed


def main(argv):
    wanted = argv[1:] or targets.UNIQUE
    proc, port = start_server()
    out, no_psk, failed = {}, [], []
    try:
        with TapProxy("127.0.0.1", port) as tap:
            for t in wanted:
                try:
                    first, resumed = capture_psk(t, tap)
                except Exception as e:
                    failed.append((t, repr(e)))
                    print(f"  {t:20s} FAILED {e!r}", file=sys.stderr)
                    continue
                if resumed is None:
                    no_psk.append(t)
                    print(f"  {t:20s} 无 PSK（该 profile 不做会话恢复）")
                    continue
                out[t] = resumed
                d = len(resumed["extensions_ordered"]) - len(first["extensions_ordered"])
                print(f"  {t:20s} PSK ✓ 扩展 {len(first['extensions_ordered'])}"
                      f"→{len(resumed['extensions_ordered'])} ({d:+d})  ja4={resumed['ja4']}")
    finally:
        proc.terminate()

    total, _ = write_golden(OUT, out)
    print(f"\n采到 PSK 形态 {len(out)}/{len(wanted)} → {os.path.normpath(OUT)}")
    if no_psk:
        print(f"不做会话恢复的 {len(no_psk)}: {' '.join(no_psk)}")
    if failed:
        print(f"失败 {len(failed)}:", file=sys.stderr)
        for t, e in failed:
            print(f"  {t}: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
