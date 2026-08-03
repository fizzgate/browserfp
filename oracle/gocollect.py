"""采集 bogdanfinn/tls-client 的 76 个 profile 指纹。

curl_cffi 只有 31 个 target 且版本滞后（Chrome 停在 136、Firefox 停在 135）；
tls-client 有 76 个，含 chrome_144/146、firefox_147、Opera、OkHttp Android、
以及若干 app profile。两张表合并才谈得上"覆盖市面主流"。

不解析 profiles/*.go 那 5851 行 Go 字面量——让库自己按 profile 发真实
ClientHello，采线上字节，与 curl_cffi 那套 golden 同格式，还能顺便验证表本身。

Go 端串行连接，顺序与 -profiles 一致；观测点按顺序收，靠顺序对应
（ClientHello 里没有地方能塞标识）。任何一个 profile 收不到就会错位，所以
逐个 profile 单独跑一次连接，宁可慢也不接受错位——错位会让整张表张冠李戴。
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.goldenio import write_golden              # noqa: E402
from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.sniffer import ClientHelloSniffer                 # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "gotls", "browserfp-probe")
OUT = os.path.join(HERE, "..", "spec", "golden", "tls_client_nosni.json")


def list_profiles():
    out = subprocess.run([PROBE, "-list"], capture_output=True, text=True, check=True)
    return [l.strip() for l in out.stdout.splitlines() if l.strip()]


def capture_one(name, sniffer):
    """单个 profile 打一次观测点。一次一连接，避免顺序错位导致张冠李戴。"""
    subprocess.run(
        [PROBE, "-addr", f"{sniffer.host}:{sniffer.port}", "-profiles", name],
        capture_output=True, text=True, timeout=30)
    return fingerprint(sniffer.pop(timeout=15))


def main(argv):
    if not os.path.exists(PROBE):
        print(f"缺 {PROBE}；先在 oracle/gotls 下 go build -o browserfp-probe .",
              file=sys.stderr)
        return 2

    wanted = argv[1:] or list_profiles()
    out, failures = {}, []
    with ClientHelloSniffer() as sniffer:
        for name in wanted:
            try:
                out[name] = capture_one(name, sniffer)
                print(f"  {name:26s} ja4={out[name]['ja4']}")
            except Exception as e:
                failures.append((name, repr(e)))
                print(f"  {name:26s} FAILED {e!r}", file=sys.stderr)

    total, _ = write_golden(OUT, out)
    print(f"\ncaptured {len(out)}/{len(wanted)} → {os.path.normpath(OUT)}")
    if failures:
        print(f"FAILURES ({len(failures)}):", file=sys.stderr)
        for n, e in failures:
            print(f"  {n}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
