"""采集 refraction-networking/utls 上游内置的 ClientHelloID。

此前的 Go 采集器（gocollect）走 bogdanfinn/utls —— tls-client 的 fork。上游
refraction v1.8.3-dev 有两个 fork 里没有、且正好落在我们版本空洞里的 profile：
  HelloFirefox_148   我们有 Firefox 147 与真机 149，中间是空的
  HelloSafari_26_3   我们有 Safari 26.0 与真机 27

构建注意：utls v1.8.3-dev 依赖 crypto/mlkem（Go 1.24+ 标准库）。**不要设
GOTOOLCHAIN=local** —— 本机 /usr/local/go 是 1.23.1，会因缺 crypto/mlkem 编译
失败；默认工具链是 1.25.7，可用。

一 profile 一连接，与其他采集器同理：串行共用连接一旦某个失败就整表错位。
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.sniffer import ClientHelloSniffer                 # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "goutls", "fizztls-utls")
OUT = os.path.join(HERE, "..", "spec", "golden", "utls_nosni.json")


def list_profiles():
    out = subprocess.run([PROBE, "-list"], capture_output=True, text=True, check=True)
    return [l.strip() for l in out.stdout.splitlines() if l.strip()]


def main(argv):
    if not os.path.exists(PROBE):
        print(f"缺 {PROBE}；先在 oracle/goutls 下 go build -o fizztls-utls .",
              file=sys.stderr)
        return 2

    wanted = argv[1:] or list_profiles()
    out, failed = {}, []
    with ClientHelloSniffer() as sniffer:
        for name in wanted:
            try:
                subprocess.run(
                    [PROBE, "-addr", f"{sniffer.host}:{sniffer.port}",
                     "-profiles", name],
                    capture_output=True, text=True, timeout=30)
                out[name] = fingerprint(sniffer.pop(timeout=15))
                print(f"  {name:22s} ja4={out[name]['ja4']}")
            except Exception as e:
                failed.append((name, repr(e)))
                print(f"  {name:22s} FAILED {e!r}", file=sys.stderr)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"\n采到 {len(out)}/{len(wanted)} → {os.path.normpath(OUT)}")
    if failed:
        for n, e in failed[:8]:
            print(f"  {n}: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
