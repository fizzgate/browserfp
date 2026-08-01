"""采集 tls-client 76 个 profile 的 h2 层指纹（SETTINGS/WINDOW_UPDATE/伪头）。

gocollect.py 只走裸 UClient 握手，采得到 TLS 层但采不到 h2——SETTINGS 这些
只有走完整 HTTP 栈才发得出来。本模块用 Go 端的 -h2 模式补齐。

一 profile 一连接，与 gocollect 同理：串行共用连接一旦某个失败就整表错位。
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.h2probe import H2Probe                            # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "gotls", "fizztls-probe")
OUT = os.path.join(HERE, "..", "spec", "golden", "h2_tls_client.json")


def main(argv):
    if not os.path.exists(PROBE):
        print(f"缺 {PROBE}", file=sys.stderr)
        return 2

    names = argv[1:] or [l.strip() for l in subprocess.run(
        [PROBE, "-list"], capture_output=True, text=True, check=True
    ).stdout.splitlines() if l.strip()]

    out, failures = {}, []
    for name in names:
        with H2Probe() as probe:
            subprocess.run(
                [PROBE, "-h2", "-addr", f"{probe.host}:{probe.port}",
                 "-profiles", name],
                capture_output=True, text=True, timeout=40)
            try:
                out[name] = probe.pop(timeout=20)
                print(f"  {name:26s} {out[name]['akamai_fingerprint']}")
            except Exception as e:
                failures.append((name, repr(e)))
                print(f"  {name:26s} FAILED {e!r}", file=sys.stderr)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"\ncaptured {len(out)}/{len(names)} → {os.path.normpath(OUT)}")
    if failures:
        print(f"FAILURES ({len(failures)}):", file=sys.stderr)
        for n, e in failures[:12]:
            print(f"  {n}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
