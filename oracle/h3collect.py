"""采真机浏览器的 HTTP/3 层指纹（SETTINGS + 伪头顺序）。

与 quiccollect 的分工：quiccollect 采 QUIC 的 ClientHello（TLS 层，旁路不握手），
本模块完成 QUIC 握手后采 H3 应用层。两者是不同的层，都要。

须用 .venv-wreq/bin/python 跑（aioquic 要求 Python ≥3.11）。
Chromium 系需 --origin-to-force-quic-on 强制走 QUIC，且 Chrome 151 起必须给
--ignore-certificate-errors-spki-list（真握手会校验证书，旁路观测时不会）。
"""

import base64
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.browsers import discover                          # noqa: E402
from oracle.goldenio import write_golden                      # noqa: E402
from oracle.h3probe import CERT, capture                      # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "spec", "golden", "h3_real_browsers.json")


def spki_pin(cert_path=CERT):
    pub = subprocess.run(["openssl", "x509", "-in", cert_path, "-pubkey", "-noout"],
                         capture_output=True, check=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"],
                         input=pub, capture_output=True, check=True).stdout
    dig = subprocess.run(["openssl", "dgst", "-sha256", "-binary"],
                         input=der, capture_output=True, check=True).stdout
    return base64.b64encode(dig).decode()


def _free_udp_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def capture_browser(binary, pin):
    profile = tempfile.mkdtemp(prefix="fizztls-h3-")
    port = _free_udp_port()

    def launch(p):
        return subprocess.Popen(
            [binary, "--headless=new", f"--user-data-dir={profile}",
             "--no-first-run", "--disable-gpu", "--enable-quic",
             f"--origin-to-force-quic-on=127.0.0.1:{p}",
             f"--ignore-certificate-errors-spki-list={pin}",
             "--ignore-certificate-errors", f"https://127.0.0.1:{p}/"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        return capture(port, launch)
    finally:
        shutil.rmtree(profile, ignore_errors=True)


def main(argv):
    wanted = set(argv[1:]) or None
    pin = spki_pin()
    out, failed = {}, []
    for name, engine, binary, version in discover():
        if engine != "chromium":
            print(f"  {name:10s} 跳过（{engine} 需 about:config 开 h3）")
            continue
        if wanted and name not in wanted:
            continue
        try:
            r = capture_browser(binary, pin)
            r["version"] = version
            out[name] = r
            print(f"  {name:10s} {version:20s} {r['h3_text']}")
        except Exception as e:
            failed.append((name, repr(e)))
            print(f"  {name:10s} FAILED {e!r}", file=sys.stderr)

    total, _ = write_golden(OUT, out)
    print(f"\n本次 {len(out)}，累计 {total} → {os.path.normpath(OUT)}")
    if failed:
        for n, e in failed:
            print(f"  {n}: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
