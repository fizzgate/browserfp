"""采真机浏览器的 QUIC ClientHello 指纹（JA4Q）。

QUIC 的 ClientHello 与 TCP 上那份**是两套东西**：实测 Chrome 151 的 QUIC 版只有
10 个扩展、TCP 版 15 个，且 QUIC 版含 `0x39 quic_transport_parameters`——那正是
srcaudit 长期报"从未观测到"的盲区之一。所以 QUIC 必须单独采，不能拿 TCP 版顶替。

Chromium 系用 `--origin-to-force-quic-on` 强制走 QUIC，否则浏览器只在服务端通过
Alt-Svc 广告 h3 之后才尝试，本地观测点不回包也就永远等不到。

Firefox 没有对应的命令行开关，但有等价的 pref：
`network.http.http3.alt-svc-mapping-for-testing`（形如 `"host;h3=:port"`），
它让 Firefox 对指定 origin 直接走 h3，不必等服务端广播 Alt-Svc —— 与 Chromium
的 `--origin-to-force-quic-on` 是同一个作用。旁路观测不做真握手，所以还要关掉
证书校验相关的拦截（`network.stricttransportsecurity.preloadlist` 之类不影响，
关键是不让它因为握手失败就放弃 h3 重试 TCP）。
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.browsers import discover                          # noqa: E402
from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.goldenio import write_golden                      # noqa: E402
from oracle.quic import ja4q                                  # noqa: E402
from oracle.quicprobe import QuicProbe                         # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "spec", "golden", "quic_real_browsers.json")


def capture_firefox(binary, port):
    """用 prefs 强制 Firefox 对本地端口走 h3。

    关键是 alt-svc-mapping-for-testing —— 没有它，Firefox 只会在服务端广播过
    Alt-Svc 之后才尝试 h3，而旁路观测端根本不完成握手、也就广播不了。
    """
    profile = tempfile.mkdtemp(prefix="tlsfp-quic-ff-")
    with open(os.path.join(profile, "user.js"), "w") as f:
        f.write(
            'user_pref("network.http.http3.enable", true);\n'
            f'user_pref("network.http.http3.alt-svc-mapping-for-testing",'
            f' "127.0.0.1;h3=:{port}");\n'
            'user_pref("network.dns.disablePrefetch", true);\n'
            'user_pref("browser.shell.checkDefaultBrowser", false);\n'
            'user_pref("browser.startup.homepage_override.mstone", "ignore");\n')
    proc = subprocess.Popen(
        [binary, "--headless", "-profile", profile, "-no-remote",
         f"https://127.0.0.1:{port}/"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc, profile


def capture(binary, port, timeout=40):
    profile = tempfile.mkdtemp(prefix="tlsfp-quic-")
    proc = subprocess.Popen(
        [binary, "--headless=new", f"--user-data-dir={profile}",
         "--no-first-run", "--disable-gpu", "--enable-quic",
         f"--origin-to-force-quic-on=127.0.0.1:{port}",
         "--ignore-certificate-errors", f"https://127.0.0.1:{port}/"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc, profile


def main(argv):
    wanted = set(argv[1:]) or None
    out, failed = {}, []
    for name, engine, binary, version in discover():
        if engine not in ("chromium", "firefox"):
            print(f"  {name:10s} 跳过（{engine} 无法强制走 h3；"
                  "Safari 没有等价开关）")
            continue
        if wanted and name not in wanted:
            continue
        with QuicProbe() as probe:
            proc, profile = (capture_firefox(binary, probe.port)
                             if engine == "firefox"
                             else capture(binary, probe.port))
            try:
                fp = fingerprint(probe.pop(timeout=40))
                fp["ja4q"] = ja4q(fp)
                out[name] = {"version": version, "fingerprint": fp}
                print(f"  {name:10s} {version:20s} {fp['ja4q']}"
                      f"  扩展{len(fp['extensions_ordered'])} alpn={fp['alpn']}")
            except Exception as e:
                failed.append((name, repr(e)))
                print(f"  {name:10s} FAILED {e!r}", file=sys.stderr)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                shutil.rmtree(profile, ignore_errors=True)
        time.sleep(0.3)

    total, _ = write_golden(OUT, out)
    print(f"\n本次 {len(out)}，累计 {total} → {os.path.normpath(OUT)}")
    if failed:
        for n, e in failed:
            print(f"  {n}: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
