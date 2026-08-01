"""采真机浏览器的会话恢复形态。

pskcollect.py 采的是 curl_cffi 的 31 个；本模块补四个真机浏览器。两者链路相同
（tapproxy 记字节 + pskserver 发票据），差别只在客户端怎么被诱导发第二次连接：

  curl_cffi   同一个 Session 直接 get 两次
  真浏览器    同 origin 会复用连接，得靠服务端 Connection: close 断开，
              再由页面里的 <img> 子资源触发一条新 TCP 连接 —— 那次才带 PSK

证书信任沿用 h2collect 的四条路径（Chromium 用 spki-list，Firefox 用 certutil
注入临时 profile，Safari 注入用户钥匙串并即删）。

跑：python -m oracle.pskbrowser [--safari]
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.browsers import discover                          # noqa: E402
from oracle.clienthello import fingerprint, parse_client_hello  # noqa: E402
from oracle.h2collect import (make_firefox_profile, spki_pin,   # noqa: E402
                              _capture_safari)                  # noqa: F401
from oracle.pskcollect import CERT, KEY, start_server          # noqa: E402
from oracle.tapproxy import TapProxy                           # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "spec", "golden", "real_browsers_psk.json")


def _launch(name, engine, binary, url, pin):
    profile = (make_firefox_profile() if engine == "firefox"
               else tempfile_mkdtemp(name))
    if engine == "chromium":
        cmd = [binary, "--headless=new", f"--user-data-dir={profile}",
               "--no-first-run", "--disable-gpu",
               f"--ignore-certificate-errors-spki-list={pin}",
               "--ignore-certificate-errors", url]
    elif engine == "firefox":
        cmd = [binary, "--headless", "--no-remote", "--profile", profile, url]
    elif engine == "safari":
        cmd = ["open", "-a", "Safari", url]
    else:
        raise ValueError(engine)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    return proc, profile


def tempfile_mkdtemp(name):
    import tempfile
    return tempfile.mkdtemp(prefix=f"tlsfp-psk-{name}-")


def capture(name, engine, binary, tap, pin, wait=25):
    """启动浏览器打观测点，收集全部 ClientHello，返回 (首连, 恢复)。"""
    proc, profile = _launch(name, engine, binary,
                            f"https://127.0.0.1:{tap.port}/", pin)
    try:
        hellos = []
        deadline = time.time() + wait
        while time.time() < deadline:
            try:
                hellos.append(tap.pop(timeout=3))
            except Exception:
                if len(hellos) >= 2:
                    break
        if not hellos:
            raise OSError("未捕获到 ClientHello")
        first = fingerprint(hellos[0])
        resumed = None
        for raw in hellos[1:]:
            if 0x0029 in parse_client_hello(raw)["raw_extensions"]:
                resumed = fingerprint(raw)
                break
        return first, resumed, len(hellos)
    finally:
        if engine != "safari":
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(profile, ignore_errors=True)


def main(argv):
    with_safari = "--safari" in argv
    srv, port = start_server()
    pin = spki_pin(CERT)
    out, failures = {}, []
    try:
        for name, engine, binary, version in discover():
            if engine == "safari" and not with_safari:
                print(f"  {name:12s} 跳过（需 --safari）")
                continue
            with TapProxy("127.0.0.1", port) as tap:
                try:
                    first, resumed, n = capture(name, engine, binary, tap, pin)
                except Exception as e:
                    failures.append((name, repr(e)))
                    print(f"  {name:12s} FAILED {e!r}", file=sys.stderr)
                    continue
                if resumed is None:
                    print(f"  {name:12s} {version:18s} 收到 {n} 个 CH，无一带 PSK")
                    continue
                out[name] = {"version": version, "engine": engine,
                             "fingerprint": resumed}
                a, b = len(first["extensions_ordered"]), len(resumed["extensions_ordered"])
                print(f"  {name:12s} {version:18s} PSK ✓ 扩展 {a}→{b}  "
                      f"ja4={resumed['ja4']}")
    finally:
        srv.terminate()

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    merged = {}
    if os.path.exists(OUT):
        try:
            with open(OUT) as f:
                merged = json.load(f)
        except (OSError, ValueError):
            merged = {}
    merged.update(out)
    with open(OUT, "w") as f:
        json.dump(merged, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"\n本次 {len(out)}，累计 {len(merged)} → {os.path.normpath(OUT)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
