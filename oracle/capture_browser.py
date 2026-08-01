"""真机浏览器 ground truth 采集：让本机装的浏览器打本地观测点。

**为什么需要这个**：curl_cffi 的 target 表停在某个版本（0.13.0 最高 chrome136），
而用户本机的 Chrome 可能远新于它。要回答"新版本还能不能被现有 target 覆盖"，
唯一可信的办法是让真浏览器自己发一次 ClientHello，跟 golden 逐字段比——
推测"指纹大概没变"不算证据。

不用 headless：headless Chrome 的 TLS 栈配置与有头版本可能不同，采出来的不是
用户真实流量的形态。用独立 user-data-dir，不碰用户正在用的 profile。
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.sniffer import ClientHelloSniffer                 # noqa: E402

BROWSERS = {
    "chrome": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "edge": "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "brave": "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
}


def browser_version(path):
    try:
        out = subprocess.run([path, "--version"], capture_output=True,
                             text=True, timeout=15)
        return out.stdout.strip() or out.stderr.strip()
    except (OSError, subprocess.SubprocessError) as e:
        return f"(unknown: {e})"


def capture(browser="chrome", sni="example.com", timeout=30):
    """启一次浏览器打观测点，返回 (version, fingerprint)。

    --host-resolver-rules 把 SNI 域名映射到本地：SNI 必须是真域名，否则 JA4 的
    SNI 标志位会从 d 变成 i，跟 curl_cffi golden 不可比。
    """
    path = BROWSERS.get(browser)
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"{browser} not found at {path}")

    version = browser_version(path)
    profile = tempfile.mkdtemp(prefix=f"tlsfp-{browser}-")
    proc = None
    try:
        with ClientHelloSniffer() as sniffer:
            url = f"https://{sni}:{sniffer.port}/"
            proc = subprocess.Popen(
                [path,
                 f"--host-resolver-rules=MAP {sni} 127.0.0.1",
                 f"--user-data-dir={profile}",
                 "--no-first-run", "--no-default-browser-check",
                 "--disable-background-networking",
                 url],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            record = sniffer.pop(timeout=timeout)
            return version, fingerprint(record)
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        time.sleep(0.5)
        shutil.rmtree(profile, ignore_errors=True)


def compare(real, golden_entry):
    """逐字段比对真机指纹与某个 golden target，返回差异列表（空 = 完全一致）。"""
    fields = ["ja4", "ciphers", "extensions_ordered", "curves", "sig_algs",
              "alpn", "supported_versions", "psk_modes", "cert_compression",
              "record_size_limit", "app_settings", "point_formats", "ech",
              "has_grease", "client_version"]
    diffs = []
    for f in fields:
        a, b = real.get(f), golden_entry.get(f)
        if a != b:
            diffs.append((f, b, a))   # (字段, golden, 真机)
    return diffs


def main(argv):
    import json

    browser = argv[1] if len(argv) > 1 else "chrome"
    version, fp = capture(browser)
    print(f"browser : {version}")
    print(f"ja4     : {fp['ja4']}")
    print(f"ciphers : {len(fp['ciphers'])}  extensions: {len(fp['extensions_ordered'])}")
    print(f"alpn    : {fp['alpn']}")

    golden_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "..", "spec", "golden", "curl_cffi.json")
    with open(golden_path) as f:
        golden = json.load(f)

    print("\n最接近的 curl_cffi target（按差异字段数排序）：")
    ranked = sorted(((len(compare(fp, g)), t) for t, g in golden.items()))
    for n, t in ranked[:5]:
        print(f"  {t:20s} 差异字段 {n}")

    best_n, best_t = ranked[0]
    print(f"\n与 {best_t} 的逐字段差异：")
    if best_n == 0:
        print("  （无差异 — 真机指纹被现有 target 完整覆盖）")
    else:
        for field, g, r in compare(fp, golden[best_t]):
            print(f"  {field}:\n    golden({best_t}): {g}\n    真机            : {r}")

    out = os.path.join(os.path.dirname(golden_path), f"real_{browser}.json")
    with open(out, "w") as f:
        json.dump({"version": version, "fingerprint": fp}, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"\n落盘 → {os.path.normpath(out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
