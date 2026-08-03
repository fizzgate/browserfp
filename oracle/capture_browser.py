"""真机浏览器 ground truth 采集：让本机装的浏览器打本地观测点。

**为什么需要这个**：curl_cffi 的 target 表停在某个版本（0.13.0 最高 chrome136），
而用户本机的 Chrome 可能远新于它。要回答"新版本还能不能被现有 target 覆盖"，
唯一可信的办法是让真浏览器自己发一次 ClientHello，跟 golden 逐字段比——
推测"指纹大概没变"不算证据。

不用 headless：headless Chrome 的 TLS 栈配置与有头版本可能不同，采出来的不是
用户真实流量的形态。用独立 user-data-dir，不碰用户正在用的 profile。

**两套启动方式，因为把域名指向本地的机制不同**：
  Chromium 系  --host-resolver-rules=MAP <sni> 127.0.0.1
  Firefox 系   profile 里 user_pref("network.dns.localDomains", "<sni>")
两者都不改 /etc/hosts（要 sudo，且会影响本机其他进程）。SNI 必须是真域名，
否则 JA4 的 SNI 标志位会从 d 变成 i，跟 golden 不可比。

用 -p 指定任意路径可采**历史版本**：本机只装了最新版，而生产 UA 里还有大量
旧版本，它们的指纹与最新版不同（实测 Firefox 123↔128 差 3 个字段），只能把
对应版本下下来实采，不能拿相邻版本顶。
"""

import os
import re
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
    # 表里原来没有 firefox —— _firefox_argv 那条分支只有显式传 path 才走得到，
    # 于是 capture("firefox") 恒报 "not found at None"。装了却用不上。
    "firefox": "/Applications/Firefox.app/Contents/MacOS/firefox",
}


def browser_version(path):
    try:
        out = subprocess.run([path, "--version"], capture_output=True,
                             text=True, timeout=15)
        return out.stdout.strip() or out.stderr.strip()
    except (OSError, subprocess.SubprocessError) as e:
        return f"(unknown: {e})"


def _is_firefox(path):
    return "firefox" in os.path.basename(path).lower()


def _firefox_argv(path, profile, sni, url):
    """Firefox 没有 --host-resolver-rules；用 localDomains 把 SNI 指向本地。

    **这条路在本机不生效**：把 firefox 加进 BROWSERS 之后实测，Firefox 正常启动
    但 45s 内一个 ClientHello 都不到；换成 `https://localhost:<port>/`（不依赖
    DNS 覆盖）立刻抓到 1892 字节。也就是说 `network.dns.localDomains` 没把
    example.com 指过来，而不是采集链路坏了 —— 关掉 DoH（`network.trr.mode=5`）
    也一样。原因未查清。

    此前这条分支**从来没被走到过**：BROWSERS 表里没有 firefox，`capture("firefox")`
    恒报 `not found at None`，于是"装了却用不上"一直没人发现。需要真机 Firefox
    指纹时，用 localhost 作 SNI 是可行的替代（代价是 JA4 的 SNI 标志位不同）。

    关掉首次运行页与遥测，否则浏览器起来先打 Mozilla 自家域名，虽然不会连到
    我们的观测端口，但会拖慢首个 ClientHello。
    """
    with open(os.path.join(profile, "user.js"), "w") as f:
        f.write(f'user_pref("network.dns.localDomains", "{sni}");\n')
        for k, v in [("browser.shell.checkDefaultBrowser", "false"),
                     ("toolkit.telemetry.enabled", "false"),
                     ("datareporting.policy.dataSubmissionEnabled", "false"),
                     ("browser.startup.homepage_override.mstone", '"ignore"'),
                     ("app.normandy.first_run", "false"),
                     ("network.dns.disablePrefetch", "true")]:
            f.write(f'user_pref("{k}", {v});\n')
    return [path, "-profile", profile, "-no-remote", "-new-instance", url]


def capture(browser="chrome", sni="example.com", timeout=30, path=None):
    """启一次浏览器打观测点，返回 (version, fingerprint)。

    path 可直接给二进制路径，用来采本机没装的历史版本。
    """
    path = path or BROWSERS.get(browser)
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"{browser} not found at {path}")

    version = browser_version(path)
    profile = tempfile.mkdtemp(prefix=f"browserfp-{browser}-")
    proc = None
    try:
        with ClientHelloSniffer() as sniffer:
            url = f"https://{sni}:{sniffer.port}/"
            if _is_firefox(path):
                argv = _firefox_argv(path, profile, sni, url)
            else:
                argv = [path,
                        f"--host-resolver-rules=MAP {sni} 127.0.0.1",
                        f"--user-data-dir={profile}",
                        "--no-first-run", "--no-default-browser-check",
                        "--disable-background-networking",
                        url]
            proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
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
    # 第二个参数给二进制路径 → 采历史版本；不给则用 BROWSERS 里本机装的那个
    path = argv[2] if len(argv) > 2 else None
    version, fp = capture(browser, path=path)
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

    # 文件名带版本号：采多个历史版本时不能互相覆盖（此前采集器覆盖式落盘
    # 已经毁过一次 golden，见 goldenio.write_golden 的注释）
    tag = re.sub(r"[^\w.]+", "_", version).strip("_") or browser
    out = os.path.join(os.path.dirname(golden_path), f"real_{tag}.json")
    with open(out, "w") as f:
        json.dump({"version": version, "fingerprint": fp}, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"\n落盘 → {os.path.normpath(out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
