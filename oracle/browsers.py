"""本机浏览器发现与真机 ClientHello 采集（多引擎）。

**为什么必须真机采**：curl_cffi 的 target 表严重滞后于市面版本——本机 Chrome 151
/ Firefox 149 / Safari 27 全部超出它的最高 target (chrome136/firefox135/safari260)，
Edge 更是停在 2022 年的 101。要"完全覆盖主流"，profile 的主来源只能是真机，
curl_cffi 退化成历史版本的补充。

**为什么统一用 IP 直连而不是域名 SNI**：Chrome 151 的 --host-resolver-rules 已
失效（headless/有头、裸规则/显式端口/关 DoH/--host-rules 四种组合实测全部不生效），
把域名映射到本地观测点这条路在 Chromium 系上走不通。改用 https://127.0.0.1:PORT/：
SNI 内容本来就不进 JA4（只有"有没有 SNI"进 d/i 标志位），只要 golden 也用同样方式
采集，两边就严格可比。collect.py 的 no_sni 模式就是为此存在。
"""

import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.sniffer import ClientHelloSniffer                 # noqa: E402

# engine 决定采集方式；chromium 系共用一套命令行开关，firefox 与 safari 各不相同。
CATALOG = [
    ("chrome",   "chromium", "/Applications/Google Chrome.app"),
    ("chromium", "chromium", "/Applications/Chromium.app"),
    ("edge",     "chromium", "/Applications/Microsoft Edge.app"),
    ("brave",    "chromium", "/Applications/Brave Browser.app"),
    ("opera",    "chromium", "/Applications/Opera.app"),
    ("vivaldi",  "chromium", "/Applications/Vivaldi.app"),
    ("arc",      "chromium", "/Applications/Arc.app"),
    ("firefox",  "firefox",  "/Applications/Firefox.app"),
    ("firefox_dev", "firefox", "/Applications/Firefox Developer Edition.app"),
    ("safari",   "safari",   "/Applications/Safari.app"),
]


def _binary(app_path):
    """从 .app 的 Info.plist 取真实可执行文件名，不猜。"""
    plist = os.path.join(app_path, "Contents", "Info.plist")
    try:
        with open(plist, "rb") as f:
            info = plistlib.load(f)
    except OSError:
        return None, None
    exe = info.get("CFBundleExecutable")
    ver = info.get("CFBundleShortVersionString")
    if not exe:
        return None, ver
    path = os.path.join(app_path, "Contents", "MacOS", exe)
    return (path if os.path.exists(path) else None), ver


def discover():
    """返回本机实际存在的浏览器 [(name, engine, binary_path, version)]。"""
    found = []
    for name, engine, app in CATALOG:
        if not os.path.isdir(app):
            continue
        binary, version = _binary(app)
        if binary:
            found.append((name, engine, binary, version))
    return found


def _launch_chromium(binary, url, profile):
    return [binary, "--headless=new", f"--user-data-dir={profile}",
            "--no-first-run", "--no-default-browser-check",
            "--disable-gpu", "--disable-background-networking", url]


def _launch_firefox(binary, url, profile):
    # Firefox 的 -headless 需要 profile 目录已存在；-no-remote 避免复用用户实例。
    return [binary, "--headless", "--no-remote", "--profile", profile, url]


def capture(name, engine, binary, port, timeout=30, sniffer=None):
    """启动浏览器打观测点，返回该浏览器的 ClientHello 指纹。

    Safari 无法用独立 profile 或 headless 启动，只能 `open -a` 唤起用户的真实
    Safari——会在屏幕上弹一个窗口，这是它唯一的采集方式。
    """
    url = f"https://127.0.0.1:{port}/"
    profile = tempfile.mkdtemp(prefix=f"fizztls-{name}-")
    proc = None
    try:
        if engine == "chromium":
            cmd = _launch_chromium(binary, url, profile)
        elif engine == "firefox":
            cmd = _launch_firefox(binary, url, profile)
        elif engine == "safari":
            cmd = ["open", "-a", "Safari", url]
        else:
            raise ValueError(f"unknown engine {engine}")

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        return fingerprint(sniffer.pop(timeout=timeout))
    finally:
        if proc and engine != "safari":
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        time.sleep(0.3)
        shutil.rmtree(profile, ignore_errors=True)


def main(argv):
    import json

    only = set(argv[1:]) or None
    found = discover()
    print(f"发现 {len(found)} 个浏览器：")
    for name, engine, _, version in found:
        print(f"  {name:14s} {engine:9s} {version}")

    results, failures = {}, []
    print("\n采集：")
    for name, engine, binary, version in found:
        if only and name not in only:
            continue
        if engine == "safari" and not (only and "safari" in only):
            print(f"  {name:14s} 跳过（会弹出真实窗口，需显式指定 safari 才采）")
            continue
        with ClientHelloSniffer() as sniffer:
            try:
                fp = capture(name, engine, binary, sniffer.port, sniffer=sniffer)
                results[name] = {"version": version, "engine": engine, "fingerprint": fp}
                print(f"  {name:14s} {version:20s} ja4={fp['ja4']}")
            except Exception as e:
                failures.append((name, repr(e)))
                print(f"  {name:14s} FAILED {e!r}", file=sys.stderr)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "spec", "golden", "real_browsers.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)

    # 合并而非覆盖：只采一个浏览器（如 safari，它必须显式指定）时若直接写
    # results，会把其余浏览器的样本静默清空，coverage 随之少算覆盖面。
    merged = {}
    if os.path.exists(out):
        try:
            with open(out) as f:
                merged = json.load(f)
        except (OSError, ValueError):
            merged = {}
    merged.update(results)

    with open(out, "w") as f:
        json.dump(merged, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"\n本次采集 {len(results)} 份，累计 {len(merged)} 份 → {os.path.normpath(out)}")
    if failures:
        for n, e in failures:
            print(f"  FAILED {n}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
