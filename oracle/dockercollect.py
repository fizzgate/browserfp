"""在 Docker 容器里采 Linux 版浏览器的指纹 —— 补非 macOS 平台。

本机只有 macOS，而平台维度已被证实是真实区分点（Firefox 桌面 vs Android 在
TLS 与 h2 两层都不同）。Linux 桌面版是否与 macOS 同指纹，此前没有直接证据。

复用本机已有的 flaresolverr 镜像（自带 /usr/bin/chromium），不必再拉几百 MB
的浏览器镜像。

两个必要条件：
  · 观测点必须绑 0.0.0.0 —— 默认 127.0.0.1 容器连不进来
  · 容器内用 host.docker.internal 访问宿主（macOS Docker Desktop 提供）

注意由此采到的是**带 SNI** 的指纹（用了域名），与库里的 no-SNI golden 比对时
要先去掉 SNI(0x0000) 扩展再比。
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.goldenio import write_golden                      # noqa: E402
from oracle.sniffer import ClientHelloSniffer                 # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "spec", "golden", "linux_browsers.json")

# 镜像 → (容器内浏览器路径, 展示名)。优先复用本机已有镜像。
IMAGES = {
    "21hsmw/flaresolverr:nodriver": ("/usr/bin/chromium", "chromium-linux"),
}


def browser_version(image, binary):
    out = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", binary, image, "--version"],
        capture_output=True, text=True, timeout=90)
    return (out.stdout or out.stderr).strip().splitlines()[-1] if (
        out.stdout or out.stderr) else "?"


def capture(image, binary, sniffer, timeout=60):
    proc = subprocess.Popen(
        ["docker", "run", "--rm", "--entrypoint", binary, image,
         "--headless=new", "--no-sandbox", "--disable-gpu",
         "--user-data-dir=/tmp/fizztls-profile", "--no-first-run",
         "--ignore-certificate-errors",
         f"https://host.docker.internal:{sniffer.port}/"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return fingerprint(sniffer.pop(timeout=timeout))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def main(argv):
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        print("Docker 未运行", file=sys.stderr)
        return 2

    out, failed = {}, []
    for image, (binary, label) in IMAGES.items():
        try:
            version = browser_version(image, binary)
            # 绑 0.0.0.0：容器要连进来
            with ClientHelloSniffer(host="0.0.0.0") as sniffer:
                fp = capture(image, binary, sniffer)
            out[label] = {"version": version, "image": image,
                          "platform": "linux", "fingerprint": fp}
            print(f"  {label:16s} {version:46s} ja4={fp['ja4']}")
        except Exception as e:
            failed.append((label, repr(e)))
            print(f"  {label:16s} FAILED {e!r}", file=sys.stderr)

    total, _ = write_golden(OUT, out)
    print(f"\n本次 {len(out)}，累计 {total} → {os.path.normpath(OUT)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
