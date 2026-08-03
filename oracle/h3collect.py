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

# Firefox 要装的是**签发者 CA**，不是叶证书。fullchain.pem 的第一张是叶
# （CN=localhost），certutil -A 只吃第一张 —— 装成叶再标 "C,,"（受信 CA）
# 语义就错了，Firefox 照样不认，表现是"未收到 H3 请求头"，看着像它不支持 h3。
CA_CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "spec", "certs", "ca.pem")

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
    profile = tempfile.mkdtemp(prefix="browserfp-h3-")
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


def capture_browser_firefox(binary):
    """Firefox 的 h3 采集 —— **目前拿不到，原因已定位，不是"没试过"**。

    两件准备工作都做对了：
      · pref `network.http.http3.alt-svc-mapping-for-testing` 确实生效，
        MOZ_LOG 里能看到 `AltSvcMapping ctor … npnToken=h3` 建出来了
      · CA 用 certutil 装进 profile 证书库（要装 **ca.pem** 不是 fullchain.pem，
        后者第一张是叶证书，装成叶再标 "CT,," 语义就错了）

    卡在第三件事上，日志里写得很清楚：

        AltSvcCache::LookupMapping … skip when storage is not ready

    alt-svc 缓存的存储是异步加载的，**首个请求发出时还没就绪**，于是 Firefox
    按普通 https 走 TCP —— 而本探针只服务 UDP，那条 TCP 直接失败且不会重试。
    Chromium 没这问题：`--origin-to-force-quic-on` 从第一个请求就强制 QUIC，
    根本不查 alt-svc 缓存。

    往下走的路是让探针**同时起一个 TCP/TLS 端**，在响应里带
    `Alt-Svc: h3=":port"` —— 那才是真实站点让浏览器升级到 h3 的方式，还能顺带
    摆脱这个测试专用 pref。工作量在 h3probe 那边，本函数先保留并如实报错。

    注意：QUIC **Initial** 那一层不受影响，已经采到了（见 oracle/quiccollect.py）
    —— 那条是旁路观测，不需要完成握手。
    """
    if not shutil.which("certutil"):
        raise RuntimeError("缺 certutil（brew install nss）—— Firefox 的 h3 采集"
                           "要往 profile 证书库装 CA，没有它做不到")
    profile = tempfile.mkdtemp(prefix="browserfp-h3-ff-")
    # **端口要先定下来**：capture(port, launch) 把 port 原样传给 launch，
    # 传 0 的话 pref 里写的是 h3=:0、URL 也是 :0，浏览器根本连不上，
    # 表现是"未收到 H3 请求头"，看着像 Firefox 不支持。
    port = _free_udp_port()
    subprocess.run(["certutil", "-N", "--empty-password", "-d", f"sql:{profile}"],
                   capture_output=True, timeout=60, check=True)
    subprocess.run(["certutil", "-A", "-n", "browserfp-ca", "-t", "CT,,", "-i",
                    CA_CERT, "-d", f"sql:{profile}"], capture_output=True,
                   timeout=60, check=True)

    def launch(p):
        with open(os.path.join(profile, "user.js"), "w") as f:
            f.write(
                'user_pref("network.http.http3.enable", true);\n'
                # 默认 Firefox 会先"验证"备用服务再启用，多一轮往返；
                # 关掉它让映射立即可用
                'user_pref("network.http.altsvc.validate", false);\n'
                # **关键的一条**：Firefox 检测到用户自装根证书时会直接禁用
                # HTTP/3（为躲开中间人设备），日志里那句
                # `Authenticated [hasThirdPartyRoots=1]` 之后就 Close 了。
                # 而我们的探针只能用自签 CA —— 不关掉这条，h3 永远握不上手，
                # 表面症状却是"未收到 H3 请求头"，很容易误判成不支持。
                'user_pref("network.http.http3.disable_when_third_party_roots_found", false);\n'
                f'user_pref("network.http.http3.alt-svc-mapping-for-testing",'
                f' "127.0.0.1;h3=:{p}");\n'
                'user_pref("browser.shell.checkDefaultBrowser", false);\n'
                'user_pref("browser.startup.homepage_override.mstone", "ignore");\n')
        return subprocess.Popen(
            [binary, "--headless", "-profile", profile, "-no-remote",
             f"https://127.0.0.1:{p}/"],
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
        if engine not in ("chromium", "firefox"):
            print(f"  {name:10s} 跳过（{engine} 没有强制走 h3 的开关）")
            continue
        if wanted and name not in wanted:
            continue
        try:
            r = (capture_browser_firefox(binary) if engine == "firefox"
                 else capture_browser(binary, pin))
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
