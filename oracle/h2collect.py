"""采集 h2 层 golden：curl_cffi 全 target + 本机真机浏览器。

用法：
    python -m oracle.h2collect            # curl_cffi 31 个 + 真机 chromium 系
    python -m oracle.h2collect --real     # 只采真机（不含 safari）
    python -m oracle.h2collect --real --safari   # 含 safari：会改用户钥匙串+弹窗
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle import targets                                    # noqa: E402
from oracle.browsers import discover                          # noqa: E402
from oracle.h2probe import H2Probe, CERT, CA_CERT                      # noqa: E402

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "golden")


def spki_pin(cert_path=CERT):
    """算证书公钥的 SPKI SHA256/base64，喂给 Chrome 的白名单开关。

    Chrome 151 起单独的 --ignore-certificate-errors 已不足以让自签证书通过
    （握手阶段直接 EOF，表现为 SSLEOFError）；必须再给
    --ignore-certificate-errors-spki-list。Chromium 142 不需要——所以这是
    版本相关的收紧，不是配置写错。
    """
    pub = subprocess.run(["openssl", "x509", "-in", cert_path, "-pubkey", "-noout"],
                         capture_output=True, check=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"],
                         input=pub, capture_output=True, check=True).stdout
    digest = subprocess.run(["openssl", "dgst", "-sha256", "-binary"],
                            input=der, capture_output=True, check=True).stdout
    return base64.b64encode(digest).decode()


def collect_curl_cffi():
    from curl_cffi import Curl, CurlOpt

    out, failures = {}, []
    for t in targets.UNIQUE:
        with H2Probe() as probe:
            c = Curl()
            try:
                c.setopt(CurlOpt.URL, f"https://127.0.0.1:{probe.port}/".encode())
                c.setopt(CurlOpt.SSL_VERIFYPEER, 0)
                c.setopt(CurlOpt.SSL_VERIFYHOST, 0)
                c.setopt(CurlOpt.TIMEOUT_MS, 8000)
                c.impersonate(t)
                try:
                    c.perform()
                except Exception:
                    pass
            finally:
                c.close()
            try:
                out[t] = probe.pop(timeout=15)
                print(f"  {t:20s} {out[t]['akamai_fingerprint']}")
            except Exception as e:
                failures.append((t, repr(e)))
                print(f"  {t:20s} FAILED {e!r}", file=sys.stderr)
    return out, failures


def certutil_path():
    """找 NSS 的 certutil —— Firefox 用自己的 cert9.db，不看系统钥匙串。"""
    for p in ("/opt/homebrew/opt/nss/bin/certutil",
              "/usr/local/opt/nss/bin/certutil",
              shutil.which("certutil")):
        if p and os.path.exists(p):
            return p
    return None


def make_firefox_profile(cert_path=None):
    """建一个信任观测点自签 CA 的临时 Firefox profile。

    Firefox 不吃 --ignore-certificate-errors 之类的命令行开关，只认 profile 里
    的 NSS 库。往**临时 profile** 注入信任，不碰用户的 profile、也不碰系统
    钥匙串——Safari 走系统钥匙串，改那个会影响全机所有程序，所以本模块不采
    Safari 的 L2。
    """
    cu = certutil_path()
    if not cu:
        raise FileNotFoundError("缺 certutil：brew install nss")
    # 注入的必须是 **CA** 证书而不是观测点的 leaf：Firefox 不接受把同一张
    # 自签证书既当信任锚又当服务器证书，会回 SSLV3_ALERT_BAD_CERTIFICATE。
    if cert_path is None:
        cert_path = CA_CERT
    profile = tempfile.mkdtemp(prefix="fizztls-ffprof-")
    subprocess.run([cu, "-N", "-d", f"sql:{profile}", "--empty-password"],
                   check=True, capture_output=True)
    subprocess.run([cu, "-A", "-n", "fizztls-observer", "-t", "C,,",
                    "-i", cert_path, "-d", f"sql:{profile}"],
                   check=True, capture_output=True)
    return profile


def collect_real(with_safari=False):
    """采 chromium 系 + Firefox。Safari 走系统钥匙串，不采（见 make_firefox_profile）。"""
    pin = spki_pin()
    out, failures = {}, []
    for name, engine, binary, version in discover():
        if engine == "firefox":
            try:
                r = _capture_firefox(binary, name)
                r["version"] = version
                out[name] = r
                print(f"  {name:20s} {version:22s} {r['akamai_fingerprint']}")
            except Exception as e:
                failures.append((name, repr(e)))
                print(f"  {name:20s} FAILED {e!r}", file=sys.stderr)
            continue
        if engine == "safari":
            if not with_safari:
                print(f"  {name:20s} 跳过（需 --safari：会改用户钥匙串并弹出窗口）")
                continue
            try:
                r = _capture_safari()
                r["version"] = version
                out[name] = r
                print(f"  {name:20s} {version:22s} {r['akamai_fingerprint']}")
            except Exception as e:
                failures.append((name, repr(e)))
                print(f"  {name:20s} FAILED {e!r}", file=sys.stderr)
            continue
        if engine != "chromium":
            print(f"  {name:20s} 跳过（未支持的引擎 {engine}）")
            continue
        profile = tempfile.mkdtemp(prefix=f"fizztls-h2-{name}-")
        with H2Probe() as probe:
            p = subprocess.Popen(
                [binary, "--headless=new", f"--user-data-dir={profile}",
                 "--no-first-run", "--disable-gpu",
                 f"--ignore-certificate-errors-spki-list={pin}",
                 "--ignore-certificate-errors",
                 f"https://127.0.0.1:{probe.port}/"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                r = probe.pop(timeout=25)
                r["version"] = version
                out[name] = r
                print(f"  {name:20s} {version:22s} {r['akamai_fingerprint']}")
            except Exception as e:
                failures.append((name, repr(e)))
                print(f"  {name:20s} FAILED {e!r}", file=sys.stderr)
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(profile, ignore_errors=True)
    return out, failures


SAFARI_CA_LABEL = "fizztls-observer-CA"
LOGIN_KEYCHAIN = os.path.expanduser("~/Library/Keychains/login.keychain-db")


def _capture_safari():
    """采 Safari 的 h2。**会改动用户钥匙串，且会弹出真实 Safari 窗口。**

    Safari 既不吃命令行证书豁免开关、也没有独立的证书库（不像 Firefox 的
    cert9.db），只认系统/用户钥匙串。这里注入到**用户**钥匙串（login）而不是
    系统钥匙串：不需要 sudo、只影响当前用户，且 finally 里立即删除并核对残留。

    观测点必须发完整链（fullchain.pem）：只发 leaf 时 Safari 回
    SSLV3_ALERT_CERTIFICATE_UNKNOWN —— Firefox 能用库里的 CA 补全，Safari 不会。
    """
    # security 操作实测要 8s 左右，偶发更久（曾撞到 60s 超时），给足余量。
    # 先查再加：已在钥匙串时重复添加会触发确认流程而卡住。
    present = subprocess.run(
        ["security", "find-certificate", "-c", SAFARI_CA_LABEL, LOGIN_KEYCHAIN],
        capture_output=True).returncode == 0
    if not present:
        subprocess.run(["security", "add-trusted-cert", "-r", "trustRoot",
                        "-k", LOGIN_KEYCHAIN, CA_CERT],
                       check=True, capture_output=True, timeout=180,
                       stdin=subprocess.DEVNULL)
    try:
        with H2Probe() as probe:
            subprocess.Popen(["open", "-a", "Safari",
                              f"https://127.0.0.1:{probe.port}/"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return probe.pop(timeout=45)
    finally:
        subprocess.run(["security", "delete-certificate", "-c", SAFARI_CA_LABEL,
                        LOGIN_KEYCHAIN], capture_output=True)
        subprocess.run(["osascript", "-e",
                        'tell application "Safari" to close '
                        '(every window whose name contains "127.0.0.1")'],
                       capture_output=True)
        left = subprocess.run(["security", "find-certificate", "-c", SAFARI_CA_LABEL,
                               LOGIN_KEYCHAIN], capture_output=True)
        if left.returncode == 0:
            raise RuntimeError("CA 未能从钥匙串删除，请手工检查 " + SAFARI_CA_LABEL)


def _capture_firefox(binary, name):
    """Firefox 走注入了信任 CA 的临时 profile；-no-remote 避免复用用户实例。"""
    profile = make_firefox_profile()
    try:
        with H2Probe() as probe:
            p = subprocess.Popen(
                [binary, "--headless", "--no-remote", "--profile", profile,
                 f"https://127.0.0.1:{probe.port}/"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                return probe.pop(timeout=40)
            finally:
                p.terminate()
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()
    finally:
        shutil.rmtree(profile, ignore_errors=True)


def _write(name, data, merge=False):
    """merge=True 时读回已有内容再更新。

    不合并会静默丢样本：本文件只采到 chromium+firefox 时直接写，会把上一次
    单独采的 safari 冲掉，而覆盖矩阵少算不会报错——纯假绿。同类 bug 在
    browsers.py 已经出现过一次，这是第二次，两处都必须合并写。
    """
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, name)
    if merge and os.path.exists(path):
        try:
            with open(path) as f:
                existing = json.load(f)
            existing.update(data)
            data = existing
        except (OSError, ValueError):
            pass
    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    return os.path.normpath(path)


def main(argv):
    only_real = "--real" in argv
    failures = []

    if not only_real:
        print("curl_cffi h2 指纹：")
        data, f1 = collect_curl_cffi()
        failures += f1
        print(f"  → {_write('h2_curl_cffi.json', data)}  ({len(data)}/{len(targets.UNIQUE)})")

    print("\n真机 h2 指纹：")
    real, f2 = collect_real(with_safari="--safari" in argv)
    failures += f2
    print(f"  → {_write('h2_real_browsers.json', real, merge=True)}  (本次 {len(real)})")

    if failures:
        print(f"\nFAILURES ({len(failures)}):", file=sys.stderr)
        for n, e in failures:
            print(f"  {n}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
