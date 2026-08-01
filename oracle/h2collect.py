"""采集 h2 层 golden：curl_cffi 全 target + 本机真机浏览器。

用法：
    python -m oracle.h2collect            # curl_cffi 31 个 + 真机 chromium 系
    python -m oracle.h2collect --real     # 只采真机
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
from oracle.h2probe import H2Probe, CERT                      # noqa: E402

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


def collect_real():
    """只采 chromium 系：Firefox/Safari 不吃命令行的证书豁免开关，L2 采不到。"""
    pin = spki_pin()
    out, failures = {}, []
    for name, engine, binary, version in discover():
        if engine != "chromium":
            print(f"  {name:20s} 跳过（{engine} 无法用命令行豁免自签证书）")
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


def _write(name, data):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, name)
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
    real, f2 = collect_real()
    failures += f2
    print(f"  → {_write('h2_real_browsers.json', real)}  ({len(real)})")

    if failures:
        print(f"\nFAILURES ({len(failures)}):", file=sys.stderr)
        for n, e in failures:
            print(f"  {n}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
