"""采集 golden：让 curl_cffi 逐个 target 打本地观测点，落盘指纹。

curl_cffi 是 curl-impersonate 指纹定义的权威实现，它发什么就是"正确答案"。
我们的 C 模块日后打同一个观测点，逐字段比对这份 golden 即为通过。

用法：
    python -m oracle.collect                  # 采全部 31 个
    python -m oracle.collect chrome131 tor145 # 只采指定的
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle import targets                                    # noqa: E402
from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.sniffer import ClientHelloSniffer                 # noqa: E402

GOLDEN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "spec", "golden", "curl_cffi.json")


def capture_one(target, sniffer, sni="claude.ai"):
    """打一次本地观测点，返回该 target 的指纹。

    走低层 Curl 而不是 requests.get：curl_cffi 0.13.0 的 requests 层**没有**
    resolve 参数（传了直接 TypeError），而我们必须让 SNI 是真域名、连接却落到
    本地观测点——只有 CURLOPT_RESOLVE 能做到。用 IP 当 host 会让 JA4 的 SNI
    标志位从 d 变成 i，golden 就失真了。

    SNI 固定为 claude.ai：ClientHello 里 SNI 的**长度**会进 record 长度，虽然
    不进 JA4，但逐字节比对时会差——采 golden 和验证必须用同一个 SNI。
    """
    from curl_cffi import Curl, CurlOpt

    c = Curl()
    try:
        if sni is None:
            # 无 SNI 模式：直连 IP。真机浏览器只能这样采（Chrome 151 的
            # --host-resolver-rules 已失效），要与真机严格可比就得有这一套。
            c.setopt(CurlOpt.URL, f"https://127.0.0.1:{sniffer.port}/".encode())
        else:
            c.setopt(CurlOpt.URL, f"https://{sni}:{sniffer.port}/".encode())
            c.setopt(CurlOpt.RESOLVE, [f"{sni}:{sniffer.port}:127.0.0.1".encode()])
        c.setopt(CurlOpt.TIMEOUT_MS, 5000)
        c.impersonate(target)
        try:
            # 观测点不回握手，这里必然抛 CurlError；ClientHello 已经送达。
            c.perform()
        except Exception:
            pass
        return fingerprint(sniffer.pop(timeout=10))
    finally:
        c.close()


def main(argv):
    argv = list(argv)
    # --no-sni：产出与真机浏览器可比的那套 golden（见 capture_one）。
    no_sni = "--no-sni" in argv
    if no_sni:
        argv.remove("--no-sni")
    sni = None if no_sni else "claude.ai"
    out_path = GOLDEN_PATH.replace("curl_cffi.json",
                                   "curl_cffi_nosni.json" if no_sni else "curl_cffi.json")

    wanted = argv[1:] or targets.UNIQUE
    unknown = [t for t in wanted if t not in targets.UNIQUE]
    if unknown:
        print(f"unknown targets: {unknown}", file=sys.stderr)
        return 2

    missing, extra = targets.verify_enum()
    if missing or extra:
        print(f"target list is stale: missing={missing} extra={extra}", file=sys.stderr)
        return 2

    out, failures = {}, []
    with ClientHelloSniffer() as sniffer:
        for t in wanted:
            try:
                out[t] = capture_one(t, sniffer, sni=sni)
                print(f"  {t:20s} ja4={out[t]['ja4']}")
            except Exception as e:
                failures.append((t, repr(e)))
                print(f"  {t:20s} FAILED {e!r}", file=sys.stderr)
            time.sleep(0.05)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"\ncaptured {len(out)}/{len(wanted)} → {os.path.normpath(out_path)}")
    if failures:
        print(f"FAILURES ({len(failures)}):", file=sys.stderr)
        for t, e in failures:
            print(f"  {t}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
