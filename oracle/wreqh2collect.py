"""采 wreq 的 h2 层指纹（SETTINGS / WINDOW_UPDATE / 伪头顺序）。

**为什么只补 wreq、不补 utls**：utls 是纯 TLS 库，profile 里根本没有 h2 定义。
给它套一个 Go 的 http2 客户端能采到 SETTINGS，但那是 golang.org/x/net/http2 的
默认值 —— **是 Go 的指纹，不是该浏览器的**。把它当作 profile 的 h2 层入库会污染
数据，且这种污染很难事后发现（它看起来完全合理）。所以 utls 那批保持只有 TLS 层。

wreq 不同：它是完整 HTTP 栈，h2 SETTINGS 与伪头顺序都按 profile 定义，采到的是
真值。

须用 .venv-wreq/bin/python 跑（wreq 要求 Python ≥3.11）。

跳过证书校验的参数是 **`tls_verify=False`**。曾试 `verify` /
`danger_accept_invalid_certs` / `cert_verification` 均无效——构造不报错但被
静默忽略，仍报 CERTIFICATE_VERIFY_FAILED，很容易误判成"库不支持"。正确名字
在包内 `grep -E 'tls_[a-z_]*\s*[:=]'` 可查到。
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.goldenio import write_golden              # noqa: E402
from oracle.h2probe import H2Probe                            # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "spec", "golden", "h2_wreq.json")


def all_variants():
    from wreq import Emulation

    return sorted(n for n in dir(Emulation) if not n.startswith("_") and n != "random")


async def _fire(name, port):
    from datetime import timedelta

    import wreq
    from wreq import Emulation

    # 参数名是 tls_verify —— verify / danger_accept_invalid_certs /
    # cert_verification 都会被静默忽略（构造不报错但仍校验证书）
    client = wreq.Client(emulation=getattr(Emulation, name), tls_verify=False)
    try:
        try:
            await client.get(f"https://127.0.0.1:{port}/",
                             timeout=timedelta(seconds=8))
        except Exception:
            pass          # 观测点收到首个 HEADERS 就断，报错是预期的
    finally:
        try:
            client.close()
        except Exception:
            pass


def capture_one(name, probe):
    import asyncio

    asyncio.run(_fire(name, probe.port))
    return probe.pop(timeout=20)


def main(argv):
    wanted = argv[1:] or all_variants()
    out, failed = {}, []
    for name in wanted:
        with H2Probe() as probe:
            try:
                out[name] = capture_one(name, probe)
                print(f"  {name:22s} {out[name]['akamai_fingerprint']}")
            except Exception as e:
                failed.append((name, repr(e)))
                print(f"  {name:22s} FAILED {e!r}", file=sys.stderr)

    total, _ = write_golden(OUT, out)
    print(f"\n采到 {len(out)}/{len(wanted)} → {os.path.normpath(OUT)}")
    if failed:
        for n, e in failed[:8]:
            print(f"  {n}: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
