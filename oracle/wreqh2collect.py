"""采 wreq 的 h2 层指纹（SETTINGS / WINDOW_UPDATE / 伪头顺序）。

**为什么只补 wreq、不补 utls**：utls 是纯 TLS 库，profile 里根本没有 h2 定义。
给它套一个 Go 的 http2 客户端能采到 SETTINGS，但那是 golang.org/x/net/http2 的
默认值 —— **是 Go 的指纹，不是该浏览器的**。把它当作 profile 的 h2 层入库会污染
数据，且这种污染很难事后发现（它看起来完全合理）。所以 utls 那批保持只有 TLS 层。

wreq 不同：它是完整 HTTP 栈，h2 SETTINGS 与伪头顺序都按 profile 定义，采到的是
真值。

须用 .venv-wreq/bin/python 跑（wreq 要求 Python ≥3.11）。

**当前不可用（已知问题）**：wreq 坚持校验服务端证书，试过
`verify=False` / `danger_accept_invalid_certs` / `cert_verification=False` /
`cert_store=CertStore.from_pem_stack(ca)` 均仍报 CERTIFICATE_VERIFY_FAILED
（前三个疑似被静默忽略，第四个构造成功但不生效）。L1 采集不受影响是因为
sniffer 不完成握手，L2 必须握手才暴露。

未继续深挖的原因：wreq 的 133 个变体按指纹去重后只贡献 5 个唯一指纹，为它们
补 h2 的收益小于继续摸索 API 的成本。代码逻辑本身是对的，等找到正确的信任
配置即可直接跑。
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

    client = wreq.Client(emulation=getattr(Emulation, name), verify=False)
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

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"\n采到 {len(out)}/{len(wanted)} → {os.path.normpath(OUT)}")
    if failed:
        for n, e in failed[:8]:
            print(f"  {n}: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
