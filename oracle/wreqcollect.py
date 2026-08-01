"""采集第三个开源指纹表：wreq（Rust，0x676e67/wreq-util）的 134 个变体。

**为什么还要第三家**：前两家都落后于真机。wreq 明显更新，且补上了我们最大的
缺口——Edge：

    来源            Chrome   Firefox   Safari    Edge    Opera   合计
    curl_cffi 0.13   ≤136     ≤135      26.0     101      —       31
    tls-client 1.14  ≤146     ≤147      16.0     101      91      76
    wreq             ≤149     ≤151      26_4     148      131    134

Edge 在前两家都停在 2022 年的 101，wreq 直接到 148。另外它独有几个维度：
FirefoxPrivate（隐私模式）、FirefoxAndroid、SafariIpad。

**必须用独立 venv**：wreq 要求 Python >= 3.11，而主 venv 是系统 Python 3.9
（curl_cffi 在上面工作正常，不动它）。这里用 anaconda 的 3.12 建 .venv-wreq。
本模块因此要用 .venv-wreq/bin/python 跑，观测点那几个模块只用标准库，3.12 兼容。

跑：.venv-wreq/bin/python -m oracle.wreqcollect [变体名…]
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.sniffer import ClientHelloSniffer                 # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "spec", "golden", "wreq_nosni.json")


def all_variants():
    from wreq import Emulation

    return sorted(n for n in dir(Emulation) if not n.startswith("_"))


async def _fire(name, port):
    """wreq 的 Python 绑定是 **async** API —— client.get() 返回 Coroutine，
    不 await 的话请求压根不会发出，表现为观测点一直等不到 ClientHello。"""
    from datetime import timedelta

    import wreq
    from wreq import Emulation

    # timeout 必须是 timedelta，传 int 会 TypeError 且被外层 except 吞掉，
    # 表现为"观测点收不到 ClientHello"——与请求没发出无法区分。
    client = wreq.Client(emulation=getattr(Emulation, name), verify=False)
    try:
        try:
            await client.get(f"https://127.0.0.1:{port}/",
                             timeout=timedelta(seconds=5))
        except Exception:
            pass          # 观测点收完 ClientHello 就断，握手必然失败
    finally:
        try:
            client.close()
        except Exception:
            pass


def capture_one(name, sniffer):
    """打一次本地观测点。与其他采集器同条件：直连 IP、不发 SNI，两侧才可比。"""
    import asyncio

    asyncio.run(_fire(name, sniffer.port))
    return fingerprint(sniffer.pop(timeout=10))


def main(argv):
    wanted = argv[1:] or all_variants()
    out, failed = {}, []
    with ClientHelloSniffer() as sniffer:
        for name in wanted:
            try:
                out[name] = capture_one(name, sniffer)
                print(f"  {name:22s} ja4={out[name]['ja4']}")
            except Exception as e:
                failed.append((name, repr(e)))
                print(f"  {name:22s} FAILED {e!r}", file=sys.stderr)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"\n采到 {len(out)}/{len(wanted)} → {os.path.normpath(OUT)}")
    if failed:
        print(f"失败 {len(failed)}:", file=sys.stderr)
        for n, e in failed[:10]:
            print(f"  {n}: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
