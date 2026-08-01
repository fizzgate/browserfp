"""识别器门禁：能认出该认的，且**认不出的必须报 unknown**。

正向通过很容易（把注册表喂回去必然命中），真正要防的是反向失效：识别器把陌生
指纹硬套到最近的已知 profile。那种失效不会报错，只会让盲区永远不可见——比认不
出更糟。所以本文件的重点是阴性对照。

跑：python -m spec.test_match
"""

import copy
import json
import os
import subprocess
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.match import Matcher                              # noqa: E402
from oracle.tapproxy import TapProxy                          # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HRRSERVER = os.path.join(ROOT, "oracle", "gotls", "hrrserver", "hrrserver")
CERT = os.path.join(HERE, "certs", "fullchain.pem")
KEY = os.path.join(HERE, "certs", "key.pem")


def t_self_identify(m):
    """注册表每条都应被自己精确命中。"""
    bad = [r["id"] for r in m.registry
           if m.identify(r["tls"])["confidence"] != "exact"]
    return not bad, f"{len(m.registry) - len(bad)}/{len(m.registry)} exact" + (
        f"，失败 {bad[:3]}" if bad else "")


def _find(m, alias):
    """按 id 或 aliases 找记录。

    注册表按指纹去重，保留下来的 id 可能是任意一个别名——只查 id 会对
    chrome136 这类被合并掉的名字 StopIteration。同一个坑在
    test_cf_discrimination 已经踩过一次，这是第二次。
    """
    for rec in m.registry:
        if rec["id"] == alias or alias in rec.get("aliases", []):
            return rec
    raise KeyError(f"{alias} 不在注册表（含 aliases）")


def t_mutations_are_unknown(m):
    """改动任一判据字段后必须判 unknown —— 不许硬套最近的。"""
    base = _find(m, "curl_cffi:chrome136")
    cases = {
        "sig_algs 增一项": lambda f: f["sig_algs"].append(0x0999),
        "ciphers 删一项": lambda f: f["ciphers"].pop(),
        "curves 改首项": lambda f: f["curves"].__setitem__(0, 0x1234),
        "扩展增一个": lambda f: f["extensions_ordered"].append(0x0039),
        "alpn 改": lambda f: f.__setitem__("alpn", ["http/1.1"]),
    }
    bad = []
    for label, mutate in cases.items():
        fp = copy.deepcopy(base["tls"])
        mutate(fp)
        r = m.identify(fp)
        if r["confidence"] != "unknown":
            bad.append(f"{label}→{r['confidence']}({r.get('match')})")
    return not bad, (f"{len(cases) - len(bad)}/{len(cases)} 变异被判 unknown"
                     + (f"；漏判 {bad}" if bad else ""))


def t_padding_tolerated(m):
    """同一指纹去掉 padding 后应仍能识别（HRR 前后的真实差异）。"""
    withpad = [r for r in m.registry
               if 0x15 in (r["tls"].get("extensions_ordered") or [])]
    if not withpad:
        return False, "注册表里没有含 padding 的 profile，无法验证"
    bad = []
    for rec in withpad:
        fp = copy.deepcopy(rec["tls"])
        fp["extensions_ordered"] = [e for e in fp["extensions_ordered"] if e != 0x15]
        r = m.identify(fp)
        if r["confidence"] not in ("exact", "exact-no-pad"):
            bad.append(rec["id"])
    return not bad, (f"{len(withpad) - len(bad)}/{len(withpad)} 去 padding 后仍识别"
                     + (f"；失败 {bad[:3]}" if bad else ""))


def t_real_hrr_identified(m):
    """端到端：真触发一次 HelloRetryRequest，第二个 ClientHello 必须能识别。"""
    if not os.path.exists(HRRSERVER):
        return False, "缺 hrrserver，先 go build -o hrrserver/hrrserver ./hrrserver"
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv = subprocess.Popen(
        [HRRSERVER, "-addr", f"127.0.0.1:{port}", "-cert", CERT, "-key", KEY,
         "-curve", "P384"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    try:
        from curl_cffi import requests

        results = []
        for target in ("chrome136", "safari184"):
            with TapProxy("127.0.0.1", port) as tap:
                try:
                    requests.get(f"https://127.0.0.1:{tap.port}/",
                                 impersonate=target, verify=False, timeout=15)
                except Exception:
                    pass
                hellos = []
                while True:
                    try:
                        hellos.append(tap.pop(timeout=3))
                    except Exception:
                        break
            if len(hellos) < 2:
                results.append(f"{target}:未触发HRR")
                continue
            r = m.identify(fingerprint(hellos[1]))
            results.append(f"{target}:{r['confidence']}")
        bad = [x for x in results if "unknown" in x or "未触发" in x]
        return not bad, "  ".join(results)
    finally:
        srv.terminate()


def main():
    m = Matcher()
    tests = [
        ("自识别", t_self_identify),
        ("变异必须 unknown（阴性对照）", t_mutations_are_unknown),
        ("容忍 padding", t_padding_tolerated),
        ("真实 HRR 端到端", t_real_hrr_identified),
    ]
    failed = 0
    for name, fn in tests:
        try:
            ok, detail = fn(m)
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        print(f"  {'✅' if ok else '❌'} {name:28s} {detail}")
        failed += 0 if ok else 1
    print(f"\n{len(tests) - failed}/{len(tests)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
