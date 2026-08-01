"""识别稳定性门禁：真机浏览器反复连接，每一次都必须被认出。

**为什么单独验这个**：注册表里每个 profile 是**某一次**握手的快照，而真实浏览器
每次握手都不同——GREASE 值每连接随机、Chromium 自 110 起打乱扩展顺序
（RFC 8701 permutation）、padding 随 ClientHello 总长度浮动。如果识别器只在
"采集时那一次"能命中，实战就是废的，而 test_match 用注册表自己喂自己，永远发现
不了这个问题。

判定两条，缺一不可：
  1. 每次连接都命中 exact / exact-no-pad —— 出现 unknown 即不稳定
  2. **Chromium 系必须确实发生了变化**（扩展顺序取值数 > 1）—— 否则这次"稳定"
     是平凡的：若 headless 下根本不乱序，等于在无变化场景里验稳定性，什么也没证明

实测 Chrome 5 次采样：扩展顺序 5 个不同取值、GREASE 10 种、ClientHello 长度 4 种
（1707/1739/1771/1803）。Firefox 则不乱序也不发 GREASE，其"稳定"属平凡通过，
故充分性只对 Chromium 系断言。

跑：python -m spec.test_real_stability [每个浏览器的连接次数]
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.browsers import discover                          # noqa: E402
from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.h2collect import make_firefox_profile             # noqa: E402
from oracle.match import Matcher                              # noqa: E402
from oracle.sniffer import ClientHelloSniffer                 # noqa: E402

ROUNDS = 5


def _launch(engine, binary, url):
    if engine == "firefox":
        profile = make_firefox_profile()
        cmd = [binary, "--headless", "--no-remote", "--profile", profile, url]
    elif engine == "chromium":
        profile = tempfile.mkdtemp(prefix="fizztls-stab-")
        cmd = [binary, "--headless=new", f"--user-data-dir={profile}",
               "--no-first-run", "--disable-gpu", url]
    else:
        return None, None
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL), profile


def probe_once(engine, binary, matcher):
    """起一次浏览器，取它发的第一个 ClientHello 并识别。"""
    with ClientHelloSniffer() as sniffer:
        proc, profile = _launch(engine, binary,
                                f"https://127.0.0.1:{sniffer.port}/")
        if proc is None:
            raise RuntimeError(f"engine {engine} 不支持无头启动")
        try:
            fp = fingerprint(sniffer.pop(timeout=30))
            return matcher.identify(fp), fp
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            shutil.rmtree(profile, ignore_errors=True)


def main(argv):
    rounds = int(argv[1]) if len(argv) > 1 else ROUNDS
    matcher = Matcher()
    browsers = [(n, e, b, v) for n, e, b, v in discover()
                if e in ("chromium", "firefox")]

    print(f"每个浏览器连接 {rounds} 次\n")
    failures = []
    for name, engine, binary, version in browsers:
        results, ja4s, orders = [], set(), set()
        for _ in range(rounds):
            try:
                r, fp = probe_once(engine, binary, matcher)
                results.append(r["confidence"])
                ja4s.add(fp["ja4"])
                orders.add(tuple(fp["raw_extensions"]))
            except Exception as e:
                results.append(f"ERR:{type(e).__name__}")
            time.sleep(0.3)
        bad = [c for c in results if c not in ("exact", "exact-no-pad")]
        # 充分性：Chromium 系应每次乱序，取值数恒为 1 说明这次验证没覆盖到变化
        weak = engine == "chromium" and len(orders) <= 1 and len(results) > 1
        if bad or weak:
            failures.append((name, results, "识别不稳定" if bad else "验证不充分：扩展顺序未变化"))
        mark = "✅" if not (bad or weak) else "❌"
        print(f"  {mark} {name:10s} {version:20s} {'/'.join(results)}"
              f"   JA4={len(ja4s)} 扩展序={len(orders)}")

    print(f"\n{len(browsers) - len(failures)}/{len(browsers)} 个浏览器识别稳定且验证充分")
    for name, results, why in failures:
        print(f"  ✗ {name}: {why} — {results}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
