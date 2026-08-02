"""`sec-ch-ua-platform` / `-mobile` 必须与 UA 里声明的系统一致。

真浏览器这两处同源：UA 字符串与 UA-CH 都由同一个平台判定生成。伪装时最容易的
出错方式是一处照抄 UA、另一处硬编码 —— UA 说 Windows 而 platform 说 macOS，
是不用任何统计就能抓的交叉矛盾。

三件事：

  1. **与本机实采一致**。macOS 上的 Chrome 实采是 `"macOS"` / `?0`，拿它的
     UA 推一遍必须得到同一对值。
  2. **平台串仍在源码里**。串是写死在 `GetPlatformForUAMetadata` 的
     （`"macOS"`、`"Android"`…），源码里有 TODO 说想改名 —— 改了就该红，
     而不是继续发一个已经不存在的值。
  3. **iOS 整族返回"没有"**。iOS 的 UA 里写着 "like Mac OS X"，不先拦下来会
     给 iPhone 推出 `"macOS"`；而 iOS 上所有浏览器都是 WebKit、根本不发
     UA-CH。这条单独断言，因为它是靠匹配顺序保证的，很容易在加新规则时被
     不小心破坏。

跑：python -m spec.test_uach_platform
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.covscan import TARGETS                               # noqa: E402
from oracle.uach import (_src, assert_platform_strings,          # noqa: E402
                         platform_hint)

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.path.join(HERE, "golden", "headers_real.json")


def main():
    bad = []

    # 1) 与本机实采一致
    with open(REAL) as f:
        real = json.load(f)
    checked = 0
    for name in ("chrome", "chromium", "edge"):
        rec = real.get(name)
        if not rec:
            continue
        h = dict(rec["headers"])
        want = (h.get("sec-ch-ua-platform"), h.get("sec-ch-ua-mobile"))
        got = platform_hint(h["user-agent"])
        checked += 1
        if got != want:
            bad.append(f"{name}: 推出 {got}，实采 {want}")
    print(f"与本机实采一致   {checked - len([b for b in bad])}/{checked}")
    if checked == 0:
        bad.append("一条实采都没比到 —— 这不是通过")

    # 2) 平台串仍在源码里
    try:
        assert_platform_strings(_src(151))
        print("平台串仍在源码里   OK")
    except Exception as e:
        bad.append(f"平台串校验失败：{e}")

    # 3) 各品牌的推导结果，且 iOS 族必须是"没有"
    print("\n按 covscan 的 UA 模板推导：")
    for brand in sorted(TARGETS):
        ver = 26 if brand.startswith("safari") else 151
        ua = TARGETS[brand][0].format(v=ver)
        got = platform_hint(ua)
        print(f"  {brand:16s} {got}")
        if brand == "safari-mobile" and got != (None, None):
            bad.append(f"safari-mobile 推出了 {got} —— iOS 整族不发 UA-CH，"
                       "而它的 UA 里写着 like Mac OS X，匹配顺序被破坏了")
        if brand == "chrome-mobile" and got != ('"Android"', "?1"):
            bad.append(f"chrome-mobile 推出 {got} —— Android 的 UA 里也有 "
                       "Linux，Android 规则必须排在 Linux 前")

    # C 与 Python 用的是两张独立的表（一张在 uach.py、一张在 tlsfp.c），
    # 顺序又是关键 —— 不逐条比的话，两边顺序漂了照样各自绿。
    import subprocess
    exe = os.path.join(os.path.dirname(HERE), "csrc", "platcli")
    r = subprocess.run(["make", "-s"], cwd=os.path.join(os.path.dirname(HERE), "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0 or not os.path.exists(exe):
        bad.append(f"C 侧没构建出来：{(r.stderr or r.stdout)[-120:]}")
    else:
        uas = [TARGETS[b][0].format(v=26 if b.startswith("safari") else 151)
               for b in sorted(TARGETS)]
        out = subprocess.run([exe], input="\n".join(uas), capture_output=True,
                             text=True, timeout=60).stdout.splitlines()
        diff = 0
        for ua, line in zip(uas, out):
            got = tuple(line.split("\t"))
            want = platform_hint(ua)
            want = ("-", "-") if want == (None, None) else want
            if got != want:
                diff += 1
        print(f"\nC/Python 一致   {len(uas) - diff}/{len(uas)}")
        if diff:
            bad.append(f"C 与 Python 的平台推导差 {diff} 条")

    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'平台提示与 UA 同源' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
