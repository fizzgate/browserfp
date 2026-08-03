"""UA 字符串 → (品牌, 版本)：C 侧必须与 Python 侧逐字节一致。

**这一步此前只在 Python 里**，而"按用户自己的浏览器出指纹"必须在数据面做 ——
网关拿到的是 UA 字符串，不是 (品牌, 版本)。移植到 C 之后，判据是与 Python 的
全量差分：两边都是我们写的，但**规则的复杂度全在分支上**，差分能抓住移植时漏
掉的分支，而这正是移植最容易出错的地方。

第一次跑就抓到一条：Android 上的 UC Browser
`… Version/4.0 UCBrowser/13.4 Mobile Safari/537.36` —— 我的 C 版只检查"后面某处
出现 Safari"，于是把它判成 safari；而 Python 的规则要求 Safari 那个标记**紧跟**
在版本号之后（中间只允许 `Mobile/xxx `）。这条 UA 里没有 Chrome/，正确答案是
"认不出"。

两组语料，缺一不可：

    生产 UA        真实分布，但只覆盖常见形态（去重后 60 条）
    合成边界       逐条打每个分支 —— 没有它，"全一致"可能只是因为
                   所有样本都走了同一条分支

跑：python -m spec.test_ua_parse
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.uamap import parse_ua                              # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLI = os.path.join(ROOT, "csrc", "uastrcli")
FIXTURE = os.path.join(HERE, "fixtures", "prod_user_agents.json")

# 每条都标着它要打的分支 —— 加用例时先问"这一条打的是哪条分支"
SYNTHETIC = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
     "like Gecko) Chrome/151.0.0.0 Safari/537.36", "chrome 桌面"),
    ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, "
     "like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36", "chrome 移动"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
     "like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0", "edge 桌面"),
    ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/125.0.0.0 Mobile Safari/537.36 EdgA/125.0.0.0", "edge 安卓"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
     "like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/110.0.0.0",
     "opera —— 版本要取内核 125 而不是 OPR 的 110"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 "
     "Firefox/153.0", "firefox 桌面"),
    ("Mozilla/5.0 (Android 14; Mobile; rv:153.0) Gecko/153.0 Firefox/153.0",
     "firefox 安卓"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
     "(KHTML, like Gecko) Version/17.4 Safari/605.1.15", "safari 桌面"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
     "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 "
     "Safari/604.1", "safari iOS —— 中间夹着 Mobile/15E148"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
     "AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.0.0 Mobile/15E148 "
     "Safari/604.1", "iOS 上的 Chrome —— 壳不同但 TLS 栈是系统 WebKit"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) "
     "AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/120.0 Mobile/15E148 "
     "Safari/605.1.15", "iOS 上的 Firefox"),
    ("Mozilla/5.0 (Linux; U; Android 14; en-US; Redmi Note 13 Pro "
     "Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Version/4.0 UCBrowser/13.4.0.1306 Mobile Safari/537.36",
     "UC Browser —— 有 Version/ 与 Safari 但不是 Safari，且没有 Chrome/，"
     "正确答案是认不出（C 侧第一版就栽在这条）"),
    ("curl/8.4.0", "不是浏览器 —— 没有 Mozilla/ 前缀"),
    ("", "空串"),
    ("Mozilla/5.0", "只有前缀，什么标记都没有"),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/ Safari/537.36",
     "Chrome/ 后面没有数字"),
    ("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/999999999999 "
     "Safari/537.36", "版本号大到溢出 —— 不能崩，也不能绕回小数"),
]


def main():
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"make 失败：{(r.stderr or r.stdout)[-200:]}")
        return 1

    with open(FIXTURE) as f:
        prod = [row["ua"] for row in json.load(f)]
    synth = [ua for ua, _ in SYNTHETIC]
    why = {ua: note for ua, note in SYNTHETIC}
    uas = prod + synth

    out = subprocess.run([CLI], input="\n".join(uas) + "\n",
                         capture_output=True, text=True,
                         timeout=120).stdout.rstrip("\n").split("\n")
    if len(out) != len(uas):
        print(f"  ✗ C 侧回了 {len(out)} 行，喂进去 {len(uas)} 条")
        return 1

    bad, brands = [], {}
    for ua, line in zip(uas, out):
        pb, pv = parse_ua(ua)
        want = "-" if pb is None else f"{pb}\t{pv}"
        if line != want:
            note = why.get(ua, "生产 UA")
            bad.append(f"{note}\n        UA     {ua[:78]}\n"
                       f"        Python {want.replace(chr(9), ' / ')}\n"
                       f"        C      {line.replace(chr(9), ' / ')}")
        brands[pb] = brands.get(pb, 0) + 1

    # **必须真的打到每条分支**。全一致有可能只是因为样本都走了同一条路 ——
    # 这个仓里"断言打不到"已经栽过好几次。
    want_brands = {"chrome", "chrome-mobile", "edge", "edge-mobile", "opera",
                   "firefox", "firefox-mobile", "safari", "safari-mobile", None}
    missing = sorted(b for b in want_brands if b not in brands
                     for b in [b] if True)
    missing = [str(b) for b in want_brands if b not in brands]
    if missing:
        bad.append(f"语料没覆盖到这些结果：{missing} —— 那几条分支等于没验")

    print(f"  差分 {len(uas)} 条 UA（生产 {len(prod)} + 合成 {len(synth)}）")
    print(f"  覆盖到的结果：{', '.join(sorted(str(k) for k in brands))}")
    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'UA 解析两侧一致' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
