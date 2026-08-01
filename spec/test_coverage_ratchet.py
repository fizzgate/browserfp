"""覆盖棘轮：全版本缺漏数只许降不许升。

**为什么需要棘轮而不是固定阈值**：缺漏数会随两件事变化 —— 补进新 golden 会降、
新版本发布会升。固定阈值要么松到失效，要么每次都得手改。棘轮记住当前水位，
只在**变差**时报警。

**为什么不能只看生产 UA 的覆盖率**：`spec/fixtures/prod_user_agents.json` 只有
60 种 UA，那个口径下 fallback 早就是 0，改坏了映射也看不出来。全版本扫描才
覆盖得到真实的版本分布。

水位存在本文件的 BASELINE 里，降下来之后要手动改小 —— 这一步刻意不自动化：
自动收紧会把"某次意外变好"固化成新基线，而那次变好可能是判据放宽导致的。

跑：python -m spec.test_coverage_ratchet
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.covscan import TARGETS, scan                       # noqa: E402
from oracle.uamap import UAMapper                              # noqa: E402

# 当前水位：每个品牌允许的最大缺漏版本数。
# 降下来后手动改小，这样"覆盖变好"是一次显式的决定而不是自动漂移。
BASELINE = {
    "chrome": 1,             # 71 —— 2018 年版本，段内无实采 golden 且二进制源不可达
    "chrome-mobile": 1,      # 同上（153 已由 Chrome for Testing 实采补上）
    "firefox": 0,            # 已全覆盖（78/83/111/121 四份 Linux 容器实采作锚）
    "firefox-mobile": 0,     # 同上（桌面等价回落 + 145-153 派生）
    "safari": 3,             # 12-14 —— 闭源无段表，桌面侧无数据
    "safari-mobile": 0,      # 已全覆盖
}


def main():
    mapper = UAMapper()
    worse, better, total = [], [], 0

    print(f"{'品牌':16s} {'缺漏':>6} {'水位':>6}")
    for brand in TARGETS:
        missing, lo, hi = scan(brand, mapper)
        n = len(missing)
        total += n
        limit = BASELINE.get(brand, 0)
        mark = ""
        if n > limit:
            worse.append((brand, n, limit, missing))
            mark = "  ✗ 变差"
        elif n < limit:
            better.append((brand, n, limit))
            mark = "  ↓ 可收紧水位"
        print(f"{brand:16s} {n:>6} {limit:>6}{mark}")

    print(f"\n合计缺漏 {total} 个版本（水位合计 {sum(BASELINE.values())}）")

    for brand, n, limit, missing in worse:
        print(f"\n✗ {brand} 缺漏 {n} 个，超过水位 {limit}：{missing}")
        print("   覆盖倒退了。要么补上缺的版本，要么先查清是不是判据被改松/改错。")
    for brand, n, limit in better:
        print(f"\n↓ {brand} 缺漏降到 {n}（水位 {limit}），"
              "确认是真的补上了而非判据放宽后，把 BASELINE 改成新值。")

    print(f"\n{'覆盖未倒退' if not worse else f'{len(worse)} 个品牌覆盖倒退'}")
    return 1 if worse else 0


if __name__ == "__main__":
    raise SystemExit(main())
