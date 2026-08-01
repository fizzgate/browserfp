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

from oracle.covscan import TARGETS, h2scan, scan                       # noqa: E402
from oracle.uamap import UAMapper                              # noqa: E402

# 当前水位：每个品牌允许的最大缺漏版本数。
# 降下来后手动改小，这样"覆盖变好"是一次显式的决定而不是自动漂移。
BASELINE = {
    "chrome": 0,             # 已全覆盖
    "chrome-mobile": 0,      # 已全覆盖
    "firefox": 0,            # 已全覆盖（78/83/111/121 四份 Linux 容器实采作锚）
    "firefox-mobile": 0,     # 同上（桌面等价回落 + 145-153 派生）
    "safari": 3,             # 12-14 —— 闭源无段表，桌面侧无数据
    "safari-mobile": 0,      # 已全覆盖
}

# h2 层的水位，单独一张表。**不能并进上面那张**：TLS 覆盖 99.5% 而 h2 只有
# 67.7%，合并成一个数字会把后者藏起来 —— 而"TLS 像 Chrome、h2 不像任何浏览器"
# 恰恰是最容易被判的组合。
#
# 缺口几乎全部来自只建模 TLS 的来源库（utls 全系没有 h2），chrome 70-98 大量
# 落在那些条目上。补法只有两条：真机采（oracle/h2probe.py 那套）或读 Chromium
# 的 h2 源码 —— 不能借隔壁 profile 的 h2 顶上，那是把两个浏览器拼在一起。
H2_BASELINE = {
    # Chromium 全家已 100%（源码推导 + 跨平台归一，见 oracle/h2table.py）
    "chrome": 0, "chrome-mobile": 0,
    "edge": 0, "edge-mobile": 0,
    "opera": 0, "opera-mobile": 0,
    # Gecko 也全覆盖了（oracle/geckoh2.py），含 78-99 那段 —— 那时 pref 还在
    # all.js 里叫 network.http.spdy.*。只剩 Safari：闭源，只能靠库与实采。
    "firefox": 0, "firefox-mobile": 0,
    # 只剩 safari 12-14 —— 与 TLS 层的缺口是同一批，已证无路径（见 README）
    "safari": 3, "safari-mobile": 3,
}


def check_scan_range(mapper):
    """扫描上限不得低于库里已有的最大版本号。

    **这是个结构性盲区，不是数据问题**：TARGETS 的上下界是写死的，谁往库里
    补一条 chrome 155 的 profile，扫描器仍然只扫到 153 —— 那条数据既不被
    覆盖度统计，也不进三方一致性的比对集，等于加了个没人看的东西。上一轮
    Edge/Opera 的教训就是"扫描器漏掉一个轴，那个轴上的缺陷就不存在"，
    版本上限是同一类盲区的时间维度。

    段表同理：段的上界超出扫描范围，说明源码已经推进到更新的版本了。
    """
    bad = []
    for brand, (_tpl, _lo, hi) in TARGETS.items():
        vt = max(mapper.by_brand.get(brand, {}) or [0])
        sg = max((s["to"] for s in mapper.segments.get(brand, [])), default=0)
        top = max(vt, sg)
        if top > hi:
            bad.append(f"{brand}: 扫描上限 {hi}，但库里已有 {top} "
                       f"（版本表 {vt} / 段表 {sg}）—— 超出的版本没人扫")
    return bad


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

    h2_worse, h2_total = [], 0
    print(f"\n{'品牌':16s} {'缺 h2':>6} {'水位':>6}")
    for brand in TARGETS:
        n = len(h2scan(brand, mapper))
        h2_total += n
        limit = H2_BASELINE.get(brand, 0)
        mark = "  ✗ 变差" if n > limit else ("  ↓ 可收紧水位" if n < limit else "")
        if n > limit:
            h2_worse.append((brand, n, limit))
        print(f"{brand:16s} {n:>6} {limit:>6}{mark}")
    print(f"\nh2 层缺口合计 {h2_total} 个版本（水位合计 {sum(H2_BASELINE.values())}）")
    for brand, n, limit in h2_worse:
        print(f"\n✗ {brand} 的 h2 缺口 {n} 超过水位 {limit} —— "
              "要么补 h2 数据，要么查清是不是映射改动把版本挪到了无 h2 的条目上。")

    rng = check_scan_range(mapper)
    print(f"\n扫描范围覆盖已有数据  {'OK' if not rng else '失败'}")
    for b in rng:
        print(f"  ✗ {b}")

    failed = worse or rng or h2_worse
    print(f"\n{'覆盖未倒退' if not failed else '覆盖或扫描范围有问题'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
