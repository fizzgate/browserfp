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

from oracle.covscan import TARGETS, h2scan, quic_coverage, scan                       # noqa: E402
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


# QUIC / h3 的水位，按**引擎**记 —— 这两层没有版本表。
# 与上面两张表一样是"只许升不许降"：这一层此前完全不在覆盖度报告里，
# 而没有覆盖度的层等于隐形，悄悄退化也看不出来。
# webkit（Safari）不在其中，理由见下面的 WONT_DO。
QUIC_ENGINES = {"quic": {"chromium", "gecko"}, "h3": {"chromium", "gecko"}}


# **已确认无路径的缺口**，与"还没做"分开记。
#
# 不区分这两者的代价是具体的：一条"待补"会让后来人（包括我自己）反复去试同一条
# 死路。本表要求写清**试过什么、观测到什么**，不接受"做不了"这种没有观测支撑的
# 说法；哪天条件变了（新的库、新的采集手段），删掉对应条目即可。
WONT_DO = {
    ("tls", "safari"): (3,
        "safari 12-14：coreTLS 闭源、无公开段表；三家库都没建模过这三个版本；"
        "真机侧拿不到那么旧的 Safari（系统绑定，无独立安装包）"),
    ("h2", "safari"): (3, "同上，与 TLS 层是同一批版本"),
    ("h2", "safari-mobile"): (3, "同上"),
    ("h3", "webkit"): (0,
        "iOS Safari **根本不发起 QUIC**。最初的理由是'自签 CA 要改系统信任'，"
        "后来这条理由消失了（simctl keychain add-root-cert 只影响模拟器）；"
        "装好 CA 后实测：Alt-Svc 送达、页面被加载 47 次、UDP 数据报 0 个。"
        "又试了把 HTTP3Enabled / WebKitHTTP3Enabled / WebKitExperimentalHTTP3Enabled "
        "写进 com.apple.mobilesafari 与 com.apple.WebKit.WebContent 并重启，仍是 0。"
        "换宿主局域网 IP（非回环）另签证书也是 0，'不对 loopback 走 QUIC'被证伪。"
        "让它访问 Cloudflare 的 trace 端点，自报 http=http/2 —— 对任何站点都不用 h3"),
}


def check_wont_do():
    """WONT_DO 里记的缺口数必须与棘轮水位对得上。

    两张表分头维护就会漂：棘轮降了而 WONT_DO 还写着"无路径"，或者反过来。
    对不上时报错，逼一次显式的决定。
    """
    bad = []
    for (layer, brand), (n, _why) in WONT_DO.items():
        table = {"tls": BASELINE, "h2": H2_BASELINE}.get(layer)
        if table is None:
            continue
        if table.get(brand) != n:
            bad.append(f"WONT_DO 说 {layer}/{brand} 有 {n} 个无路径缺口，"
                       f"而棘轮水位是 {table.get(brand)} —— 两张表漂了")
    return bad


def check_quic():
    cov = quic_coverage()
    bad = []
    for layer, want in QUIC_ENGINES.items():
        got = set(cov.get(layer) or {})
        missing = want - got
        if missing:
            bad.append(f"{layer} 少了引擎 {sorted(missing)}（现有 {sorted(got)}）"
                       " —— 覆盖倒退了")
        extra = got - want
        if extra:
            bad.append(f"{layer} 多出引擎 {sorted(extra)} —— 覆盖变好了，"
                       "确认是真采到而非归类错误后，把 QUIC_ENGINES 改大")
    return cov, bad


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

    cov, quic_bad = check_quic()
    print(f"\nQUIC/h3 按引擎")
    for layer in ("quic", "h3"):
        got = cov.get(layer) or {}
        print(f"  {layer:5s} " + ("  ".join(f"{e}:{','.join(v)}"
                                            for e, v in sorted(got.items()))
                                  or "（空）"))
    for b in quic_bad:
        print(f"  ✗ {b}")

    wd = check_wont_do()
    print(f"\n已确认无路径（不再投入）")
    for (layer, brand), (n, why) in sorted(WONT_DO.items()):
        print(f"  {layer:4s} {brand:14s} {n} 个   {why[:58]}…")
    for b in wd:
        print(f"  ✗ {b}")

    rng = check_scan_range(mapper)
    print(f"\n扫描范围覆盖已有数据  {'OK' if not rng else '失败'}")
    for b in rng:
        print(f"  ✗ {b}")

    failed = worse or rng or h2_worse or quic_bad or wd
    print(f"\n{'覆盖未倒退' if not failed else '覆盖或扫描范围有问题'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
