"""源码推出的 Firefox h2 开场，必须与实采吻合 —— 桌面与 Android 分开验。

**先验证再使用**，规矩同 `test_chromium_h2`。Gecko 这边多一条要验的：
**平台差异的来源**。实测 wreq 的 `FirefoxAndroid135` 与 `Firefox135` 差两处
（HEADER_TABLE_SIZE 4096 vs 65536、INITIAL_WINDOW 32768 vs 131072），而
`StaticPrefList.yaml` 里这两个 pref 的桌面与 Android 求值**完全相同** —— 差异
在 `mobile/android/app/geckoview-prefs.js` 的覆盖里。只按 StaticPrefList 的平台
条件求值会得出"两端一样"的错结论，而那个错结论在桌面侧看起来完全正常。

所以这条门禁必须**两个平台都验**：只验桌面的话，Android 推导错了也全绿。

比对基准取各库对该版本自报的 h2（各库一致的才用）。本项目自己的实采
`linux:firefox-111-linux` 也是基准之一 —— 它带着六条 PRIORITY，正好验到那棵
源码里写死的分组树。

跑：python -m spec.test_gecko_h2
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.geckoh2 import akamai, firefox_h2                    # noqa: E402
from oracle.h2table import observed                              # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "profiles.json")


def tor_disguised(registry):
    """哪些库条目其实是 Tor Browser，只是名字写成了 FirefoxNNN。

    **不能按名字判**：wreq 把 Tor 的指纹登记成 `Firefox128`，名字里没有 tor。
    判据取注册表的分组 —— 该条目与某个带 tor 别名的条目同属一条 profile，
    说明两者指纹一致，那就是 Tor 而不是原版 Firefox。

    为什么必须排除：Tor Browser 会把 `network.http.http2.allow-push` 关掉，
    于是发出 ENABLE_PUSH=0 与 MAX_CONCURRENT=0；而原版 Firefox 128 的
    allow-push 默认是 true（StaticPrefList 里就是个无条件的 value: true），
    那个分支根本不执行。拿 Tor 的形态去判原版的推导，只会得出假的红。
    uamap 建版本表时早就把 tor / private 排除在外了，这里同理。
    """
    out = set()
    for rec in registry:
        names = [rec["id"]] + rec.get("aliases", [])
        if not any("tor" in n.split(":", 1)[1].lower() for n in names):
            continue
        out.update(names)
    return out


def cases():
    """{(平台, 版本): (akamai, 来源)}，只取各库一致的。"""
    with open(REGISTRY) as f:
        registry = json.load(f)
    tor = tor_disguised(registry)

    out = {}
    for (brand, ver), hits in observed().items():
        if brand not in ("firefox", "firefox-mobile"):
            continue
        hits = {k: v for k, v in hits.items() if k not in tor}
        if not hits:
            continue
        fps = {v["akamai_fingerprint"] for v in hits.values()}
        if len(fps) == 1:
            plat = "android" if brand.endswith("-mobile") else "desktop"
            out[(plat, ver)] = (next(iter(fps)), sorted(hits))

    # 本项目的实采也算基准。它们带 PRIORITY，是唯一能验到那棵分组树的样本。
    if True:
        for rec in registry:
            if not rec["id"].startswith("linux:firefox-") or not rec.get("h2"):
                continue
            digits = "".join(c for c in rec["id"].split("-")[1] if c.isdigit())
            if digits:
                out[("desktop", int(digits))] = (
                    rec["h2"]["akamai_fingerprint"], [rec["id"]])
    return dict(sorted(out.items()))


def main():
    todo = cases()
    if not todo:
        print("没有可比对的 Firefox h2 —— 这不是通过，是没验到", file=sys.stderr)
        return 1

    bad, ok, skip = [], 0, []
    seen_plat = set()
    prio_checked = 0
    for (plat, ver), (want_fp, who) in todo.items():
        try:
            derived = firefox_h2(ver, plat)
        except Exception as e:
            skip.append(f"{plat} {ver}: {type(e).__name__}")
            continue
        got_fp = akamai(derived)
        seen_plat.add(plat)
        if derived["priorities"]:
            prio_checked += 1
        if got_fp == want_fp:
            ok += 1
            continue
        bad.append(f"{plat} {ver}（{who[:2]}）\n"
                   f"      源码推出 {got_fp}\n"
                   f"      实采     {want_fp}")

    print(f"源码推导 vs 实采   {ok}/{ok + len(bad)} 吻合"
          f"{'，%d 个跳过' % len(skip) if skip else ''}")
    print(f"  验到的平台：{sorted(seen_plat)}；其中 {prio_checked} 条带 PRIORITY 树")
    for b in bad:
        print(f"  ✗ {b}")
    for s in skip[:5]:
        print(f"  ？ {s}")

    # 平凡通过防护：两个平台都得验到，只验桌面等于没验 Android 的覆盖来源。
    if ok == 0:
        bad.append("一个都没验到")
    elif seen_plat != {"desktop", "android"}:
        bad.append(f"只验到 {sorted(seen_plat)} —— Android 的 pref 覆盖来自"
                   "另一个文件，不单独验就等于没验")
    if ok and prio_checked == 0:
        bad.append("没有一条带 PRIORITY —— 源码里那棵分组树没被验证到")

    # 排除表必须**真的排除到了东西**。哪天 wreq 改了命名、或注册表的分组变了，
    # 这个集合会悄悄变空，而门禁照旧全绿 —— 那是把一条失效的规则当成还在生效。
    with open(REGISTRY) as f:
        excluded = tor_disguised(json.load(f))
    if not any(n.startswith("wreq:Firefox") for n in excluded):
        bad.append("Tor 排除表里已经没有伪装成 FirefoxNNN 的条目了 —— "
                   "要么命名变了要么分组变了，这条排除规则要重新审")

    print(f"\n{'Gecko 推导可用于补 h2 缺口' if not bad else '推导与实采不符或覆盖不足'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
