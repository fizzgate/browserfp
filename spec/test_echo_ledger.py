"""台账：每一种能发出的字节形态，是不是都被第三方确认过、且没有过期。

第三方回显那条门禁要联网、要对公开服务节流，跑一次十几分钟，所以它只在手工加
`LIVE=1` 时才跑。**于是"全部指纹都被对端确认过"这个结论没有任何常驻门禁看着**
—— 它可以静静地烂掉：新增一条 profile 谁也不会注意到它从没被外部验过；改了
h2 表让某个组合的指纹变了，台账里那条旧记录还挂着，看上去仍然"已确认"。

本门禁离线跑，只查台账与当前用例集对不对得上：

    有用例没记录      这种字节从来没有任何外部判据 —— 最要紧的一条
    有记录没用例      profile 改名/删除后的残留，会把"全部已确认"撑虚
    记录过期          超过 STALE_DAYS 天没复验，浏览器与回显服务都在变

台账由 spec/tlsfp_echo_it.sh（网关那侧）在验过之后写入，**只记这一轮全对的**。

跑：python -m spec.test_echo_ledger
"""

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.echocases import (LEDGER, cases, key_of,          # noqa: E402
                              load_ledger)

# 多久算过期。取值要能容忍"一阵子没跑联网门禁"，又不能长到让结论失去意义。
STALE_DAYS = 90


def main():
    cs = cases()
    led = load_ledger()
    keys = {key_of(c) for c in cs}
    by_key = {key_of(c): c for c in cs}

    bad = []

    missing = sorted(keys - set(led))
    for k in missing:
        c = by_key[k]
        bad.append(f"{c['brand']} {c['version']}（{c['pid']}）从未被第三方确认过 —— "
                   "这种字节没有任何外部判据。跑 LIVE=1 bash spec/tlsfp_echo_it.sh")

    orphan = sorted(set(led) - keys)
    for k in orphan:
        bad.append(f"台账里的 {k} 已经不在用例集里 —— profile 改名或删掉之后的"
                   "残留，留着会把「全部已确认」撑虚")

    today = datetime.date.today()
    stale = []
    for k in sorted(keys & set(led)):
        try:
            d = datetime.date.fromisoformat(str(led[k]))
        except ValueError:
            bad.append(f"台账里 {k} 的日期读不出来：{led[k]!r}")
            continue
        age = (today - d).days
        if age > STALE_DAYS:
            stale.append((k, age))
    for k, age in stale:
        c = by_key[k]
        bad.append(f"{c['brand']} {c['version']} 已经 {age} 天没复验（上限 "
                   f"{STALE_DAYS} 天）—— 浏览器与回显服务都在变，旧结论不作数")

    # 防平凡通过：用例集读空时"0 缺 0 残留"看着是绿的
    if len(cs) < 30:
        bad.append(f"用例集只有 {len(cs)} 条，远少于预期（44）—— "
                   "注册表或 h2 表是不是读空了？")
    if len(keys) != len(cs):
        bad.append(f"{len(cs)} 条用例只有 {len(keys)} 个不同的键 —— 去重口径与"
                   "台账键不一致，两个数会永远对不上")

    print(f"  用例 {len(cs)} 种字节形态，台账 {len(led)} 条")
    print(f"  从未确认 {len(missing)}，残留 {len(orphan)}，"
          f"超过 {STALE_DAYS} 天没复验 {len(stale)}")
    if not bad and cs:
        oldest = min(led[key_of(c)] for c in cs)
        print(f"  最旧的一条确认于 {oldest}")

    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'台账与用例集一致且未过期' if not bad else f'{len(bad)} 处问题'}")
    print(f"  （台账文件 {os.path.relpath(LEDGER, os.path.dirname(LEDGER))}）")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
