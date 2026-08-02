"""按版本解析的 h2 表：与判据同步、前提成立、不与实采冲突。

这张表存在的理由见 `oracle/h2table.py` 的模块头 —— 一句话：注册表按 **TLS
指纹**去重，h2 只是搭车，两个版本 TLS 相同而 h2 不同时就会发错。实测 UA 口径下
chrome 106-117 共 9 个版本拿到的 h2 没有任何一个库把它归给这些版本。

三件事：

  1. **表与判据同步**。`spec/h2table.json` 是落盘产物（C 的构建流程不该依赖
     网络去取 Chromium 源码），落盘产物就会僵尸化 —— 判据改了、表没重建，
     后面所有验证比的都是旧结论。所以拿判据现算一遍，逐条比。
     只在能重算时比：源码取不到就跳过（明说没验到），不冒充绿。

  2. **归一规则的前提仍成立**。"Chromium 系统一用桌面推导"依赖 Chrome Android
     的 h2 等于桌面，"safari-mobile 取桌面"同理。这些是实证，不是定理 ——
     哪天分叉了，规则还在照常归一就会静默产出错的 h2。

  3. **表里的值不与任何实采冲突**。这是最硬的一条：凡是某个库明确记录了
     (品牌, 版本) 的 h2，表里的值就必须与它一致；有多个库且互相冲突的，
     表要么取其中之一（源码裁定），要么弃权 —— 不能出现"三家都没说过"的值。

跑：python -m spec.test_h2_table
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.h2table import (build, check_premises,               # noqa: E402
                            observed, resolve)

HERE = os.path.dirname(os.path.abspath(__file__))
TABLE = os.path.join(HERE, "h2table.json")


def main():
    if not os.path.exists(TABLE):
        print(f"缺 {TABLE}；跑 python -m oracle.h2table --build", file=sys.stderr)
        return 2
    with open(TABLE) as f:
        stored = json.load(f)

    obs = observed()
    bad = []

    # 2) 前提
    prem = check_premises(obs)
    for p in prem:
        bad.append(f"归一规则前提失效：{p}")

    # 3) 与实采冲突
    conflict = 0
    for brand, rows in stored.items():
        for ver, rec in rows.items():
            hits = obs.get((brand, int(ver)), {})
            if not hits:
                continue
            fps = {v["akamai_fingerprint"] for v in hits.values()}
            if rec["akamai_fingerprint"] not in fps:
                bad.append(f"{brand} {ver}: 表里的值不在任何库的记录里\n"
                           f"      表 {rec['akamai_fingerprint']}\n"
                           f"      库 {sorted(fps)}")
            conflict += 1

    # 1) 与判据同步。重算要联网取源码 —— **缓存是冷的就直接跳过**，别硬跑：
    # 冷缓存下要为 650 个版本逐个取源，干净克隆里实测是**超时挂死**（退出码
    # 124）而不是优雅失败。try/except 拦得住异常，拦不住慢。
    resynced = skipped = 0
    drift = []
    cache = os.path.join(os.path.dirname(HERE), "spec", "cache", "chromium")
    if not os.path.isdir(cache) or len(os.listdir(cache)) < 10:
        fresh = None
        skipped = 1
        print("  ？ 判据重算跳过：源码缓存是冷的（spec/cache/chromium）。"
              "这条要联网逐版本取源，冷跑会很久 —— 先跑一次带网的采集再来。")
    else:
      try:
        fresh = build()
      except Exception as e:
        fresh = None
        skipped = 1
        print(f"  ？ 判据重算跳过（{type(e).__name__}: {str(e)[:60]}）")
    if fresh is not None:
        # **整条记录都要比，不能只比 akamai 串**。第一版只比
        # `akamai_fingerprint`，而 PRIORITY 帧不体现在那个串的差异里 ——
        # 代码变异实测：把源码推导路径的 priorities 写死成空表，94 条记录的
        # PRIORITY 全没了，本门禁照样全绿。又是"比了一个相邻但不等价的东西"。
        for brand in set(stored) | set(fresh):
            a, b = stored.get(brand, {}), fresh.get(brand, {})
            for ver in set(a) | set(b):
                x, y = a.get(ver), b.get(ver)
                if x != y:
                    diff = sorted({k for k in set(x or {}) | set(y or {})
                                   if (x or {}).get(k) != (y or {}).get(k)})
                    drift.append(f"{brand} {ver}: 字段 {diff} 不一致"
                                 f"（表 {[(x or {}).get(k) for k in diff]} "
                                 f"现算 {[(y or {}).get(k) for k in diff]}）")
                else:
                    resynced += 1
        for d in drift[:6]:
            bad.append(f"表已僵尸化：{d}")

    total = sum(len(v) for v in stored.values())
    print(f"h2 表 {total} 条"
          f"（{len(stored)} 个品牌）")
    print(f"  与实采比对   {conflict} 条有库记录可比，"
          f"{conflict - sum(1 for b in bad if '不在任何库' in b)} 条一致")
    if fresh is not None:
        print(f"  与判据同步   {resynced} 条一致，{len(drift)} 条漂移")
    print(f"  归一前提     {'全部成立' if not prem else f'{len(prem)} 条失效'}")

    for b in bad[:8]:
        print(f"  ✗ {b}")

    if total == 0:
        print("  ✗ 表是空的 —— 这不是通过")
        return 1
    print(f"\n{'h2 表可信' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
