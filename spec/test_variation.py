"""每连接该变的东西必须在变 —— 逐引擎，判据来自真机实测。

伪装有两类破绽，形态相反：

  照抄了本该变的     一个 JA4 永不变化的"Chrome"，看两次连接就能认出来
  变了本不该变的     那就不再是那个浏览器

本项目在第一类上连着栽过 7 次（key_share 形状、GREASE ECH 内容与长度、
pre_shared_key、SNI 被静默忽略、padding 规则、GREASE 取值），全是**逐个撞出来**
的 —— 每次靠一条与被模仿者的 A/B 不符再回溯。

后来换了做法：**让真客户端连采若干次，逐扩展比内容，看哪些在变**；再拿我们自己
构造同样次数做同样比对，差集就是下一处。一轮就把"还有什么在变"问完了。

这条门禁把那份实测结论固化下来 —— **它是逐引擎的，因为三个栈的行为完全不同**：

```
chromium   0x0a 0x2b 0x33 0xfe0d 都在变，且 GREASE 每次换（扩展序列 8/8 各不相同）
gecko      只有 0x33 0xfe0d 在变，**根本不发 GREASE**，扩展序列恒定
webkit     0x0a 0x2b 0x33 在变、GREASE 每次换，**不发 ECH**
```

差一个引擎不扫，那一族的缺陷就等于不存在 —— Gecko 那条尤其重要：**如果哪天有人
"顺手"给 Firefox 也加上 GREASE 随机，那是把它变成一个不存在的浏览器**。

跑：python -m spec.test_variation
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chbuild import build_client_hello                    # noqa: E402
from oracle.clienthello import is_grease, parse_client_hello     # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "profiles.json")
ROUNDS = 8

# 判据取自**真机实测**（本地 sniffer 连采 6~8 次）：
#   chromium  curl_cffi chrome119 × 8
#   gecko     /Applications/Firefox.app × 6
#   webkit    /Applications/Safari.app × 6
#
# `must_vary` 是**必须在变**的扩展；没列的不代表必须不变（有些取决于长度是否
# 跨过阈值）。`grease` 说的是"GREASE 值要不要每次换" —— 它同时也断言了
# **GREASE 在不在**：Gecko 那条要求一个 GREASE 都没有。
EXPECT = {
    "chromium": {"profile": "curl_cffi:chrome119",
                 "must_vary": {0x0033, 0xFE0D}, "grease": True},
    "gecko":    {"profile": "real:firefox",
                 "must_vary": {0x0033, 0xFE0D}, "grease": False},
    "webkit":   {"profile": "real:safari",
                 "must_vary": {0x000A, 0x002B, 0x0033}, "grease": True},
}


def observe(profile, rounds=ROUNDS):
    caps = [parse_client_hello(build_client_hello(profile, sni=None))
            for _ in range(rounds)]
    keys = set()
    for c in caps:
        keys |= set(c["extension_bodies"])
    varying = {int(k) for k in keys
               if len({c["extension_bodies"].get(k) for c in caps}) > 1}
    grease_ids = {e for c in caps for e in c["raw_extensions"] if is_grease(e)}
    seqs = {tuple(c["raw_extensions"]) for c in caps}
    return varying, grease_ids, len(seqs)


def main():
    with open(REGISTRY) as f:
        registry = {r["id"]: r for r in json.load(f)}

    bad = []
    for engine, spec in sorted(EXPECT.items()):
        rec = registry.get(spec["profile"])
        if not rec:
            bad.append(f"{engine}: 注册表里没有 {spec['profile']} —— 判据失效")
            continue
        varying, grease_ids, n_seq = observe(rec["tls"])

        missing = spec["must_vary"] - varying
        if missing:
            bad.append(f"{engine}（{spec['profile']}）: "
                       f"{[hex(x) for x in sorted(missing)]} 每次构造都一样 —— "
                       "真机实测它们是变的，照抄等于给自己留一个恒定特征")

        if spec["grease"]:
            if not grease_ids:
                bad.append(f"{engine}: 一个 GREASE 都没发 —— 真机实测它发")
            elif n_seq < 2:
                bad.append(f"{engine}: {ROUNDS} 次构造的扩展序列完全一样 —— "
                           "GREASE 没在换，看两次连接就能认出来")
        else:
            if grease_ids:
                bad.append(f"{engine}: 发了 GREASE {[hex(x) for x in sorted(grease_ids)]}"
                           " —— 真机实测这个栈**不发 GREASE**，加上去等于造一个"
                           "不存在的浏览器")
            if n_seq != 1:
                bad.append(f"{engine}: 扩展序列有 {n_seq} 种 —— 真机实测它恒定")

        print(f"  {engine:9s} {spec['profile']:20s} "
              f"变={sorted(hex(x) for x in varying & spec['must_vary'])} "
              f"GREASE={'换' if spec['grease'] else '无'}({len(grease_ids)}) "
              f"序列种类={n_seq}/{ROUNDS}")

    if len(EXPECT) < 3:
        bad.append(f"只覆盖了 {len(EXPECT)} 个引擎 —— 差一个不扫，"
                   "那一族的缺陷就等于不存在")

    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'逐引擎的变化谱与真机一致' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
