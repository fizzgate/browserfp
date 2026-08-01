"""源码推出的 Chrome h2 开场，必须与实采 golden 吻合。

**先验证再使用**。这条规矩是 Safari 那次换来的：Apple 开源的 coreTLS 里有套件
表、有扩展写入顺序，形态上完全是需要的东西，拿已有真值一比才发现它根本不描述
Safari 的栈（扩展序毫无相似、曲线表缺了实测必有的 x25519）。所以任何源码推导在
用来补缺口之前，都得先在**有实采的版本**上逐字段验一遍。

**比对基准取「该版本自己的库条目」，不是 profile 里存的 h2**。后者不能当
oracle —— 注册表按 TLS 指纹去重，h2 只是搭车：`curl_cffi:chrome100` 一条记录的
36 个别名带着三种不同的 h2，存下来的只有一种。第一版门禁就是拿它当基准，于是
把「M110 推导正确」报成了不符。改用各库对该版本自报的值之后，三家（curl_cffi /
tls_client / wreq）与源码推导逐字节一致。

跑：python -m spec.test_chromium_h2
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chromiumh2 import akamai, chrome_h2                  # noqa: E402
from oracle.h2table import observed                              # noqa: E402


def cases():
    """{版本: {来源: akamai}} —— 各库对每个桌面 Chrome 版本自报的 h2。

    只取**各库一致**的版本作比对基准。库间冲突的版本本来就没有确定的真值，
    拿它去判推导对错只会得出没有意义的红或绿；冲突的裁决另在 h2table 里做。
    """
    out = {}
    for (brand, ver), hits in observed().items():
        if brand != "chrome":
            continue
        fps = {v["akamai_fingerprint"] for v in hits.values()}
        if len(fps) == 1:
            out[ver] = (next(iter(fps)), sorted(hits))
    return dict(sorted(out.items()))


def main():
    todo = cases()
    if not todo:
        print("没有可比对的 Chromium 系 h2 profile —— 这不是通过，是没验到",
              file=sys.stderr)
        return 1

    bad, ok, skip = [], 0, []
    for ver, (want_fp, who) in todo.items():
        try:
            derived = chrome_h2(ver)
        except Exception as e:
            # 取不到源码不算失败（网络/该版本不在索引里），但要明说没验到
            skip.append(f"M{ver}: {type(e).__name__}")
            continue
        got_fp = akamai(derived)
        if got_fp == want_fp:
            ok += 1
            continue
        bad.append(f"M{ver}（{len(who)} 个库一致：{who[:3]}）\n"
                   f"      源码推出 {got_fp}\n"
                   f"      各库自报 {want_fp}")

    print(f"源码推导 vs 实采   {ok}/{ok + len(bad)} 吻合"
          f"{'，%d 个版本取不到源码' % len(skip) if skip else ''}")
    for b in bad:
        print(f"  ✗ {b}")
    for s in skip[:5]:
        print(f"  ？ {s}")

    if ok == 0:
        print("  ✗ 一个都没验到 —— 这不是通过")
        return 1
    print(f"\n{'源码推导可用于补 h2 缺口' if not bad else '推导与实采不符，不能用来补缺口'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
