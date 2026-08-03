"""Chrome 106+ 每连接打乱扩展顺序 —— 我们此前恒发同一个顺序。

本仓自己的真机实测就在 README 里（每浏览器 5 次连接）：

    chrome 151 / chromium 142 / edge 151    扩展顺序取值 = 5
    firefox 149                             扩展顺序取值 = 1

而我们 12 次构造只出 1 种。**一个固定的扩展顺序是真 Chrome 110+ 永远产不出来
的东西**，与当初照抄固定 GREASE 属于同一类破绽：不用比长度，看两次连接就够。

置换规则取自 utls 的 `ShuffleChromeTLSExtensions`（本仓的 profile 就采自它）：
**GREASE / padding / pre_shared_key 位置钉住，其余全部打乱**。padding 要钉住是
因为它得留在末尾承担补齐，PSK 则是 RFC 8446 强制最后一个。

**置换从 random32 派生，不用系统随机。** 否则 Python / C / Lua 三方差分立刻炸
—— 同一条连接必须排得出同一个顺序。这与 GREASE 取值同一个套路（C 侧的
`grease_at` 也是 SHA256(random32 || 计数器)）。

本门禁验六件事，每一件对应一处"不做会安静出错"：

    每连接不同        恒定顺序 = 破绽本身
    同 random32 可复现  否则跨实现对不上，而且不可调试
    钉住的位置不动    padding 挪走会破坏补齐，PSK 不在末尾直接被拒
    扩展集合不变      少一个/多一个就不是那个浏览器了
    JA4 不受影响      JA4 排序后哈希，变了说明我们动到了别的东西
    verbatim 不打乱   那是"照采集那条重建"，打乱会让重建门禁比两条不同的报文

跑：python -m spec.test_permute
"""

import json
import os
import secrets
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chbuild import (PADDING_EXT, PSK_EXT,                # noqa: E402
                            build_client_hello, permute_extensions)
from oracle.clienthello import (fingerprint, is_grease,          # noqa: E402
                                parse_client_hello)

HERE = os.path.dirname(os.path.abspath(__file__))
ROUNDS = 12

# 三个引擎各一条：扩展条数不同，钉住的东西也不同（safari 无 ECH、firefox 无 GREASE）
CASES = ("real:edge", "real:firefox153", "real:safari")


def order_of(raw):
    """GREASE 取值每连接随机，比顺序时归一成 G —— 不归一的话「顺序变了」这个
    结论会被 GREASE 的变化冒充，实测第一次就这么误判过。"""
    return tuple("G" if is_grease(e) else e
                 for e in parse_client_hello(raw)["raw_extensions"])


# buildcli 用固定的 random32（i*7+1），正好拿来做跨实现比对
C_RND = bytes((i * 7 + 1) & 0xFF for i in range(32))
C_SID = bytes((i * 3 + 2) & 0xFF for i in range(32))
BUILDCLI = os.path.join(os.path.dirname(HERE), "csrc", "buildcli")

# 引擎决定打不打乱：C 侧从 profile 的 engine 字段自己判，Python 侧由调用方给。
# 两边必须**在同一批 profile 上做出同一个决定**，所以这里把 gecko/webkit 也列进来
# ——它们必须"都不打乱"，否则说明 C 的判断跑偏了。
# curl_cffi:chrome100 在 buildcli 那个固定 random32 下**会带 padding**（实测
# 82 条里有 21 条会）。少了这样一条，"padding 位置钉住"在 C 侧根本验不到 ——
# 变异实测：把 padding 从 C 的钉住名单里去掉，门禁照样全绿。
C_CASES = (("real:edge", True), ("real:chrome153", True),
           ("curl_cffi:chrome100", True),
           ("real:firefox153", False), ("real:safari", False))


def check_c_parity(reg):
    """同一个 random32，Python 与 C 必须排出**同一个顺序**。

    这是整个设计的目的：置换从 random32 派生而不是用系统随机，就是为了让两侧
    可复现。对不上意味着三方差分永远红，而且不可调试。

    顺带验引擎判断：gecko/webkit 两侧都必须**不打乱**。
    """
    bad = []
    r = subprocess.run(["make", "-s"], cwd=os.path.dirname(BUILDCLI),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        return [f"make 失败：{(r.stderr or r.stdout)[-200:]}"]

    lines = "".join(f"={pid}\n" for pid, _ in C_CASES)
    out = subprocess.run([BUILDCLI], input=lines, capture_output=True,
                         text=True, timeout=120).stdout.strip().split("\n")
    if len(out) != len(C_CASES):
        return [f"buildcli 只回了 {len(out)} 行，应为 {len(C_CASES)}"]

    for (pid, perm), hexs in zip(C_CASES, out):
        if hexs == "-" or pid not in reg:
            bad.append(f"{pid}: C 侧构造失败或注册表里没有")
            continue
        c = order_of(bytes.fromhex(hexs))
        py = order_of(build_client_hello(reg[pid]["tls"], sni=None,
                                         random32=C_RND, session_id=C_SID,
                                         permute=perm))
        if c != py:
            bad.append(f"{pid}: 同一个 random32，Python 与 C 排出的顺序不同 —— "
                       "置换的全部意义就是两侧可复现")
        else:
            print(f"  ✅ 跨实现 {pid:16s} 打乱={perm}，Python 与 C 逐位相同")
    return bad


def main():
    with open(os.path.join(HERE, "profiles.json")) as f:
        reg = {r["id"]: r for r in json.load(f)}

    bad, checked = [], 0
    for pid in CASES:
        rec = reg.get(pid)
        if not rec:
            bad.append(f"{pid}: 注册表里没有这条 profile")
            continue
        prof = rec["tls"]

        orders, ja4s = set(), set()
        for _ in range(ROUNDS):
            raw = build_client_hello(prof, sni="example.com", permute=True,
                                     random32=secrets.token_bytes(32))
            orders.add(order_of(raw))
            ja4s.add(fingerprint(raw)["ja4"])

        n_move = sum(1 for e in prof["raw_extensions"]
                     if e not in (PADDING_EXT, PSK_EXT) and not is_grease(e))
        if n_move >= 2 and len(orders) < ROUNDS - 1:
            bad.append(f"{pid}: {ROUNDS} 次只出 {len(orders)} 种顺序 —— "
                       f"可移动的扩展有 {n_move} 个，本该几乎次次不同")
        if len(ja4s) != 1:
            bad.append(f"{pid}: 打乱之后 JA4 出现 {len(ja4s)} 种取值 —— "
                       "JA4 是排序后哈希，变了说明动到了别的东西")

        # 不打乱时必须恒定：否则上面那条断言等于没在区分什么
        fixed = {order_of(build_client_hello(prof, sni="example.com",
                                             random32=secrets.token_bytes(32)))
                 for _ in range(ROUNDS)}
        if len(fixed) != 1:
            bad.append(f"{pid}: 不打乱时出了 {len(fixed)} 种顺序 —— "
                       "对照组不成立，说明变化来自别处")

        # 同一个 random32 必须排出同一个顺序（跨实现能对上的前提）
        r = secrets.token_bytes(32)
        a = order_of(build_client_hello(prof, sni="example.com",
                                        permute=True, random32=r))
        b = order_of(build_client_hello(prof, sni="example.com",
                                        permute=True, random32=r))
        if a != b:
            bad.append(f"{pid}: 同一个 random32 排出了两种顺序 —— "
                       "C 侧永远对不上，而且不可调试")

        # 钉住的位置必须不动，集合必须不变
        base = order_of(build_client_hello(prof, sni="example.com",
                                           random32=secrets.token_bytes(32)))
        for got in list(orders)[:4]:
            if sorted(map(str, got)) != sorted(map(str, base)):
                bad.append(f"{pid}: 打乱改变了扩展集合 —— 少一个多一个就不是"
                           "那个浏览器了")
                break
            for i, e in enumerate(base):
                if (e == "G" or e in (PADDING_EXT, PSK_EXT)) and got[i] != e:
                    bad.append(f"{pid}: 第 {i} 位的 {e} 被挪走了 —— "
                               "GREASE/padding/PSK 位置必须钉住")
                    break

        # verbatim 是"照采集那条重建"，绝不能打乱
        # **必须给不同的 random32**：不给的话两边都用同一个默认种子，就算真被
        # 打乱了也排出同一个顺序，这条断言等于没在区分什么（变异测试实测到）。
        v1 = order_of(build_client_hello(prof, sni=None, verbatim=True,
                                         permute=True,
                                         random32=secrets.token_bytes(32)))
        v2 = order_of(build_client_hello(prof, sni=None, verbatim=True,
                                         permute=True,
                                         random32=secrets.token_bytes(32)))
        if v1 != v2:
            bad.append(f"{pid}: verbatim 模式被打乱了 —— 重建门禁会因此比两条"
                       "本来就不同的报文")

        checked += 1
        print(f"  ✅ {pid:18s} {ROUNDS} 次 {len(orders)} 种顺序，"
              f"可移动 {n_move} 个，JA4 恒定")

    # —— 下面两条用合成用例，不用真 profile ——
    #
    # 真 profile 太长（带 MLKEM 的 key_share 上千字节），padding 按长度重算的
    # 结果是**永远不出现**，于是"padding 位置钉住"这条断言在真 profile 上根本
    # 打不到 —— 变异测试实测到：把 padding 从钉住名单里去掉，门禁照样全绿。
    synth = [0x0A0A, 0x000D, 0x002B, 0x0017, 0x0005, 0x0033,
             PADDING_EXT, PSK_EXT]
    moved = 0
    for _ in range(24):
        got = permute_extensions(synth, secrets.token_bytes(32))
        if sorted(got) != sorted(synth):
            bad.append("合成用例：置换改变了扩展集合")
            break
        for i, e in enumerate(synth):
            if e in (0x0A0A, PADDING_EXT, PSK_EXT) and got[i] != e:
                bad.append(f"合成用例：第 {i} 位的 {e:#06x} 被挪走了 —— "
                           "GREASE / padding / pre_shared_key 位置必须钉住")
                break
        if got != synth:
            moved += 1
    if moved < 20:
        bad.append(f"合成用例 24 次只有 {moved} 次真的换了顺序 —— "
                   "可移动的有 5 个，本该几乎次次不同")
    else:
        print(f"  ✅ 合成用例          24 次 {moved} 次换序，"
              "GREASE/padding/PSK 钉住")

    # 置换函数本身的边界：可移动项不足 2 个时原样返回，不能报错也不能乱动
    tiny = [0x0A0A, PADDING_EXT, 0x2A2A]
    if permute_extensions(tiny, b"\0" * 32) != tiny:
        bad.append("可移动项少于 2 个时置换函数动了顺序 —— 那种情况没什么可打乱的")

    bad += check_c_parity(reg)

    if checked < len(CASES):
        bad.append(f"只验了 {checked}/{len(CASES)} 条 —— 三个引擎钉住的东西不同，"
                   "差一条就是差一种形状没验")

    print(f"\n逐引擎打乱 {checked}/{len(CASES)}")
    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'扩展顺序每连接打乱且可复现' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
