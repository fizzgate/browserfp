"""三份 ClientHello 构造器不许分叉。

本项目有**三处**在拼 ClientHello，而且它们服务于不同场景：

```
oracle/chbuild.py   发货用（Python 侧），也是 golden 重建的判据
csrc/browserfp.c        发货用（C/Lua 侧），生产真正调的那份
oracle/tls13.py     参考实现自带的一份，真机端到端握手用它
```

**能干的那份会把不能干的那份遮住。** 真机端到端（`test_live_handshake`）用的是
tls13 那份，它补 SNI、新鲜生成 GREASE ECH、跳过 `pre_shared_key`；发货那两份
一度三样都不做。于是"端到端全绿"证明的是**测试用的构造器**能用，而不是**我们
发货的**能用 —— 三处缺陷（key_share 形状、ECH 照抄、PSK 旧票据）都是这么藏住的。

第四处更露骨：`sni=` 这个参数在 Python 侧对 **80/82 条 profile 被静默忽略**
（那些 profile 采自 nosni 场景，扩展里根本没有 0x0000，遍历它当然发不出来）。
C 与 tls13 都在补，只有 chbuild 没有 —— 而三方差分都用 `sni=None`、真机走
tls13、C 的 SNI 由 snitest 单独验，三条路恰好各自绕开了它。

所以这条门禁按**结构**比三份实现的产物，忽略本来就该每次不同的内容：

```
必须相同   扩展 id 的顺序（含补进去的 SNI 的位置）、密码套件、压缩、
           client_version、key_share 的 (分组, 长度) 形状、SNI 的值
必须不同   random、session_id、key_share 公钥内容、GREASE ECH 的 config_id/
           enc/payload 内容 —— 相同才是缺陷（见 test_keyshare）
```

跑：python -m spec.test_builder_parity
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chbuild import build_client_hello                   # noqa: E402
from oracle.clienthello import is_grease, parse_client_hello    # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SNITEST = os.path.join(ROOT, "csrc", "snitest")
REGISTRY = os.path.join(HERE, "profiles.json")

SNI = "example.com"
MIN_COMPARED = 3        # 三份实现能同时跑到的品牌数下限

# snitest 只按 (品牌, 版本) 取 profile，所以拿它验的是这几条有代表性的
CASES = (("chrome", 151), ("firefox", 135), ("safari", 26), ("edge", 151))


def key_share_shape(ch):
    k = [x for x in ch["extension_bodies"] if int(x) == 0x0033]
    if not k:
        return None
    b = bytes.fromhex(ch["extension_bodies"][k[0]])
    out, i = [], 2
    while i + 4 <= len(b):
        g = int.from_bytes(b[i:i + 2], "big")
        n = int.from_bytes(b[i + 2:i + 4], "big")
        out.append((g, n))
        i += 4 + n
    return out


# GREASE 值**按设计就该每次连接不同**（RFC 8701），所以比结构时把它们归一成一个
# 记号 —— 比具体值等于要求三份实现抽到同一个随机数，那不是"结构一致"。
# **只归一 GREASE 的取值，位置照比**：位置错了仍然要红。
GREASE_MARK = 0x0AAA        # 任取一个非 GREASE 的记号


def degrease(vals):
    return [GREASE_MARK if is_grease(v) else v for v in vals]


def structure(ch):
    """只取"必须相同"的那些维度。"""
    return {
        "ext_order": degrease(ch["raw_extensions"]),
        "ciphers": degrease(ch["raw_ciphers"]),
        "compression": list(ch["compression"]),
        "client_version": ch["client_version"],
        "key_share": [(GREASE_MARK if is_grease(g) else g, n)
                      for g, n in (key_share_shape(ch) or [])],
        "sni": ch.get("sni"),
    }


def c_build(brand, ver):
    r = subprocess.run([SNITEST, brand, str(ver), SNI],
                       capture_output=True, text=True, timeout=60)
    out = r.stdout.strip()
    return bytes.fromhex(out) if out else None


# 参考实现明确做不了的分组：cryptography 只有 ML-KEM，没有 Kyber draft00。
# 写在这里而不是让断言"发现不了"—— 服务端真选中它时握手会明确失败。
REF_UNSUPPORTED = {0x6399}


def ref_build(profile):
    """参考实现那份。借它的密钥生成 + 组装，不真连。返回 (字节, 生成的分组集)。"""
    from oracle.tls13 import TLS13Client
    cli = TLS13Client.__new__(TLS13Client)
    cli.profile = profile
    cli.sni = SNI
    shares, _privs = cli._gen_shares()
    return cli._build_hello(shares), set(shares)


def main():
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0 or not os.path.exists(SNITEST):
        print(f"make 失败或缺 snitest：{(r.stderr or r.stdout)[-200:]}",
              file=sys.stderr)
        return 2

    with open(REGISTRY) as f:
        registry = json.load(f)
    by_alias = {}
    for rec in registry:
        for a in [rec["id"]] + list(rec.get("aliases") or []):
            by_alias[a] = rec

    from oracle.covscan import TARGETS
    from oracle.uamap import UAMapper
    mapper = UAMapper()

    bad, n = [], 0
    for brand, ver in CASES:
        pid = mapper.lookup(TARGETS[brand][0].format(v=ver)).get("profile")
        rec = by_alias.get(pid)
        if not rec:
            bad.append(f"{brand} {ver}: 查不到 profile（{pid}）")
            continue
        craw = c_build(brand, ver)
        if craw is None:
            bad.append(f"{brand} {ver}: C 侧构造失败")
            continue

        try:
            builds = {
                "chbuild": build_client_hello(rec["tls"], sni=SNI),
                "C": craw,
                "tls13": ref_build(rec["tls"])[0],
            }
            ref_groups = ref_build(rec["tls"])[1]
        except Exception as e:
            bad.append(f"{brand} {ver}: 构造抛异常 {type(e).__name__}: {str(e)[:70]}")
            continue

        structs = {k: structure(parse_client_hello(v)) for k, v in builds.items()}
        n += 1
        ref = structs["chbuild"]
        for other in ("C", "tls13"):
            diff = [f for f in ref if ref[f] != structs[other][f]]
            if diff:
                bad.append(f"{brand} {ver}: chbuild 与 {other} 在 {diff} 上不同\n"
                           f"      chbuild {[ref[f] for f in diff]}\n"
                           f"      {other:7s} {[structs[other][f] for f in diff]}")
        # **发出去的每一组都必须有对应私钥**。这一条形状比对看不见：构造器会给
        # 没提供公钥的分组填随机字节，形状照样对 —— 但握手时若服务端选中那一组，
        # 我们既解不出共享密钥，发出去的也是一把假公钥。实测这正是 tls13 原来的
        # 毛病（只发首选那一条），而只比形状的话它不会红。
        want_groups = {g for g, _ in (key_share_shape(
            parse_client_hello(builds["chbuild"])) or [])
            if not is_grease(g)} - REF_UNSUPPORTED
        missing = want_groups - ref_groups
        if missing:
            bad.append(f"{brand} {ver}: 参考实现发了 {[hex(g) for g in missing]} "
                       "却没有对应私钥 —— 服务端选中就解不出共享密钥")

        # 该不同的必须不同：两次 chbuild 的 random 不能一样
        a, b = (parse_client_hello(build_client_hello(rec["tls"], sni=SNI))
                for _ in range(2))
        if a["random_hex"] == b["random_hex"]:
            bad.append(f"{brand} {ver}: 两次构造的 random 相同 —— 那是写死的")

    print(f"三份构造器逐结构比对   {n}/{len(CASES)} 组，"
          f"{len([x for x in bad if '上不同' in x])} 组有差异")
    if n < MIN_COMPARED:
        bad.append(f"只比到 {n} 组（下限 {MIN_COMPARED}）—— 比对集太小")

    for b in bad[:8]:
        print(f"  ✗ {b}")
    print(f"\n{'三份构造器结构一致' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
