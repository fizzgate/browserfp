"""key_share：形状必须与真机一致，公钥必须能由调用方注入。

这一层长期没人看。JA4 **不哈希 key_share 的内容**，所以三方差分、重建闭环、
真机握手（服务端只要能算出共享密钥就不在乎你发了几组）全部照样绿 —— 而实测
两处都是错的：

```
Python  只给 curves[0] 发一个随机公钥
        chrome131 真机 GREASE(1)+X25519MLKEM768(1216)+X25519(32) → 重建只有一条
C       照抄 golden 整段
```

于是 **C 与 Python 产出的字节形状长期不同**，也没人发现。两个后果都很硬：

  · **Chrome 恒发一个 GREASE key_share**，丢掉它本身就是破绽；少发一组也与
    自己的 supported_groups 对不上
  · 真出网时照抄 golden 的公钥根本用不了 —— 那把私钥不在我们手里，算不出
    共享密钥；而一把固定公钥反复出现，比不伪装还显眼

所以本门禁验三件事：

  1. **形状保真**：每条 profile 重建出来的 key_share，分组/顺序/每条长度
     与 golden 逐项相同（C 与 Python 各验一遍，且两者相同）
  2. **注入生效**：给了公钥就必须真的用上 —— 断言注入后的字节里出现的是
     我们给的那把，不是 golden 里那把
  3. **拒绝将就**：长度不符、分组在 profile 里不存在，必须报错而不是忽略。
     "以为注入了、实际被忽略"是最难查的一类错：握手会拿一把旧公钥去算密钥

跑：python -m spec.test_keyshare
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chbuild import _parse_key_share, build_client_hello   # noqa: E402
from oracle.clienthello import parse_client_hello                 # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KSCLI = os.path.join(ROOT, "csrc", "kscli")
REGISTRY = os.path.join(HERE, "profiles.json")

# 比对集下限：读空 profiles.json 时"0 条一致"看着也是绿的
MIN_PROFILES = 40


def golden_shape(rec):
    eb = rec["tls"]["extension_bodies"]
    k = [x for x in eb if int(x) == 0x0033]
    return _parse_key_share(bytes.fromhex(eb[k[0]])) if k else None


def built_shape(raw):
    ch = parse_client_hello(raw)
    k = [x for x in ch["extension_bodies"] if int(x) == 0x0033]
    return _parse_key_share(bytes.fromhex(ch["extension_bodies"][k[0]])) if k else None


def built_pubs(raw):
    """{group: pub} —— 用来验注入是否真的生效。"""
    ch = parse_client_hello(raw)
    k = [x for x in ch["extension_bodies"] if int(x) == 0x0033]
    if not k:
        return {}
    b = bytes.fromhex(ch["extension_bodies"][k[0]])
    out, i = {}, 2
    while i + 4 <= len(b):
        g = int.from_bytes(b[i:i + 2], "big")
        n = int.from_bytes(b[i + 2:i + 4], "big")
        out[g] = b[i + 4:i + 4 + n]
        i += 4 + n
    return out


def c_build(pid, inject=None):
    """kscli: 一行 "<profile_id>\\t<group>:<pubhex>,..." → ClientHello 的 hex。"""
    arg = f"{pid}\t" + ",".join(f"{g:04x}:{p.hex()}" for g, p in (inject or {}).items())
    r = subprocess.run([KSCLI], input=arg + "\n", capture_output=True,
                       text=True, timeout=60)
    out = r.stdout.strip()
    return None if out.startswith("ERR") or not out else bytes.fromhex(out)


def main():
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0 or not os.path.exists(KSCLI):
        print(f"make 失败或缺 kscli：{(r.stderr or r.stdout)[-200:]}", file=sys.stderr)
        return 2

    with open(REGISTRY) as f:
        registry = json.load(f)

    bad, n_shape, n_c = [], 0, 0
    for rec in registry:
        want = golden_shape(rec)
        if not want:
            continue
        n_shape += 1
        got = built_shape(build_client_hello(rec["tls"], sni=None))
        if got != want:
            bad.append(f"{rec['id']}: Python 重建的 key_share 形状与 golden 不同\n"
                       f"      golden {want}\n      重建   {got}")
        craw = c_build(rec["id"])
        if craw is None:
            continue
        n_c += 1
        cgot = built_shape(craw)
        if cgot != want:
            bad.append(f"{rec['id']}: C 重建的 key_share 形状与 golden 不同\n"
                       f"      golden {want}\n      C      {cgot}")

    print(f"形状保真   Python {n_shape} 条、C {n_c} 条与 golden 逐项比对，"
          f"{len([b for b in bad if '形状' in b])} 条不符")
    if n_shape < MIN_PROFILES:
        bad.append(f"只比了 {n_shape} 条（下限 {MIN_PROFILES}）—— 注册表读空了？")

    # 2) 注入生效 + 3) 拒绝将就
    sample = next((x for x in registry if golden_shape(x)
                   and any(not (0x0a0a <= g <= 0xfafa and (g & 0x0f0f) == 0x0a0a)
                           for g, _ in golden_shape(x))), None)
    if not sample:
        bad.append("找不到含非 GREASE key_share 的 profile —— 注入验不了")
    else:
        shape = golden_shape(sample)
        group, plen = next((g, n) for g, n in shape
                           if not (0x0a0a <= g <= 0xfafa and (g & 0x0f0f) == 0x0a0a))
        mine = bytes([0x5a]) * plen
        gold_pub = built_pubs(build_client_hello(sample["tls"], sni=None))

        # **注入这一步要包起来**：构造器对不合法的注入是抛异常的，而这里给的
        # 是合法注入 —— 真抛了说明实现坏了，那是**发现**，不该表现成门禁自己
        # 崩掉。实测过：代码变异让形状退化成只剩 GREASE 之后，这里直接抛
        # ValueError 把整条门禁打死，后面的检查一条都没跑。
        try:
            py_raw = build_client_hello(sample["tls"], sni=None,
                                        key_shares={group: mine})
        except Exception as e:
            py_raw = None
            bad.append(f"Python 对合法注入抛了 {type(e).__name__}: {str(e)[:80]}")
        for side, raw in (("Python", py_raw),
                          ("C", c_build(sample["id"], {group: mine}))):
            if raw is None:
                bad.append(f"{side}: 注入后构造失败")
                continue
            pubs = built_pubs(raw)
            if pubs.get(group) != mine:
                bad.append(f"{side}: 注入的公钥没被用上 —— "
                           f"发出去的是 {pubs.get(group, b'')[:8].hex()}…")
            if built_shape(raw) != shape:
                bad.append(f"{side}: 注入后形状变了")
        print(f"注入生效   组 0x{group:04x}（{plen} 字节）两侧都用上了我们给的公钥")

        # 拒绝将就：长度不符 / 组不存在
        absent = 0x0102
        while any(g == absent for g, _ in shape):
            absent += 1
        for tag, ks in (("长度不符", {group: mine[:-1]}),
                        ("组不存在", {absent: b"\x01" * 32})):
            try:
                build_client_hello(sample["tls"], sni=None, key_shares=ks)
                py_ok = True
            except Exception:
                py_ok = False
            c_out = c_build(sample["id"], ks)
            if py_ok:
                bad.append(f"Python 接受了{tag}的注入 —— "
                           "要么形状会变，要么调用方以为注入成功了，都必须报错")
            if c_out is not None:
                bad.append(f"C 接受了{tag}的注入 —— 形状会变，必须报错")
            print(f"拒绝将就   {tag}："
                  f"Python {'报错' if not py_ok else '✗ 接受了'}，"
                  f"C {'报错' if c_out is None else '✗ 接受了'}")

    for b in bad[:8]:
        print(f"  ✗ {b}")
    print(f"\n{'key_share 形状保真且可注入' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
