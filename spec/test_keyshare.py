"""key_share 与 GREASE ECH：形状必须与真机一致，内容必须每次新鲜。

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

GREASE ECH（0xFE0D）是同一族的第二处，而且更险：**config_id 只有 1 字节**，
照抄 golden 的固定值一旦撞上服务端真实的 ECH 配置，服务端会拿自己的私钥去解
payload、失败，回 handshake_failure(40)。34/81 条默认 profile 带这个扩展，也就是
绝大多数 Chrome 形态。参考实现 `oracle/tls13.py` 早就每次新鲜生成（注释里写着
实测原因），而**发货的构造器一直在照抄** —— `test_build_live` 只打三个站点，
撞不上就一直是绿的。

跑：python -m spec.test_keyshare
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chbuild import (ECH_BODY_LENS, _parse_key_share,     # noqa: E402
                            ech_family,
                            build_client_hello)
from oracle.clienthello import is_grease, parse_client_hello     # noqa: E402

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


def py_build(rec, bad, why, **kw):
    """Python 侧构造，**失败当成发现而不是让门禁崩掉**。

    这个教训在本文件里撞了三次：形状比对循环、注入那一段、ECH 那一段 —— 每次
    都是"某条 profile 让构造器抛异常，整条门禁当场死掉，后面几段一条没跑"。
    崩掉时终端只有一个 traceback，看不到哪几条不符、也看不到还有没有别的问题。
    所以不逐处补 try，只留这一个入口。
    """
    try:
        return build_client_hello(rec["tls"], **kw)
    except Exception as e:
        bad.append(f"{rec['id']}: {why}（{type(e).__name__}: {str(e)[:70]}）")
        return None


def c_build(pid, inject=None):
    """kscli: 一行 "<profile_id>\\t<group>:<pubhex>,..." → ClientHello 的 hex。"""
    # kscli 的输入是**三段**：id / sni / 注入的公钥。改这个契约时忘了回头查
    # 调用方，本门禁的 C 侧当场变成"70 条全失败"—— 好在它自己就是查这个的。
    # 改 CLI 的输入格式要先 grep 调用方，别指望"应该没人用"。
    arg = f"{pid}\t\t" + ",".join(f"{g:04x}:{p.hex()}"
                                  for g, p in (inject or {}).items())
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
        # **构造失败要当成发现，不能让门禁崩掉**。同一个教训在本文件里出现两次：
        # 崩掉时终端只有一个 traceback，看不到"哪几条不符"，也看不到后面几段
        # 检查跑没跑。门禁的职责是报告。
        raw = py_build(rec, bad, "无注入构造就失败了 —— 重建闭环要靠它",
                       sni=None, verbatim=True)
        if raw is None:
            continue
        got = built_shape(raw)
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
        gold_pub = built_pubs(build_client_hello(sample["tls"], sni=None,
                                                 verbatim=True))

        # **注入这一步要包起来**：构造器对不合法的注入是抛异常的，而这里给的
        # 是合法注入 —— 真抛了说明实现坏了，那是**发现**，不该表现成门禁自己
        # 崩掉。实测过：代码变异让形状退化成只剩 GREASE 之后，这里直接抛
        # ValueError 把整条门禁打死，后面的检查一条都没跑。
        try:
            py_raw = build_client_hello(sample["tls"], sni=None,
                                        key_shares={group: mine}, verbatim=True)
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
                build_client_hello(sample["tls"], sni=None, key_shares=ks,
                                   verbatim=True)
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

    # —— 会话恢复态：真出网时必须拒绝 ——
    #
    # profile 里那张 pre_shared_key 是采集当时的票据，发出去验不过，服务端会
    # 退回完整握手 —— 一个"声称自己来过"却拿不出有效票据的客户端，比干净的
    # 首连更可疑。by_ua 本来就只返回 initial 态，但**构造器本身**此前会照发。
    #
    # 区分信号是"有没有注入 key_share"：注入了就说明调用方真要握手。不注入时
    # 必须照常原样构造 —— 重建闭环要靠它。
    psk = [x for x in registry if 0x0029 in (x["tls"].get("raw_extensions") or [])]
    if not psk:
        bad.append("注册表里一条会话恢复态 profile 都没有 —— 这段断言等于没验")
    else:
        rec = psk[0]
        shape = golden_shape(rec)
        grp = next(((g, n) for g, n in (shape or [])
                    if not (0x0a0a <= g <= 0xfafa and (g & 0x0f0f) == 0x0a0a)), None)
        # 不注入：必须照常构造出来（重建验证要用）
        plain = py_build(rec, bad,
                         "不注入时也拒绝了恢复态 profile —— 重建闭环要靠它原样构造",
                         sni=None, verbatim=True)
        plain_ok = plain is not None and \
            0x0029 in parse_client_hello(plain)["raw_extensions"]
        if not plain_ok:
            bad.append("不注入时构造出的字节里没有 pre_shared_key —— "
                       "重建验证会失真")
        if c_build(rec["id"]) is None:
            bad.append("C 不注入时也拒绝了恢复态 profile —— 重建闭环要靠它")
        # 注入：两侧都必须拒绝
        if grp:
            inj = {grp[0]: bytes([0x5a]) * grp[1]}
            try:
                build_client_hello(rec["tls"], sni=None, key_shares=inj)
                bad.append("Python 允许对会话恢复态 profile 注入 key_share —— "
                           "那等于真要握手，会把过期票据发出去")
                py_ref = False
            except Exception:
                py_ref = True
            c_ref = c_build(rec["id"], inj) is None
            if not c_ref:
                bad.append("C 允许对会话恢复态 profile 注入 key_share —— 同上")
            print(f"会话恢复态 {rec['id']}：不注入照常构造，"
                  f"注入时 Python {'拒绝' if py_ref else '✗ 接受'}、"
                  f"C {'拒绝' if c_ref else '✗ 接受'}")
        else:
            bad.append(f"{rec['id']} 没有非 GREASE 的 key_share，注入验不了")

    # —— GREASE ECH：形状照抄、内容新鲜 ——
    ech = [x for x in registry if 0xFE0D in (x["tls"].get("raw_extensions") or [])]
    n_ech = 0
    for rec in ech:
        eb = rec["tls"]["extension_bodies"]
        gk = [x for x in eb if int(x) == 0xFE0D][0]
        gold = bytes.fromhex(eb[gk])
        for side, raw in (("Python", py_build(rec, bad, "ECH 段构造失败", sni=None)),
                          ("C", c_build(rec["id"]))):
            if raw is None:
                continue
            got_eb = parse_client_hello(raw)["extension_bodies"]
            k = [x for x in got_eb if int(x) == 0xFE0D]
            if not k:
                bad.append(f"{rec['id']}: {side} 把 GREASE ECH 整个丢了 —— "
                           "部分站点缺了它直接 handshake_failure")
                continue
            got = bytes.fromhex(got_eb[k[0]])
            n_ech += 1
            # **长度不再要求等于 golden**：实测 GREASE ECH 的体长每次连接从
            # {186,218,250,282} 里随机取（26 次抓包，两条 golden 不同的 profile
            # 抽到同一组数）。要求等于 golden 反而是要求"我们比真客户端更固定"。
            # 改成必须落在那个集合里。
            fam = ech_family(len(gold))
            if fam and len(got) not in fam:
                bad.append(f"{rec['id']}: {side} 的 ECH 体长 {len(got)} 不在实测集合 "
                           f"{fam} 里")
            elif not fam and len(got) != len(gold):
                bad.append(f"{rec['id']}: {side} 改了没测过的栈的 ECH 长度 "
                           f"（{len(gold)}→{len(got)}）—— 那等于凭空造一个长度")
            elif got[:5] != gold[:5]:
                bad.append(f"{rec['id']}: {side} 改了 ECH 的 type/kdf/aead")
            elif got == gold:
                bad.append(f"{rec['id']}: {side} 照抄了 golden 的 ECH —— "
                           "config_id 固定会撞上服务端真实配置，回 handshake_failure")
    # 新鲜性：同一条 profile 连造两次必须不同
    two = [py_build(ech[0], bad, "新鲜性检查构造失败", sni=None)
           for _ in range(2)] if ech else []
    if all(x is not None for x in two) and two:
        bodies = []
        for raw in two:
            e = parse_client_hello(raw)["extension_bodies"]
            bodies.append(e[[x for x in e if int(x) == 0xFE0D][0]])
        if bodies[0] == bodies[1]:
            bad.append("同一条 profile 连造两次的 ECH 完全相同 —— 没有新鲜性，"
                       "等于换了个地方写死")
    print(f"GREASE ECH {n_ech} 次构造：形状照抄、内容新鲜、两次不重复")

    # —— GREASE：每连接随机，且各槽位的关系要对 ——
    #
    # GREASE 的全部意义就是每连接随机（RFC 8701）。恒定不变比长度类的破绽更容易
    # 被发现：不用比长度，**看两次连接就够**。规格实测自真机（6~10 次采样）：
    # 两个扩展 id 每次随机且恒不相同；密码套件独立；supported_groups 首项随机
    # 且 key_share 里那条与它相同；supported_versions 独立。
    sample_g = next((x for x in registry
                     if any(is_grease(e) for e in (x["tls"].get("raw_extensions") or []))
                     and 0x0029 not in (x["tls"].get("raw_extensions") or [])), None)
    if not sample_g:
        bad.append("找不到含 GREASE 扩展的 profile —— 这段断言等于没验")
    else:
        seen, ndiff = set(), 0
        for _ in range(12):
            raw = py_build(sample_g, bad, "GREASE 检查构造失败", sni=None)
            if raw is None:
                break
            ch = parse_client_hello(raw)
            exts = [e for e in ch["raw_extensions"] if is_grease(e)]
            ciph = [c for c in ch["raw_ciphers"] if is_grease(c)]
            eb = ch["extension_bodies"]

            def first_grease(eid, off):
                k = [x for x in eb if int(x) == eid]
                if not k:
                    return None
                b = bytes.fromhex(eb[k[0]])
                v = int.from_bytes(b[off:off + 2], "big")
                return v if is_grease(v) else None

            grp, ks = first_grease(0x000A, 2), first_grease(0x0033, 2)
            # **先查"还在不在"，再查"对不对"**。做阴性对照时把 GREASE 换成
            # 0，集合直接空了 —— 而只在集合里比的断言什么都没查到，看着是绿的。
            # 这与"零处不符先拆跳过"是同一族。
            want_n = len([e for e in (sample_g["tls"].get("raw_extensions") or [])
                          if is_grease(e)])
            if len(exts) != want_n:
                bad.append(f"GREASE 扩展数 {len(exts)} != golden 的 {want_n} —— "
                           "被换成了非 GREASE 值？")
            if len(exts) >= 2 and exts[0] == exts[1]:
                bad.append(f"两个 GREASE 扩展 id 相同（{exts}）—— 实测真客户端 "
                           "0/10 相同")
            if grp is not None and ks is not None and grp != ks:
                bad.append(f"supported_groups 的 GREASE {grp:#06x} 与 key_share 的 "
                           f"{ks:#06x} 不同 —— 实测真客户端 6/6 相同")
            seen.add((tuple(exts), tuple(ciph), grp,
                      first_grease(0x002B, 1)))
            ndiff += 1
        if ndiff and len(seen) < 2:
            bad.append(f"{ndiff} 次构造的 GREASE 组合完全一样 —— "
                       "那是写死的，看两次连接就能认出来")
        print(f"GREASE 每连接随机  {ndiff} 次构造得到 {len(seen)} 种组合，"
              "两个扩展 id 互不相同、组与 key_share 同源")

    for b in bad[:8]:
        print(f"  ✗ {b}")
    print(f"\n{'key_share 与 ECH 都形状保真、内容新鲜' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
