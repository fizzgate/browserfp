"""把判据改坏，看有没有门禁会红 —— 对**代码**做的平凡通过扫描。

`test_trivial_pass` 扫的是数据源：清空 `profiles.json`，看有没有门禁变红。
但它管不到另一半 —— **代码坏了，断言响不响**。这半边不是假想风险，本项目
连着栽过两次，两次都是断言看起来完全合理却根本不会红：

```
并发检查      比的是 profile id，而 id 根本不在共享缓冲里 —— 往解析中间
              注入 ngx.sleep 制造真实的缓冲踩踏，检查照样 60/60 绿
分支覆盖      计数器放在 switch **之前**，计的是"看见了这个扩展"而不是
              "解析体执行了" —— 把四个 case 的体掏空，计数照样满额
```

两次都是靠临时手搓一次阴性对照抓出来的，抓完那次对照就随手扔了。这个门禁
把这件事固化：一份变异清单，每条都是**语义**改动（不是改注释、改空白），
跑一遍看有没有门禁变红。没有红的那条，就是一处无人看管的判据。

三条硬要求，都是踩过的坑：

  1. **只在临时副本里改**。工作区一个字节都不碰 —— 曾经在工作区里清空
     数据文件，恰好后台有 `--live` 在跑，整轮结论作废。
  2. **锚点找不到就判失败，不许跳过**。变异靠精确文本定位，代码一重构锚点
     就失效；这时候"跳过"等于把这条判据悄悄取消看管，正是僵尸断言的长法。
  3. **先确认原样是绿的**。原样就红的话，"变异后红"证明不了任何事。

跑：python -m spec.test_mutation
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# (名字, 文件, 原文, 改成, 该变红的候选门禁, 这条判据是什么)
#
# 每条都得是**语义**改动。改注释、改变量名、加空行不算 —— 那种"变异"不红是
# 应该的，混进来只会稀释信号。
MUTANTS = [
    ("ja4:cipher 不排序", "csrc/tlsfp.c",
     "    qsort(tmp, h->ciphers.len, sizeof(uint16_t), cmp_u16);",
     "    /* 变异：不排序 */",
     ["test_ja4_vectors", "test_c_parity", "test_lua_parity"],
     "JA4 的 cipher 段必须排序后再哈希"),

    ("ja4:扩展段没排除 SNI", "csrc/tlsfp.c",
     "        if (e == 0x0000 || e == 0x0010) continue;",
     "        if (e == 0x0010) continue;",
     ["test_ja4_vectors", "test_c_parity"],
     "JA4 的扩展段要排除 SNI 与 ALPN"),

    ("解析:GREASE 不剔除", "csrc/tlsfp.c",
     "        if (tlsfp_is_grease(eid)) {\n            out->has_grease = 1;",
     "        if (0) {\n            out->has_grease = 1;",
     ["test_c_parity", "test_ja4t"],
     "扩展列表里的 GREASE 要剔除并置 has_grease"),

    ("构造:SNI 插在首个 GREASE 之前", "csrc/tlsfp.c",
     "        if (p->n_rawext && tlsfp_is_grease(p->rawext[0])) sni_at = 1;",
     "        sni_at = 0;",
     ["test_build_parity"],
     "重建 ClientHello 时 SNI 排在首个 GREASE 之后"),

    ("SNI:Python 不补入", "oracle/chbuild.py",
     "    if sni is not None and 0x0000 not in ext_order:",
     "    if False:",
     ["test_builder_parity"],
     "profile 不含 SNI 扩展时必须补进去（80/82 条采自 nosni 场景）"),

    ("tls13:key_share 只发一条", "oracle/tls13.py",
     "        return pubs, privs",
     "        k = sorted(pubs)[:1]\n        return {x: pubs[x] for x in k}, privs",
     ["test_builder_parity"],
     "参考实现发出去的每一组都要有对应私钥"),

    ("PSK:真出网时不拒绝恢复态", "oracle/chbuild.py",
     "    if key_shares and PSK_EXT in raw_extensions:",
     "    if False:",
     ["test_keyshare"],
     "注入 key_share（=真要握手）时必须拒绝会话恢复态 profile"),

    ("padding:照抄 golden 不重算", "oracle/chbuild.py",
     "    if not verbatim and PAD_LO <= fixed < PAD_TO:",
     "    if False:",
     ["test_keyshare", "test_build_parity"],
     "padding 要按实际长度补齐到 512，超过就不发（照抄会多一个扩展）"),

    ("发货路径:C 默认改回重建口径", "csrc/tlsfp.c",
     "                                       NULL, 0, 0, out, outlen);",
     "                                       NULL, 0, TLSFP_BUILD_VERBATIM, out, outlen);",
     ["test_variation"],
     "plain 名必须是出网口径 —— Lua 绑定用的正是它，改回去七处修复在生产上全死"),

    ("GREASE:退回固定值", "oracle/chbuild.py",
     "    if verbatim:\n        return None",
     "    if True:\n        return None",
     ["test_keyshare", "test_variation"],
     "GREASE 必须每连接随机（RFC 8701），固定值看两次连接就能认出来"),

    ("GREASE:key_share 与 groups 不同源", "oracle/chbuild.py",
     "            if grease_group is not None:\n                group = grease_group",
     "            if False:\n                group = grease_group",
     ["test_keyshare"],
     "key_share 里那条 GREASE 组要与 supported_groups 一致（实测 6/6）"),

    ("ECH:内容也照抄 golden", "oracle/chbuild.py",
     '    if verbatim:\n        payload_len = struct.unpack_from(">H", golden_body, 8 + enc_len)[0]',
     "    if True:\n        return golden_body",
     ["test_variation"],
     "GREASE ECH 的内容每次连接都要新鲜（三个引擎里有两个发它）"),

    ("ECH:照抄 golden 的 config_id", "oracle/chbuild.py",
     '            body = grease_ech(bodies.get(ext_id, b""), verbatim=verbatim)',
     '            body = bodies.get(ext_id, b"")',
     ["test_keyshare"],
     "GREASE ECH 必须每次新鲜（固定 config_id 会撞上服务端真实配置）"),

    ("ECH:C 侧不重写", "csrc/tlsfp.c",
     "        if (id == 0xFE0D && blen >= 8) {",
     "        if (0) {",
     ["test_keyshare"],
     "C 侧同样必须新鲜生成 ECH，不能照抄 profile"),

    ("key_share:只重建第一条", "oracle/chbuild.py",
     "    shape = _parse_key_share(golden_body)",
     "    shape = _parse_key_share(golden_body)[:1]",
     ["test_keyshare"],
     "key_share 的分组/顺序/长度必须与真机一致（Chrome 恒发一条 GREASE）"),

    ("key_share:注入长度不校验", "oracle/chbuild.py",
     "            if len(pub) != plen:",
     "            if False:",
     ["test_keyshare"],
     "注入的公钥长度与 profile 不符必须报错，不能将就"),

    ("解析:supported_versions 长度不夹紧", "csrc/tlsfp.c",
     "                    if (n + 1 > elen) n = elen - 1;",
     "                    /* 变异：不夹紧 */",
     ["test_robustness"],
     "对方给的长度字段必须夹到实际扩展长度内（这是真出过的堆越界）"),

    ("UA:chromium_engine 不剥 -mobile", "oracle/uamap.py",
     '    mobile = brand.endswith("-mobile")\n'
     '    base = brand[: -len("-mobile")] if mobile else brand',
     '    mobile = False\n    base = brand',
     ["test_c_ua_parity", "test_ua_mapping", "test_strict_ua"],
     "Edge/Opera 的 Android 版要先剥后缀再判内核"),

    ("h2:PRIORITY 写死空表", "oracle/h2table.py",
     '            "priorities": [list(x) for x in (rec.get("priorities") or [])],',
     '            "priorities": [],',
     # 只有 test_h2_table 会拿判据重算一遍再比 —— 其余几个读的都是落盘的
     # spec/h2table.json，判据改坏它们一律不知道。这正是落盘产物的代价。
     ["test_h2_table", "test_h2_build", "test_coherence"],
     "源码推导出的 PRIORITY 帧不能被丢掉（Firefox 发 6 条）"),

    ("coherence:矛盾不报", "csrc/tlsfp.c",
     "    return strcmp(t, h) != 0;            /* 1=矛盾 */",
     "    return 0;",
     ["test_coherence"],
     "TLS 与 h2 两层引擎不一致时必须报矛盾（split-brain 正是这么漏出去的）"),

    ("h2:开场不发 WINDOW_UPDATE", "csrc/tlsfp.c",
     "    if (p->window) {\n",
     "    if (0) {\n",
     ["test_h2_build"],
     "h2 开场里的 WINDOW_UPDATE 帧要按 profile 发"),

    ("QUIC:重组不校验收齐", "oracle/quic.py",
     "    if len(buf) < want:",
     "    if False:",
     ["test_quic", "test_h3"],
     "多个 Initial 拆包时，无空洞不等于收齐（Firefox 会拆）"),

    ("QUIC:空洞检查去掉", "oracle/quic.py",
     "    if not all(seen):",
     "    if False:",
     ["test_quic", "test_h3"],
     "CRYPTO 片段有空洞必须拒绝"),

    ("JA4Q:首字符不换", "oracle/quic.py",
     '    return "q" + ja4[1:] if ja4.startswith("t") else ja4',
     "    return ja4",
     ["test_quic", "test_h3", "test_registry_fresh"],
     "QUIC 的 JA4 首字符是 q 不是 t"),

    ("注册表:去重键不排序集合字段", "oracle/registry.py",
     '        {f: (sorted(fp.get(f) or []) if f in SET_FIELDS else fp.get(f))\n'
     '         for f in FIELDS}, sort_keys=True)',
     "        {f: fp.get(f) for f in FIELDS}, sort_keys=True)",
     ["test_registry_fresh", "test_rebuild", "test_derive"],
     "集合类字段要排序后才能当去重键，否则同一指纹被拆成多条"),

    ("JA4T:不取 window scale", "oracle/ja4t.py",
     "        elif kind == OPT_WSCALE and len(val) == 1:",
     "        elif False:",
     ["test_ja4t"],
     "window scale 只在 SYN 包里，是 JA4T 的第四段"),
]


def _snapshot(dest):
    def ignore(d, names):
        return [n for n in names if n in {"__pycache__", ".git", "cache", ".venv"}]
    for sub in ("spec", "oracle", "csrc", "lua"):
        shutil.copytree(os.path.join(ROOT, sub), os.path.join(dest, sub),
                        ignore=ignore, symlinks=True)
    # 40MB 的源码缓存不复制，但要**软链进去** —— 少了它，走源码推导的那些判据
    # 整条路径都不执行，改坏了当然没人红。第一版就是这么误报的：
    # "h2 的 PRIORITY 写死空表无人看管"，实际是变异那行压根没跑到。
    # 环境把某条路径关掉，看起来和"没有门禁"一模一样。
    src = os.path.join(ROOT, "spec", "cache")
    if os.path.isdir(src):
        os.symlink(src, os.path.join(dest, "spec", "cache"))


def _force_rebuild(work):
    """删掉临时副本里的 C 产物，逼下一次 make 真的重编。

    **不能指望 mtime**。变异是一条接一条写同一个 `tlsfp.c` 的，上一条留下的
    `tlsfp.o` 常常与本次写入落在同一秒里，make 就认为不用重编 —— 于是门禁比的
    是上一条变异（或原样）的二进制。实测这条是**偶发**的：同一份代码连跑两次，
    "SNI 插在首个 GREASE 之前"一次红一次不红。

    偶发的绿比稳定的红危险得多 —— 它会被当成噪声解释掉。所以不调 mtime，
    直接删产物。还原之后也要删：否则后面几条变异跑的是上一条留下的二进制。
    这是本项目第 6 次撞"用了 stale 产物所以断言失灵"。
    """
    d = os.path.join(work, "csrc")
    for fn in os.listdir(d):
        f = os.path.join(d, fn)
        if not os.path.isfile(f):
            continue
        if fn.endswith((".o", ".so")) or "." not in fn:
            os.remove(f)


def _run(workdir, gate, timeout=300):
    env = dict(os.environ)
    env["PYTHONPYCACHEPREFIX"] = os.path.join(workdir, ".pyc")
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        env.pop(k, None)
    try:
        r = subprocess.run([sys.executable, "-m", f"spec.{gate}"], cwd=workdir,
                           capture_output=True, text=True, timeout=timeout,
                           env=env)
        return r.returncode
    except subprocess.TimeoutExpired:
        return -1


def main():
    work = tempfile.mkdtemp(prefix="tlsfp-mut-")
    bad, guarded = [], 0
    try:
        _snapshot(work)

        # 原样基线：每个门禁跑一遍，只有原样绿的才有资格当这条变异的观察者
        gates = sorted({g for m in MUTANTS for g in m[4]})
        base = {g: _run(work, g) for g in gates}
        green = {g for g, c in base.items() if c == 0}
        print(f"基线 {len(green)}/{len(gates)} 个门禁原样为绿")
        for g in sorted(set(gates) - green):
            print(f"  ？ {g} 原样就不绿（{base[g]}），本轮不拿它当观察者")
        print()

        for name, rel, old, new, cands, why in MUTANTS:
            path = os.path.join(work, rel)
            src = open(path).read()
            if old not in src:
                # 锚点失效 = 这条判据悄悄脱离看管。绝不能跳过。
                bad.append(f"{name}: 锚点在 {rel} 里找不到了 —— 代码重构了？"
                           "变异清单跟着更新，别让它静默失效")
                print(f"  ✗ {name:32s} 锚点失效")
                continue
            if src.count(old) != 1:
                bad.append(f"{name}: 锚点在 {rel} 里出现 {src.count(old)} 次，"
                           "不唯一，变异落点不确定")
                continue

            watchers = [g for g in cands if g in green]
            if not watchers:
                bad.append(f"{name}: 候选门禁一个都不是原样绿的，验不了")
                continue

            open(path, "w").write(src.replace(old, new, 1))
            if rel.startswith("csrc/"):
                _force_rebuild(work)
            try:
                red = [g for g in watchers if _run(work, g) != 0]
            finally:
                open(path, "w").write(src)     # 还原：写回原字节，不碰 git
                if rel.startswith("csrc/"):
                    _force_rebuild(work)

            if red:
                guarded += 1
                print(f"  ✅ {name:32s} → 变红 {red}")
            else:
                print(f"  ✗ {name:32s} → 一个都没红（试了 {watchers}）")
                bad.append(f"{name} 改坏之后没有任何门禁变红 —— "
                           f"「{why}」这条判据无人看管")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print(f"\n{guarded}/{len(MUTANTS)} 条变异被门禁抓到")
    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'每条判据都有门禁把守' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
