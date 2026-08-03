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
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chbuild import build_client_hello                    # noqa: E402
from oracle.clienthello import is_grease, parse_client_hello     # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KSCLI = os.path.join(ROOT, "csrc", "kscli")
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
                 "must_vary": {0x0033, 0xFE0D}, "grease": True,
                 "ua": ("chrome", 119)},
    "gecko":    {"profile": "real:firefox",
                 "must_vary": {0x0033, 0xFE0D}, "grease": False,
                 "ua": ("firefox", 135)},
    "webkit":   {"profile": "real:safari",
                 "must_vary": {0x000A, 0x002B, 0x0033}, "grease": True,
                 "ua": ("safari", 26)},
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


def observe_c(pid, rounds=ROUNDS):
    """走 **C 的出网口径**（kscli 不带前缀）看同样的性质。

    这一段是补上来的，理由很硬：`test_variation` 原来只查 Python 侧，而**生产走
    的是 C/Lua**。实测过一次真实后果 —— C 的旧签名当时默认 VERBATIM（为了不动
    既有调用方），Lua 绑定用的正是它，于是生产路径上 GREASE 恒为 0x4a4a/0x5a5a、
    ECH 恒为 218，**七处修复全是死的**，而所有门禁照样全绿。

    "写了但没接"这一类，只能靠**在发货那条路上取样**来发现。
    """
    outs = []
    for i in range(rounds):
        r = subprocess.run([KSCLI], input=f"{pid}\t\t\n", capture_output=True,
                           text=True, timeout=60).stdout.strip()
        if r and not r.startswith("ERR"):
            outs.append(parse_client_hello(bytes.fromhex(r)))
    if not outs:
        return None
    keys = set()
    for c in outs:
        keys |= set(c["extension_bodies"])
    varying = {int(k) for k in keys
               if len({c["extension_bodies"].get(k) for c in outs}) > 1}
    return varying, {tuple(c["raw_extensions"]) for c in outs}


LUA_SNIPPET = """
package.path = "%s/lua/?.lua;" .. package.path
local t = require "browserfp"
t.load("%s")
for i = 1, %d do
  local rec = t.client_hello("%s", %d, "example.com")
  if not rec then print("ERR"); os.exit(1) end
  print((rec:gsub('.', function(c) return string.format('%%02x', c:byte()) end)))
end
"""


def observe_lua(brand, version, rounds=ROUNDS):
    """走 **Lua FFI**（生产真正调的那层）看同样的性质。

    C CLI 与 Lua 之间还能再分叉一次：参数传错、绑定漏字段、走了另一个签名。
    上一处缺陷（七处修复在生产路径上全是死的）就是**手动去戳 Lua** 才发现的 ——
    当时 C CLI 那档已经在变了，因为它走的是另一个入口。

    没有 luajit 时返回 None（跳过，不冒充通过）。
    """
    lua = shutil.which("luajit") or shutil.which("resty")
    if not lua:
        return None
    lib = os.path.join(ROOT, "csrc", "libbrowserfp.so")
    if not os.path.exists(lib):
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".lua", delete=False) as f:
        f.write(LUA_SNIPPET % (ROOT, lib, rounds, brand, version))
        script = f.name
    try:
        out = subprocess.run([lua, script], capture_output=True, text=True,
                             timeout=120, cwd=ROOT)
    finally:
        os.unlink(script)
    caps = []
    for line in out.stdout.split():
        if len(line) > 100:
            try:
                caps.append(parse_client_hello(bytes.fromhex(line)))
            except Exception:
                pass
    if not caps:
        return None
    keys = set()
    for c in caps:
        keys |= set(c["extension_bodies"])
    varying = {int(k) for k in keys
               if len({c["extension_bodies"].get(k) for c in caps}) > 1}
    return varying, {tuple(c["raw_extensions"]) for c in caps}, len(caps)


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

    # —— 发货路径（C 出网口径）也要在变 ——
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0 or not os.path.exists(KSCLI):
        bad.append(f"C 侧没构建出来：{(r.stderr or r.stdout)[-120:]}")
    else:
        for engine, spec in sorted(EXPECT.items()):
            got = observe_c(spec["profile"])
            if got is None:
                bad.append(f"{engine}: C 侧构造不出 {spec['profile']}")
                continue
            varying, seqs = got
            # **key_share（0x33）不算在发货路径的必变项里**：C 库内不产密钥，
            # 公钥由调用方注入（架构约束，见 browserfp_build_client_hello_ex 的
            # browserfp_keyshare 参数），kscli 这里没注入，所以非 GREASE 的那几条
            # 恒定。chromium/webkit 之所以还在变，是因为里面那条 GREASE 在换。
            # "注入了公钥就必须用上"由 test_keyshare 单独验。
            missing = spec["must_vary"] - {0x0033} - varying
            if missing:
                bad.append(f"{engine} 的**发货路径**: "
                           f"{[hex(x) for x in sorted(missing)]} 每次都一样 —— "
                           "Python 侧在变而 C 侧不变，说明修复没接到生产那条路")
            if spec["grease"] and len(seqs) < 2:
                bad.append(f"{engine} 的**发货路径**: {ROUNDS} 次的扩展序列完全"
                           "一样 —— GREASE 没在换")
            print(f"  发货路径 {engine:9s} 变={sorted(hex(x) for x in varying & spec['must_vary'])} "
                  f"序列种类={len(seqs)}/{ROUNDS}")

    # —— Lua（生产真正调的那层）——
    for engine, spec in sorted(EXPECT.items()):
        ua = spec.get("ua")
        if not ua:
            continue
        got = observe_lua(*ua)
        if got is None:
            print(f"  ？ Lua {engine}: 缺 luajit 或 libbrowserfp.so，跳过（非通过）")
            continue
        varying, seqs, n = got
        missing = spec["must_vary"] - {0x0033} - varying
        if missing:
            bad.append(f"{engine} 的 **Lua 路径**: "
                       f"{[hex(x) for x in sorted(missing)]} 每次都一样 —— "
                       "C CLI 在变而 Lua 不变，说明绑定走了另一个入口")
        if spec["grease"] and len(seqs) < 2:
            bad.append(f"{engine} 的 **Lua 路径**: {n} 次的扩展序列完全一样 —— "
                       "GREASE 没在换")
        if not spec["grease"] and len(seqs) != 1:
            bad.append(f"{engine} 的 **Lua 路径**: 扩展序列有 {len(seqs)} 种 —— "
                       "这个栈的序列应当恒定")
        print(f"  Lua 路径 {engine:9s} 变={sorted(hex(x) for x in varying & spec['must_vary'])} "
              f"序列种类={len(seqs)}/{n}")

    # —— 反方向：h2 开场**必须恒定** ——
    #
    # 同一套方法扫 h2 层：三个引擎各连采 6~8 次，settings / window_update /
    # priorities / 伪头序 / 帧序 / akamai 指纹**没有一项在变**。所以我们发固定值
    # 是对的 —— 这一层没有第 8 处。
    #
    # 但要把这条**反过来钉住**：哪天有人照着 TLS 层的经验"顺手"给 h2 也加随机，
    # 那是把它变成一个不存在的浏览器。与 gecko 不发 GREASE 那条同理。
    h2cli = os.path.join(ROOT, "csrc", "h2cli")
    if not os.path.exists(h2cli):
        bad.append("缺 csrc/h2cli，h2 恒定性没验到")
    else:
        for engine, spec in sorted(EXPECT.items()):
            ua = spec.get("ua")
            if not ua:
                continue
            outs = set()
            for _ in range(4):
                r = subprocess.run([h2cli], input=f"{ua[0]} {ua[1]}\n",
                                   capture_output=True, text=True, timeout=60)
                outs.add(r.stdout.strip())
            if len(outs) != 1:
                bad.append(f"{engine} 的 h2 开场有 {len(outs)} 种 —— "
                           "三个引擎实测都恒定，随机化它等于造一个不存在的浏览器")
            print(f"  h2 恒定  {engine:9s} 4 次构造 {len(outs)} 种")

    if len(EXPECT) < 3:
        bad.append(f"只覆盖了 {len(EXPECT)} 个引擎 —— 差一个不扫，"
                   "那一族的缺陷就等于不存在")

    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'逐引擎的变化谱与真机一致' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
