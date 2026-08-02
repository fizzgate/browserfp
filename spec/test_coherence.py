"""三层一致性：自己拼的必须自洽，跨引擎拼的必须被抓出来。

检测方查的就是这个 —— TLS 指纹说 Chromium 而 h2 说 Gecko，一眼就假。所以库
自己也得能查：使用者能拿它自审伪装，我们能拿它守住"库产出的三层永远同源"。

**两侧都要验**，只验一侧都是半个门禁：

  正向  库为每个 (品牌,版本) 产出的 (ja4, akamai, 头顺序) 三元组必须判 ok。
        这一条挂了说明库自己就在产出矛盾的组合。
  反向  故意跨引擎拼的三元组必须判 mismatch。只验正向的话，一个恒返回 ok
        的实现也能全绿 —— 那正是最坏的情况：使用者以为自审过了。

另外验四条语义：

  · 信息不足时报 unknown，不报 ok。只有一层认得出来时谈不上"一致"。
  · 头顺序按**子序列**匹配，多解时报"认不出"而不是硬选一个。实测 600 个随机
    子序列里 549 个唯一，短子集（3 个头）容易多解 —— 那时必须弃权。

  · **ALPN 与 h2 层不得矛盾**：有 h2 数据的组合，其 ClientHello 通告的 ALPN
    必须含 `h2`。当前 644 条全部相符；另有 3 条 ALPN 含 h2 却没有 h2 数据，
    那是合理的（走 HTTP/1.1，就是 safari 12-14 那三个缺口）。

  · **`by_ua` 绝不能返回会话恢复态的 profile**。库里有 15 条 `resumed`，它们
    带 `pre_shared_key`(41)，里面是采集当时的会话票据 —— 合成不出来。发一个
    带陈旧 binder 的恢复态握手，服务端验不过会退回完整握手，比干净的首连**更
    可疑**。`oracle/uamap.py` 里显式过滤了 `mode != "initial"`，这条断言守的就是
    那个过滤别被人"顺手优化掉"。

    **可达性单独验过**：只去掉那个过滤**不会**让本断言变红 —— 版本表用
    setdefault，先注册的 initial 条目已经占住了版本号，恢复态挤不进去。要同时
    改动注册顺序才会漏（去过滤 + 反转顺序 → 退出码 1；只反转顺序 → 0）。
    所以它守的是"双重保护同时失效"，不是摆设 —— 但也别指望单点变异能触发它。
    写下这一点，免得后人试一次没红就当它是死代码删掉。

跑：python -m spec.test_coherence
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.uamap import UAMapper                                # noqa: E402
from oracle.covscan import NEVER_RELEASED, TARGETS               # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
COHCLI = os.path.join(ROOT, "csrc", "cohcli")


def engine_of(brand):
    base = brand.split("-")[0]
    return ("chromium" if base in ("chrome", "edge", "opera")
            else "gecko" if base == "firefox" else "webkit")


def run(cases):
    out = subprocess.run([COHCLI], input="\n".join(cases), capture_output=True,
                         text=True, timeout=120).stdout.splitlines()
    return [l.split("\t") for l in out]


def main():
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0 or not os.path.exists(COHCLI):
        print(f"C 侧没构建出来：{(r.stderr or r.stdout)[-160:]}", file=sys.stderr)
        return 2

    with open(os.path.join(HERE, "profiles.json")) as f:
        regs = {x["id"]: x for x in json.load(f)}
    with open(os.path.join(HERE, "h2table.json")) as f:
        h2t = json.load(f)
    mapper = UAMapper()

    # 正向：库自己产出的三元组
    fwd, meta = [], []
    for brand, (tpl, lo, hi) in TARGETS.items():
        for ver in range(lo, hi + 1):
            if ver in NEVER_RELEASED.get(brand, set()):
                continue
            pid = mapper.lookup(tpl.format(v=ver)).get("profile")
            ak = (h2t.get(brand, {}).get(str(ver)) or {}).get("akamai_fingerprint")
            if not pid or not ak:
                continue
            ja4 = regs[pid]["tls"].get("ja4")
            if not ja4:
                continue
            fwd.append(f"{ja4}\t{ak}")
            meta.append((brand, ver))

    bad = []
    res = run(fwd)
    ok = sum(1 for v in res if v[0] == "ok")
    for (brand, ver), v in zip(meta, res):
        if v[0] != "ok":
            bad.append(f"{brand} {ver}: 库自己产出的两层判 {v[0]}（{v[1:]}）")
    print(f"正向：库产出的二元组   {ok}/{len(fwd)} 判 ok")
    if len(fwd) < 300:
        bad.append(f"只凑出 {len(fwd)} 个二元组，太少 —— 怀疑取数据的口径错了")

    # 反向：故意跨引擎
    cross, tags = [], []
    pairs = [("chrome", 151, "firefox", 135), ("firefox", 135, "safari", 26),
             ("safari", 26, "chrome", 151)]
    for b1, v1, b2, v2 in pairs:
        pid = mapper.lookup(TARGETS[b1][0].format(v=v1))["profile"]
        ja4 = regs[pid]["tls"]["ja4"]
        ak2 = h2t[b2][str(v2)]["akamai_fingerprint"]
        cross.append(f"{ja4}\t{ak2}")
        tags.append(f"TLS={b1} + h2={b2}")
    caught = 0
    for tag, v in zip(tags, run(cross)):
        if v[0] == "mismatch":
            caught += 1
        else:
            bad.append(f"跨引擎却没被抓：{tag} → {v[0]}")
    print(f"反向：跨引擎组合       {caught}/{len(cross)} 判 mismatch")

    # 语义：只有一层观测 → unknown（谈不上"一致"）
    pid = mapper.lookup(TARGETS["chrome"][0].format(v=151))["profile"]
    ja4 = regs[pid]["tls"]["ja4"]
    ak = h2t["chrome"]["151"]["akamai_fingerprint"]
    sem = run([f"{ja4}\t-", f"-\t{ak}"])
    for i, side in enumerate(("只有 TLS", "只有 h2")):
        if sem[i][0] != "unknown":
            bad.append(f"{side}却判 {sem[i][0]} —— 谈不上一致就该报 unknown")
    print(f"语义：单层观测→unknown   "
          f"{'OK' if all(x[0] == 'unknown' for x in sem) else '失败'}")

    # ALPN 与 h2 层不得矛盾
    alpn_bad, alpn_ok = 0, 0
    for brand, ver in meta:
        pid = mapper.lookup(TARGETS[brand][0].format(v=ver)).get("profile")
        alpn = regs[pid]["tls"].get("alpn") or []
        if "h2" in alpn:
            alpn_ok += 1
        else:
            alpn_bad += 1
            if alpn_bad <= 3:
                bad.append(f"{brand} {ver}: 有 h2 数据但 ALPN 不含 h2（{alpn}）"
                           " —— 通告的和实际要说的对不上")
    print(f"ALPN vs h2 层        {alpn_ok}/{alpn_ok + alpn_bad} 相符")

    # by_ua 绝不能给出会话恢复态
    resumed = {r["id"] for r in regs.values() if r.get("mode") != "initial"}
    leaked = set()
    for brand, (tpl, lo, hi) in TARGETS.items():
        for ver in range(lo, hi + 1):
            if ver in NEVER_RELEASED.get(brand, set()):
                continue
            pid = mapper.lookup(tpl.format(v=ver)).get("profile")
            if pid in resumed:
                leaked.add((brand, ver, pid))
    print(f"by_ua 不返回恢复态    {'OK' if not leaked else f'漏了 {len(leaked)} 个'}"
          f"（库里有 {len(resumed)} 条非 initial）")
    if leaked:
        bad.append(f"by_ua 返回了恢复态 profile：{sorted(leaked)[:3]} —— "
                   "那里面的 pre_shared_key 是采集当时的票据，发出去验不过，"
                   "服务端会退回完整握手，比干净的首连更可疑")
    if not resumed:
        bad.append("库里一条非 initial 的 profile 都没有 —— 这条断言等于没验")

    for b in bad[:8]:
        print(f"  ✗ {b}")
    print(f"\n{'两层一致性可信' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
