"""三层一致性：自己拼的必须自洽，跨引擎拼的必须被抓出来。

检测方查的就是这个 —— TLS 指纹说 Chromium 而 h2 说 Gecko，一眼就假。所以库
自己也得能查：使用者能拿它自审伪装，我们能拿它守住"库产出的三层永远同源"。

**两侧都要验**，只验一侧都是半个门禁：

  正向  库为每个 (品牌,版本) 产出的 (ja4, akamai, 头顺序) 三元组必须判 ok。
        这一条挂了说明库自己就在产出矛盾的组合。
  反向  故意跨引擎拼的三元组必须判 mismatch。只验正向的话，一个恒返回 ok
        的实现也能全绿 —— 那正是最坏的情况：使用者以为自审过了。

另外验两条语义：

  · 信息不足时报 unknown，不报 ok。只有一层认得出来时谈不上"一致"。
  · 头顺序按**子序列**匹配，多解时报"认不出"而不是硬选一个。实测 600 个随机
    子序列里 549 个唯一，短子集（3 个头）容易多解 —— 那时必须弃权。

跑：python -m spec.test_coherence
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.headerorder import engine_orders, order_for          # noqa: E402
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
            od, _ = order_for(brand)
            if not pid or not ak or not od:
                continue
            ja4 = regs[pid]["tls"].get("ja4")
            if not ja4:
                continue
            fwd.append(f"{ja4}\t{ak}\t{','.join(od)}")
            meta.append((brand, ver))

    bad = []
    res = run(fwd)
    ok = sum(1 for v in res if v[0] == "ok")
    for (brand, ver), v in zip(meta, res):
        if v[0] != "ok":
            bad.append(f"{brand} {ver}: 库自己产出的三层判 {v[0]}（{v[1:]}）")
    print(f"正向：库产出的三元组   {ok}/{len(fwd)} 判 ok")
    if len(fwd) < 300:
        bad.append(f"只凑出 {len(fwd)} 个三元组，太少 —— 怀疑取数据的口径错了")

    # 反向：故意跨引擎
    orders = {e: o for e, (o, _) in engine_orders().items()}
    cross, tags = [], []
    pairs = [("chrome", 151, "firefox", 135), ("firefox", 135, "safari", 26),
             ("safari", 26, "chrome", 151)]
    for b1, v1, b2, v2 in pairs:
        pid = mapper.lookup(TARGETS[b1][0].format(v=v1))["profile"]
        ja4 = regs[pid]["tls"]["ja4"]
        ak2 = h2t[b2][str(v2)]["akamai_fingerprint"]
        od1 = ",".join(orders[engine_of(b1)])
        cross.append(f"{ja4}\t{ak2}\t{od1}")
        tags.append(f"TLS={b1} + h2={b2}")
        ak1 = h2t[b1][str(v1)]["akamai_fingerprint"]
        od2 = ",".join(orders[engine_of(b2)])
        cross.append(f"{ja4}\t{ak1}\t{od2}")
        tags.append(f"TLS/h2={b1} + 头序={b2}")
    caught = 0
    for tag, v in zip(tags, run(cross)):
        if v[0] == "mismatch":
            caught += 1
        else:
            bad.append(f"跨引擎却没被抓：{tag} → {v[0]}")
    print(f"反向：跨引擎组合       {caught}/{len(cross)} 判 mismatch")

    # 语义：信息不足 → unknown；短子集多解 → 头层认不出
    pid = mapper.lookup(TARGETS["chrome"][0].format(v=151))["profile"]
    ja4 = regs[pid]["tls"]["ja4"]
    ak = h2t["chrome"]["151"]["akamai_fingerprint"]
    sem = run([f"{ja4}\t-\t-", f"{ja4}\t{ak}\taccept,sec-fetch-site,sec-fetch-user"])
    if sem[0][0] != "unknown":
        bad.append(f"只有一层却判 {sem[0][0]} —— 谈不上一致就该报 unknown")
    if sem[1][3] != "-":
        bad.append(f"短子集多解却认成了 {sem[1][3]} —— 该弃权")
    print(f"语义：信息不足→unknown、短子集多解→弃权   "
          f"{'OK' if sem[0][0] == 'unknown' and sem[1][3] == '-' else '失败'}")

    for b in bad[:8]:
        print(f"  ✗ {b}")
    print(f"\n{'三层一致性可信' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
