"""按 akamai 指纹反查（入站识别）：闭环、前提成立、且不夸大识别力。

本项目一直是双向的 —— 出站按 UA 造指纹，入站按指纹认浏览器。TLS 侧早有
`identify()`（按 ja4 查），h2 侧的数据一直都在（记录里就带 akamai），却没有
反查接口。

**先量识别力再定接口形态**：实测 644 个 (品牌,版本) 只归成 **19 个** akamai，
最常见的一个覆盖 223 个组合。所以这一层能回答的是**引擎**，不是版本 ——
接口据此返回 engine 与一个版本区间，而不是假装能给出确切版本。

三件事：

  1. **闭环**：h2 表里每一条的 akamai 反查回来，引擎必须与它自己的品牌相符，
     版本必须落在返回的区间内。
  2. **前提仍成立**：没有一个 akamai 跨引擎。这是反查有意义的**唯一**理由 ——
     跨了就只能报"不确定"，而不是继续给一个引擎名。生成器里也有同样的断言，
     这里再验一次，因为它是接口语义的基础。
  3. **不夸大**：区间宽度必须真的很宽（最常见那条覆盖上百个版本）。若哪天
     每条 akamai 都只对应一两个版本，说明数据变了，接口语义该重新审 ——
     那时"只能认引擎"这句话就成了没必要的保守。

跑：python -m spec.test_h2_identify
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
IDCLI = os.path.join(ROOT, "csrc", "idcli")
TABLE = os.path.join(HERE, "h2table.json")


def engine_of(brand):
    base = brand.split("-")[0]
    return ("chromium" if base in ("chrome", "chromium", "edge", "opera")
            else "gecko" if base == "firefox" else "webkit")


def main():
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0 or not os.path.exists(IDCLI):
        print(f"C 侧没构建出来：{(r.stderr or r.stdout)[-160:]}", file=sys.stderr)
        return 2

    with open(TABLE) as f:
        table = json.load(f)

    cases = [(b, int(v), table[b][v]["akamai_fingerprint"])
             for b in sorted(table) for v in sorted(table[b], key=int)]
    out = subprocess.run([IDCLI], input="\n".join(fp for _, _, fp in cases),
                         capture_output=True, text=True, timeout=120).stdout.splitlines()

    bad, ok = [], 0
    by_fp = {}
    for (brand, ver, fp), line in zip(cases, out):
        by_fp.setdefault(fp, set()).add((engine_of(brand), ver))
        if line == "-":
            bad.append(f"{brand} {ver}: 自己的指纹反查不出来")
            continue
        eng, lo, hi = line.split("\t")
        if eng != engine_of(brand):
            bad.append(f"{brand} {ver}: 反查得 {eng}，实为 {engine_of(brand)}")
        elif not (int(lo) <= ver <= int(hi)):
            bad.append(f"{brand} {ver}: 不在返回区间 {lo}-{hi} 内")
        else:
            ok += 1

    print(f"反查闭环   {ok}/{len(cases)} 条")
    print(f"  {len(cases)} 个 (品牌,版本) → {len(by_fp)} 个不同的 akamai")

    # 前提：没有一个 akamai 跨引擎
    mixed = {fp: sorted({e for e, _ in s}) for fp, s in by_fp.items()
             if len({e for e, _ in s}) > 1}
    if mixed:
        bad.append(f"有 akamai 跨引擎，反查语义不成立：{list(mixed.items())[:2]}")
    else:
        print("  没有一个 akamai 跨引擎 —— 反查引擎这一层是确定的")

    # 不夸大：识别力确实粗
    widest = max(len(s) for s in by_fp.values())
    print(f"  最粗的一条覆盖 {widest} 个 (引擎,版本) 组合")
    if widest < 20:
        bad.append(f"最粗的 akamai 只覆盖 {widest} 个组合 —— 识别力比预期高得多，"
                   "「只能认引擎」这句话该重新审，接口也许能给出更精确的答案")

    for b in bad[:8]:
        print(f"  ✗ {b}")
    print(f"\n{'h2 反查可信' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
