"""源码推出的 `sec-ch-ua` 必须与真机实采逐字节相同。

`sec-ch-ua` 是伪装里最容易露馅的一项：它含一个按主版本号确定性生成的 GREASE
品牌，既非固定串也非随机串，手写必然对不上，而它就明晃晃摆在请求头里。

**先验证再使用**（Safari coreTLS 那次的规矩）。实采取自本机三个真实浏览器，
刻意覆盖三条不同分支：

    chrome-151     三项列表 + 品牌名 "Google Chrome"
    chromium-142   **两项列表** —— CHROMIUM_BRANDING 构建没有品牌项，
                   走 GetRandomOrder 的 size==2 分支
    edge-151       同 151 的 GREASE 品牌，只换品牌名

只验 chrome 一条是不够的：两项分支和品牌替换各自都可能单独写错，而错了之后
另外两条仍会绿。

实采怎么来的记在 golden 里的 `how` 字段 —— UA-CH 只在安全上下文发送，
而 localhost 算安全上下文，所以本地 HTTP 服务就能采到，不用自签证书。

跑：python -m spec.test_uach
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.uach import assert_scatter, sec_ch_ua                # noqa: E402
from oracle.uach import _src                                     # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.path.join(HERE, "golden", "uach_real.json")


def main():
    with open(REAL) as f:
        real = json.load(f)
    if not real:
        print("实采表是空的 —— 这不是通过，是没验到", file=sys.stderr)
        return 1

    bad, ok = [], 0
    shapes = set()
    for name, rec in sorted(real.items()):
        try:
            got = sec_ch_ua(rec["major"], rec["brand"])
        except Exception as e:
            bad.append(f"{name}: 推导失败 {type(e).__name__}: {str(e)[:60]}")
            continue
        shapes.add((rec["brand"] is None, rec["brand"]))
        if got == rec["sec_ch_ua"]:
            ok += 1
        else:
            bad.append(f"{name}\n      源码推出 {got}\n      真机实采 {rec['sec_ch_ua']}")

    print(f"源码推导 vs 真机实采   {ok}/{len(real)} 逐字节相同")
    for name, rec in sorted(real.items()):
        print(f"  {name:14s} {rec['sec_ch_ua']}")
    for b in bad:
        print(f"  ✗ {b}")

    # 洗牌方向实采验不到（本机能拿到的版本置换全是自逆的，散射与收集等价），
    # 只能从源码断言。变异测试实证过：把散射改成收集，三条实采依然 3/3。
    try:
        assert_scatter(_src(151))
        print("  洗牌方向     源码确认为散射（实采区分不了这条，见 uach.py）")
    except Exception as e:
        bad.append(f'洗牌方向断言失败：{e}')

    # 平凡通过防护：两项分支（brand 为空）必须被验到，否则 CHROMIUM_BRANDING
    # 构建那条路等于没测 —— 而它是唯一会让列表长度变化的分支。
    if ok and not any(is_none for is_none, _ in shapes):
        bad.append("没有一条验到「无品牌」（两项列表）分支")
    if ok and len({b for _, b in shapes if b}) < 2:
        bad.append("只验到一个品牌名 —— 品牌替换那条路没被覆盖")

    # C 表由 gen_profiles 独立生成，必须与 Python 逐条一致 —— 只验 Python
    # 的话，C 侧漏一条或转义错了照样绿，而生产跑的是 C 那份。
    import subprocess
    table_path = os.path.join(os.path.dirname(HERE), "spec", "uach.json")
    exe = os.path.join(os.path.dirname(HERE), "csrc", "uachcli")
    r = subprocess.run(["make", "-s"], cwd=os.path.join(os.path.dirname(HERE), "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0 or not os.path.exists(exe):
        bad.append(f"C 侧没构建出来：{(r.stderr or r.stdout)[-120:]}")
    else:
        with open(table_path) as f:
            table = json.load(f)
        cases = [(b, v) for b in sorted(table) for v in sorted(table[b], key=int)]
        out = subprocess.run([exe], input="\n".join(f"{b} {v}" for b, v in cases),
                             capture_output=True, text=True, timeout=60).stdout.splitlines()
        diff = sum(1 for (b, v), got in zip(cases, out) if got != table[b][v])
        print(f"  C/Python 一致  {len(cases) - diff}/{len(cases)}")
        if diff:
            bad.append(f"C 表与 Python 差 {diff} 条")
        if len(cases) < 100:
            bad.append(f"表里只有 {len(cases)} 条 —— 太少，怀疑生成时大面积弃权")

    print(f"\n{'sec-ch-ua 推导可信' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
