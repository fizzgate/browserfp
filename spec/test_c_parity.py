"""C 实现与 Python 实现的差分门禁 —— C 版的唯一验收标准。

Python 侧的 clienthello.py 是权威：它的行为已被真机数据与 RFC 官方向量反复校准
（GREASE 剔除、JA4 各段的排序与占位、SNI/ALPN 排除规则）。C 版不做"照规范重写"
的独立实现，而是要求**在全部 golden 样本上与 Python 输出逐字符一致**。

样本来源：注册表里每条 profile 都能用 chbuild 重建出 ClientHello 字节，直接拿
这些字节喂给两边，比 JA4 字符串。

跑：python -m spec.test_c_parity
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chbuild import build_client_hello                 # noqa: E402
from oracle.clienthello import fingerprint                    # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLI = os.path.join(ROOT, "csrc", "ja4cli")
REGISTRY = os.path.join(HERE, "profiles.json")

# 防平凡通过：注册表被截断或读空时，"0 一致，0 不符"看着是绿的 —— 实测过，
# 清空 profiles.json 后本门禁照样退出码 0。下限**不是棘轮**，它只回答
# "比对集是不是还在"，所以取一个远低于真实值（81）又远高于零的数。
MIN_PROFILES = 50



def _make():
    """**门禁自己跑 make**，不能依赖跑的人记得编。

    实测：改坏 `tlsfp.c` 里 JA4 的 cipher 排序，本门禁照样 82/82 全绿 ——
    它比的是上一次编出来的旧 `ja4cli`。这是本项目第 5 次撞"用了 stale 产物
    所以断言失灵"，前四次分别是 fuzzcli、profiles 表、libtlsfp.so 与 .o。
    退出码非零必须判失败，不能只看产物在不在（编译失败时旧产物还在原地）。
    """
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"make 失败：{(r.stderr or r.stdout)[-300:]}", file=sys.stderr)
        return False
    return True

def main():
    if not _make():
        return 2
    if not os.path.exists(CLI):
        print(f"缺 {CLI}；先在 csrc 下编译：\n"
              f"  cc -O2 -I$(brew --prefix openssl@3)/include -o ja4cli "
              f"tlsfp.c ja4cli.c -L$(brew --prefix openssl@3)/lib -lcrypto",
              file=sys.stderr)
        return 2

    with open(REGISTRY) as f:
        registry = json.load(f)

    records, expected, names = [], [], []
    for rec in registry:
        try:
            raw = build_client_hello(rec["tls"], sni=None)
        except Exception:
            continue
        records.append(raw.hex())
        expected.append(fingerprint(raw)["ja4"])
        names.append(rec["id"])

    out = subprocess.run([CLI], input="\n".join(records), capture_output=True,
                         text=True, timeout=60)
    got = [l for l in out.stdout.splitlines() if l.strip()]

    if len(got) != len(expected):
        print(f"输出条数不符：C {len(got)} vs Python {len(expected)}",
              file=sys.stderr)
        return 1

    bad = [(n, e, g) for n, e, g in zip(names, expected, got) if e != g]
    _n_compared = len(expected)
    print(f"差分比对 {len(expected)} 个 profile："
          f"{len(expected) - len(bad)} 一致，{len(bad)} 不符")
    for n, e, g in bad[:10]:
        print(f"  ✗ {n}\n      Python {e}\n      C      {g}")
    # 比对集为空时上面每一项都会"通过" —— 实测过：清空
    # profiles.json 后本门禁照样退出码 0，打印"0 一致，0 不符"。
    if _n_compared < MIN_PROFILES:
        print(f"  ✗ 只比对了 {_n_compared} 条（下限 "
              f"{MIN_PROFILES}）—— 注册表被截断或读空了？")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
