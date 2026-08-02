"""`spec/profiles.json` 必须与 golden 同步 —— 它是落盘产物，会僵尸化。

**这是 TLS 侧一直缺的一环**。h2 表早就有同样的检查（`test_h2_table` 的"与判据
同步"），而 profiles.json 一直没有：所有门禁读的都是这份已提交的产物，golden
被改坏、或判据变了没重建，全部门禁照样绿。

实测过：清空 `spec/golden/real_browsers.json` 后，把不联网的门禁全跑一遍，
**没有一个变红**。

判据是拿 `oracle.registry.build()` 现算一遍，与落盘的逐条比。比的是**指纹身份**
（id、别名集合、13 个确定性字段）**加上 h2/h3 载荷**，不比 `versions` 这类会随
判据微调的注解 —— 那些变动是正常演进，钉太死会变成每次改判据都要重跑的噪声。

h2/h3 载荷是后加的：第一版只比 TLS 那 13 个字段，于是清空
`spec/golden/h3_real_browsers.json` 之后本门禁**照样绿** —— 那份 golden 明明被
`registry.py` 读，却没有任何门禁看着它。实测确认过：清 quic 那份会红（TLS 指纹
变了），清 h3 那份不会（h3 不在比对集里）。

跑：python -m spec.test_registry_fresh
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.coverage import FIELDS, SET_FIELDS                   # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "profiles.json")

# 防平凡通过：golden 读空时 build() 会返回空表，"0 条一致"看着是绿的
MIN_PROFILES = 50


def _norm(tls, field):
    v = tls.get(field)
    return sorted(v) if field in SET_FIELDS and v else v


def _ident(rec):
    """一条 profile 的"身份"：id + 别名集合 + 13 个确定性字段 + h2/h3 载荷。"""
    h2 = (rec.get("h2") or {}).get("akamai_fingerprint")
    h3 = (rec.get("h3") or {}).get("h3_text")
    return (rec["id"], tuple(sorted(rec.get("aliases") or [])),
            tuple(str(_norm(rec["tls"], f)) for f in FIELDS), h2, h3)


def main():
    with open(REGISTRY) as f:
        stored = json.load(f)
    try:
        from oracle.registry import build
        # build() 返回的是 {指纹键: 记录} 的字典（键是 13 字段的 JSON 串），
        # 不是列表 —— 落盘时才摊成数组。这里取 values()。
        fresh = list(build().values())
    except Exception as e:
        print(f"重建失败：{type(e).__name__}: {str(e)[:120]}", file=sys.stderr)
        return 1

    a = {r["id"]: _ident(r) for r in stored}
    b = {r["id"]: _ident(r) for r in fresh}
    only_stored = sorted(set(a) - set(b))
    only_fresh = sorted(set(b) - set(a))
    drift = [k for k in set(a) & set(b) if a[k] != b[k]]

    print(f"落盘 {len(a)} 条 / 现算 {len(b)} 条")
    print(f"  只在落盘里 {len(only_stored)}   只在现算里 {len(only_fresh)}   "
          f"同 id 但内容不同 {len(drift)}")

    bad = []
    for k in only_stored[:4]:
        bad.append(f"{k}: 落盘里有、从 golden 重建不出来 —— golden 被改坏了？")
    for k in only_fresh[:4]:
        bad.append(f"{k}: golden 里能建出来、落盘里没有 —— 忘了重建 profiles.json？")
    for k in drift[:4]:
        bad.append(f"{k}: 指纹身份与重建结果不同 —— 落盘产物僵尸化了")

    if len(b) < MIN_PROFILES:
        bad.append(f"重建只得到 {len(b)} 条（下限 {MIN_PROFILES}）—— "
                   "golden 被清空的话，「0 条一致」也是绿的")

    for x in bad:
        print(f"  ✗ {x}")
    print(f"\n{'落盘产物与 golden 同步' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
