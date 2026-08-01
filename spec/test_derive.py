"""派生规则门禁：库里的 source-derived profile 必须仍然站得住。

`oracle/derive.py` 按源码给出的平台差异，从桌面 golden 派生移动端 profile。
它每次运行都会自检规则，但**没人跑它的时候规则失效了也没人知道** —— 而库里
已经躺着派生出来的 profile 在服务生产映射。

查三件事：
  1. 派生规则在锚点版本上仍成立（桌面 − 平台差异 = 实采移动端，逐字段一致）
  2. 库里每条 source-derived profile 都能从它记录的来源**重新派生出来**，
     且结果与库里存的一致 —— 源 profile 若被更新过，派生结果就该跟着变
  3. source-derived 的 provenance 没有混进 real-capture 统计

第 2 条是这个门禁的核心：派生产物是**推导结果而非观测**，一旦它的输入变了却
没重新派生，库里那份就成了无人负责的陈旧数据。

跑：python -m spec.test_derive
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.coverage import FIELDS, SET_FIELDS                 # noqa: E402
from oracle.derive import (ANCHOR, derive, verify_rule,        # noqa: E402
                           _load_registry)

HERE = os.path.dirname(os.path.abspath(__file__))
DERIVED_GOLDEN = os.path.join(HERE, "golden", "derived_mobile.json")
REGISTRY = os.path.join(HERE, "profiles.json")


def _norm(tls, field):
    v = tls.get(field)
    return sorted(v) if field in SET_FIELDS and v else v


def check_rules(registry):
    """每个有锚点的品牌，派生规则都必须仍成立。"""
    bad, checked = [], 0
    for brand in ANCHOR:
        ok, why = verify_rule(brand, registry)
        checked += 1
        if not ok:
            bad.append(f"{brand}: {why}")
    return bad, checked


def check_reproducible(registry):
    """库里每条派生 profile 都必须能从记录的来源重新派生出同样的结果。"""
    if not os.path.exists(DERIVED_GOLDEN):
        return [], 0
    with open(DERIVED_GOLDEN) as f:
        entries = json.load(f)

    bad, checked = [], 0
    for name, entry in entries.items():
        src_alias = entry.get("derived_from")
        stored = entry.get("fingerprint") or {}
        if not src_alias:
            bad.append(f"{name}: 没记 derived_from，无从复现")
            continue
        # 名字形如 firefox-mobile-153
        parts = name.rsplit("-", 1)
        if len(parts) != 2 or not parts[1].isdigit():
            bad.append(f"{name}: 名字里读不出品牌与版本")
            continue
        brand, ver = parts[0], int(parts[1])
        checked += 1
        try:
            fresh, _ = derive(brand, ver, registry, src_alias)
        except Exception as e:
            bad.append(f"{name}: 重新派生失败 {type(e).__name__}: {e}")
            continue
        diff = [f for f in FIELDS if _norm(fresh, f) != _norm(stored, f)]
        if diff:
            bad.append(f"{name}: 重新派生的结果与库里存的不符，差异 {diff}"
                       f"（来源 {src_alias} 可能已更新，需重跑 oracle.derive）")
    return bad, checked


def check_provenance():
    """source-derived 不得混进 real-capture 统计。"""
    with open(REGISTRY) as f:
        registry = json.load(f)
    derived = [r for r in registry if r.get("provenance") == "source-derived"]
    mislabeled = []
    for rec in derived:
        names = [rec["id"]] + rec.get("aliases", [])
        if any(n.startswith("real:") or n.startswith("linux:") for n in names):
            mislabeled.append(rec["id"])
    return derived, mislabeled


def main():
    registry = _load_registry()

    rule_bad, n_rules = check_rules(registry)
    repro_bad, n_repro = check_reproducible(registry)
    derived, mislabeled = check_provenance()

    print(f"派生规则仍成立   {'OK' if not rule_bad else '失败'}（{n_rules} 个品牌）")
    for b in rule_bad:
        print(f"  ✗ {b}")
    print(f"派生结果可复现   {'OK' if not repro_bad else '失败'}（{n_repro} 条）")
    for b in repro_bad:
        print(f"  ✗ {b}")
    print(f"provenance 未混淆 {'OK' if not mislabeled else '失败'}"
          f"（{len(derived)} 条 source-derived）")
    for b in mislabeled:
        print(f"  ✗ {b} 被标成实采来源")

    for rec in derived:
        print(f"    {rec['id']}  ← 派生，不计入真机采集数")

    failed = len(rule_bad) + len(repro_bad) + len(mislabeled)
    print(f"\n{'派生链可信' if not failed else f'{failed} 处问题'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
