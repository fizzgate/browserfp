"""门禁：跨库比较不可作为版本演进的证据。

实测同一版本在不同来源库里的指纹就不一致：
    Firefox133  wreq vs tls_client   差 2 项（extensions_ordered, psk_modes）
    Firefox135  wreq vs curl_cffi    差 1 项（record_size_limit）
    Firefox120  tls_client vs utls   差 2 项
各库抓包的环境、时间、feature 配置不同。因此"相邻版本指纹不同"若来自两个库，
既可能是版本演进、也可能只是库间建模差异，**不能据此下结论**。

这条曾导致真实的误判：先前用 tls_client:firefox_123 与 wreq:Firefox128 比较，
得出"Firefox 123↔128 差 3 项、中间必有变更点"，进而把 Firefox 124-127 判为
"不能安全替代的缺口"——而那个差异有多少来自版本、多少来自库，根本无从区分。

本门禁做两件事：
  1. 量出跨库分歧的规模（有多少同名版本在不同库里指纹不同）
  2. 断言 uamap 的 same-seg 判定只在同库相邻时成立

跑：python -m spec.test_cross_source
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.coverage import FIELDS, SET_FIELDS                # noqa: E402
from oracle.uamap import UAMapper                             # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "golden")

SOURCES = {
    "wreq": ("wreq_nosni.json", r"^(Chrome|Firefox|Edge|Safari)(\d+)$"),
    "tls_client": ("tls_client_nosni.json", r"^(chrome|firefox|edge|safari)_(\d+)$"),
    "utls": ("utls_nosni.json", r"^(Chrome|Firefox|Edge|Safari)_(\d+)$"),
    "curl_cffi": ("curl_cffi_nosni.json", r"^(chrome|firefox|edge|safari)(\d+)$"),
}


def norm(fp):
    return {f: (sorted(fp.get(f) or []) if f in SET_FIELDS else fp.get(f))
            for f in FIELDS}


def t_cross_source_divergence():
    """量出跨库分歧：同 品牌+版本 在不同库里是否一致。"""
    tables = {}
    for src, (fn, pat) in SOURCES.items():
        path = os.path.join(GOLDEN, fn)
        if not os.path.exists(path):
            continue
        with open(path) as f:
            data = json.load(f)
        rx = re.compile(pat)
        for k, v in data.items():
            m = rx.match(k)
            if m:
                tables.setdefault((m.group(1).lower(), int(m.group(2))), {})[src] = v

    shared = {k: v for k, v in tables.items() if len(v) > 1}
    diverge = []
    for key, per_src in shared.items():
        vals = list(per_src.items())
        base_src, base = vals[0]
        for src, fp in vals[1:]:
            d = [f for f in FIELDS if norm(base)[f] != norm(fp)[f]]
            if d:
                diverge.append((key, base_src, src, d))
    ratio = len(diverge) / len(shared) if shared else 0
    return True, (f"{len(shared)} 个版本被多库同时收录，"
                  f"其中 {len(diverge)} 个存在跨库分歧（{ratio*100:.0f}%）")


def t_same_seg_is_intra_source():
    """same-seg 判定必须两端同库 —— 否则那个"相同"没有意义。"""
    m = UAMapper()
    bad = []
    for brand, table in m.by_brand.items():
        vs = sorted(table)
        for i in range(len(vs) - 1):
            lo, hi = vs[i], vs[i + 1]
            if hi - lo <= 1:
                continue
            probe = lo + 1
            klo, khi = table[lo][1], table[hi][1]
            if klo != khi:
                continue
            rlo, rhi = table[lo][0], table[hi][0]
            slo = {a.split(":", 1)[0] for a in [rlo["id"]] + rlo.get("aliases", [])}
            shi = {a.split(":", 1)[0] for a in [rhi["id"]] + rhi.get("aliases", [])}
            if slo & shi:
                continue
            # 两端指纹相同但来自不同库 —— uamap 必须**不**判为 same-seg
            ua = {"chrome": f"Mozilla/5.0 AppleWebKit/537.36 Chrome/{probe}.0.0.0 Safari/537.36",
                  "firefox": f"Mozilla/5.0 rv:{probe}.0 Gecko/20100101 Firefox/{probe}.0",
                  "edge": f"Mozilla/5.0 AppleWebKit/537.36 Chrome/{probe}.0.0.0 Safari/537.36 Edg/{probe}.0.0.0",
                  }.get(brand)
            if not ua:
                continue
            if m.lookup(ua)["confidence"] == "same-seg":
                bad.append(f"{brand} {probe}（{lo}/{hi} 跨库）")
    return not bad, ("same-seg 均为同库判定" if not bad
                     else f"跨库被误判为 same-seg: {bad[:4]}")


def main():
    tests = [("跨库分歧规模", t_cross_source_divergence),
             ("same-seg 仅同库成立", t_same_seg_is_intra_source)]
    failed = 0
    for name, fn in tests:
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        print(f"  {'✅' if ok else '❌'} {name:20s} {detail}")
        failed += 0 if ok else 1
    print(f"\n{len(tests) - failed}/{len(tests)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
