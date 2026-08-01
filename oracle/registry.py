"""合成最终 profile 注册表 —— 给 C 模块读的交付物。

三个来源合并去重：
  curl_cffi   31 个（Chrome≤136 / Firefox≤135）
  tls_client  67 个 TLS + 71 个 h2（Chrome≤146 / Firefox≤147 / Opera / OkHttp）
  real        4 个真机采集（补两库都没跟上的当前版本）

**严禁自我确认**：真机 profile 进交付表是对的（它就是我们要覆盖的目标形态），
但绝不能拿它去证明"开源表覆盖了真机"——用真机指纹匹配真机必然 0 差异，那是
循环论证。所以 provenance 字段把两类严格分开，coverage.py 判覆盖率时只读
开源表（SOURCES），不读本注册表。

去重按 TLS 指纹的 13 个确定性字段：同指纹的多个名字并成 aliases，因为
"覆盖了多少浏览器"要数唯一指纹，不是数名字（tls_client 里 safari_ios_15_5 /
15_6 / 16_0 / 17_0 是同一个指纹的四个名字）。
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.coverage import FIELDS, SET_FIELDS                # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
G = os.path.join(HERE, "..", "spec", "golden")
OUT = os.path.join(HERE, "..", "spec", "profiles.json")

# (来源标签, TLS golden, h2 golden, provenance, mode)
#
# mode=resumed 是会话恢复形态（ClientHello 带 pre_shared_key）。它**必须单列**
# 而不能与首连混为一谈：同一个 profile 的两种形态 JA4 完全不同，用首连的表去
# 认恢复连接一个都认不出。浏览器打开站点后的后续请求基本都走会话复用，这部分
# 流量占比很高。
SOURCES = [
    ("curl_cffi", "curl_cffi_nosni.json", "h2_curl_cffi.json", "opensource-table", "initial"),
    ("tls_client", "tls_client_nosni.json", "h2_tls_client.json", "opensource-table", "initial"),
    ("real", "real_browsers.json", "h2_real_browsers.json", "real-capture", "initial"),
    ("curl_cffi_psk", "curl_cffi_psk.json", "h2_curl_cffi.json", "opensource-table", "resumed"),
]


def _load(name):
    path = os.path.join(G, name)
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def _key(fp):
    return json.dumps(
        {f: (sorted(fp.get(f) or []) if f in SET_FIELDS else fp.get(f))
         for f in FIELDS}, sort_keys=True)


def build():
    registry = {}
    for source, tls_file, h2_file, provenance, mode in SOURCES:
        tls_data = _load(tls_file)
        h2_data = _load(h2_file)
        for name, entry in tls_data.items():
            # real_browsers.json 多包一层 {version, engine, fingerprint}
            fp = entry.get("fingerprint", entry)
            version = entry.get("version")
            k = _key(fp)
            rec = registry.setdefault(k, {
                "id": f"{source}:{name}",
                "aliases": [],
                "provenance": provenance,
                "mode": mode,
                "tls": fp,
                "h2": None,
                "versions": [],
            })
            rec["aliases"].append(f"{source}:{name}")
            if version:
                rec["versions"].append(version)
            # 真机来源优先当 id：它是当前版本的权威形态
            if provenance == "real-capture":
                rec["id"] = f"{source}:{name}"
                rec["provenance"] = provenance
            h2 = h2_data.get(name)
            if h2 and not rec["h2"]:
                rec["h2"] = {
                    "akamai_fingerprint": h2.get("akamai_fingerprint"),
                    "settings": h2.get("settings"),
                    "window_update": h2.get("window_update"),
                    "priorities": h2.get("priorities"),
                    "pseudo_header_order": h2.get("pseudo_header_order"),
                }
    return registry


def main():
    registry = build()
    out = sorted(registry.values(), key=lambda r: r["id"])

    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")

    by_prov, by_mode, with_h2 = {}, {}, 0
    for rec in out:
        by_prov[rec["provenance"]] = by_prov.get(rec["provenance"], 0) + 1
        by_mode[rec["mode"]] = by_mode.get(rec["mode"], 0) + 1
        if rec["h2"]:
            with_h2 += 1

    total_names = sum(len(r["aliases"]) for r in out)
    print(f"注册表：{len(out)} 个唯一指纹（来自 {total_names} 个 target 名）")
    for prov, n in sorted(by_prov.items()):
        print(f"  {prov:18s} {n}")
    for mode, n in sorted(by_mode.items()):
        print(f"  形态 {mode:<13} {n}")
    print(f"  含 h2 层           {with_h2}/{len(out)}")
    print(f"\n→ {os.path.normpath(OUT)}")

    missing_h2 = [r["id"] for r in out if not r["h2"]]
    if missing_h2:
        print(f"\n缺 h2 层的 {len(missing_h2)} 个（只有 TLS 层，C 模块跑 h2 时不可用）：")
        print("  " + " ".join(missing_h2[:14]) + (" …" if len(missing_h2) > 14 else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
