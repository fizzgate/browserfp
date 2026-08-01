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

# 某条**实采**指纹经验证同时适用的其他主版本。
# 只在有硬证据时添加，并写明依据——这不是"猜测相邻版本相同"，而是把已验证的
# 等价关系记下来，避免为此往库里塞推导出来的假样本。
COVERS = {
    # surf 源码写明 HelloChrome_150 = HelloChrome_144 + 前置 ML-DSA；据此推导的
    # Chrome150 指纹与真机 Chrome151 实测 13 字段差异为 0。生产 UA 里 Chrome 150
    # 是第一大浏览器版本，必须能命中。
    # 注意：Chrome151 与 Edge151 指纹相同，去重后合并为一条，id 可能是任一别名。
    # 故这里按**当前实际 id** 写，且 uamap 会从全部 aliases 推断它服务哪些品牌。
    "real:edge": [150],

}

# (来源标签, TLS golden, h2 golden, provenance, mode)
#
# mode=resumed 是会话恢复形态（ClientHello 带 pre_shared_key）。它**必须单列**
# 而不能与首连混为一谈：同一个 profile 的两种形态 JA4 完全不同，用首连的表去
# 认恢复连接一个都认不出。浏览器打开站点后的后续请求基本都走会话复用，这部分
# 流量占比很高。
SOURCES = [
    ("curl_cffi", "curl_cffi_nosni.json", "h2_curl_cffi.json", "opensource-table", "initial"),
    ("tls_client", "tls_client_nosni.json", "h2_tls_client.json", "opensource-table", "initial"),
    ("wreq", "wreq_nosni.json", "h2_wreq.json", "opensource-table", "initial"),
    ("utls", "utls_nosni.json", None, "opensource-table", "initial"),
    ("real", "real_browsers.json", "h2_real_browsers.json", "real-capture", "initial"),
    ("curl_cffi_psk", "curl_cffi_psk.json", "h2_curl_cffi.json", "opensource-table", "resumed"),
    ("real_psk", "real_browsers_psk.json", "h2_real_browsers.json", "real-capture", "resumed"),
    # QUIC 的 ClientHello 是**独立形态**，不是 TCP 那份的附加字段：实测
    # Chrome 151 的 QUIC 版 10 个扩展、TCP 版 15 个，且含 quic_transport_parameters。
    # 用首连表去认 QUIC 连接一个都认不出，故必须单列。
    ("real_quic", "quic_real_browsers.json", None, "real-capture", "quic"),
    ("linux", "linux_browsers.json", None, "real-capture", "initial"),
    # 按源码给出的平台差异从桌面 golden 派生的移动端形态（oracle/derive.py）。
    # provenance 单列 source-derived，**不能混进 real-capture 的统计** ——
    # 它没有被任何来源实际观测过，只是规则推出来的。派生规则本身在有实采
    # golden 的锚点版本上验证过（桌面 Firefox 135 减 SCT 减 MLKEM = 实采
    # wreq:FirefoxAndroid135，逐字段一致），且每次派生都会重跑该验证。
    ("derived", "derived_mobile.json", None, "source-derived", "initial"),
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
        h2_data = _load(h2_file) if h2_file else {}
        for name, entry in tls_data.items():
            # real_browsers.json 多包一层 {version, engine, fingerprint}
            fp = entry.get("fingerprint", entry)
            # QUIC 形态的 JA4 首字符按规范是 q（t=TCP / q=QUIC）。
            # fingerprint() 是传输层无关的通用函数，恒产出 t 开头，故在此规范化——
            # 否则查表时 q 开头的实测值永远命中不了库里 t 开头的记录。
            if mode == "quic" and isinstance(fp.get("ja4"), str) \
                    and fp["ja4"].startswith("t"):
                fp = dict(fp, ja4="q" + fp["ja4"][1:])
            version = entry.get("version")
            k = _key(fp)
            # default_config：该形态是否为浏览器**默认配置**下发出的。
            # 非默认（需显式 --enable-features 才出现）的形态仍值得入库——Finch
            # 可能把它下发给部分真实用户——但识别时应优先按默认形态理解流量，
            # 也不必为枚举 flag 组合而扩表。
            flags = entry.get("flags") if isinstance(entry, dict) else None
            rec = registry.setdefault(k, {
                "id": f"{source}:{name}",
                "aliases": [],
                "provenance": provenance,
                "mode": mode,
                "default_config": not flags,
                "tls": fp,
                "h2": None,
                "h3": None,
                "versions": [],
            })
            rec["aliases"].append(f"{source}:{name}")
            if version:
                rec["versions"].append(version)
            # 真机来源优先当 id：它是当前版本的权威形态
            if provenance == "real-capture":
                rec["id"] = f"{source}:{name}"
                rec["provenance"] = provenance
            if mode == "quic":
                h3 = _load("h3_real_browsers.json").get(name)
                if h3 and not rec.get("h3"):
                    rec["h3"] = {"h3_text": h3.get("h3_text"),
                                 "settings": h3.get("settings"),
                                 "pseudo_header_order": h3.get("pseudo_header_order"),
                                 "has_grease_setting": h3.get("has_grease_setting")}
            # 派生条目把 h2 存在同一份 golden 里（derived_mobile.json 的
            # entry["h2"]），没有独立的 h2 文件 —— 只查 h2_data 会让派生 profile
            # 永远缺 h2 层，而只有 TLS 层的 profile 在生产里用不完整：伪装浏览器
            # 流量必然要发 HTTP/2，没有 SETTINGS 帧一看就露。
            h2 = h2_data.get(name)
            if h2 is None and isinstance(entry, dict):
                h2 = entry.get("h2")
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

    # 必须在写盘之前标注 —— 先前放在 json.dump 之后，导致 profiles.json 里
    # 一条 covers_versions 都没有，而终端输出看起来一切正常。
    for rec in out:
        extra = COVERS.get(rec["id"])
        if extra:
            rec["covers_versions"] = extra

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
    nondefault = [r["id"] for r in out if not r.get("default_config", True)]
    print(f"  默认配置形态       {len(out) - len(nondefault)}/{len(out)}"
          + (f"（非默认: {' '.join(nondefault)}）" if nondefault else ""))
    with_h3 = sum(1 for r in out if r.get("h3"))
    print(f"  含 h2 层           {with_h2}/{len(out)}")
    print(f"  含 h3 层           {with_h3}（QUIC 形态）")
    print(f"\n→ {os.path.normpath(OUT)}")

    missing_h2 = [r["id"] for r in out if not r["h2"]]
    if missing_h2:
        print(f"\n缺 h2 层的 {len(missing_h2)} 个（只有 TLS 层，C 模块跑 h2 时不可用）：")
        print("  " + " ".join(missing_h2[:14]) + (" …" if len(missing_h2) > 14 else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
