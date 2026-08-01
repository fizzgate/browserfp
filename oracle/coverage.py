"""覆盖矩阵：真机浏览器指纹 vs curl_cffi target 全集，逐字段判定。

回答的是"我们要覆盖市面主流，现在差多少"。判据不用 JA4——14 个 chrome target
只产生 4 个不同的 JA4，拿它当断言会假绿。用 FIELDS 里 13 个字段逐项比，
0 个差异才算被覆盖。

两侧必须都是 no-SNI 采集（curl_cffi_nosni.json + real_browsers.json）：真机侧
无法带域名 SNI（Chrome 151 的 --host-resolver-rules 已失效），拿带 SNI 的
golden 去比会凭空多出一个 SNI 扩展的差异。
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "..", "spec", "golden", "curl_cffi_nosni.json")
REAL = os.path.join(HERE, "..", "spec", "golden", "real_browsers.json")

# 两张开源表并用：curl_cffi 31 个但版本滞后（Chrome 停 136 / Firefox 停 135）；
# tls-client 76 个含 chrome_146 / firefox_147 / Opera / OkHttp。判"有没有覆盖"
# 必须看并集，只看其中一张会低估覆盖面。
SOURCES = [
    ("curl_cffi", os.path.join(HERE, "..", "spec", "golden", "curl_cffi_nosni.json")),
    ("tls_client", os.path.join(HERE, "..", "spec", "golden", "tls_client_nosni.json")),
]


def load_all_golden():
    """合并全部来源，key 形如 'curl_cffi:chrome136'，值是指纹。"""
    merged = {}
    for source, path in SOURCES:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for name, fp in json.load(f).items():
                merged[f"{source}:{name}"] = fp
    return merged


def dedupe_key(fp):
    """指纹去重键：两个 target 的这些字段全同就是同一个指纹，名字不同也算一个。"""
    return json.dumps({f: (sorted(fp.get(f) or []) if f in SET_FIELDS else fp.get(f))
                       for f in FIELDS}, sort_keys=True)

# 决定 TLS 指纹的字段全集。ja4 不在内——它是这些字段的有损摘要，只用于展示。
FIELDS = ["ciphers", "extensions_ordered", "curves", "sig_algs", "alpn",
          "supported_versions", "psk_modes", "cert_compression",
          "record_size_limit", "app_settings", "point_formats", "ech",
          "client_version"]

# 扩展顺序：Chromium 自 110 起每连接随机置换扩展顺序（RFC 8701），所以顺序本身
# 不能当判据，只比集合。Firefox/Safari 不置换，但统一按集合比更稳。
SET_FIELDS = {"extensions_ordered"}


def diff(real_fp, golden_fp):
    out = []
    for f in FIELDS:
        a, b = real_fp.get(f), golden_fp.get(f)
        if f in SET_FIELDS:
            a, b = sorted(a or []), sorted(b or [])
        if a != b:
            out.append((f, b, a))
    return out


def main():
    golden = load_all_golden()
    if not golden or not os.path.exists(REAL):
        print("缺 golden：先跑 `python -m oracle.collect --no-sni`、"
              "`python -m oracle.gocollect`、`python -m oracle.browsers`",
              file=sys.stderr)
        return 2

    with open(REAL) as f:
        real = json.load(f)

    unique = {dedupe_key(fp) for fp in golden.values()}
    print(f"开源表 target: {len(golden)}（去重后 {len(unique)} 个唯一指纹）"
          f"    真机样本: {len(real)}\n")
    print(f"{'真机浏览器':<26} {'最接近 target':<18} {'差异':<6} 缺口字段")
    print("-" * 78)

    gaps = []
    for name, entry in sorted(real.items()):
        fp = entry["fingerprint"]
        ranked = sorted((len(diff(fp, g)), t) for t, g in golden.items())
        n, best = ranked[0]
        label = f"{name} {entry['version']}"
        if n == 0:
            print(f"{label:<26} {best:<18} {'✅ 0':<6} —")
        else:
            fields = ", ".join(d[0] for d in diff(fp, golden[best]))
            print(f"{label:<26} {best:<18} {'❌ ' + str(n):<6} {fields}")
            gaps.append((name, entry["version"], best, diff(fp, golden[best])))

    if gaps:
        print("\n缺口明细：")
        for name, version, best, ds in gaps:
            print(f"\n  {name} {version}  （最接近 {best}）")
            for field, g, r in ds:
                print(f"    {field}")
                print(f"      curl_cffi: {g}")
                print(f"      真机     : {r}")

    covered = len(real) - len(gaps)
    print(f"\n覆盖 {covered}/{len(real)} 个真机浏览器；{len(gaps)} 个需自建 profile")
    return 1 if gaps else 0


if __name__ == "__main__":
    raise SystemExit(main())
