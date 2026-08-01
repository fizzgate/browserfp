"""扫描全部主版本的源码，划出**指纹段**——段边界精确到"哪个版本改的"。

**为什么必须做到全版本**：真实用户的浏览器版本极其分散，随便挑个相邻版本顶
就会发指纹与 UA 矛盾的握手。要对任意版本都给出确定答案，就得知道每个段从
哪个版本开始、到哪个版本结束，以及边界上究竟改了什么。

段的定义：相邻版本的三张有序表（ciphers / sig_algs / extensions）完全相同，
即划入同一段。段内任一版本可以安全地共用同一个 profile —— 这是**源码证据**，
不是"两端指纹看起来一样"的推断。此前 uamap 判 same-seg 只能比两端已采到的
指纹，遇到两端分属不同来源库就只能弃权（Firefox 126 就卡在这里），现在能答。

**当前局限（未解决，不要拿这份段表直接判生产）**：只比了 ciphers / sig_algs /
extensions 三张表，**没有覆盖 curves(supported_groups)**。三个参考项目
（curl_cffi、tls_client、wreq）各自独立地把 Firefox 133 与 135 判成不同指纹，
而本扫描器认为 124–135 同段——差异正落在没覆盖的那一维（Firefox 在此区间
引入 X25519MLKEM768）。参考项目的分段是独立的第三方证据，与本扫描器不一致
时以"我们漏了维度"为默认假设，而不是反过来说人家错。

补齐要读 sslsock.c 的 named group 表 + gecko 侧的 SSL_NamedGroupConfig 调用
与 security.tls.enable_kyber / enable_mlkem 这类 pref。

**并发要克制**：这是别人家的公共 hg 服务器，源码文件也不小。用小并发 + 磁盘
缓存，重跑几乎不产生网络请求。

跑：
    python -m oracle.segments firefox 78 150      # 扫描并输出段表
    python -m oracle.segments firefox 78 150 --write   # 落盘到 spec/segments/
"""

import concurrent.futures
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.nsssrc import extract                              # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "..", "spec", "segments")

MAX_WORKERS = 5          # 对方是公共服务器，别打太狠
KEYS = ("ciphers", "sig_algs", "extensions")


def _key(tables):
    return json.dumps({k: tables[k] for k in KEYS}, sort_keys=True)


def scan(brand, lo, hi):
    """返回 {version: tables}，取不到的版本不入表并单独报告。"""
    if brand != "firefox":
        raise NotImplementedError(
            f"{brand} 的源码站本机不可达（chromium.googlesource.com 连不上），"
            "暂时只能扫 firefox")

    versions = [str(v) for v in range(lo, hi + 1)]
    tables, failed = {}, {}
    with concurrent.futures.ThreadPoolExecutor(MAX_WORKERS) as ex:
        futs = {ex.submit(extract, v): v for v in versions}
        for fut in concurrent.futures.as_completed(futs):
            v = futs[fut]
            try:
                tables[v] = fut.result()
            except Exception as e:
                # 如实记下失败原因。曾经在这里 except: pass，结果取不到的版本
                # 与"该版本没差异"长得一模一样，段表凭空变长。
                failed[v] = f"{type(e).__name__}: {e}"
    return tables, failed


def segment(tables):
    """把逐版本的表压成连续段。缺失的版本会切断连续性——不能跨着并。"""
    segs = []
    for v in sorted(tables, key=int):
        k = _key(tables[v])
        if segs and segs[-1]["key"] == k and int(v) == segs[-1]["to"] + 1:
            segs[-1]["to"] = int(v)
        else:
            segs.append({"from": int(v), "to": int(v), "key": k,
                         "tables": tables[v]})
    return segs


def boundary_diff(a, b):
    """两段之间到底改了什么 —— 段边界的价值全在这里。"""
    out = {}
    for k in KEYS:
        x, y = a["tables"][k], b["tables"][k]
        if x == y:
            continue
        added = [f"0x{v:04x}" for v in y if v not in x]
        removed = [f"0x{v:04x}" for v in x if v not in y]
        if not added and not removed:
            out[k] = "顺序变化"
        else:
            bits = []
            if added:
                bits.append(f"新增 {' '.join(added)}")
            if removed:
                bits.append(f"移除 {' '.join(removed)}")
            out[k] = "，".join(bits)
    return out


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    brand = args[0] if args else "firefox"
    lo = int(args[1]) if len(args) > 1 else 78
    hi = int(args[2]) if len(args) > 2 else 150

    print(f"扫描 {brand} {lo}..{hi}（共 {hi - lo + 1} 个版本，有缓存则不走网络）")
    tables, failed = scan(brand, lo, hi)
    segs = segment(tables)

    print(f"取到 {len(tables)} 个版本，失败 {len(failed)} 个\n")
    print(f"划出 {len(segs)} 个指纹段：")
    for i, s in enumerate(segs):
        span = f"{s['from']}" if s["from"] == s["to"] else f"{s['from']}–{s['to']}"
        n = s["to"] - s["from"] + 1
        print(f"  段{i + 1:<2} {span:<10} {n:>2} 个版本  "
              f"ciphers={len(s['tables']['ciphers']):2d} "
              f"sig={len(s['tables']['sig_algs']):2d} "
              f"ext={len(s['tables']['extensions']):2d}")
        if i:
            why = boundary_diff(segs[i - 1], s)
            if why:
                for k, v in why.items():
                    print(f"        ↳ {s['from']} 起 {k}: {v}")
            else:
                # 表其实相同，只是中间有版本取不到，连续性被切断。必须说出来，
                # 否则读段表的人会以为这里发生了指纹变化。
                gap = segs[i - 1]["to"] + 1
                print(f"        ↳ 表与上一段相同，仅因 {gap} 缺失而切断")

    if failed:
        print("\n取不到的版本（不能当成无差异并进相邻段）：")
        for v, why in sorted(failed.items(), key=lambda x: int(x[0])):
            print(f"  {v}: {why}")

    if "--write" in argv:
        os.makedirs(OUT_DIR, exist_ok=True)
        path = os.path.join(OUT_DIR, f"{brand}.json")
        payload = {
            "brand": brand,
            "scanned": [lo, hi],
            "unavailable": sorted(failed, key=int),
            "segments": [{"from": s["from"], "to": s["to"],
                          "tables": s["tables"]} for s in segs],
        }
        with open(path, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"\n落盘 → {os.path.normpath(path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
