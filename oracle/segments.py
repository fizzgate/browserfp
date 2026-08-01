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
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.nsssrc import extract as ff_extract                # noqa: E402
from oracle.chromiumsrc import extract as cr_extract           # noqa: E402
from oracle.coverage import FIELDS, SET_FIELDS                 # noqa: E402

# 由调用方设置、与浏览器版本无关，判段内一致性时排除
CALLER_SET = ("alpn",)


def _fp_key(tls):
    return json.dumps(
        {f: (sorted(tls.get(f) or []) if f in SET_FIELDS else tls.get(f))
         for f in FIELDS if f not in CALLER_SET}, sort_keys=True)


def golden_by_version(brand):
    """{主版本: [(来源库, 指纹key)]}，取自实采注册表。"""
    if not os.path.exists(REGISTRY):
        return {}
    with open(REGISTRY) as f:
        registry = json.load(f)
    pat = (r"^(\w+):(?:[Cc]hrome|[Cc]hromium)[-_]?(\d+)$" if brand == "chrome"
           else r"^(\w+):[Ff]irefox[-_]?(\d+)$")
    out = {}
    for rec in registry:
        if rec.get("mode") != "initial" or not rec.get("default_config", True):
            continue
        for alias in [rec["id"]] + rec.get("aliases", []):
            m = re.match(pat, alias)
            if m:
                out.setdefault(int(m.group(2)), []).append(
                    (m.group(1), _fp_key(rec["tls"])))
    return out


def segment_substitutable(seg, golden):
    """该段能否用于段内替代 —— **逐段判**，不是整个品牌一刀切。

    判据：段内实采 golden 指纹一致。一致说明"同段即同指纹"在这一段被实测证实；
    不一致说明段划粗了，段内替代会发错指纹。段内无 golden 也判 false——没有可
    替代者，谈不上替代。

    **必须在同一来源库内比**。各库抓包的环境、时间、feature 配置都不同，实测
    同一版本在不同库里指纹就不一致（29 个多库收录版本中 17 个有分歧）。拿跨库
    差异当"段划粗"的证据，会把采集噪声记成我们的错，几乎每段都会被误判成不可
    替代。

    这比品牌级开关精确得多：Chrome 段 83-96 内 utls 自己的 83 与 96 就不同
    （ALPS 差异），该段必须禁止；而某些段内各库自洽，就可以放开。
    """
    per_src = {}
    for v in range(seg["from"], seg["to"] + 1):
        for src, key in golden.get(v, []):
            per_src.setdefault(src, {}).setdefault(key, set()).add(v)
    if not per_src:
        return False, "段内无实采 golden"

    # **证据强度不等**：一家库覆盖 13 个版本全部一致，与另一家只收录 2 个版本
    # 且不一致，不该被当作同等分量。前者是段内一致的强证据，后者可能只是那两
    # 条数据里有一条不全（实测 tls_client:firefox_135 只有 14 个扩展，而同段的
    # curl_cffi、wreq、utls 都是 16）。
    STRONG = 3        # 覆盖到这么多版本才算强证据
    strong_ok, strong_bad, weak_bad = [], [], []
    for src, keys in per_src.items():
        n_ver = len({v for vs in keys.values() for v in vs})
        if len(keys) == 1:
            if n_ver >= STRONG:
                strong_ok.append((src, n_ver))
        elif n_ver >= STRONG:
            strong_bad.append((src, len(keys), n_ver))
        else:
            weak_bad.append((src, len(keys), n_ver))

    if strong_bad:
        return False, ("段划粗了（强证据）："
                       + "、".join(f"{s} 覆盖 {n} 版本却有 {k} 种指纹"
                                   for s, k, n in sorted(strong_bad)))
    if strong_ok:
        why = "、".join(f"{s} 覆盖 {n} 个版本一致" for s, n in sorted(strong_ok))
        if weak_bad:
            why += ("；另有 " + "、".join(f"{s}({n} 版本 {k} 种)"
                                         for s, k, n in sorted(weak_bad))
                    + " 分歧，证据弱于前者")
        return True, why
    if weak_bad:
        return False, ("证据不足："
                       + "、".join(f"{s} 覆盖 {n} 版本有 {k} 种指纹"
                                   for s, k, n in sorted(weak_bad)))
    covered = {v for keys in per_src.values() for vs in keys.values() for v in vs}
    return True, f"{sorted(per_src)} 各自内部一致（共 {len(covered)} 个版本）"

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "..", "spec", "segments")
REGISTRY = os.path.join(HERE, "..", "spec", "profiles.json")

MAX_WORKERS = 5          # 对方是公共服务器，别打太狠

# 判段用哪些字段，**按品牌不同**：
#   firefox  三张有序表 + curves + sct（扩展顺序稳定，可比）
#   chrome   curves + key_share 组 + 签名算法。三处**不能**用：
#            · 扩展顺序 —— Chromium 自 110 起随机置换（permute_extensions）
#            · extensions_set —— 那是"实现了的"而非"会发的"
#            · boringssl revision —— 几乎每个版本都换 revision，拿它判段会让
#              每一版自成一段。它只是"相同则必定同段"的充分条件，不能反过来
#              当"不同则不同段"用
KEYS_BY_BRAND = {
    "firefox": ("ciphers", "sig_algs", "extensions", "curves", "sct", "ech"),
    # 用 verify_* 而非 sign_*：ClientHello 里发的 signature_algorithms 表示
    # "我能验证哪些签名"。verify_prefs 是 Chromium 的硬编码覆盖（有它就压过
    # BoringSSL 默认），cipher_excludes 是 :!3DES 这类排除项。补上这两项之前，
    # Chrome 72 与 78 会被判成不同段，而它们其实逐项相同。
    #
    # **ext_order 刻意不在此列**。它和 extensions_set 同病：kExtensions 是
    # "实现了的"而非"会发的"，表里多一个扩展不代表 ClientHello 变了。实测把
    # 它纳入后，70-96 区间凭空多出 8 个边界（87 起 0x0022、88 起 0x4469、
    # 89 起 0xfe09…），而这些扩展是否真发根本没有依据。要用它必须先按实采
    # 学到的发送集合过滤，那已经依赖 golden 而不是纯源码推导了。
    "chrome": ("curves", "key_share_groups", "verify_sigalgs", "verify_prefs",
               "cipher_excludes", "channel_id", "alps"),
}
KEYS = KEYS_BY_BRAND["firefox"]


def keys_for(brand):
    return KEYS_BY_BRAND.get(brand, KEYS)


def _key(tables, brand="firefox"):
    return json.dumps({k: tables.get(k) for k in keys_for(brand)}, sort_keys=True)


EXTRACTORS = {"firefox": ff_extract,
              "chrome": lambda v: cr_extract(int(v))}


def scan(brand, lo, hi):
    """返回 {version: tables}，取不到的版本不入表并单独报告。"""
    if brand not in EXTRACTORS:
        raise NotImplementedError(
            f"没有 {brand} 的抽取器；现支持 {sorted(EXTRACTORS)}")
    extract = EXTRACTORS[brand]

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


def segment(tables, brand="firefox"):
    """把逐版本的表压成连续段。缺失的版本会切断连续性——不能跨着并。"""
    segs = []
    for v in sorted(tables, key=int):
        k = _key(tables[v], brand)
        if segs and segs[-1]["key"] == k and int(v) == segs[-1]["to"] + 1:
            segs[-1]["to"] = int(v)
        else:
            segs.append({"from": int(v), "to": int(v), "key": k,
                         "tables": tables[v]})
    return segs


def boundary_diff(a, b, brand="firefox"):
    """两段之间到底改了什么 —— 段边界的价值全在这里。"""
    out = {}
    for k in keys_for(brand):
        x, y = a["tables"].get(k), b["tables"].get(k)
        if x == y:
            continue
        if not isinstance(x, list) or not isinstance(y, list):
            out[k] = f"{x} → {y}"
            continue
        fmt = (lambda v: f"0x{v:04x}") if all(isinstance(v, int) for v in x + y) else str
        added = [fmt(v) for v in y if v not in x]
        removed = [fmt(v) for v in x if v not in y]
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
    segs = segment(tables, brand)

    print(f"取到 {len(tables)} 个版本，失败 {len(failed)} 个\n")
    print(f"划出 {len(segs)} 个指纹段：")
    for i, s in enumerate(segs):
        span = f"{s['from']}" if s["from"] == s["to"] else f"{s['from']}–{s['to']}"
        n = s["to"] - s["from"] + 1
        t = s["tables"]
        if brand == "chrome":
            desc = f"curves={t['curves']}  sig={len(t['sign_sigalgs'])}"
        else:
            desc = (f"ciphers={len(t['ciphers']):2d} sig={len(t['sig_algs']):2d} "
                    f"ext={len(t['extensions']):2d}")
        print(f"  段{i + 1:<2} {span:<10} {n:>2} 个版本  {desc}")
        if i:
            why = boundary_diff(segs[i - 1], s, brand)
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
        # **段表能否用于段内替代，按品牌不同**，必须写进产物本身——只写在
        # 文档里迟早被误用。
        #   firefox  可以：ClientHello 由几张静态表决定，静态分析覆盖得全，
        #            实测 SCT 维度 47 条与实采全对
        #   chrome   不可以：feature 默认值不代表实际行为，Finch 会在运行期
        #            覆盖。实证——kUseNewAlpsCodepointHttp2 在源码里 M126~133
        #            全是 DISABLED（M140 才 ENABLED），而四家实采一致显示
        #            M131 发旧 codepoint 0x4469、M132+ 发新的 0x44cd。同一个
        #            Chrome 版本在不同用户/地区/时间可能发出不同指纹，
        #            "版本 → 唯一指纹"对 Chrome 不成立。它只能用于反向判断：
        #            curves/sigalgs 这类硬编码表变了则**必定**不同段。
        golden = golden_by_version(brand)
        seg_flags = [segment_substitutable(s, golden) for s in segs]
        n_ok = sum(1 for ok, _ in seg_flags if ok)
        substitutable = brand == "firefox"
        payload = {
            "brand": brand,
            "usable_for_substitution": substitutable,
            "substitutable_segments": n_ok,
            "substitution_note": (
                "段内可安全替代（源码三表 + curves + sct 已覆盖决定性维度）"
                if substitutable else
                "**不可**用于段内替代：仅证明跨段必定不同，不保证段内相同。"
                "Chrome 的 feature 默认值会被 Finch 运行期覆盖（实证："
                "kUseNewAlpsCodepointHttp2 源码里 M126~133 全为 DISABLED，"
                "而四家实采一致显示 M132+ 已改发新 codepoint 0x44cd），"
                "同一版本在不同用户/地区/时间可能发出不同指纹"),
            "scanned": [lo, hi],
            "unavailable": sorted(failed, key=int),
            "segments": [{"from": s["from"], "to": s["to"],
                          "tables": s["tables"],
                          "substitutable": ok, "substitution_reason": why}
                         for s, (ok, why) in zip(segs, seg_flags)],
        }
        with open(path, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"\n逐段可替代性：{n_ok}/{len(segs)} 段可用于段内替代")
        for s, (ok, why) in zip(segs, seg_flags):
            span = f"{s['from']}-{s['to']}"
            print(f"  {'✅' if ok else '❌'} {span:<10} {why}")
        print(f"\n落盘 → {os.path.normpath(path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
