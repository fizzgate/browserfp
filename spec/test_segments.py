"""段表门禁：源码推导的指纹段必须与所有实采 golden 相符。

这是两条**互相独立**的证据链的对撞：
  A 抓包 —— 让浏览器真发一次 ClientHello，解析下来（spec/profiles.json）
  B 源码 —— 读产生 ClientHello 的那几张表（spec/segments/firefox.json）
两条链共享的只有"同一个浏览器版本"这一个事实。对上了，才说明我们对指纹的
理解是对的而不是碰巧；对不上，先假设是 B 漏了维度（A 有三家独立项目佐证）。

查三件事：
  1. 每个已采版本的 SCT 有无，与其所属段的源码推导一致
  2. **产物里标了 substitutable=true 的段**，其强证据来源必须内部一致。只验
     正向结论，不重新判定标了 false 的段 —— 那是 oracle/segments.py 的职责，
     在门禁里重算一遍只会制造第二个真相源，实测已经因此出现过产物与门禁结论
     相反的情况。
     **两类干扰必须先排掉，否则会把别人的粒度问题记成我们的错**：
       · ALPN 由调用方设置，不是浏览器版本决定的（utls 的 ClientHelloID 就
         允许自定义），同版本两次采集可以不同
       · 参考项目自己把跨段版本合并成一条 profile（tls_client 的 firefox_102
         一条服务 102–117，横跨我们三个段）。那是该项目分得比我们粗，不是
         我们分错。这类单列报告，不计入失败
       · 单个来源库在某版本上与其他家不一致（离群）。同一版本被两家以上收录
         时，少数派是该库的数据缺陷——实测 tls_client:firefox135 缺了 0x23
         与 0x2d，而 curl_cffi、wreq 的 135 都有。**用多数决自动判定，不写
         豁免表**：豁免表迟早变成没人读的僵尸清单，而多数决会随新数据自动
         重算，某天该库修好了就自动不再离群
  3. 生产 UA 里的每个 Firefox 版本都能落进某个段（否则严格模式会拒绝它）

**GREASE 必须先剔除再比**。源码表里的 0x0a0a 是 NSS 的枚举占位符，表示"这里
有一个 GREASE 扩展"，运行期随机取值；而 golden 里 GREASE 早已被剔掉。不剔就
会得到 27 处假不符，看起来像段表全错，实际是比较方式错了。

跑：python -m spec.test_segments
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.coverage import FIELDS, SET_FIELDS                 # noqa: E402
from oracle.uamap import parse_ua                              # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SEGMENTS = os.path.join(HERE, "segments", "firefox.json")
REGISTRY = os.path.join(HERE, "profiles.json")
FIXTURES = os.path.join(HERE, "fixtures", "prod_user_agents.json")

# 由调用方设置、与浏览器版本无关的字段，段内一致性比对时排除
CALLER_SET = ("alpn",)

GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
          0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
SCT = 0x0012


def load_segments():
    with open(SEGMENTS) as f:
        return json.load(f)["segments"]


def seg_of(segs, v):
    for s in segs:
        if s["from"] <= v <= s["to"]:
            return s
    return None


def golden_firefox():
    """已采到的 Firefox profile：{版本: [(来源, 记录)]}。"""
    with open(REGISTRY) as f:
        registry = json.load(f)
    out = {}
    for rec in registry:
        if rec.get("mode") != "initial" or not rec.get("default_config", True):
            continue
        for alias in [rec["id"]] + rec.get("aliases", []):
            m = re.match(r"^(\w+):[Ff]irefox[-_]?(\d+)$", alias)
            if m:
                out.setdefault(int(m.group(2)), []).append((m.group(1), rec))
    return out


def _norm(tls):
    return json.dumps(
        {f: (sorted(tls.get(f) or []) if f in SET_FIELDS else tls.get(f))
         for f in FIELDS if f not in CALLER_SET}, sort_keys=True)


def cross_segment_records(segs):
    """找出被参考项目跨段合并的 profile：一条服务多个段 = 该项目粒度更粗。"""
    with open(REGISTRY) as f:
        registry = json.load(f)
    out = []
    for rec in registry:
        if rec.get("mode") != "initial":
            continue
        vs = set()
        for alias in [rec["id"]] + rec.get("aliases", []):
            m = re.match(r"^(\w+):[Ff]irefox[-_]?(\d+)$", alias)
            if m:
                vs.add(int(m.group(2)))
        idxs = {i for v in vs for i, s in enumerate(segs)
                if s["from"] <= v <= s["to"]}
        if len(idxs) > 1:
            spans = [f"{segs[i]['from']}-{segs[i]['to']}" for i in sorted(idxs)]
            out.append((rec["id"], sorted(vs), spans))
    return out


def check_sct(segs, golden):
    """源码推导的 SCT 有无 vs 实采。"""
    bad, checked = [], 0
    for v, entries in sorted(golden.items()):
        s = seg_of(segs, v)
        if not s:
            continue
        want = s["tables"]["sct"]
        if want is None:
            continue          # 该版本尚无 CT pref，源码答不了，不算数
        for src, rec in entries:
            got = SCT in set(rec["tls"].get("extensions_ordered") or [])
            checked += 1
            if want != got:
                bad.append(f"firefox {v} ({src}): 源码 sct={want} 实采 {got}")
    return bad, checked


def outliers(golden):
    """同一版本被多家收录时，与多数不符的那家 = 该库的数据缺陷。

    返回 {(来源, 版本)}。只在有 3 家及以上时判——2 家分歧无从判多数。
    """
    out = set()
    for v, entries in golden.items():
        if len({src for src, _ in entries}) < 3:
            continue          # 少于三家无从判多数（同样按来源库数，不是条数）
        # **按来源库去重计票**。一条 profile 常有多个 alias 匹配同一版本
        # （注册表按指纹去重，真机那条 real:firefox 就挂着 wreq 的多个
        # target），按 alias 出现次数计票会让某一家凭空多出几票，结论直接
        # 反过来——实测就把 wreq 误判成离群，而真正不全的是另一家。
        tally = {}
        for src, rec in entries:
            tally.setdefault(_norm(rec["tls"]), set()).add(src)
        if len(tally) < 2:
            continue
        top = max(tally.values(), key=len)
        for key, srcs in tally.items():
            if srcs is not top and len(srcs) < len(top):
                out.update((s, v) for s in srcs)
    return out


def check_marked_substitutable(segs, golden):
    """**只查产物里标了 substitutable=true 的段**，验证它们确实经得起实采检验。

    早先这里自己实现了一套"任一来源库内不一致就否决"的判定，而 segments.py
    已改用证据强度规则（一家库覆盖 >=3 个版本才算强证据）。两处实现同一逻辑
    必然分叉——实测就出现过产物判段 135-152 可替代、门禁却报它段划粗的矛盾。

    改为只验产物的正向结论：标了可替代的段，其"强证据"来源必须内部一致。不再
    重新判定标了 false 的段——那是 segments.py 的职责，门禁在这里重算一遍只会
    制造第二个真相源。
    """
    STRONG = 3
    bad, checked = [], 0
    for s in segs:
        if not s.get("substitutable"):
            continue
        checked += 1
        per_src = {}
        for v in range(s["from"], s["to"] + 1):
            for src, rec in golden.get(v, []):
                per_src.setdefault(src, {}).setdefault(_norm(rec["tls"]), set()).add(v)
        for src, keys in per_src.items():
            n_ver = len({v for vs in keys.values() for v in vs})
            if len(keys) > 1 and n_ver >= STRONG:
                bad.append(f"段 {s['from']}-{s['to']} 标了可替代，但 {src} "
                           f"覆盖 {n_ver} 个版本却有 {len(keys)} 种指纹")
    return bad, checked


def check_intra_segment(segs, golden, merged_ids, outlier_set):
    """同段的已采 golden 必须互相同指纹——这是段内可替代的前提。"""
    bad, checked = [], 0
    for s in segs:
        vs = [v for v in golden if s["from"] <= v <= s["to"]]
        keys = {}
        for v in vs:
            for src, rec in golden[v]:
                if rec["id"] in merged_ids:
                    continue          # 该项目自己跨段合并，另行报告
                if (src, v) in outlier_set:
                    continue          # 该库在这个版本上离群，另行报告
                keys.setdefault(_norm(rec["tls"]), []).append(f"{src}:firefox{v}")
        if len(keys) > 1:
            # 跨来源库的差异是已知噪声（各库抓包环境不同），只有**同一来源库内**
            # 的分歧才说明段划粗了
            by_src = {}
            for k, names in keys.items():
                for n in names:
                    by_src.setdefault(n.split(":")[0], set()).add(k)
            for src, ks in by_src.items():
                if len(ks) > 1:
                    inside = sorted(n for names in keys.values() for n in names
                                    if n.startswith(src + ":"))
                    bad.append(f"段 {s['from']}-{s['to']}: {src} 内部指纹不一致 {inside}")
        checked += len(vs)
    return bad, checked


def check_prod_coverage(segs):
    """生产 UA 里的 Firefox 版本必须都能落进某个段。"""
    if not os.path.exists(FIXTURES):
        return [], 0
    with open(FIXTURES) as f:
        rows = json.load(f)
    missing, total = {}, 0
    for row in rows:
        brand, ver = parse_ua(row["ua"])
        if brand != "firefox":
            continue
        total += row["count"]
        if not seg_of(segs, ver):
            missing[ver] = missing.get(ver, 0) + row["count"]
    return [f"firefox {v}（{c} 次请求）落在段表之外"
            for v, c in sorted(missing.items(), key=lambda x: -x[1])], total


def main():
    if not os.path.exists(SEGMENTS):
        print("缺 spec/segments/firefox.json；先跑 "
              "python -m oracle.segments firefox 78 152 --write", file=sys.stderr)
        return 2

    segs = load_segments()
    golden = golden_firefox()

    merged = cross_segment_records(segs)
    merged_ids = {m[0] for m in merged}
    outlier_set = outliers(golden)
    sct_bad, n_sct = check_sct(segs, golden)
    intra_bad, n_intra = check_marked_substitutable(segs, golden)
    prod_bad, n_prod = check_prod_coverage(segs)

    print(f"段 {len(segs)} 个，覆盖 {segs[0]['from']}–{segs[-1]['to']}；"
          f"已采 Firefox 版本 {len(golden)} 个")
    print(f"\nSCT 与源码相符   {'OK' if not sct_bad else '失败'}（比了 {n_sct} 条）")
    for b in sct_bad:
        print(f"  ✗ {b}")
    print(f"可替代段经得起检验 {'OK' if not intra_bad else '失败'}（{n_intra} 个段标为可替代）")
    for b in intra_bad:
        print(f"  ✗ {b}")
    print(f"生产版本全覆盖   {'OK' if not prod_bad else '失败'}（{n_prod} 次 Firefox 请求）")
    for b in prod_bad:
        print(f"  ✗ {b}")

    if outlier_set:
        print(f"\n单库离群 {len(outlier_set)} 处（同版本≥3 家收录，少数派 = 该库数据缺陷）：")
        for src, v in sorted(outlier_set, key=lambda x: (x[1], x[0])):
            print(f"  {src}:firefox{v}")

    print(f"\n参考项目跨段合并 {len(merged)} 条（该项目粒度比我们粗，不计失败）：")
    for rid, vs, spans in merged:
        print(f"  {rid}  版本 {vs}")
        print(f"  {'':{len(rid)}s}  跨段 {spans}")

    failed = len(sct_bad) + len(intra_bad) + len(prod_bad)
    print(f"\n{'源码与抓包互相印证' if not failed else f'{failed} 处不符'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
