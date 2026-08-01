"""从 NSS 源码推导 Firefox 的 ClientHello 构成 —— 不跑浏览器就能判版本异同。

**为什么这条路比抓包更强**：抓包只能采到本机装得上的版本，历史版本要下几百 MB
二进制、还未必能在新系统上跑起来。而 ClientHello 的构成完全由 NSS 源码里三张
**有序表**决定，源码按 tag 取几个文件就有，是产生指纹的东西本身：

    cipherSuites[]            ssl3con.c  —— cipher 顺序（只发 enabled 的）
    defaultSignatureSchemes[] ssl3con.c  —— signature_algorithms 内容与顺序
    clientHelloSendersTLS[]   ssl3ext.c  —— extension 顺序

符号到数值的映射也从同版本的头文件解析（sslproto.h / sslt.h），不硬编码——
新版本引入的常量会自动跟上，写死一份表迟早僵尸化。

**能回答的问题**：库里缺 Firefox 126，它到底跟 123 一样还是跟 128 一样？抓包
答不了（两端还分属不同来源库，本就不可比），源码 diff 能直接答。

**边界**：这里只覆盖 NSS 层。Firefox 另有 prefs（security.ssl3.*）可以关掉
个别 suite，故"源码表相同"是"指纹相同"的必要条件而非充分条件——两个版本表
不同就一定不同指纹（可据此判缺口为真），表相同则还需 prefs 未变。prefs 比对
见 check_prefs()。

跑：
    python -m oracle.nsssrc 123 126 127 128     # 比对若干版本
    python -m oracle.nsssrc --verify 133        # 与 golden 对照验证抽取正确性
"""

import os
import re
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "..", "spec", "cache", "nss")

HG = "https://hg.mozilla.org/releases/mozilla-release/raw-file"
FILES = {
    "ssl3con.c": "security/nss/lib/ssl/ssl3con.c",
    "ssl3ext.c": "security/nss/lib/ssl/ssl3ext.c",
    "sslproto.h": "security/nss/lib/ssl/sslproto.h",
    "sslt.h": "security/nss/lib/ssl/sslt.h",
    "prefs": "modules/libpref/init/all.js",
    # Firefox 不直接用 NSS 的默认表：它在这里调 SSL_SignatureSchemePrefSet /
    # SSL_CipherPrefSet 覆盖顺序。只读 NSS 会得到错的 sig_algs 次序。
    "gecko_ssl": "security/manager/ssl/nsNSSComponent.cpp",
}


def tag_candidates(version):
    """一个主版本可能对应多个 tag，必须挨个试。

    并非每个主版本都有 `FIREFOX_<N>_0_RELEASE`：有些版本首发就是点版本
    （125 只有 125.0.1、130 只有 130.0.1），只试 `_0_` 会 404。把 404 当成
    "该版本无差异"并进相邻段，会让段表凭空变长、边界落错位置。
    """
    if "." in version or "_" in version:
        return [f"FIREFOX_{version.replace('.', '_')}_RELEASE"]
    n = version
    return ([f"FIREFOX_{n}_0_RELEASE"]
            + [f"FIREFOX_{n}_0_{p}_RELEASE" for p in (1, 2, 3)]
            + [f"FIREFOX_{n}_0esr_RELEASE"])


def fetch(version, name, attempts=3):
    """取某个 Firefox release tag 下的一个文件，带磁盘缓存。

    走 no-proxy：本机 shell 里的 http_proxy 指向一个 30s 就 502 的转发代理，
    大文件必被截断（见项目根 CLAUDE.md 的 dev gotcha）。

    网络类错误重试：hg.mozilla.org 在并发下偶发 EOF/超时，一次失败就放弃会
    让"取不到"和"真的没有该 tag"混在一起，段表因此被无谓切断。404 不重试
    ——那是 tag 不存在，重试多少次都一样。
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    last = None
    for tag in tag_candidates(version):
        path = os.path.join(CACHE, tag, name)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read()

        url = f"{HG}/{tag}/{FILES[name]}"
        for i in range(attempts):
            try:
                with opener.open(url, timeout=120) as r:
                    data = r.read().decode("utf-8", errors="replace")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(data)
                return data
            except urllib.error.HTTPError as e:
                last = e
                break                      # tag 不存在，换下一个候选
            except Exception as e:
                last = e
                if i + 1 < attempts:
                    time.sleep(1.5 * (i + 1))
    raise last if last else RuntimeError(f"{version}/{name} 取不到")


def _consts(text, pattern):
    """从头文件里抽 `#define NAME 0xVALUE` 或枚举 `name = 0xVALUE`。"""
    out = {}
    for m in re.finditer(pattern, text):
        try:
            out[m.group(1)] = int(m.group(2), 0)
        except ValueError:
            pass
    return out


def symbol_table(version):
    """符号名 → 数值。cipher 走 #define，extension 走枚举。"""
    proto = fetch(version, "sslproto.h")
    slt = fetch(version, "sslt.h")
    ciphers = _consts(proto, r"#define\s+(TLS_\w+)\s+(0x[0-9a-fA-F]+)")
    # 交替顺序要紧：`\d+` 放前面会把 0xff01 抢先匹配成 "0"。中招的恰好只有
    # renegotiation_info(0xff01) 与 ECH(0xfe0d) 两个十六进制常量，十进制的
    # 全对，症状看起来像"缺两项"而不是"解析错"。
    exts = _consts(slt, r"(ssl_\w+_xtn)\s*=\s*(0x[0-9a-fA-F]+|\d+)")
    sigs = _consts(slt, r"(ssl_sig_\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)")
    return ciphers, exts, sigs


def _block(text, start_pat):
    """取形如 `xxx[] = {` 到匹配 `};` 之间的内容。"""
    m = re.search(start_pat, text)
    if not m:
        return None
    end = text.index("\n};", m.end())
    return text[m.end():end]


def _strip_comments(s):
    """必须连注释一起剥。NSS 的表里大量整块注释掉的 suite，不剥会把它们
    当成启用项读进来——`/* { TLS_RSA_..., SSL_ALLOWED, PR_TRUE ... } */`
    长得跟真条目一模一样。"""
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    return re.sub(r"//[^\n]*", "", s)


def extract(version):
    """返回该版本的三张有序表（数值形式）。"""
    con = fetch(version, "ssl3con.c")
    ext = fetch(version, "ssl3ext.c")
    cmap, emap, smap = symbol_table(version)

    body = _strip_comments(_block(con, r"cipherSuites\[[^\]]*\]\s*=\s*\{"))
    ciphers = []
    for m in re.finditer(r"\{\s*(TLS_\w+)\s*,\s*\w+\s*,\s*(PR_TRUE|PR_FALSE)", body):
        if m.group(2) == "PR_TRUE" and m.group(1) in cmap:
            ciphers.append(cmap[m.group(1)])

    body = _strip_comments(_block(con, r"defaultSignatureSchemes\[\]\s*=\s*\{"))
    sigs = [smap[n] for n in re.findall(r"(ssl_sig_\w+)", body) if n in smap]

    body = _strip_comments(_block(ext, r"clientHelloSendersTLS\[\]\s*=\s*\{"))
    exts = [emap[n] for n in re.findall(r"(ssl_\w+_xtn)", body) if n in emap]

    return {"ciphers": ciphers, "sig_algs": sigs, "extensions": exts}


def check_prefs(version):
    """抽 security.ssl3.* / security.tls.* 相关 pref，用于补足 NSS 层之外的差异。"""
    try:
        text = fetch(version, "prefs")
    except Exception as e:
        return {"_error": str(e)}
    out = {}
    for m in re.finditer(r'pref\("(security\.(?:ssl3|tls)\.[\w.-]+)",\s*([^)]+)\)', text):
        out[m.group(1)] = m.group(2).strip()
    return out


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    if "--verify" in argv:
        return verify(args[0] if args else "133")
    versions = args or ["123", "126", "127", "128"]

    tables, prefs = {}, {}
    for v in versions:
        try:
            tables[v] = extract(v)
            prefs[v] = check_prefs(v)
        except Exception as e:
            print(f"  {v}: 取不到（{type(e).__name__}: {e}）", file=sys.stderr)

    print("各版本 NSS 层表规模：")
    for v, t in tables.items():
        print(f"  Firefox {v:>4}  ciphers={len(t['ciphers']):2d}  "
              f"sig_algs={len(t['sig_algs']):2d}  extensions={len(t['extensions']):2d}  "
              f"prefs={len(prefs.get(v, {}))}")

    print("\n两两比对（相同 = 该版本区间内 NSS 层不产生指纹差异）：")
    vs = list(tables)
    for i in range(len(vs) - 1):
        a, b = vs[i], vs[i + 1]
        diff = [k for k in ("ciphers", "sig_algs", "extensions")
                if tables[a][k] != tables[b][k]]
        pdiff = [k for k in set(prefs.get(a, {})) | set(prefs.get(b, {}))
                 if prefs.get(a, {}).get(k) != prefs.get(b, {}).get(k)]
        if not diff and not pdiff:
            print(f"  {a} ↔ {b}   完全相同 → 同一指纹段")
        else:
            print(f"  {a} ↔ {b}   NSS 差异={diff or '无'}  pref 差异={pdiff or '无'}")
            for k in diff:
                sa, sb = tables[a][k], tables[b][k]
                only_a = [f"0x{x:04x}" for x in sa if x not in sb]
                only_b = [f"0x{x:04x}" for x in sb if x not in sa]
                order = (sorted(sa) == sorted(sb)) and sa != sb
                print(f"      {k}: 仅 {a} 有 {only_a or '-'}  仅 {b} 有 {only_b or '-'}"
                      f"{'  （集合相同，顺序不同）' if order else ''}")
    return 0


def verify(version):
    """拿源码推导的表对照已采到的 golden —— 独立于抓包的第二条验证路径。

    两条路径互相独立：一条是让浏览器真发一次、抓下来解析；另一条是读产生它
    的源码。两者对上，才说明我们对指纹的理解是对的而不是碰巧。
    """
    import json
    reg_path = os.path.join(HERE, "..", "spec", "profiles.json")
    with open(reg_path) as f:
        registry = json.load(f)

    want = f"firefox{version}"
    rec = None
    for r in registry:
        names = [r["id"]] + r.get("aliases", [])
        if any(want == n.split(":", 1)[1].lower().replace("_", "").replace("-", "")
               for n in names):
            rec = r
            break
    if not rec:
        print(f"注册表里没有 {want}，无从对照", file=sys.stderr)
        return 2

    src = extract(version)
    tls = rec["tls"]
    print(f"源码推导 vs golden（{rec['id']}）：\n")

    ok = True
    # extension：golden 里含 GREASE 与 padding，源码表里没有——前者是运行期
    # 生成的噪声，比对前必须剔掉，否则必然假红。
    GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
              0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
    got_ext = [e for e in (tls.get("extensions_ordered") or [])
               if e not in GREASE and e != 0x0015]
    src_ext = [e for e in src["extensions"] if e not in GREASE]

    for label, a, b in [
            ("ciphers", src["ciphers"], tls.get("ciphers") or []),
            ("sig_algs", src["sig_algs"], tls.get("sig_algs") or []),
            ("extensions", src_ext, got_ext)]:
        a2 = [x for x in a if x in set(b)]        # 源码里有但该次握手没发的（pref 关掉/条件发送）
        same = a2 == b
        ok = ok and same
        print(f"  {label:11s} 源码 {len(a):2d} 项  golden {len(b):2d} 项  "
              f"{'一致' if same else '不一致'}")
        if not same:
            print(f"      源码序(交集): {[hex(x) for x in a2]}")
            print(f"      golden      : {[hex(x) for x in b]}")
    print(f"\n{'源码与抓包互相印证' if ok else '两条路径不一致 —— 需要查是抽取错了还是理解错了'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
