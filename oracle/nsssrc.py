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
    # curves 顺序不在 NSS 里：gecko 硬编码了两份 group 列表，按 enable_kyber
    # 分支选。只读 NSS 的 ssl_named_groups 会得到 33 项的完整定义表，那不是
    # ClientHello 里发的东西。
    "iolayer": "security/manager/ssl/nsNSSIOLayer.cpp",
    # 条件发送的扩展由 pref 决定，而 pref 默认值在这里（不在 all.js）。
    "staticprefs": "modules/libpref/init/StaticPrefList.yaml",
}

# release 桌面构建里**未定义**的宏。StaticPrefList.yaml 的默认值大量包在
# 这些条件里，取错分支会得到与真实 release 相反的结论。
UNDEFINED_IN_RELEASE = ("EARLY_BETA_OR_EARLIER", "ANDROID", "NIGHTLY_BUILD",
                        "MOZ_WIDGET_ANDROID", "MOZ_DEV_EDITION", "DEBUG")


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


def _cond_holds(expr):
    """在 release 桌面构建下求值一个 #if 条件（只支持 defined/!/&&/||）。"""
    e = expr.strip()
    for macro in UNDEFINED_IN_RELEASE:
        e = e.replace(f"defined({macro})", "False")
    e = re.sub(r"defined\([A-Za-z_]\w*\)", "True", e)   # 其余宏视为已定义
    e = e.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    try:
        return bool(eval(e, {"__builtins__": {}}, {"True": True, "False": False}))
    except Exception:
        return True          # 判不了就按"条件成立"走，宁可保守


def pref_value(text, name):
    """取某个 pref 在 **release 桌面构建**下的默认值。

    **不能只取第一个 `value:`**。这些默认值大量包在 C 预处理条件里，而首个
    分支往往是 nightly/android 的值。实测 Firefox 133 首个 value 是 2、
    release 实为 0；135 首个是 0、桌面 release 实为 2——两个版本恰好都取反，
    据此推出的结论会与真实完全颠倒。
    """
    m = re.search(r"- name: " + re.escape(name) + r"\n(.*?)(?=\n- name:|\Z)",
                  text, re.S)
    if not m:
        return None
    body = m.group(1)
    if "#if" not in body:
        v = re.search(r"value:\s*(\S+)", body)
        return v.group(1) if v else None

    # 逐行走一遍条件块，只收当前分支成立时的 value
    active, taken, val = True, False, None
    for line in body.splitlines():
        t = line.strip()
        if t.startswith("#ifdef "):
            active, taken = _cond_holds(f"defined({t[7:].strip()})"), False
            taken = active
        elif t.startswith("#ifndef "):
            active = not _cond_holds(f"defined({t[8:].strip()})")
            taken = active
        elif t.startswith("#if "):
            active = _cond_holds(t[4:])
            taken = active
        elif t.startswith("#else"):
            active = not taken
        elif t.startswith("#elif "):
            active = (not taken) and _cond_holds(t[6:])
            taken = taken or active
        elif t.startswith("#endif"):
            active, taken = True, False
        elif active and t.startswith("value:"):
            val = t.split(":", 1)[1].strip()
    return val


def gecko_groups(version):
    """gecko 硬编码的 group 列表：[含 KEM 的, 不含的]。ClientHello 用前者
    （enable_kyber 默认开、TLS1.3、非 retry），后者是降级路径。"""
    d = fetch(version, "iolayer")
    out = []
    for m in re.finditer(r"const SSLNamedGroup namedGroups\[\]\s*=\s*\{(.*?)\};",
                         d, re.S):
        out.append(re.findall(r"ssl_grp_\w+", m.group(1)))
    return out


def sends_sct(version):
    """是否发 signed_certificate_timestamp(0x0012)。

    该扩展在 sender 表里恒存在，是否真发由 SSL_ENABLE_SIGNED_CERT_TIMESTAMPS
    决定，而它 = (CT mode != Disabled)。只读 sender 表会认为所有版本都发，
    与三个参考项目的实测（133 不发、135 发）矛盾。
    """
    v = pref_value(fetch(version, "staticprefs"),
                   "security.pki.certificate_transparency.mode")
    return None if v is None else v.strip() != "0"


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

    # 条件发送的扩展要按实际条件裁剪，否则段表看不出 133/134 与 135 的区别
    sct = sends_sct(version)
    if sct is False and emap.get("ssl_signed_cert_timestamp_xtn") in exts:
        exts = [e for e in exts if e != emap["ssl_signed_cert_timestamp_xtn"]]

    groups = gecko_groups(version)
    return {"ciphers": ciphers, "sig_algs": sigs, "extensions": exts,
            "curves": groups[0] if groups else [], "sct": sct}


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
