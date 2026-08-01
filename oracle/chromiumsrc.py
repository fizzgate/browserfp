"""从 Chromium + BoringSSL 源码推导 Chrome 系的 ClientHello 构成。

与 Firefox 那条线（oracle/nsssrc.py）同样的思路，但取源与可用维度都不同：

**取源链路**（chromium.googlesource.com 本机不可达，走 CDN 上的 GitHub 镜像）：
    主版本 → 完整版本号   npmmirror 的 chromedriver / chrome-for-testing 目录
    版本号 → DEPS         jsDelivr 上的 chromium/chromium@<tag>
    DEPS  → boringssl_revision
    revision → BoringSSL 源码   jsDelivr 上的 google/boringssl@<revision>

**可用维度和 Firefox 不一样**：Chromium 自 110 起对 ClientHello 扩展做随机置换
（BoringSSL 的 ssl_setup_extension_permutation，由 permute_extensions 开关控制），
所以**扩展顺序对 Chrome 没有意义**，只能比集合。能比顺序的是 cipher 与
signature_algorithms，它们不参与置换。

**同一链路覆盖 Chrome / Edge / Opera**：三家共用 Chromium 内核，段边界应当一致，
可以互相印证；不一致的地方就是各家自己改过的，值得单独标注。

**extensions_set 不能直接当成 ClientHello 里的扩展集合**：kExtensions 列的是
BoringSSL **实现了**的扩展，25 条里 add_clienthello 回调无一为 NULL，是否真发
全在回调内部按运行期配置决定（ECH 要配了才发、ALPS 要 Chromium 开了才发）。
静态分析拿不到这一层，所以该字段只用于"两个 revision 之间 BoringSSL 支持面有
没有变"，不能拿去和实采的 extensions 比。Firefox 那边同样的坑是 SCT——表里恒
存在、实际由 CT pref 决定发不发。判段请优先用 sign_sigalgs（顺序敏感且不参与
随机置换）与 boringssl_revision 是否相同。

跑：
    python -m oracle.chromiumsrc 78 95 120 126     # 抽这几个主版本并比对
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "..", "spec", "cache", "chromium")

JSD = "https://cdn.jsdelivr.net/gh"
NPMM = "https://registry.npmmirror.com/-/binary"
# 两个目录合起来覆盖 M70..M153；chromedriver 管老版本，chrome-for-testing 管新的
VERSION_DIRS = ("chromedriver/", "chrome-for-testing/")

# BoringSSL 里决定 ClientHello 的表所在文件
BSSL_FILES = ("ssl/extensions.cc", "ssl/ssl_privkey.cc")


def _get(url, cache_path, timeout=90, attempts=3):
    if os.path.exists(cache_path) and os.path.getsize(cache_path) > 0:
        with open(cache_path, encoding="utf-8", errors="replace") as f:
            return f.read()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    last = None
    for i in range(attempts):
        try:
            with opener.open(url, timeout=timeout) as r:
                data = r.read().decode("utf-8", errors="replace")
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(data)
            return data
        except urllib.error.HTTPError as e:
            raise                      # 4xx/5xx 重试没意义
        except Exception as e:
            last = e
            if i + 1 < attempts:
                time.sleep(1.5 * (i + 1))
    raise last


def version_index():
    """主版本 → 该主版本下的完整版本号列表（升序）。"""
    path = os.path.join(CACHE, "versions.json")
    if os.path.exists(path):
        with open(path) as f:
            return {int(k): v for k, v in json.load(f).items()}

    seen = set()
    for d in VERSION_DIRS:
        raw = _get(NPMM + "/" + d, os.path.join(CACHE, d.strip("/") + ".json"))
        for item in json.loads(raw):
            n = (item.get("name") or "").rstrip("/")
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", n):
                seen.add(n)

    index = {}
    for v in seen:
        index.setdefault(int(v.split(".")[0]), []).append(v)
    for k in index:
        index[k].sort(key=lambda s: [int(x) for x in s.split(".")])
    os.makedirs(CACHE, exist_ok=True)
    with open(path, "w") as f:
        json.dump({str(k): v for k, v in index.items()}, f)
    return index


def boringssl_revision(major):
    """取该主版本某个具体 tag 的 DEPS，解析 boringssl_revision。

    同一主版本的不同 patch 版本理论上可能指向不同 BoringSSL revision，这里取
    该主版本**最后一个** patch —— 那是用户实际跑得最多的形态（Chrome 强制自动
    更新，停在早期 patch 的很少）。
    """
    index = version_index()
    if major not in index:
        raise KeyError(f"M{major} 不在版本索引里（覆盖 {min(index)}..{max(index)}）")

    last_err = None
    for tag in reversed(index[major][-4:]):        # 末尾几个里挑一个能取到的
        try:
            deps = _get(f"{JSD}/chromium/chromium@{tag}/DEPS",
                        os.path.join(CACHE, tag, "DEPS"))
        except Exception as e:
            last_err = e
            continue
        m = re.search(r"boringssl_revision'?\s*:\s*'([0-9a-f]{40})'", deps)
        if m:
            return tag, m.group(1)
        last_err = RuntimeError(f"{tag} 的 DEPS 里没有 boringssl_revision")
    raise last_err


def extract(major):
    """返回该 Chrome 主版本的 ClientHello 相关表。"""
    tag, rev = boringssl_revision(major)
    src = {}
    for f in BSSL_FILES:
        src[f] = _get(f"{JSD}/google/boringssl@{rev}/{f}",
                      os.path.join(CACHE, "bssl", rev, f.replace("/", "_")))

    ext_src = src["ssl/extensions.cc"]
    # 扩展只取集合：Chromium 自 110 起随机置换顺序，比顺序毫无意义
    m = re.search(r"static const struct tls_extension kExtensions\[\]\s*=\s*\{",
                  ext_src)
    exts = []
    if m:
        body = ext_src[m.end():ext_src.index("\n};", m.end())]
        exts = sorted(set(re.findall(r"TLSEXT_TYPE_(\w+)", body)))

    def _u16_list(text, name):
        mm = re.search(re.escape(name) + r"\[\]\s*=\s*\{(.*?)\};", text, re.S)
        if not mm:
            return []
        body = re.sub(r"/\*.*?\*/", "", mm.group(1), flags=re.S)
        body = re.sub(r"//[^\n]*", "", body)
        return [x for x in re.findall(r"SSL_SIGN_\w+", body)]

    # 签名算法表在两个文件间搬过家：老 revision 在 extensions.cc，较新的在
    # ssl_privkey.cc。只查一个会静默得到空列表，而空列表看起来就像"该版本没
    # 这张表"，比报错更难发现。
    sign = verify = []
    for text in src.values():
        sign = sign or _u16_list(text, "kSignSignatureAlgorithms")
        verify = verify or _u16_list(text, "kVerifySignatureAlgorithms")
    if not sign:
        raise RuntimeError(f"M{major}({rev[:10]}) 找不到 kSignSignatureAlgorithms，"
                           "表可能又搬家了——不要当成空列表用")
    return {
        "tag": tag,
        "boringssl": rev,
        "extensions_set": exts,
        "sign_sigalgs": sign,
        "verify_sigalgs": verify,
    }


def main(argv):
    majors = [int(a) for a in argv[1:] if a.isdigit()] or [78, 95, 120, 126, 150]

    got = {}
    for mj in majors:
        try:
            got[mj] = extract(mj)
        except Exception as e:
            print(f"  M{mj}: 取不到（{type(e).__name__}: {e}）", file=sys.stderr)

    print(f"{'版本':>5}  {'tag':<18} {'boringssl':<12} {'扩展':>4} {'签名算法':>6}")
    for mj, t in sorted(got.items()):
        print(f"{mj:>5}  {t['tag']:<18} {t['boringssl'][:10]:<12} "
              f"{len(t['extensions_set']):>4} {len(t['sign_sigalgs']):>6}")

    print("\n相邻版本比对：")
    ms = sorted(got)
    for i in range(len(ms) - 1):
        a, b = got[ms[i]], got[ms[i + 1]]
        if a["boringssl"] == b["boringssl"]:
            print(f"  M{ms[i]} ↔ M{ms[i+1]}   同一 BoringSSL revision → 同段")
            continue
        ea, eb = set(a["extensions_set"]), set(b["extensions_set"])
        bits = []
        if eb - ea:
            bits.append(f"扩展新增 {sorted(eb - ea)}")
        if ea - eb:
            bits.append(f"扩展移除 {sorted(ea - eb)}")
        if a["sign_sigalgs"] != b["sign_sigalgs"]:
            bits.append("签名算法列表变化")
        print(f"  M{ms[i]} ↔ M{ms[i+1]}   {'；'.join(bits) or '三表相同（revision 不同但表未变）'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
