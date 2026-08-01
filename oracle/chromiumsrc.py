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

**Chrome 的 feature 默认值不代表实际行为 —— Finch 会在运行期覆盖它**。这是
Chrome 与 Firefox 最本质的区别，也是 chrome 段表 usable_for_substitution=false
的真正原因。实证：
    源码 net/base/features.cc 里 kUseNewAlpsCodepointHttp2 在 M126/130/131/
    132/133 全部是 FEATURE_DISABLED_BY_DEFAULT（M140 起才 ENABLED）
    但 curl_cffi、tls_client、utls、wreq **四家实采一致**显示 M131 发旧
    codepoint 0x4469、M132+ 发新的 0x44cd
四家独立数据不会同时错，唯一解释是 Finch 实验在 132 前后把该 feature 推开了，
而源码默认值直到 140 才跟上。这意味着**同一个 Chrome 版本在不同用户/地区/
时间可能发出不同指纹**，"版本 → 唯一指纹"对 Chrome 根本不成立。

因此 Chrome 只能靠实采，且实采到的也只是"某个 Finch 配置下的一种形态"。源码
在 Chrome 这条线上只能用于反向判断：curves/sigalgs 这类硬编码表变了则**必定**
不同段；不能反过来证明同段。

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

# Chrome 82 从未发布：2020 年因疫情直接从 81 跳到 83。把它当成"取不到"会在
# 段表里留一个假缺口，还会把本该连续的段切断。
SKIPPED_MILESTONES = {82}

JSD = "https://cdn.jsdelivr.net/gh"
NPMM = "https://registry.npmmirror.com/-/binary"
# 两个目录合起来覆盖 M70..M153；chromedriver 管老版本，chrome-for-testing 管新的
VERSION_DIRS = ("chromedriver/", "chrome-for-testing/")

# BoringSSL 里决定 ClientHello 的表所在文件。**这些表搬过好几次家**，只能按
# 候选逐个试、允许 404：
#   · 2019 年（M78 时代）kExtensions 与 kSignSignatureAlgorithms 都在 t1_lib.cc
#   · 后来扩展代码拆出 extensions.cc
#   · 更晚 kSignSignatureAlgorithms 又挪进 ssl_privkey.cc
# 只查固定一个文件会 404 或静默拿到空表，而空表看起来像"该版本没这张表"。
BSSL_FILES = ("ssl/extensions.cc", "ssl/t1_lib.cc", "ssl/ssl_privkey.cc")


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
    if major in SKIPPED_MILESTONES:
        raise LookupError(f"Chrome M{major} 从未发布（2020 年疫情期间跳过）")
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
        if not m:
            last_err = RuntimeError(f"{tag} 的 DEPS 里没有 boringssl_revision")
            continue
        # curves 配置也必须在这个 tag 上能取到 —— 同一主版本的不同 patch，
        # 文件内容可能不同（M79 的末尾 patch 就抽不到 curves，靠前的能）。
        # 只按 DEPS 能否取到来选 tag，会让 curves 抽取在一个本可用的主版本上
        # 整体失败，进而在段表里留下假缺口、切断本该连续的段。
        try:
            chromium_curves(tag)
        except Exception as e:
            last_err = e
            continue
        return tag, m.group(1)
    raise last_err


# curves 的配置点在 Chromium 侧（不在 BoringSSL），且随版本搬过家：
#   老版本  net/socket/ssl_client_socket_impl.cc 里硬编码 kCurves[]
#   新版本  net/ssl/ssl_config_service.cc 里 kDefaultSSLSupportedGroups[]，
#           每项还带 send_key_share —— 决定该 group 是否进 key_share 扩展，
#           这正是 Chrome 同时发两个 key_share 的来源
CHROMIUM_CURVE_FILES = ("net/ssl/ssl_config_service.cc",
                        "net/socket/ssl_client_socket_impl.cc")


# 同一条曲线在两种配置形态里叫不同名字（老形态用 OpenSSL 的 NID_*，新形态用
# BoringSSL 的 SSL_GROUP_*）。不归一化就会把纯命名变化读成 curves 变了，段表
# 凭空多出边界——M126↔M131 那次差异里就同时混着真变化（Kyber→MLKEM）和
# 假变化（X9_62_prime256v1 → SECP256R1，本是同一条 P-256）。
CURVE_ALIASES = {
    "NID_X25519": "x25519",
    "SSL_GROUP_X25519": "x25519",
    "NID_X9_62_prime256v1": "secp256r1",
    "SSL_GROUP_SECP256R1": "secp256r1",
    "NID_secp384r1": "secp384r1",
    "SSL_GROUP_SECP384R1": "secp384r1",
    "NID_secp521r1": "secp521r1",
    "SSL_GROUP_SECP521R1": "secp521r1",
    "NID_CECPQ2": "cecpq2",
    "NID_X25519Kyber768Draft00": "x25519_kyber768_draft00",
    # M113/114 的过渡命名（后来才加 Draft00 后缀），以及短命的 P256 混合组
    "NID_X25519Kyber768": "x25519_kyber768_draft00",
    "NID_P256Kyber768": "p256_kyber768",
    "SSL_GROUP_X25519_KYBER768_DRAFT00": "x25519_kyber768_draft00",
    "SSL_GROUP_X25519_MLKEM768": "x25519_mlkem768",
}


def norm_curve(name):
    """归一化曲线名。未知名字**原样保留**并加前缀标记，不静默丢弃——
    丢掉一条未知曲线会让两个本不同的版本看起来同段。"""
    return CURVE_ALIASES.get(name, f"?{name}")


# BASE_FEATURE 的默认值可能包在平台条件里，必须按目标平台求值。实测
# kPostQuantumKyber：
#     #if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
#       FEATURE_DISABLED_BY_DEFAULT   ← 移动端默认关
#     #else
#       FEATURE_ENABLED_BY_DEFAULT
# 这正是 Android Chrome 131 不发 MLKEM 的原因（curl_cffi:chrome131_android 的
# curves 里确实没有 0x11ec，而桌面 131 有）。不按平台求值就会把移动端推导成
# 与桌面一样。
PLATFORM_BUILDFLAGS = {
    "desktop": {"IS_ANDROID": False, "IS_IOS": False, "IS_CHROMEOS": False,
                "IS_WIN": False, "IS_MAC": True, "IS_LINUX": False},
    "android": {"IS_ANDROID": True, "IS_IOS": False, "IS_CHROMEOS": False,
                "IS_WIN": False, "IS_MAC": False, "IS_LINUX": False},
}


def _buildflag_holds(expr, platform):
    """求值 BUILDFLAG(X) 组成的条件（只支持 || && ! 与 BUILDFLAG）。"""
    flags = PLATFORM_BUILDFLAGS.get(platform, PLATFORM_BUILDFLAGS["desktop"])
    e = expr
    for name, val in flags.items():
        e = e.replace(f"BUILDFLAG({name})", "True" if val else "False")
    e = re.sub(r"BUILDFLAG\(\w+\)", "False", e)      # 未知平台标志一律当假
    e = e.replace("||", " or ").replace("&&", " and ").replace("!", " not ")
    try:
        return bool(eval(e, {"__builtins__": {}}, {"True": True, "False": False}))
    except Exception:
        return False


def _resolve_platform_block(body, platform):
    """在 BASE_FEATURE 的默认值块里按平台挑出生效的那一行。"""
    if "#if" not in body:
        return body
    active, taken, out = True, False, []
    for line in body.splitlines():
        t = line.strip()
        if t.startswith("#if "):
            active = _buildflag_holds(t[4:], platform)
            taken = active
        elif t.startswith("#elif "):
            active = (not taken) and _buildflag_holds(t[6:], platform)
            taken = taken or active
        elif t.startswith("#else"):
            active = not taken
        elif t.startswith("#endif"):
            active, taken = True, False
        elif active:
            out.append(line)
    return "\n".join(out)


def feature_default(tag, name, platform="desktop"):
    """取某个 base::Feature 的默认状态。

    与 Firefox 那边的 pref 求值同构：源码里写的是三元表达式，真正发什么取决于
    flag 默认值。M133 的 postquantum_group 就是
        IsEnabled(kUseMLKEM) ? X25519_MLKEM768 : X25519_KYBER768_DRAFT00
    只看表达式无法判断，必须解出默认值。
    """
    try:
        d = _get(f"{JSD}/chromium/chromium@{tag}/net/base/features.cc",
                 os.path.join(CACHE, tag, "features.cc"))
    except Exception:
        return None
    # **两种声明语法都要认**。老版本写
    #     const base::Feature kPostQuantumCECPQ2{"...", FEATURE_DISABLED_BY_DEFAULT};
    # 新版本改成 BASE_FEATURE(kX, "...", ...)。只认新语法会让老版本一律返回
    # None，退回"保守当作生效"，于是 CECPQ2 这类默认关闭的实验被当成真会发，
    # 段表凭空多出边界（实测 74-77、80-81 因此被切出来，而 golden 证明这些
    # 版本根本没发 CECPQ2）。
    # **块内含 #if 时不能按第一个 `);` 收尾**：源码里每个平台分支各自带 `);`
    #     #if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
    #                  base::FEATURE_DISABLED_BY_DEFAULT);
    #     #else
    #                  base::FEATURE_ENABLED_BY_DEFAULT);
    #     #endif
    # 按 `);` 截断只会拿到第一个分支，#else 永远读不到 —— 实测因此把桌面的
    # kPostQuantumKyber 判成 DISABLED，与实采相反。
    body = None
    anchor = re.search(r"BASE_FEATURE\(\s*" + re.escape(name) + r"\s*,", d)
    if anchor:
        seg = d[anchor.end():anchor.end() + 800]
        first_end = seg.find(");")
        head = seg[:first_end] if first_end >= 0 else seg
        # 判据只看第一个 `);` 之前有没有 #if：有才是平台分支写法，需扩到
        # #endif；没有就是单行定义，扩过去只会读进后面别的 feature 的分支
        # （实测 M120 因此被误判成 Android 上 ENABLED，而它根本没有平台分支）。
        if "#if" in head:
            stop = seg.find("#endif")
            body = seg[:stop] if stop >= 0 else head
        else:
            body = head
    if body is None:
        m = re.search(r"(?:const\s+)?base::Feature\s+" + re.escape(name)
                      + r"\s*(?:\{|=\s*\{)(.*?)\};", d, re.S)
        if not m:
            return None
        body = m.group(1)
    m = type("M", (), {"group": lambda self, i: body})()
    if not body:
        return None
    return "FEATURE_ENABLED_BY_DEFAULT" in _resolve_platform_block(m.group(1), platform)


def _is_experiment_only(text, pos, tag, platform="desktop"):
    """判断这处 curves 配置是否只在 Finch 实验下才生效。

    **不判这个会把实验分支当成默认行为**，整个 CECPQ2 时代都会抽错：M78 的
    kCurves 包在
        const std::string post_quantum_group = kPostQuantumGroup.Get();
        if (post_quantum_group == "CECPQ2") { ... kCurves ... }
    里，Finch 参数默认是空串，所以默认根本不配置 curves。实采可证：golden 里
    Chrome 58-123 的 curves 全是 [0x1d,0x17,0x18]，没有 CECPQ2；后量子组直到
    124 才真正出现（0x6399），131 起换成 0x11ec。

    判据有两种形态，都要覆盖：
      a) Finch 参数取值 + 字符串比较（M78 的 kPostQuantumGroup.Get() == "CECPQ2"）
      b) feature 开关（M83 的 FeatureList::IsEnabled(features::kPostQuantumCECPQ2)）
         —— 这类要真的去查该 feature 的默认值，DISABLED 才算实验分支
    """
    head = text[max(0, pos - 700):pos]
    if re.search(r"\.Get\(\)", head) and re.search(r'==\s*"', head):
        return True
    # PostQuantumKeyAgreementEnabled() 的实现就是 IsEnabled(kPostQuantumKyber)
    # （见 net/ssl/ssl_config_service.cc），而该 feature 在 Android/iOS 上默认
    # 关闭。不把这层展开就判不出移动端不发后量子组。
    if "PostQuantumKeyAgreementEnabled()" in head:
        on = feature_default(tag, "kPostQuantumKyber", platform)
        return on is False
    m = re.search(r"IsEnabled\(\s*features::(\w+)\s*\)", head)
    if m:
        on = feature_default(tag, m.group(1), platform)
        # 查不到默认值时保守当作"生效"——宁可多切一个段，也不要把实际会发的
        # 配置当成不存在
        return on is False
    return False


def chromium_curves(tag, platform="desktop"):
    """返回 (supported_groups, key_share_groups)；取不到时抛错而非给空表。"""
    for f in CHROMIUM_CURVE_FILES:
        try:
            d = _get(f"{JSD}/chromium/chromium@{tag}/{f}",
                     os.path.join(CACHE, tag, os.path.basename(f)))
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            continue

        m = re.search(r"kDefaultSSLSupportedGroups\[\]\s*=\s*\{(.*?)\};", d, re.S)
        if m:
            groups, shares = [], []
            for item in re.finditer(
                    r"\.group_id\s*=\s*(\w+).*?\.send_key_share\s*=\s*(true|false)",
                    m.group(1), re.S):
                groups.append(item.group(1))
                if item.group(2) == "true":
                    shares.append(item.group(1))
            if groups:
                return [norm_curve(g) for g in groups], [norm_curve(g) for g in shares]

        # 形态二/三：硬编码数组，变量名在 kCurves 与 kGroups 之间换过，
        # 且首项可能是个由 feature flag 决定的三元表达式
        m = re.search(r"(?:static\s+)?const\s+(?:int|uint16_t)\s+"
                      r"k(?:Curves|Groups)\[\]\s*=\s*\{(.*?)\};", d, re.S)
        if m and _is_experiment_only(d, m.start(), tag, platform):
            # 判定为实验分支：默认不生效，用 BoringSSL 默认组。直接返回而不是
            # 继续往下找——否则会掉进"有配置调用却抽不出数组"的错误分支。
            return ["boringssl-default"], []
        if m:
            body = m.group(1)
            groups = re.findall(r"(?:NID_|SSL_GROUP_)\w+", body)
            if "postquantum_group" in body:
                # 该项的实参在上文的三元表达式里，按 feature 默认值解出来
                tern = re.search(
                    r"postquantum_group\s*=\s*.*?IsEnabled\(\s*features::(\w+)\s*\)"
                    r"\s*\?\s*(\w+)\s*:\s*(\w+)", d, re.S)
                if tern:
                    on = feature_default(tag, tern.group(1), platform)
                    pq = tern.group(2) if on else tern.group(3)
                    if on is None:
                        raise RuntimeError(
                            f"{tag} 解不出 features::{tern.group(1)} 的默认值，"
                            "不能猜 postquantum_group")
                    groups = [pq] + groups
            if groups:
                # 老版本没有 send_key_share 概念，key_share 由 BoringSSL 决定
                return [norm_curve(g) for g in groups], []
    # 走到这里有两种可能，**必须分清**：
    #   a) Chromium 这个版本根本不配置 curves，用 BoringSSL 默认值
    #   b) 配置点又搬家了，我们没找到
    # 判据是有没有 SSL_set1_curves / SSL_set1_group_ids 的调用。混为一谈的话，
    # (a) 会被当成抽取失败而在段表里留假缺口（M79 就是这种：它没有任何配置
    # 调用，只有读取用的 SSL_get_curve_id），(b) 会被当成"没配置"而静默用错值。
    impl = None
    try:
        impl = _get(f"{JSD}/chromium/chromium@{tag}/net/socket/ssl_client_socket_impl.cc",
                    os.path.join(CACHE, tag, "ssl_client_socket_impl.cc"))
    except Exception:
        pass
    if impl is not None and not re.search(r"SSL_set1_(?:curves|group_ids)\s*\(", impl):
        return ["boringssl-default"], []
    raise RuntimeError(f"{tag} 有 curves 配置调用但抽不出数组 —— 配置点可能又搬家了")


def chromium_sig_and_cipher(tag):
    """Chromium 侧对签名算法与 cipher 的**覆盖**，这两处决定了 ClientHello。

    只读 BoringSSL 会漏掉它们，而它们正是 Chrome 72↔83 差异的全部来源：
      · kVerifyPrefs —— Chromium 硬编码的 signature_algorithms 列表，有它就
        完全覆盖 BoringSSL 默认（M83 有，M72/78 没有）
      · command.append(":!XXX") —— cipher 排除项，M83 起加了 :!3DES
    客户端 ClientHello 里发的是"我能验证哪些签名"，所以对应 kVerify* 而非
    kSign*——用错会把两个不同的版本判成同段。
    """
    try:
        d = _get(f"{JSD}/chromium/chromium@{tag}/net/socket/ssl_client_socket_impl.cc",
                 os.path.join(CACHE, tag, "ssl_client_socket_impl.cc"))
    except Exception:
        return None, [], False
    # Channel ID(0x7550) 是 Google 私有扩展，BoringSSL 的 kExtensions 表里
    # **每个版本都有**，但 Chromium 在 M72 把使用它的代码整片删掉了（M70 有
    # 35 处引用、M72 起 0 处）。utls 实采印证：Chrome_70 发 0x7550、Chrome_72
    # 不发。只看 BoringSSL 的表会以为所有版本都发——又一例"表里有 ≠ 会发"。
    channel_id = bool(re.search(r"[Cc]hannel[_ ]?[Ii][Dd]", d))
    prefs = None
    m = re.search(r"kVerifyPrefs\[\]\s*=\s*\{(.*?)\};", d, re.S)
    if m:
        prefs = re.findall(r"SSL_SIGN_\w+", m.group(1))
    excludes = sorted(set(re.findall(r'command\.append\("?:!(\w+)"?\)', d)))
    return prefs, excludes, channel_id


def ordered_extensions(rev):
    """BoringSSL kExtensions 的**有序**列表（数值）。

    只对 Chrome <110 有指纹意义——110 起随机置换，顺序不再是稳定特征。但表
    本身的变化在任何版本都值得记录，所以这里照抽，由调用方决定用不用。
    """
    src = None
    for f in ("ssl/extensions.cc", "ssl/t1_lib.cc"):
        try:
            t = _get(f"{JSD}/google/boringssl@{rev}/{f}",
                     os.path.join(CACHE, "bssl", rev, f.replace("/", "_")))
            if "kExtensions[]" in t:
                src = t
                break
        except Exception:
            continue
    if not src:
        return []
    m = re.search(r"static const struct tls_extension kExtensions\[\]\s*=\s*\{", src)
    if not m:
        return []
    names = re.findall(r"TLSEXT_TYPE_(\w+)", src[m.end():src.index("\n};", m.end())])
    try:
        hdr = _get(f"{JSD}/google/boringssl@{rev}/include/openssl/tls1.h",
                   os.path.join(CACHE, "bssl", rev, "tls1.h"))
    except Exception:
        return []
    vals = {mm.group(1): int(mm.group(2), 0) for mm in
            re.finditer(r"#define TLSEXT_TYPE_(\w+)\s+(0x[0-9a-fA-F]+|\d+)", hdr)}
    return [vals[n] for n in names if n in vals]


def alps_enabled(tag):
    """ALPS(application_settings) 是否默认发送。

    判据是 net/base/features.cc 里有没有 kAlpsForHttp2 且默认 ENABLED —— 该
    feature 自 M92 出现即默认开启，M91 及以前根本没有这个符号。实采两侧都对
    得上：utls:Chrome_87 不发 ALPS、utls:Chrome_96 发。

    **只判"发不发"，不判用哪个 codepoint**。codepoint 从 0x4469 迁到 0x44cd
    由 kUseNewAlpsCodepointHttp2 控制，而那个 feature 的源码默认值与实际行为
    相反（源码里 M126~133 全是 DISABLED，四家实采却显示 M132+ 已改发新值），
    是 Finch 在运行期覆盖的，静态分析拿不到。
    """
    try:
        d = _get(f"{JSD}/chromium/chromium@{tag}/net/base/features.cc",
                 os.path.join(CACHE, tag, "features.cc"))
    except Exception:
        return None
    if "kAlpsForHttp2" not in d:
        return False
    return bool(feature_default(tag, "kAlpsForHttp2"))


def extract(major, platform="desktop"):
    """返回该 Chrome 主版本在指定平台下的 ClientHello 相关表。

    platform="android" 时按 Android 构建求值。实测差异集中在后量子密钥交换：
    kPostQuantumKyber 在 `#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)` 下
    默认关闭，所以 Android Chrome 131 的 curves 里没有 0x11ec，而桌面有
    （curl_cffi:chrome131_android 与 chrome131 因此是两条不同记录）。
    """
    tag, rev = boringssl_revision(major)
    src = {}
    for f in BSSL_FILES:
        try:
            src[f] = _get(f"{JSD}/google/boringssl@{rev}/{f}",
                          os.path.join(CACHE, "bssl", rev, f.replace("/", "_")))
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            continue           # 该 revision 没这个文件，表在别处

    # 扩展只取集合：Chromium 自 110 起随机置换顺序，比顺序毫无意义
    exts = []
    for text in src.values():
        m = re.search(r"static const struct tls_extension kExtensions\[\]\s*=\s*\{",
                      text)
        if m:
            body = text[m.end():text.index("\n};", m.end())]
            exts = sorted(set(re.findall(r"TLSEXT_TYPE_(\w+)", body)))
            break
    if not exts:
        raise RuntimeError(f"M{major}({rev[:10]}) 在 {list(src)} 里都找不到 "
                           "kExtensions —— 表可能又搬家了，别当成空集合用")

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
    curves, key_shares = chromium_curves(tag, platform)
    verify_prefs, cipher_excludes, channel_id = chromium_sig_and_cipher(tag)
    # Chrome 自 110 起随机置换扩展顺序，届时顺序不再是指纹特征
    ext_order = ordered_extensions(rev) if major < 110 else []
    return {
        "verify_prefs": verify_prefs,
        "cipher_excludes": cipher_excludes,
        "channel_id": channel_id,
        "alps": alps_enabled(tag),
        "ext_order": ext_order,
        "tag": tag,
        "boringssl": rev,
        "curves": curves,
        "key_share_groups": key_shares,
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

    print(f"{'版本':>5}  {'tag':<18} {'boringssl':<12} {'扩展':>4} {'签名':>4}  curves")
    for mj, t in sorted(got.items()):
        print(f"{mj:>5}  {t['tag']:<18} {t['boringssl'][:10]:<12} "
              f"{len(t['extensions_set']):>4} {len(t['sign_sigalgs']):>4}  {t['curves']}")

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
        if a["curves"] != b["curves"]:
            bits.append(f"curves {a['curves']} → {b['curves']}")
        print(f"  M{ms[i]} ↔ M{ms[i+1]}   {'；'.join(bits) or '三表相同（revision 不同但表未变）'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
