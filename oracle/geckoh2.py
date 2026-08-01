"""从 Gecko 源码推出 Firefox 的 HTTP/2 连接开场。

h2 层剩余 136 个缺口里有 125 个是 Gecko 的（firefox 50/76、firefox-mobile
75/76）。判据全在源码里，且比 Chromium 那边还完整 —— 连 PRIORITY 树都是写死的。

判据链（Firefox 135 逐项对得上 golden）：

    netwerk/protocol/http/Http2Session.cpp  Http2Session::SendHello()
        SETTINGS **按源码书写顺序**写（不是 Chromium 那种 std::map 升序）：
          1 HEADER_TABLE_SIZE = DefaultHpackBuffer()      ← pref
          if !allow_push:
            2 ENABLE_PUSH = 0
            if send-push-max-concurrent-frame: 3 MAX_CONCURRENT = 0
          4 INITIAL_WINDOW  = mPushAllowance               ← pref
          5 MAX_FRAME_SIZE  = kMaxFrameData = 0x4000
          if disableRFC7540Priorities && send_NO_RFC7540_PRI:
            9 NO_RFC7540_PRIORITIES = 1
        WINDOW_UPDATE = mInitialRwin - kDefaultRwin        ← pref - 65535
        PRIORITY：6 个固定分组，只在 UseH2Deps() 时发

    modules/libpref/init/StaticPrefList.yaml        各 pref 的默认值
    mobile/android/app/geckoview-prefs.js           **Android 的覆盖**

最后一行是这次的关键发现。实测 wreq 的 FirefoxAndroid135 与 Firefox135 差两处
（HEADER_TABLE_SIZE 4096 vs 65536、INITIAL_WINDOW 32768 vs 131072），而
StaticPrefList 里这两个 pref 的桌面与 Android 求值**完全相同** —— 差异不在那里，
在 geckoview-prefs.js：

    pref("network.http.http2.default-hpack-buffer", 4096);
    pref("network.http.http2.push-allowance", 32768);

只按 StaticPrefList 的平台条件求值会得出"两端一样"的错结论。TLS 那边的
`nsssrc.py` 用平台构建标记就够了，h2 这边不够 —— 同一套基础设施，不同的坑。

PRIORITY 树也是源码里写死的（`CreatePriorityNode(id, dep, weight)`）：

    3(leader) dep=0 w=200   5(other) dep=0 w=100   7(background) dep=0 w=0
    9(speculative) dep=7 w=0   11(follower) dep=3 w=0   13(urgentStart) dep=0 w=240

线上权重比实际小 1（RFC 7540 §6.3），解析时 +1 还原 —— 与本项目那份
linux:firefox-111-linux 实采逐条吻合（201/101/1/1/1/241）。

跑：python -m oracle.geckoh2 [版本]
"""

import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import oracle.nsssrc as nss                                      # noqa: E402

# 源码文件登记到 nsssrc.FILES 里，复用它的取源与缓存。
# **每个文件必须有自己的名字**：nsssrc.fetch 按名字缓存，复用同一个名字会让
# 后取的文件静默拿到先取那个的内容（实测三个不同文件返回同样的长度）。
nss.FILES.setdefault("h2session", "netwerk/protocol/http/Http2Session.cpp")
nss.FILES.setdefault("h2session_h", "netwerk/protocol/http/Http2Session.h")
nss.FILES.setdefault("gvprefs", "mobile/android/app/geckoview-prefs.js")

PSEUDO = [":method", ":path", ":authority", ":scheme"]
H2_INITIAL_WINDOW = 65535           # kDefaultRwin

# Http2Session.cpp 里 CreatePriorityNode 的六个分组，(流ID, 依赖, 权重)。
# 权重是**源码里的值**，线上就发这个数，解析端 +1 还原。
PRIORITY_GROUPS = [(0x3, 0, 200), (0x5, 0, 100), (0x7, 0, 0),
                   (0x9, 0x7, 0), (0xB, 0x3, 0), (0xD, 0, 240)]

# 数值 pref：**恒为必需**。它们不经 StaticPrefs:: 读（源码里走
# gHttpHandler->DefaultHpackBuffer()、mPushAllowance、mInitialRwin），
# 所以"SendHello 里有没有引用"这条判据对它们不适用 —— 一视同仁地套用会把
# 它们全部当成"没引用"而清零，推出 1:0,4:0 这种明显不对的值。
NUM_PREFS = {
    "hpack": "network.http.http2.default-hpack-buffer",
    "push_allowance": "network.http.http2.push-allowance",
    "pull_allowance": "network.http.http2.pull-allowance",
}

# 布尔开关：都是 SendHello 里直接 StaticPrefs::…() 读的，可以按引用与否判断。
# 老版本里对应的代码段还不存在时，引用也不存在，当假即可。
BOOL_PREFS = {
    "allow_push": "network.http.http2.allow-push",
    "send_maxconc": "network.http.http2.send-push-max-concurrent-frame",
    "send_no_rfc": "network.http.http2.send_NO_RFC7540_PRI",
    "deps": "network.http.http2.enabled.deps",
}

PREFS = {**NUM_PREFS, **BOOL_PREFS}

# 同一个 pref 在不同年代有**两套名字、两个文件**：
#   Firefox 100 起  StaticPrefList.yaml   network.http.http2.*
#   Firefox 78-99   all.js                network.http.spdy.*
# 只查 StaticPrefList 的 http2 名字，78-99 整段都推不出来（实测缺 22 个版本）。
# 顺序：先 StaticPrefList 后 all.js，先 http2 名后 spdy 名。
def _prefs_js_value(text, name):
    """读 all.js 里的 `pref("name", value);`。

    **不能拿 StaticPrefList 的解析器去读它** —— 那是 YAML（`- name:` / `value:`），
    而 all.js 是 JS 调用，语法完全不同。混用的表现是"文件取到了、值恒为 None"，
    看起来像"这个版本没有这个 pref"。
    """
    m = re.search(r'pref\(\s*"' + re.escape(name) + r'"\s*,\s*([^\)]+)\)', text)
    return m.group(1).strip() if m else None


def _lookup_pref(version, name, platform):
    http2_name = name
    spdy_name = name.replace(".http2.", ".spdy.")
    # StaticPrefList（YAML，带平台条件）优先，再退到 all.js（JS，无平台条件）
    try:
        text = nss.fetch(version, "staticprefs")
        for n in (http2_name, spdy_name):
            v = nss.pref_value(text, n, platform)
            if v is not None:
                return v
    except Exception:
        pass
    try:
        text = nss.fetch(version, "prefs")
        for n in (http2_name, spdy_name):
            v = _prefs_js_value(text, n)
            if v is not None:
                return v
    except Exception:
        pass
    return None


def _android_overrides(version):
    """geckoview-prefs.js 里对 http2 pref 的覆盖。取不到就返回空表。

    取不到**不能当成"没有覆盖"**，那会让 Android 的推导悄悄退化成桌面值。
    所以这里返回的空表由调用方判断：android 平台拿不到覆盖就弃权。
    """
    try:
        text = nss.fetch(version, "gvprefs")
    except Exception:
        return None
    out = {}
    for m in re.finditer(r'pref\(\s*"(network\.http\.http2\.[\w\-\.]+)"\s*,'
                         r'\s*([^\)]+)\)', text):
        raw = m.group(2).strip()
        if raw.isdigit():
            out[m.group(1)] = int(raw)
        elif raw in ("true", "false"):
            out[m.group(1)] = (raw == "true")
    return out


def _as_bool(v):
    """pref_value 对布尔 pref 返回的是字符串 "true"/"false"。

    **直接拿去做真值判断会全错**：Python 里非空字符串恒为真，于是
    `not "false"` 是 False —— 实测因此让 Firefox 135 少发了 ENABLE_PUSH=0、
    反而多发了六个 PRIORITY 帧。巧的是那份错的输出恰好等于本项目的
    linux:firefox-111-linux 实采（111 那会儿这两个 pref 确实是 true），
    看起来"对上了"，其实是撞上的。
    """
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() == "true"
    return bool(v)


def _referenced_prefs(src):
    """SendHello() 实际引用了哪些 StaticPrefs。

    老版本里有些 pref 根本还不存在（send-push-max-concurrent-frame 是后加的），
    无差别地要求全部 pref 会让那些版本整体推不出来。以源码实际引用为准，
    没引用的就不参与判断 —— 这比维护一张"哪个版本有哪个 pref"的表可靠。
    """
    i = src.find("Http2Session::SendHello")
    if i < 0:
        raise LookupError("源码里没有 Http2Session::SendHello —— 函数改名或"
                          "搬家了，不能当成「该版本没有」处理")
    end = src.find("\nvoid Http2Session::", i + 10)
    body = src[i:end if end > 0 else i + 12000]
    return {"network.http." + m.group(1).replace("_", ".")
            for m in re.finditer(r"StaticPrefs::network_http_(\w+)\(\)", body)}


def _brace_block(src, start):
    """从 start 之后的第一个 { 起，按配对括号取到闭合处。"""
    k = src.find("{", start)
    if k < 0:
        return ""
    depth = 0
    for pos in range(k, len(src)):
        if src[pos] == "{":
            depth += 1
        elif src[pos] == "}":
            depth -= 1
            if depth == 0:
                return src[k:pos]
    return src[k:]


def _sendhello_body(src):
    """SendHello 的函数体。**按配对括号取，不能按"下一个 void Http2Session::"切**
    —— 后者会把后面几个函数一起圈进来，于是在 128 上把收帧那边出现的
    SETTINGS_NO_RFC7540_PRIORITIES 当成"SendHello 会发它"，进而要求一个那时
    还不存在的 pref。"""
    i = src.find("Http2Session::SendHello")
    return _brace_block(src, i) if i >= 0 else ""


def _push_branch(src):
    """SendHello 里"不支持推送"那个分支的函数体。

    **两种写法都要认**：新版本是 `StaticPrefs::network_http_http2_allow_push()`，
    78-99 是 `gHttpHandler->AllowPush()`。只认前者会让老版本的分支体取成空，
    于是 allow_push 被判成假、给 78-99 错发 ENABLE_PUSH=0 —— 而那些版本的
    allow-push 默认恰恰是 true。
    """
    body = _sendhello_body(src)
    for pat in ("allow_push()", "AllowPush()"):
        j = body.find(pat)
        if j >= 0:
            return _brace_block(body, j)
    return ""


def _pref_name_for_symbol(version, symbol):
    """StaticPrefs 符号 → 真实 pref 名。

    符号是把 pref 名里的 `.` 与 `-` 一律换成 `_` 得到的，反过来推不回去
    （network.http.priority_header.enabled 两种分隔符都有）。所以正向来：
    把文件里出现的每个 pref 名归一后与符号比。
    """
    def norm(x):
        return x.replace(".", "_").replace("-", "_")
    for src_name, pat in (("staticprefs", r"name:\s*([\w\.\-]+)"),
                          ("prefs", r'pref\(\s*"([\w\.\-]+)"')):
        try:
            text = nss.fetch(version, src_name)
        except Exception:
            continue
        for m in re.finditer(pat, text):
            if norm(m.group(1)) == symbol:
                return m.group(1)
    return None


def _disable_rfc7540(src, version, platform):
    """求值源码里那句 `bool disableRFC7540Priorities = …;`。

    **表达式本身随版本变**，不能写死：132 起是
    `!enabled_deps() || !CriticalRequestPrioritization()`，128 还多一项
    `|| priority_header_enabled()`。写死任何一版都会在别的版本上算错 ——
    而这个布尔同时决定发不发 PRIORITY、以及 NO_RFC7540 那项的值。

    只处理 `||` 与前缀 `!`：源码里就是这个形状。出现别的运算符宁可抛错，
    也不要猜 —— 猜错的代价是整段版本的 h2 指纹都错。
    """
    body = _sendhello_body(src)
    m = re.search(r"bool\s+disableRFC7540Priorities\s*=\s*([^;]+);", body)
    if not m:
        return None                      # 这一版没有这个概念
    expr = " ".join(m.group(1).split())
    if "&&" in expr:
        raise LookupError(f"disableRFC7540Priorities 出现了 && ：{expr}")
    result = False
    for term in expr.split("||"):
        term = term.strip()
        neg = term.startswith("!")
        term = term.lstrip("!").strip()
        pm = re.match(r"StaticPrefs::(\w+)\(\)", term)
        if pm:
            # **不能从符号反推 pref 名**：符号把 `.` 和 `_` 都压成 `_`，
            # 而 network.http.priority_header.enabled 两种都有，怎么还原都
            # 猜不对。改成正向匹配 —— 把文件里的 pref 名归一后与符号比。
            name = _pref_name_for_symbol(version, pm.group(1))
            if name is None:
                raise LookupError(f"disableRFC7540Priorities 用到符号 "
                                  f"{pm.group(1)}，在 pref 文件里找不到对应项")
            val = _lookup_pref(version, name, platform)
            if val is None:
                raise LookupError(f"disableRFC7540Priorities 用到 {name} "
                                  "却取不到默认值")
            v = _as_bool(val)
        elif term.startswith("gHttpHandler->"):
            # 处理器上的访问器（CriticalRequestPrioritization 等）：没有独立
            # pref，默认开。它只在与别的项 || 时出现，取默认不影响结论。
            v = True
        else:
            raise LookupError(f"disableRFC7540Priorities 里有看不懂的项：{term}")
        result = result or ((not v) if neg else v)
    return result


def _no_rfc_write(src):
    """SendHello 里 NO_RFC7540_PRIORITIES 的写入形态。

    与 MAX_CONCURRENT 同一个模式：先无条件写（128），后来才包进
    send_NO_RFC7540_PRI（132+）。返回 "absent" / "always" / "gated"。
    """
    b = _sendhello_body(src)
    i = b.find("SETTINGS_NO_RFC7540_PRIORITIES")
    if i < 0:
        return "absent"
    return "gated" if "send_NO_RFC7540_PRI" in b[:i] else "always"


def _emits_max_concurrent(src):
    return "SETTINGS_TYPE_MAX_CONCURRENT" in _push_branch(src)


def _gated_by_maxconc_pref(src):
    b = _push_branch(src)
    i = b.find("SETTINGS_TYPE_MAX_CONCURRENT")
    return i > 0 and "send_push_max_concurrent_frame" in b[:i]


def _const(text, name):
    m = re.search(re.escape(name) + r"\s*=\s*(0x[0-9a-fA-F]+|\d+)", text)
    return int(m.group(1), 0) if m else None


def firefox_h2(version, platform="desktop"):
    """返回 {settings, window_update, priorities, pseudo_header_order}。"""
    version = str(version)
    prefs_text = nss.fetch(version, "staticprefs")
    src = nss.fetch(version, "h2session")

    referenced = _referenced_prefs(src)
    vals = {k: _lookup_pref(version, name, platform)
            for k, name in PREFS.items()}

    if platform == "android":
        over = _android_overrides(version)
        if over is None:
            raise LookupError(f"Firefox {version} 取不到 geckoview-prefs.js；"
                              "Android 的两个关键 pref 在那里覆盖，"
                              "拿桌面值顶替会得出错的 h2")
        for k, name in PREFS.items():
            if name in over:
                vals[k] = over[name]

    def _norm(x):
        return x.replace("-", "_").replace(".", "_")
    ref_norm = {_norm(x) for x in referenced}

    # 数值 pref 缺一个就弃权 —— 拿默认值顶替等于编一个 h2 指纹
    missing = [n for k, n in NUM_PREFS.items() if vals[k] is None]
    if missing:
        raise LookupError(f"Firefox {version}/{platform} 取不到数值 pref：{missing}")

    # 布尔开关：判据取**源码结构**而不是"SendHello 有没有 StaticPrefs:: 引用"。
    # 老版本读 pref 走的是 gHttpHandler->AllowPush() 这类访问器，压根不出现
    # StaticPrefs:: —— 按引用判会把 allow_push 判成假，于是给 78-99 错发
    # ENABLE_PUSH=0。改成看那条设置在源码里能不能被写出来：
    #   写不出来 → 与 pref 无关，恒不发
    #   写得出来 → 用 pref 决定，pref 取不到就弃权
    body = _push_branch(src)
    emits = {
        "allow_push": bool(body),                       # 有 !push 分支才谈得上
        "send_maxconc": _emits_max_concurrent(src) and _gated_by_maxconc_pref(src),
        # **只在 SendHello 体内找**：这个常量在文件别处也会出现（收帧那边要认
        # 它），扫全文会在 128 上判成"会发"，进而要求一个那时还不存在的 pref。
        "send_no_rfc": _no_rfc_write(src) == "gated",
        "deps": True,                                   # UseH2Deps 一直都在
    }
    for k, name in BOOL_PREFS.items():
        if not emits[k]:
            vals[k] = False
        elif vals[k] is None:
            raise LookupError(f"Firefox {version}/{platform} 会用到 {name} "
                              "却取不到它的默认值")

    max_frame = _const(src, "kMaxFrameData")
    if max_frame is None:
        # Http2Session.cpp 里没有就去头文件找；两处都没有说明常量搬家了，
        # 不能拿 16384 硬顶 —— 那正是它可能变过的那个值。
        max_frame = _const(nss.fetch(version, "h2session_h"), "kMaxFrameData")
    if max_frame is None:
        raise LookupError(f"Firefox {version} 找不到 kMaxFrameData")

    settings = [(1, int(vals["hpack"]))]
    if not _as_bool(vals["allow_push"]):
        settings.append((2, 0))
        # MAX_CONCURRENT 的门是**后加的**：128 的源码在这个分支里无条件写它，
        # 132 之后才包进 send-push-max-concurrent-frame。所以不能只看 pref ——
        # pref 不存在时按"关"处理会让 128 少发一项。判据取源码结构：分支里有
        # 没有这条写入、写入是不是被 pref 包着。
        if _emits_max_concurrent(src):
            if _gated_by_maxconc_pref(src):
                if _as_bool(vals["send_maxconc"]):
                    settings.append((3, 0))
            else:
                settings.append((3, 0))
    settings.append((4, int(vals["push_allowance"])))
    settings.append((5, max_frame))

    # 发不发 PRIORITY、以及 NO_RFC7540 那项的值，都由源码里那句
    # disableRFC7540Priorities 决定。它在老版本里不存在，那时按 deps 走。
    disable_deps = _disable_rfc7540(src, version, platform)
    if disable_deps is None:
        disable_deps = not _as_bool(vals["deps"])

    mode = _no_rfc_write(src)
    if mode == "always":
        settings.append((9, 1 if disable_deps else 0))
    elif mode == "gated" and disable_deps and _as_bool(vals["send_no_rfc"]):
        settings.append((9, 1))

    priorities = [] if disable_deps else [
        [sid, dep, 0, w + 1] for sid, dep, w in PRIORITY_GROUPS]

    return {
        "settings": [list(x) for x in settings],
        "window_update": int(vals["pull_allowance"]) - H2_INITIAL_WINDOW,
        "priorities": priorities,
        "pseudo_header_order": list(PSEUDO),
    }


def akamai(rec):
    s = ",".join(f"{k}:{v}" for k, v in rec["settings"]) or "0"
    p = "|".join(f"{sid}:{excl}:{dep}:{wt}"
                 for sid, dep, excl, wt in rec["priorities"]) or "0"
    h = ",".join(k[1] for k in rec["pseudo_header_order"]) or "0"
    return f"{s}|{rec['window_update']}|{p}|{h}"


def main(argv):
    vers = [argv[1]] if len(argv) > 1 else ["102", "111", "121", "135", "151"]
    for v in vers:
        for plat in ("desktop", "android"):
            try:
                print(f"  {v:>4} {plat:8s} {akamai(firefox_h2(v, plat))}")
            except Exception as e:
                print(f"  {v:>4} {plat:8s} ✗ {type(e).__name__}: {str(e)[:70]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
