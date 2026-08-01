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


def _push_branch(src):
    """SendHello 里 `if (!…allow_push())` 那个分支的函数体。"""
    i = src.find("Http2Session::SendHello")
    j = src.find("allow_push()", i)
    if i < 0 or j < 0:
        return ""
    k = src.find("{", j)
    depth, end = 0, k
    for pos in range(k, min(len(src), k + 4000)):
        if src[pos] == "{":
            depth += 1
        elif src[pos] == "}":
            depth -= 1
            if depth == 0:
                end = pos
                break
    return src[k:end]


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
    vals = {k: nss.pref_value(prefs_text, name, platform)
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
    # 布尔开关：源码没引用的说明那段代码在这个版本还不存在，当假
    for k, name in BOOL_PREFS.items():
        if _norm(name) not in ref_norm:
            vals[k] = False
        elif vals[k] is None:
            raise LookupError(f"Firefox {version}/{platform} 引用了 {name} "
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

    # UseH2Deps() 为假时不发 PRIORITY，也就是 SETTINGS_NO_RFC7540_PRIORITIES
    # 那条分支成立的时候。CriticalRequestPrioritization() 是运行期取值，
    # 默认跟 enabled.deps 走。
    disable_deps = not _as_bool(vals["deps"])
    if disable_deps and _as_bool(vals["send_no_rfc"]):
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
