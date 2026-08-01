"""从 Chromium 源码推出 Chrome 的 HTTP/2 连接开场（SETTINGS / WINDOW_UPDATE）。

**为什么要推**：h2 层覆盖只有 67.7%，而 TLS 层是 99.5%。缺口几乎全部来自只建模
TLS 的来源库（utls 全系没有 h2 数据，chrome 70-98 大量落在那些条目上）。补法只有
两条 —— 真机采集，或读源码。TLS 层的缺口当初就是靠读 Chromium 源码补上的，h2 层
的判据同样都在源码里，而且比 TLS 那边更直接。

判据链（M120 实测逐项对得上 golden）：

    net/http/http_network_session.cc  AddDefaultHttp2Settings()
        决定**发哪些 SETTINGS 键**，以及每个键取哪个常量
    net/http/http_network_session.h   kSpdyMaxHeaderTableSize = 64*1024
                                      kSpdyMaxHeaderListSize  = 256*1024
                                      kSpdyMaxConcurrentPushedStreams = 1000
    net/http/http_network_session.cc  kSpdySessionMaxRecvWindowSize = 15*1024*1024
                                      kSpdyStreamMaxRecvWindowSize  =  6*1024*1024

    WINDOW_UPDATE = kSpdySessionMaxRecvWindowSize - 65535
                  = 15728640 - 65535 = 15663105   ← 与实采完全一致

**键集会随版本变**，这正是源码比猜测强的地方：

    M100  {HEADER_TABLE_SIZE, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE,
           MAX_HEADER_LIST_SIZE}                       → 1,3,4,6
    M120  {ENABLE_PUSH, HEADER_TABLE_SIZE, INITIAL_WINDOW_SIZE,
           MAX_HEADER_LIST_SIZE}                       → 1,2,4,6

服务端推送被移除后，Chrome 改成显式发 `ENABLE_PUSH=0`、不再发
`MAX_CONCURRENT_STREAMS`。两代 golden 恰好就是这两种形态。

**顺序不是我们定的**：`spdy::SettingsMap` 是 `std::map<uint16_t, uint32_t>`，
迭代按键升序，所以线上顺序恒为键号从小到大。不能按源码里的书写顺序发 ——
M120 源码里 ENABLE_PUSH 写在最前，线上却排在 HEADER_TABLE_SIZE 之后。

**先验证再使用**：spec/test_chromium_h2.py 要求"凡是已有 golden 的版本，推导
结果必须逐字段吻合"。这条规矩是 Safari 那次换来的 —— 当时 coreTLS 的表看着
形态完全对，拿已有真值一比才发现它根本不描述那个栈。

跑：python -m oracle.chromiumh2 [主版本号]
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chromiumsrc import (CACHE, JSD, SKIPPED_MILESTONES,  # noqa: E402
                                _get, version_index)

# spdy 的 SETTINGS 键号（RFC 7540 §6.5.2）
SETTING_IDS = {
    "SETTINGS_HEADER_TABLE_SIZE": 1,
    "SETTINGS_ENABLE_PUSH": 2,
    "SETTINGS_MAX_CONCURRENT_STREAMS": 3,
    "SETTINGS_INITIAL_WINDOW_SIZE": 4,
    "SETTINGS_MAX_FRAME_SIZE": 5,
    "SETTINGS_MAX_HEADER_LIST_SIZE": 6,
}

# 常量可能定义在 .cc 也可能在 .h 里，两边都要找
SRC_FILES = ("net/http/http_network_session.cc", "net/http/http_network_session.h")

# HTTP/2 的初始连接窗口是 65535（RFC 7540 §6.9.2），Chrome 发的 WINDOW_UPDATE
# 增量就是"想要的窗口 - 这个初始值"。
H2_INITIAL_WINDOW = 65535

# Chrome 的伪头序，自 SPDY 时代起未变
CHROME_PSEUDO = [":method", ":authority", ":scheme", ":path"]


def _src(tag):
    out = {}
    for f in SRC_FILES:
        out[f] = _get(f"{JSD}/chromium/chromium@{tag}/{f}",
                      os.path.join(CACHE, tag, f.replace("/", "_")))
    return out


def _const(files, name):
    """在两个文件里找 `name = <算式>;`，算式只含数字与乘法。

    只认数字与 `*`：源码里这些常量都写成 `64 * 1024` 这种形式，放开到任意
    表达式就得处理标识符引用，反而容易把"没找到"错认成"算出来是 0"。
    """
    for text in files.values():
        m = re.search(re.escape(name) + r"\s*=\s*([0-9*\s]+);", text)
        if m:
            expr = m.group(1).strip()
            if re.fullmatch(r"[0-9*\s]+", expr):
                total = 1
                for part in expr.split("*"):
                    total *= int(part.strip())
                return total
    return None


def h2_defaults(tag):
    """返回 {settings: [(id, val)...], window_update: int, pseudo: [...]}。

    settings 按键号升序 —— 那是 std::map 的迭代序，也是线上实际顺序。
    """
    files = _src(tag)
    cc = files[SRC_FILES[0]]

    i = cc.find("AddDefaultHttp2Settings")
    if i < 0:
        raise LookupError(f"{tag} 的 http_network_session.cc 里没有 "
                          "AddDefaultHttp2Settings —— 这个函数改名或搬家了，"
                          "不能当成'该版本没有默认值'处理")
    body = cc[i:]
    end = body.find("\n}")
    body = body[:end if end > 0 else len(body)]

    # 形如 http2_settings[spdy::SETTINGS_X] = <常量或字面量>;
    # 赋值常常换行，所以跨行匹配
    pairs = re.findall(
        r"http2_settings\[spdy::(SETTINGS_\w+)\]\s*=\s*([A-Za-z_0-9]+)\s*;",
        body)
    if not pairs:
        raise LookupError(f"{tag} 的 AddDefaultHttp2Settings 里一个赋值都没解析到")

    settings = []
    for key, rhs in pairs:
        sid = SETTING_IDS.get(key)
        if sid is None:
            raise LookupError(f"{tag} 出现未知 SETTINGS 键 {key} —— "
                              "键号表要补，静默丢掉会少发一项")
        if rhs.isdigit():
            val = int(rhs)
        else:
            val = _const(files, rhs)
            if val is None:
                raise LookupError(f"{tag} 找不到常量 {rhs} 的定义")
        settings.append((sid, val))
    settings.sort()                       # std::map 迭代序 = 键号升序

    sess = _const(files, "kSpdySessionMaxRecvWindowSize")
    if sess is None:
        raise LookupError(f"{tag} 找不到 kSpdySessionMaxRecvWindowSize")

    return {
        "settings": settings,
        "window_update": sess - H2_INITIAL_WINDOW,
        "pseudo_header_order": list(CHROME_PSEUDO),
    }


def chrome_h2(major):
    """按主版本号取；同一主版本取末尾能拿到源码的那个 patch。"""
    if major in SKIPPED_MILESTONES:
        raise LookupError(f"Chrome M{major} 从未发布")
    index = version_index()
    if major not in index:
        raise KeyError(f"M{major} 不在版本索引里")
    last = None
    for tag in reversed(index[major][-4:]):
        try:
            return h2_defaults(tag)
        except Exception as e:
            last = e
    raise last


def akamai(rec):
    """把推导结果拼成 akamai 指纹，方便与 golden 直接比字符串。"""
    s = ",".join(f"{k}:{v}" for k, v in rec["settings"]) or "0"
    h = ",".join(k[1] for k in rec["pseudo_header_order"]) or "0"
    return f"{s}|{rec['window_update']}|0|{h}"


def main(argv):
    majors = [int(argv[1])] if len(argv) > 1 else [100, 106, 110, 120, 131]
    for m in majors:
        try:
            rec = chrome_h2(m)
            print(f"  M{m:<4} {akamai(rec)}")
        except Exception as e:
            print(f"  M{m:<4} ✗ {type(e).__name__}: {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
