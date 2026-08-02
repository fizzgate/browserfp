"""对端**实际看到的**指纹，是不是我们想冒充的那个 —— 整条链的最终判据。

此前所有"端到端"验的都是**服务端接受了我们的握手**：`test_live_handshake` 看
ServerHello 与 `:status`，`test_build_live` 看回的是 ServerHello 还是 Alert。
接受 ≠ 认成那个浏览器 —— 一条把 GREASE 全丢掉、密码套件顺序打乱的 ClientHello
照样能握上手，只是任何指纹库都会把它归成"不是浏览器"。

而 JA4 一直是**我们自己算的**：Python 与 C 互校，golden 里的 `ja4` 字段也是采集
时由 `oracle/clienthello.py` 算的。`test_ja4_vectors` 用规范的官方向量补了算法这
一层，但那是一条合成的输入；**真实流量在真实对端眼里长什么样，从来没验过**。

这条门禁把回路闭上：用参考实现按某条 profile 出网，打一个会回显 TLS/h2 指纹的
服务，拿它回显的值与我们自己算的比。

```
我们发出的字节 ──→ 网络 ──→ 第三方指纹实现 ──→ 回显 JA4 / JA3 / akamai
      │                                              │
      └────────── 我们自己算的 JA4 ──── 必须相同 ──────┘
```

**分三档，与其它联网门禁同一口径**：对端回显与我们算的不符才是缺陷；连不上、
超时、回非 JSON 一律算"没验到"，不算失败也不冒充通过 —— 把网络问题报成字节
问题，会把排查引向根本不存在的 bug（本项目在 `test_build_live` 上栽过一次）。

**只打一个公开的指纹回显服务，不带任何凭据**，且逐条之间节流。

跑：python -m spec.test_echo_fingerprint [host]
"""

import json
import os
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.clienthello import fingerprint, is_grease          # noqa: E402

KSCLI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "csrc", "kscli")
from oracle.h2client import H2Client                           # noqa: E402
from oracle.tls13 import TLS13Client                           # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "profiles.json")

# 回显服务：返回 JSON，含 tls.ja3 / tls.ja4 与 http2.akamai_fingerprint。
# 换服务时只要它回同样的字段名即可 —— 判据是"第三方怎么算"，不绑定某一家。
ECHO_HOST = "tls.peet.ws"
ECHO_PATH = "/api/all"

# 覆盖面与"别把公开服务打爆"之间的取舍：默认取**跨引擎铺开**的一批，
# 加 --all 才把全部可联网验证的 profile 跑一遍。
#
# 选取是**确定性**的（按 id 排序后逐引擎轮取），不是随机抽样 —— 随机会让
# "这次绿了"与"上次绿了"验的不是同一批，覆盖率就成了一个会漂的数字。
DEFAULT_PER_ENGINE = 5

# C 路径（生产真正发的那份字节）额外再打一遍的条数 —— 每引擎取前 N 条。
# 不对全部再打一遍，是对公开服务的克制；但**必须覆盖到每个引擎**，
# 否则"生产那条路"只在一族浏览器上验过。
C_PATH_PER_ENGINE = 2

# 与被模仿者 A/B 的条数上限 —— 每条要额外打一次回显服务，对公开服务克制些。
# `--all` 时不限：那是"深跑一遍"的用法，不是常态。这一档的产出率最高
# （padding 那处缺陷就是它抓到的，另外四档全绿），所以深跑值得。
AB_LIMIT = 6
PACE = 2.5

# 这一层能验到几条、覆盖几个引擎，本身要有下限：回显服务挂掉时"0 条全绿"
# 看着也像通过。
MIN_VERIFIED = 8
MIN_ENGINES = 3


def engine_of(rec):
    """按 profile 的别名判引擎 —— 与覆盖率报告同一口径。"""
    names = " ".join([rec["id"]] + list(rec.get("aliases") or [])).lower()
    if "firefox" in names or "tor" in names:
        return "gecko"
    if "safari" in names or "ios" in names:
        return "webkit"
    if any(k in names for k in ("chrome", "chromium", "edge", "opera")):
        return "chromium"
    return "其它"


def pick(registry, take_all=False):
    """挑可联网验证的 profile。跳过的四类与 test_live_handshake 同一套判据。"""
    KYBER, MLKEM = 0x6399, 0x11EC
    ok = []
    for rec in registry:
        tls = rec["tls"]
        if not rec.get("h2"):
            continue                       # 只有 TLS 层，验不了 h2 那一路
        if not rec.get("default_config", True):
            continue
        if 0x0029 in (tls.get("raw_extensions") or []):
            continue                       # 会话恢复态：没有有效票据
        if "quic" in rec["id"].lower():
            continue
        if 0x0304 not in (tls.get("supported_versions") or []):
            continue                       # 纯 TLS1.2，参考实现只做 1.3
        curves = tls.get("curves") or []
        if KYBER in curves and MLKEM not in curves:
            continue                       # 参考实现做不了这个密钥交换
        ok.append(rec)
    ok.sort(key=lambda r: r["id"])
    if take_all:
        return ok
    by_engine = {}
    for rec in ok:
        by_engine.setdefault(engine_of(rec), []).append(rec)
    out = []
    for eng in sorted(by_engine):
        out += by_engine[eng][:DEFAULT_PER_ENGINE]
    return out

OK, MISMATCH, NET = "ok", "mismatch", "net"


# **已知的实现分歧，逐条写明，不做笼统忽略。**
#
# 回显服务把 padding 扩展（0x0015）计入扩展**数量**，却不放进 ja4_c 的哈希列表。
# FoxIO 的规范只说排除 SNI(0x0000) 与 ALPN(0x0010)，没提 padding —— 也就是说
# **我们按规范做，回显服务偏离了规范**（`test_ja4_vectors` 用官方向量验过我们）。
#
# 这对伪装本身**无害**：我们发的字节与真浏览器相同，任何一个确定性实现算两边都
# 会得到同一个值。它只影响"拿我们表里的 ja4 去比对某个公开库"这种用法。
#
# 实测对应关系是干净的：4 条不符的 profile 全部含 0x0015，3 条通过的全部不含。
# 所以这里按段比 ja4_r，并且**只**豁免这一处、还要断言豁免之后确实一致 ——
# 笼统地"忽略第三段"会把真差异一起放过。
PEER_EXCLUDES_FROM_JA4C = {0x0015}

# 第二处分歧：**ALPN 那两位**。规范说取 ClientHello 里 ALPN 列表的**首项**，
# 而回显服务填的是**协商结果**。证据是它自己给的：`tls_client:chrome_133` 提供
# `h3, h2, http/1.1`，对端回显里明明记着 `"protocols": ["h3","h2","http/1.1"]`，
# JA4 却写 `h2` —— 那正是 TCP 上协商出来的协议。
#
# 与 padding 同样：对伪装无害（我们发的字节与真浏览器相同，同一实现算两边同值），
# 只影响"拿我们表里的 ja4 去比对公开库"。判定要求**对端自己记录的首项与我们一致**，
# 不是见到 ALPN 不同就放过。
PEER_USES_NEGOTIATED_ALPN = True


def parse_akamai(fp, peer):
    """akamai 指纹 → 结构化四段，把**记法差异**在这里吸收掉。

    实测与回显服务有三处记法分歧，逐条建模而不是笼统忽略：

      分隔符    对端 `2:0;3:100`，我们与三家库 `2:0,3:100`
      权重      对端报**有效权重**，我们与三家库存**线上字节** —— RFC 7540 说
                线上值加一才是权重，所以对端恒比我们大 1（实测 6 条全部 +1）
      未知设置  对端把设置 id 8 渲染成空（`;:1;`），数值仍在

    每一处都窄：只吸收这三种，其余差异照报。笼统地"两边都排序后比集合"会把
    顺序差异抹掉，而顺序本身就是指纹。
    """
    if not isinstance(fp, str):
        return None
    # **多条 PRIORITY 之间，我们与三家库用 `|`，对端用 `,`** —— 于是同一个指纹
    # 在我们这边会被切成 4 段以上。按"首二段 + 末段固定，中间全是 PRIORITY"解，
    # 而不是要求恰好 4 段（第一版就是这么写的，firefox-111 直接报"解析不了"）。
    parts = fp.split("|")
    if len(parts) < 4:
        return None
    st_raw, win, pseudo = parts[0], parts[1], parts[-1]
    pri_raw = ",".join(parts[2:-1])

    settings = []
    for i, item in enumerate(st_raw.replace(";", ",").split(",")):
        if not item:
            continue
        k, _, v = item.partition(":")
        settings.append((k.strip() or None, v))     # 空 id 记成 None

    prios = []
    for item in pri_raw.replace("|", ",").split(","):
        if not item or item == "0":
            continue
        f = item.split(":")
        if len(f) != 4:
            return None
        sid, excl, dep, w = f
        w = int(w) - 1 if peer else int(w)          # 对端报有效权重
        prios.append((sid, excl, dep, w))
    return settings, win, prios, pseudo


def akamai_diff(want, got):
    """profile 的 akamai 与对端看到的比。相同返回 None。"""
    a, b = parse_akamai(want, peer=False), parse_akamai(got, peer=True)
    if a is None or b is None:
        return f"解析不了：profile={want!r} 对端={got!r}"
    if len(a[0]) != len(b[0]):
        return f"SETTINGS 条数不同：{a[0]} vs {b[0]}"
    for (ka, va), (kb, vb) in zip(a[0], b[0]):
        if va != vb:
            return f"SETTINGS 取值不同：{ka}:{va} vs {kb}:{vb}"
        if kb is not None and ka != kb:
            return f"SETTINGS id 不同：{ka} vs {kb}"
    if a[1] != b[1]:
        return f"WINDOW_UPDATE 不同：{a[1]} vs {b[1]}"
    if a[2] != b[2]:
        return f"PRIORITY 不同（已按 RFC 7540 扣回线上值）：{a[2]} vs {b[2]}"
    if a[3] != b[3]:
        return f"伪头序不同：{a[3]} vs {b[3]}"
    return None


def curl_cffi_echo(target, host):
    """让 **curl_cffi 本尊**打同一个回显端点，返回它的 JSON。

    这一档回答的是最直白的那个问题：**我们照着某个库建模的 profile，发出去之后
    在对端眼里跟那个库本尊是不是同一个指纹**。前面几档都是"我们与我们自己算的
    一致"，只有这一档是"我们与被模仿者一致"。

    不同于其它档，这里连字节都不是我们发的 —— curl_cffi 自己发。所以它同时验了
    两件事：语料里那条 profile 记得对不对，以及我们的构造器复现得对不对。
    """
    try:
        from curl_cffi import requests as creq
    except ImportError:
        return None
    # **这一档也要重试**。实测做阴性对照时它偶发取不到，结果那次对照报成"网络档"
    # —— 比较根本没发生，却看着像验过了。网络档不算失败是对的，但一条会偶发
    # 消失的判据等于没有判据。
    for attempt in range(3):
        try:
            r = creq.get(f"https://{host}{ECHO_PATH}", impersonate=target,
                         timeout=25)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        time.sleep(PACE)
    return None


WREQ_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       ".venv-wreq", "bin", "python")

WREQ_SNIPPET = """
import asyncio, datetime, json, sys, wreq
async def main():
    c = wreq.Client(emulation=getattr(wreq.Emulation, sys.argv[1]))
    r = await c.get(sys.argv[2], timeout=datetime.timedelta(seconds=25))
    print(await r.text())
asyncio.run(main())
"""


def wreq_echo(target, host):
    """让 **wreq 本尊**打同一个回显端点。

    wreq 装在另一个 venv（它要 Python ≥3.11），所以走子进程。curl_cffi 覆盖不到
    的 profile 有 10 条只有 wreq 别名 —— 只用一家库做 A/B，另一家建模的那批就
    没有"与被模仿者比"这一层。
    """
    if not os.path.exists(WREQ_PY):
        return None
    for _ in range(2):
        try:
            r = subprocess.run([WREQ_PY, "-c", WREQ_SNIPPET, target,
                                f"https://{host}{ECHO_PATH}"],
                               capture_output=True, text=True, timeout=60)
            if r.returncode == 0 and r.stdout.strip():
                return json.loads(r.stdout)
        except Exception:
            pass
        time.sleep(PACE)
    return None


def c_hello(pid, sni, pubs):
    """让 **C 构造器**出 ClientHello，把我们生成的公钥注进去。"""
    spec = ",".join(f"{g:04x}:{p.hex()}" for g, p in pubs.items())
    # 不带前缀 = 出网口径（与库的默认一致）。这一档验的正是生产发的字节。
    out = subprocess.run([KSCLI], input=f"{pid}\t{sni}\t{spec}\n",
                         capture_output=True, text=True, timeout=60).stdout.strip()
    return None if not out or out.startswith("ERR") else bytes.fromhex(out)


def fetch(profile, h2_profile, host, pid=None, use_c=False):
    """按 profile 出网取回显 JSON。返回 (档位, 详情, 我们发的字节)。

    use_c 时**发的是 C 构造器出的字节**，Python 只负责完成握手 —— 生产走的是
    C 那条路，只验参考实现等于没验到生产。
    """
    try:
        raw = socket.create_connection((host, 443), timeout=20)
        raw.settimeout(20)
    except Exception as e:
        return NET, f"连不上：{type(e).__name__}", None
    try:
        if use_c:
            from oracle.tls13 import TLS13Client as _T
            probe = _T.__new__(_T)
            probe.profile, probe.sni = profile, host
            pubs, privs = probe._gen_shares()
            hello = c_hello(pid, host, pubs)
            if hello is None:
                return NET, "C 构造器出不了这条 profile", None
            conn = TLS13Client(raw, profile, sni=host, hello=hello, privs=privs)
        else:
            conn = TLS13Client(raw, profile, sni=host)
        conn.handshake()
        if conn.negotiated_alpn != "h2":
            return NET, f"没协商出 h2（{conn.negotiated_alpn}）", None
        h2 = H2Client(conn, h2_profile).connect()
        sid = h2.request("GET", ECHO_PATH, host,
                         headers=[("user-agent", "tlsfp-echo"),
                                  ("accept", "application/json")])
        headers, body = h2.read_response(sid)
        status = dict(headers).get(":status")
        if status != "200":
            return NET, f"回显服务返回 :status={status}", None
        return OK, json.loads(body.decode()), conn.client_hello
    except Exception as e:
        return NET, f"{type(e).__name__}: {str(e)[:70]}", None
    finally:
        try:
            raw.close()
        except Exception:
            pass


def prefix_diff(data, ours, peer_prefix):
    """JA4 前缀（`t13d1516h2`）逐位比。相同或只差已知分歧返回 None。"""
    our_prefix = ours["ja4"].split("_")[0]
    if peer_prefix == our_prefix:
        return None
    if peer_prefix[:-2] != our_prefix[:-2]:
        return (f"前缀不同（版本/SNI/计数）：对端 {peer_prefix} 我们 {our_prefix}")
    # 只差 ALPN 两位 —— 查对端自己记录的 ALPN 首项是不是与我们一致
    txt = json.dumps(data, ensure_ascii=False)
    m = re.search(r'"protocols"\s*:\s*\[([^\]]*)\]', txt)
    offered = [x.strip().strip('"') for x in m.group(1).split(",")] if m else []
    ours_first = (ours.get("alpn") or [""])[0]
    if PEER_USES_NEGOTIATED_ALPN and offered and offered[0] == ours_first:
        return None                      # 已知分歧：对端填的是协商结果
    return (f"ALPN 两位不同：对端 {peer_prefix[-2:]} 我们 {our_prefix[-2:]}"
            f"（对端记录的 ALPN 列表 {offered}）")


def ja4r_diff(data, ours):
    """对端的 ja4_r 与我们逐段比。只差已知分歧返回 None，否则返回差异描述。

    ja4_r 是 `t13d2613h2_<ciphers>_<extensions>_<sigalgs>` 四段。**别按下划线
    切两刀**：第一版切错段位，把扩展列表当成签名算法比，得出的差异完全是假的。
    """
    pr = (data.get("tls") or {}).get("ja4_r") or ""
    parts = pr.split("_")
    if len(parts) != 4:
        return f"回显的 ja4_r 不是四段：{pr[:60]}"
    _, p_ciph, p_ext, p_sig = parts

    o_ciph = ",".join(f"{c:04x}" for c in sorted(
        c for c in ours["raw_ciphers"] if not is_grease(c)))
    o_ext = sorted(e for e in ours["raw_extensions"]
                   if not is_grease(e) and e not in (0x0000, 0x0010))
    o_sig = ",".join(f"{x:04x}" for x in ours["sig_algs"])

    if p_ciph != o_ciph:
        return f"密码套件不同：对端 {p_ciph[:50]}… 我们 {o_ciph[:50]}…"
    if p_sig != o_sig:
        return f"签名算法不同：对端 {p_sig[:50]}… 我们 {o_sig[:50]}…"
    if ",".join(f"{e:04x}" for e in o_ext) == p_ext:
        # 三段都相同，那差异只可能在**前缀**（版本/SNI标志/计数/ALPN 两位）。
        # 第一版这里写的是"哈希算法本身有问题"，那是误导 —— 我压根没比前缀。
        return prefix_diff(data, ours, parts[0])
    trimmed = [e for e in o_ext if e not in PEER_EXCLUDES_FROM_JA4C]
    if ",".join(f"{e:04x}" for e in trimmed) == p_ext:
        return prefix_diff(data, ours, parts[0])
    return (f"扩展列表不同（已扣除 padding 仍不同）：\n"
            f"      对端 {p_ext}\n      我们 {','.join(f'{e:04x}' for e in o_ext)}")


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    take_all = "--all" in argv
    host = args[0] if args else ECHO_HOST
    with open(REGISTRY) as f:
        registry = json.load(f)
    cases = pick(registry, take_all)

    print(f"回显服务 {host}{ECHO_PATH}")
    print(f"比对 {len(cases)} 条 profile"
          + ("（--all：全部可联网验证的）" if take_all
             else f"（每引擎最多 {DEFAULT_PER_ENGINE} 条；加 --all 跑全部）") + "\n")
    bad, netbad, n = [], [], 0
    seen_engines, peer_seen = set(), {}
    for rec in cases:
        pid = rec["id"]
        time.sleep(PACE)
        kind, data, sent = fetch(rec["tls"], rec.get("h2"), host)
        if kind is NET:
            # 只对网络类重试一次：协议级的不符重发无意义，还更像扫描。
            time.sleep(PACE)
            kind, data, sent = fetch(rec["tls"], rec.get("h2"), host)
        if kind is NET:
            netbad.append(f"{pid}: {data}")
            print(f"  ⚠️ {pid:16s} {data}")
            continue
        n += 1
        seen_engines.add(engine_of(rec))
        peer_seen[pid] = (data.get("tls") or {}).get("ja4")

        ours = fingerprint(sent)
        peer_ja4 = (data.get("tls") or {}).get("ja4")
        peer_ja3 = (data.get("tls") or {}).get("ja3_hash") \
            or (data.get("tls") or {}).get("ja3")
        peer_ak = (data.get("http2") or {}).get("akamai_fingerprint")

        line = []
        if peer_ja4 == ours["ja4"]:
            line.append("JA4✅")
        else:
            # 不一致时**按段查**，别停在"哈希不同"上 —— 哈希只说明有差异，
            # 说不出差在哪，而差在哪决定了它是缺陷还是实现分歧。
            why = ja4r_diff(data, ours)
            if why is None:
                line.append("JA4✅*")     # 只差已知的 padding 分歧
            else:
                bad.append(f"{pid}: 对端看到的 JA4 与我们算的不同（{why}）\n"
                           f"      我们 {ours['ja4']}\n      对端 {peer_ja4}")
                line.append("JA4✗")
        if peer_ja3 and peer_ja3 not in (ours["ja3"], ours["ja3_hash"]):
            bad.append(f"{pid}: 对端看到的 JA3 与我们算的不同\n"
                       f"      我们 {ours['ja3_hash']}\n      对端 {peer_ja3}")
            line.append("JA3✗")
        elif peer_ja3:
            line.append("JA3✅")
        want_ak = (rec.get("h2") or {}).get("akamai_fingerprint")
        ak_why = (akamai_diff(want_ak, peer_ak)
                  if (want_ak and peer_ak) else None)
        if ak_why:
            bad.append(f"{pid}: 对端看到的 akamai 指纹与 profile 不同 —— {ak_why}\n"
                       f"      profile {want_ak}\n      对端    {peer_ak}")
            line.append("h2✗")
        elif want_ak and peer_ak:
            line.append("h2✅")
        print(f"  {' '.join(line):18s} {pid:16s} {ours['ja4']}")

    # —— 第二档：同一条 profile 再用 **C 构造器出的字节** 打一遍 ——
    #
    # 上面那一档验的是参考实现发的字节。生产走的是 C 那条路，两者一旦分叉，
    # 上面全绿也说明不了生产没问题 —— 本项目已经栽过五次"两份实现悄悄分叉"。
    # 这里断言的是最直接的性质：**同一条 profile，两条路径在对端眼里是同一个
    # 指纹**，而且都等于我们自己算的。
    c_by_engine = {}
    for rec in cases:
        c_by_engine.setdefault(engine_of(rec), []).append(rec)
    c_cases = [r for eng in sorted(c_by_engine)
               for r in c_by_engine[eng][:C_PATH_PER_ENGINE]]
    c_ok, c_engines = 0, set()
    for rec in c_cases:
        pid = rec["id"]
        if pid not in peer_seen:
            continue                     # Python 那档就没验到，无从比较
        time.sleep(PACE)
        kind, data, sent = fetch(rec["tls"], rec.get("h2"), host,
                                 pid=pid, use_c=True)
        if kind is NET:
            netbad.append(f"{pid}（C 路径）: {data}")
            print(f"  ⚠️ C 路径 {pid:16s} {data}")
            continue
        c_ok += 1
        c_engines.add(engine_of(rec))
        peer_c = (data.get("tls") or {}).get("ja4")
        ours_c = fingerprint(sent)["ja4"]
        # 与上一档**用同一套判据**：不一致时按段查 ja4_r，只豁免已知的
        # padding 分歧。这里第一版直接比哈希，于是含 padding 的四条全报错 ——
        # 同一个已知分歧在两处各判一次、判法还不同，等于自己给自己造假警报。
        why = None if peer_c == ours_c else ja4r_diff(data, fingerprint(sent))
        if why:
            bad.append(f"{pid}（C 路径）: 对端看到的 JA4 与我们算的不同（{why}）\n"
                       f"      我们 {ours_c}\n      对端 {peer_c}")
        elif peer_c != peer_seen[pid]:
            bad.append(f"{pid}: **C 路径与参考实现在对端眼里不是同一个指纹**\n"
                       f"      参考实现 {peer_seen[pid]}\n      C 路径   {peer_c}")
        else:
            print(f"  C✅              {pid:16s} 与参考实现同一指纹")
    print(f"\nC 路径（生产发的字节）{c_ok}/{len(c_cases)} 条，"
          f"覆盖引擎 {sorted(c_engines)}")
    if c_ok and len(c_engines) < MIN_ENGINES:
        bad.append(f"C 路径只覆盖了 {sorted(c_engines)} —— "
                   "生产那条路必须每个引擎都验到")

    # —— 第三档：与**被模仿者本尊**比 ——
    #
    # 前两档都是"我们与我们自己算的一致"。这一档换个问法：同一个 target，
    # 我们发的字节与 **curl_cffi 本尊**发的字节，在对端眼里是不是同一个指纹。
    # 它同时验两件事：语料里那条 profile 记得对不对，我们的构造器复现得对不对。
    # 前两档全绿而这一档红，说明我们"自洽地错着"。
    ab_ok, ab_n = 0, 0
    for rec in cases:
        names = [rec["id"]] + list(rec.get("aliases") or [])
        target = next((a.split(":", 1)[1] for a in names
                       if a.startswith("curl_cffi:")), None)
        lib, echo = "curl_cffi", curl_cffi_echo
        if not target:
            # curl_cffi 覆盖不到的，换 wreq 比 —— 只用一家库做 A/B，另一家建模
            # 的那批就没有"与被模仿者比"这一层。
            target = next((a.split(":", 1)[1] for a in names
                           if a.startswith("wreq:")), None)
            lib, echo = "wreq", wreq_echo
        if not target or rec["id"] not in peer_seen:
            continue
        if not take_all and ab_n >= AB_LIMIT:
            break
        ab_n += 1
        time.sleep(PACE)
        d = echo(target, host)
        if d is None:
            netbad.append(f"{rec['id']}: {lib}[{target}] 取不到回显")
            print(f"  ⚠️ A/B  {rec['id']:16s} {lib} 取不到回显")
            continue
        theirs = (d.get("tls") or {}).get("ja4")
        if theirs == peer_seen[rec["id"]]:
            ab_ok += 1
            print(f"  A/B✅            {rec['id']:16s} 与 {lib}[{target}] 同一指纹")
        else:
            bad.append(f"{rec['id']}: **与被模仿者不是同一个指纹**\n"
                       f"      我们        {peer_seen[rec['id']]}\n"
                       f"      {lib:11s} {theirs}\n"
                       "      （两者都由对端计算，所以不是记法问题）")
    print(f"\n与被模仿者 A/B  {ab_ok}/{ab_n} 条同一指纹")
    if ab_n and ab_ok == 0:
        bad.append("A/B 一条都没对上 —— 要么语料错了，要么构造器错了")

    print(f"\n{n}/{len(cases)} 条完成回显比对，覆盖引擎 {sorted(seen_engines)}")
    for b in bad:
        print(f"  ✗ {b}")
    for m in netbad:
        print(f"  ⚠️ {m}")

    if bad:
        print("\n对端看到的与我们算的不一致 —— 这是**最硬的一类失败**："
              "服务端接受了握手不代表把我们认成那个浏览器。")
        return 1
    if n < MIN_VERIFIED:
        print(f"\n只验到 {n} 条（下限 {MIN_VERIFIED}）—— 回显服务挂掉时"
              "\"0 条全绿\"看着也像通过，所以这一层自己也要有下限。")
        return 1
    if len(seen_engines) < MIN_ENGINES:
        print(f"\n只覆盖了 {sorted(seen_engines)}（下限 {MIN_ENGINES} 个引擎）—— "
              "只验一个引擎的话，另两族的构造路径等于没验。")
        return 1
    if netbad:
        print(f"\n{len(netbad)} 条因网络原因没验到。")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
