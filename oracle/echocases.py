"""第三方回显验证的用例集：**能发出多少种不同的字节**。

644 个可达 (品牌, 版本) 去重之后只有几十种真正不同的出网形态 —— 逐个组合去打
公开的指纹回显服务是浪费，而漏掉任何一种就是真的没验到。

**去重的键是 (profile id, akamai)**，不是注册表里的 ja4。那个 ja4 采自 nosni
场景，既会把同一条 profile 的 padding 差异当成两种指纹、又会把不同 profile 归成
一条 —— 实测按它去重得 41 个用例却只有 39 个不同的带 SNI ja4，于是"41/41 已
确认"配着一个 40 条的台账文件，两个数永远对不上。按 (pid, akamai) 去重得 44 条，
台账也是 44 条。

抽成模块是因为**有两个消费者**：联网那条门禁按它逐条去打，离线那条按它检查台账
有没有漏、有没有过期、有没有已经不存在的残留。埋在 shell 的 heredoc 里时，离线
门禁复用不了，于是"44/44 已确认"这个结论没有任何常驻门禁看着。
"""

import hashlib
import json
import os

from oracle.chbuild import build_client_hello
from oracle.clienthello import fingerprint, is_grease, parse_client_hello
from oracle.covscan import NEVER_RELEASED, TARGETS
from oracle.uamap import UAMapper

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(HERE, "spec")
LEDGER = os.path.join(SPEC, "echo_ledger.json")

# 回显服务看到的 SNI 会进 JA4 的第一段，所以期望值必须按它来算
SNI = "tls.peet.ws"

PADDING_EXT = 0x0015


def _ja4c_without(raw, drop):
    """按 JA4 规范算 ja4_c，但额外排除几个扩展。

    回显服务把 padding 计进**扩展数量**却**不放进 ja4_c 的哈希列表**，与 FoxIO
    规范（只排除 SNI 与 ALPN）不同。带 padding 的 profile 因此要多给一个可接受值。
    """
    ch = parse_client_hello(raw)
    exts = [e for e in ch["raw_extensions"]
            if not is_grease(e) and e not in (0x0000, 0x0010) and e not in drop]
    sig = [v for v in (ch.get("sig_algs") or []) if not is_grease(v)]
    text = (",".join(f"{e:04x}" for e in sorted(exts)) + "_"
            + ",".join(f"{v:04x}" for v in sig))
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def _engine_of(pid, rec):
    names = " ".join([pid] + list(rec.get("aliases") or [])).lower()
    if any(k in names for k in ("firefox", "gecko", "tor")):
        return "gecko"
    if any(k in names for k in ("safari", "ios", "ipad", "webkit")):
        return "webkit"
    return "chromium"


def key_of(case):
    """台账的键。**必须与去重口径同一个** —— 用 ja4 当键会撞（padding 差异）。"""
    return f"{case['pid']}|{case['akamai']}"


def cases():
    """每种可发出的字节形态取一个代表，附上第三方应当看到的期望值。"""
    with open(os.path.join(SPEC, "profiles.json")) as f:
        reg = {x["id"]: x for x in json.load(f)}
    with open(os.path.join(SPEC, "h2table.json")) as f:
        h2t = json.load(f)
    mapper = UAMapper()

    out, seen = [], set()
    for brand, (tpl, lo, hi) in sorted(TARGETS.items()):
        for v in range(lo, hi + 1):
            if v in NEVER_RELEASED.get(brand, set()):
                continue
            pid = mapper.lookup(tpl.format(v=v))["profile"]
            rec = reg.get(pid)
            hh = (h2t.get(brand) or {}).get(str(v))
            if not rec or not hh:
                continue
            key = (pid, hh["akamai_fingerprint"])
            if key in seen:
                continue
            seen.add(key)

            raw = build_client_hello(rec["tls"], sni=SNI)
            fp = fingerprint(raw)
            a, b, c = fp["ja4"].split("_")
            ch = parse_client_hello(raw)

            def csv(xs):
                return "-".join(str(x) for x in xs)

            out.append({
                "brand": brand, "version": v, "pid": pid,
                "akamai": hh["akamai_fingerprint"],
                "engine": _engine_of(pid, rec),
                "ja4_a": a, "ja4_b": b, "ja4_c": c,
                # padding 排除版：回显服务的口径差，见 _ja4c_without
                "ja4_c_alt": _ja4c_without(raw, {PADDING_EXT}),
                # 线上顺序。JA4 排序后哈希，顺序差异它看不见；Firefox/Safari 不
                # 打乱顺序，错了对 JA3 一类检测就是破绽。GREASE 取值每连接随机、
                # 位置固定，只记 G；padding 随长度出现或消失，剔掉。
                "order": ",".join("G" if is_grease(e) else f"{e:04x}"
                                  for e in ch["raw_extensions"]
                                  if e != PADDING_EXT),
                "ja3_version": str(ch["client_version"]),
                "ja3_ciphers": csv([x for x in ch["raw_ciphers"]
                                    if not is_grease(x)]),
                "ja3_exts": csv(sorted(x for x in ch["raw_extensions"]
                                       if not is_grease(x) and x != PADDING_EXT)),
                "ja3_curves": csv([x for x in (ch.get("curves") or [])
                                   if not is_grease(x)]),
                "ja3_pf": csv(ch.get("point_formats") or []),
            })
    return out


def load_ledger():
    if not os.path.exists(LEDGER):
        return {}
    with open(LEDGER) as f:
        return json.load(f)


TSV_FIELDS = ("brand", "version", "ja4_a", "ja4_b", "ja4_c", "ja4_c_alt",
              "akamai", "order", "engine", "pid", "ja3_version",
              "ja3_ciphers", "ja3_exts", "ja3_curves", "ja3_pf")


def to_tsv(case):
    return "\t".join(str(case[k]) for k in TSV_FIELDS)
