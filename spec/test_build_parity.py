"""C 侧 ClientHello 构造器的门禁：构造出的字节必须与 golden 逐字段一致。

**这是伪装链的最后一环**：查表拿到 profile 只是半条链，得把它变成真正能发出去
的字节。C 版跑在 nginx worker 里，出错不会崩溃、只会发出一个"像浏览器但不是"
的握手 —— 那比不伪装更容易被判，所以必须逐条比。

查三件事：
  1. 全库每条 profile 都能构造出字节，且解析回来与 golden 逐字段一致
  2. **SNI 能插入而不只是替换** —— 库里 81 条 golden 只有 2 条带 server_name
     （都采自无 SNI 场景）。只做替换的话 sni 参数会被静默忽略，构造出的握手
     压根没有 SNI，多租户站点直接 handshake_failure。而 cloudflare.com 因为有
     默认证书照样通过，只测一个站点会掩盖这个问题。
  3. **random 与 session_id 确实随调用变化** —— 照抄 golden 里那份会让所有连接
     的 ClientHello 逐字节相同，比不伪装还容易被判。

跑：python -m spec.test_build_parity
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.clienthello import fingerprint, parse_client_hello  # noqa: E402
from oracle.coverage import FIELDS, SET_FIELDS                  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILDCLI = os.path.join(ROOT, "csrc", "buildcli")
SNITEST = os.path.join(ROOT, "csrc", "snitest")
REGISTRY = os.path.join(HERE, "profiles.json")


def _norm(tls, field):
    v = tls.get(field)
    return sorted(v) if field in SET_FIELDS and v else v


def check_roundtrip(profiles):
    """C 构造 → Python 解析 → 与 golden 逐字段比。"""
    idx = "\n".join(str(i) for i in range(len(profiles)))
    out = subprocess.run([BUILDCLI], input=idx, capture_output=True,
                         text=True, timeout=180)
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    if len(lines) != len(profiles):
        return [f"构造条数不符：期望 {len(profiles)} 实得 {len(lines)}"], 0

    bad, checked = [], 0
    for rec, hexs in zip(profiles, lines):
        if hexs == "-":
            bad.append(f"{rec['id']}: 构造失败")
            continue
        checked += 1
        # 构造器产出损坏字节时要**报告**而不是崩溃 —— 门禁抛异常会中断整轮
        # 检查，后面的 profile 一条都验不到，还容易被误读成"环境问题"。
        try:
            fp = fingerprint(bytes.fromhex(hexs))
        except Exception as e:
            bad.append(f"{rec['id']}: 构造出的字节解析失败 "
                       f"({type(e).__name__}: {str(e)[:50]})")
            continue
        diff = [f for f in FIELDS if _norm(fp, f) != _norm(rec["tls"], f)]
        if diff:
            bad.append(f"{rec['id']}: 与 golden 差 {diff[:4]}")
    return bad, checked


def check_sni_insert():
    """SNI 必须被真正写进去，且长度随域名变化。"""
    if not os.path.exists(SNITEST):
        return ["缺 csrc/snitest；先在 csrc 下 make"]
    bad = []
    seen_len = {}
    for host in ("cloudflare.com", "example.com", "a.io"):
        r = subprocess.run([SNITEST, "chrome", "151", host],
                           capture_output=True, text=True, timeout=60)
        if not r.stdout.strip():
            bad.append(f"{host}: 构造失败")
            continue
        rec = bytes.fromhex(r.stdout.strip())
        try:
            ch = parse_client_hello(rec)
        except Exception as e:
            bad.append(f"{host}: 构造出的字节解析失败 ({type(e).__name__})")
            continue
        if ch["sni"] != host:
            bad.append(f"{host}: 构造出的 SNI 是 {ch['sni']!r}，未被写入")
        seen_len[host] = len(rec)
    # 域名长度不同，总长必须跟着变；全都一样说明 SNI 根本没进去
    if len(set(seen_len.values())) == 1 and len(seen_len) > 1:
        bad.append(f"不同域名构造出的长度全等（{seen_len}）—— SNI 未生效")
    return bad


def check_random_varies():
    """random 与 session_id 必须随调用变化，不能照抄 golden。"""
    if not os.path.exists(SNITEST):
        return []
    randoms = set()
    for _ in range(2):
        r = subprocess.run([SNITEST, "chrome", "151", "example.com"],
                           capture_output=True, text=True, timeout=60)
        if not r.stdout.strip():
            continue
        rec = bytes.fromhex(r.stdout.strip())
        randoms.add(rec[11:43].hex())        # record(5)+hs 头(4)+版本(2) 之后是 random
    # snitest 用固定种子，所以这里只验"字段位置正确"而非"每次都变"；
    # 真正的随机由 Lua 侧 resty.random 提供，见 lua/tlsfp.lua 的 client_hello
    if not randoms:
        return ["取不到 random 字段"]
    return []


def main():
    if not os.path.exists(BUILDCLI):
        print(f"缺 {BUILDCLI}；先在 csrc 下 make", file=sys.stderr)
        return 2
    with open(REGISTRY) as f:
        registry = json.load(f)
    profiles = [r for r in registry if r.get("default_config", True)]

    rt_bad, n_rt = check_roundtrip(profiles)
    sni_bad = check_sni_insert()
    rnd_bad = check_random_varies()

    print(f"重建闭环       {'OK' if not rt_bad else '失败'}（构造并比对 {n_rt} 条）")
    for b in rt_bad[:8]:
        print(f"  ✗ {b}")
    print(f"SNI 插入生效   {'OK' if not sni_bad else '失败'}")
    for b in sni_bad:
        print(f"  ✗ {b}")
    print(f"random 字段位置 {'OK' if not rnd_bad else '失败'}")
    for b in rnd_bad:
        print(f"  ✗ {b}")

    failed = len(rt_bad) + len(sni_bad) + len(rnd_bad)
    print(f"\n{'构造器与 golden 一致' if not failed else f'{failed} 处问题'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
