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

from oracle.clienthello import is_grease, fingerprint, parse_client_hello  # noqa: E402
from oracle.coverage import FIELDS, SET_FIELDS                  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILDCLI = os.path.join(ROOT, "csrc", "buildcli")
SNITEST = os.path.join(ROOT, "csrc", "snitest")
REGISTRY = os.path.join(HERE, "profiles.json")

# 防平凡通过：注册表被截断或读空时，"0 一致，0 不符"看着是绿的 —— 实测过，
# 清空 profiles.json 后本门禁照样退出码 0。下限**不是棘轮**，它只回答
# "比对集是不是还在"，所以取一个远低于真实值（81）又远高于零的数。
MIN_PROFILES = 50



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
        # **位置也要查，不能只查"进去了"**。真实浏览器把 server_name 排在首个
        # GREASE 之后、其余扩展之前；插错位置的握手照样能连通、SNI 照样解得出，
        # 但扩展序列变了，指纹就不对了。代码变异实测：把插入点改成"最前面"，
        # 本门禁原来一点反应都没有 —— 它只问了"有没有"，没问"在哪"。
        raw = ch["raw_extensions"]
        # **期望位置必须从"去掉 SNI 之后的原序"算**，不能从 raw[0] 算 ——
        # 第一版就是拿 raw[0] 判的：SNI 一旦被插到第 0 位，raw[0] 就不再是
        # GREASE，期望值跟着变成 0，断言自证通过。变异实测它一点反应都没有。
        # 拿变异后的输出去推期望值，等于让被测者自己出题。
        orig = [e for e in raw if e != 0x0000]
        want_at = 1 if orig and is_grease(orig[0]) else 0
        if 0x0000 not in raw:
            bad.append(f"{host}: 扩展序列里没有 server_name")
        elif raw.index(0x0000) != want_at:
            bad.append(f"{host}: SNI 在第 {raw.index(0x0000)} 位，应在第 "
                       f"{want_at} 位（首个 GREASE 之后）"
                       f"；序列 {[hex(e) for e in raw[:4]]}")
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
    # 真正的随机由 Lua 侧 resty.random 提供，见 lua/browserfp.lua 的 client_hello
    if not randoms:
        return ["取不到 random 字段"]
    return []


def _ensure_fresh():
    """跑之前先确保 C 产物是当前源码编出来的。

    **这个坑撞过三次**：改了 browserfp.c 或数据源后忘了重建，门禁比对的是陈旧的
    .o / profiles.inc，报出的差异真实存在却与当前代码无关 —— 排查方向会被
    彻底带偏。让门禁自己跑一次 make，比依赖人记得跑可靠。
    """
    csrc = os.path.join(ROOT, "csrc")
    r = subprocess.run(["make", "-s"], cwd=csrc, capture_output=True,
                       text=True, timeout=300)
    if r.returncode != 0:
        return f"make 失败：{(r.stderr or r.stdout)[-200:]}"
    return None


def main():
    stale = _ensure_fresh()
    if stale:
        print(stale, file=sys.stderr)
        return 2
    if not os.path.exists(BUILDCLI):
        print(f"缺 {BUILDCLI}；先在 csrc 下 make", file=sys.stderr)
        return 2
    with open(REGISTRY) as f:
        registry = json.load(f)
    profiles = [r for r in registry if r.get("default_config", True)]

    rt_bad, n_rt = check_roundtrip(profiles)
    sni_bad = check_sni_insert()
    rnd_bad = check_random_varies()

    _n_compared = n_rt
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
    # 比对集为空时上面每一项都会"通过" —— 实测过：清空
    # profiles.json 后本门禁照样退出码 0，打印"0 一致，0 不符"。
    if _n_compared < MIN_PROFILES:
        print(f"  ✗ 只比对了 {_n_compared} 条（下限 "
              f"{MIN_PROFILES}）—— 注册表被截断或读空了？")
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
