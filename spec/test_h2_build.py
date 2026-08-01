"""C 侧 HTTP/2 连接开场构造器：构造出的帧必须与 golden 的 h2 数据一致。

**为什么需要这一层**：伪装是分层的，TLS 指纹对了、h2 层不对，照样能被判出来
—— 而且这种"半对"比全不伪装更可疑，因为它显示出一个现实中不存在的组合。
`test_build_parity` 只管 ClientHello，h2 层此前根本没有构造器：C 只导出
`h2_akamai` **字符串**，那是识别用的标识符，出站伪装拿它没用，调用方还得自己
反解析才知道该发什么 SETTINGS。

**比对基准是 `spec/h2table.json`，按 (品牌, 版本) 查**，不是 profiles.json 里
挂在 TLS profile 上的那份 —— 后者按 TLS 指纹去重，h2 只是搭车，实测 chrome
106-117 共 9 个版本因此拿到了没有任何一个库归给它们的 h2。

验的是真闭环，不是自洽：
    C 构造字节 → 用 oracle/h2probe.py 那套帧解析器读回来 → 重算 akamai
    → 与 golden 的 akamai_fingerprint 逐段比

解析器**必须复用 h2probe 的**。另写一份"验证用解析器"是在拿自己的理解验自己的
理解 —— 两边一起错就一起绿。h2probe 那套是真机采集时用来读浏览器帧的，它读得
懂真浏览器，才有资格判我们造的像不像。

开场里没有 HEADERS（内容依赖具体请求），所以 akamai 的第四段（伪头序）单独从
`h2_pseudo` 取，其余三段（SETTINGS / WINDOW_UPDATE / PRIORITY）从构造的字节里
解析。

跑：python -m spec.test_h2_build
"""

import json
import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.h2probe import PREFACE, H2Probe                     # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
H2CLI = os.path.join(ROOT, "csrc", "h2cli")
TABLE = os.path.join(HERE, "h2table.json")


def parse_preface(raw):
    """把构造出的开场拆回 (settings, window_update, priorities)。

    帧头解析直接用 H2Probe 的实现 —— 它是真机采集时读浏览器帧用的那份。
    """
    if not raw.startswith(PREFACE):
        raise ValueError(f"开场不是以 PREFACE 起头：{raw[:24]!r}")
    o = len(PREFACE)
    settings, window_update, priorities = [], None, []
    while o < len(raw):
        length, ftype, flags, sid = H2Probe._parse_frame_header(raw[o:o + 9])
        o += 9
        payload = raw[o:o + length]
        if len(payload) != length:
            raise ValueError(f"帧载荷截断：需要 {length} 实得 {len(payload)}")
        o += length
        if ftype == 4 and not (flags & 0x1):
            for i in range(0, len(payload), 6):
                k, v = struct.unpack_from(">HI", payload, i)
                settings.append((k, v))
        elif ftype == 8:
            window_update = struct.unpack_from(">I", payload, 0)[0] & 0x7FFFFFFF
        elif ftype == 2:
            dep, weight = struct.unpack_from(">IB", payload, 0)
            priorities.append((sid, dep & 0x7FFFFFFF, (dep >> 31) & 1, weight + 1))
        else:
            raise ValueError(f"开场里出现了不该有的帧类型 {ftype}")
    return settings, window_update, priorities


def main():
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"make 失败：{(r.stderr or r.stdout)[-200:]}", file=sys.stderr)
        return 2
    if not os.path.exists(H2CLI):
        print(f"缺 {H2CLI}；先在 csrc 下 make", file=sys.stderr)
        return 2

    with open(TABLE) as f:
        table = json.load(f)

    # 覆盖全表，外加一批**表里没有**的组合 —— 后者必须被拒绝。只验有数据的
    # 那些等于没验"该拒绝时会不会拒绝"，而凭空造一个开场比不发更容易被判。
    from oracle.covscan import NEVER_RELEASED, TARGETS
    cases, want_ok = [], {}
    for brand, rows in sorted(table.items()):
        for ver, rec in sorted(rows.items(), key=lambda kv: int(kv[0])):
            cases.append((brand, int(ver)))
            want_ok[(brand, int(ver))] = rec
    negatives = 0
    for brand, (_t, lo, hi) in sorted(TARGETS.items()):
        for v in range(lo, hi + 1):
            if v in NEVER_RELEASED.get(brand, set()):
                continue
            if str(v) not in table.get(brand, {}):
                cases.append((brand, v))
                negatives += 1

    inp = "\n".join(f"{b} {v}" for b, v in cases)
    out = subprocess.run([H2CLI], input=inp, capture_output=True,
                         text=True, timeout=180)
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    if len(lines) != len(cases):
        print(f"构造条数不符：期望 {len(cases)} 实得 {len(lines)}", file=sys.stderr)
        return 1

    exercised = {"settings": 0, "window_update": 0, "priorities": 0}
    bad, built, refused = [], 0, 0
    for (brand, ver), line in zip(cases, lines):
        hexs, _, pseudo = line.partition("\t")
        rec = want_ok.get((brand, ver))
        if hexs == "-":
            if rec:
                bad.append(f"{brand} {ver}: 表里有 h2 却构造失败")
            else:
                refused += 1
            continue
        if not rec:
            bad.append(f"{brand} {ver}: 表里没有 h2 却构造出了开场")
            continue

        built += 1
        try:
            settings, window, prios = parse_preface(bytes.fromhex(hexs))
        except Exception as e:
            bad.append(f"{brand} {ver}: 构造出的字节解析失败（{e}）")
            continue
        if settings:
            exercised["settings"] += 1
        if window:
            exercised["window_update"] += 1
        if prios:
            exercised["priorities"] += 1

        want_set = [tuple(x) for x in (rec.get("settings") or [])]
        if settings != want_set:
            bad.append(f"{brand} {ver}: SETTINGS {settings} != {want_set}")
        if (window or 0) != (rec.get("window_update") or 0):
            bad.append(f"{brand} {ver}: WINDOW_UPDATE {window} != "
                       f"{rec.get('window_update')}")
        want_prio = [tuple(x) for x in (rec.get("priorities") or [])]
        if prios != want_prio:
            bad.append(f"{brand} {ver}: PRIORITY {prios} != {want_prio}")

        got_full = H2Probe._akamai(settings, window, prios,
                                   [":" + c for c in pseudo.split(",") if c])
        if got_full != rec["akamai_fingerprint"]:
            bad.append(f"{brand} {ver}: akamai 重算不符\n"
                       f"      得 {got_full}\n      期 {rec['akamai_fingerprint']}")

    print(f"h2 开场重建闭环   {'OK' if not bad else '失败'}"
          f"（构造并比对 {built} 条，{refused}/{negatives} 条无 h2 数据按规拒绝）")
    for b in bad[:10]:
        print(f"  ✗ {b}")

    # 平凡通过防护：全库若一条都没构造出来，上面每一项都会"通过"。
    if built == 0:
        print("  ✗ 一条都没构造出来 —— 这不是通过，是没验到")
        return 1

    # 分支覆盖下限。priorities 只有 Firefox 系会发（实测 4 条），数字小但不能
    # 为 0 —— 为 0 意味着构造器里 PRIORITY 那段（含 RFC 7540 §6.3 的权重
    # 减一）根本没被执行过，它的正确性就是一句没验过的声明。
    floor = {"settings": 400, "window_update": 400, "priorities": 4}
    print("  分支覆盖：" + "  ".join(
        f"{k}={exercised[k]}(下限{v})" for k, v in floor.items()))
    for k, v in floor.items():
        if exercised[k] < v:
            bad.append(f"分支 {k} 只跑到 {exercised[k]} 条，低于下限 {v}"
                       f" —— 这条分支实际上没被验证")
    print(f"\n{'h2 层与 golden 一致' if not bad else f'{len(bad)} 处不符'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
