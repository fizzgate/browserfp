"""Lua FFI 绑定的差分门禁 —— Python / C / Lua 三方必须一致。

C 版已由 test_c_parity 对齐 Python。但 FFI 绑定层还有独立的出错空间：结构体
布局不匹配、字符串所有权、transport 参数传错等，都会在不崩溃的情况下给出错误
结果。所以 Lua 侧要单独比一遍，而不是"C 对了 Lua 就一定对"。

**比的不止 JA4。** 伪装是四层的，Lua 侧每层都有对应函数，而此前只有 ja4 被比过
—— `header_order` / `sort_headers` / `header_value` / `ua_platform` /
`sec_ch_ua` 的正确性只有 `test_openresty` 覆盖，那条要起容器，常态下不跑。
代码变异实测：把 Lua 的 `sort_headers` 改成不排序，全部离线门禁一个都不红。
所以这里补上第二段，逐品牌比这五个函数。

分层归属：`sec_ch_ua` 比的是 **Lua vs C**（那张表本身是构建产物，C 与 Python
的一致性归 test_uach 管）；其余四个比 **Lua vs Python**。

需要 luajit（或 OpenResty 自带的 resty）与已编译的 csrc/libtlsfp.so。

跑：python -m spec.test_lua_parity
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chbuild import build_client_hello                 # noqa: E402
from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.headerorder import (BRAND_ENGINE, order_for,      # noqa: E402
                                sort_headers, values_for)
from oracle.uach import platform_hint                         # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LIB = os.path.join(ROOT, "csrc", "libtlsfp.so")
REGISTRY = os.path.join(HERE, "profiles.json")

# 防平凡通过：注册表被截断或读空时，"0 一致，0 不符"看着是绿的 —— 实测过，
# 清空 profiles.json 后本门禁照样退出码 0。下限**不是棘轮**，它只回答
# "比对集是不是还在"，所以取一个远低于真实值（81）又远高于零的数。
MIN_PROFILES = 50

# 同理：品牌表读空时"0 一致，0 不符"也是绿的
MIN_MASQ = 40


LUA_SCRIPT = """
package.path = "%s/lua/?.lua;" .. package.path
local tlsfp = require "tlsfp"
tlsfp.load("%s")
for line in io.lines("%s") do
    local hex, want, id = line:match("^(%%x+)\\t(%%S+)\\t(%%S+)$")
    if hex then
        local raw = hex:gsub("%%x%%x", function(c) return string.char(tonumber(c,16)) end)
        local got = tlsfp.ja4(raw)
        if got ~= want then print("MISMATCH\\t" .. id .. "\\t" .. want .. "\\t" .. tostring(got)) end
    end
end
print("DONE")
"""


# 排序用的样例：故意混入库不认识的头与大小写，排序逻辑的两个分支都要走到
SORT_SAMPLE = ["Accept-Encoding", "X-Custom", "User-Agent", "Accept"]

# 每个平台一条的 UA 样例，验 ua_platform 的分派
PLAT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/151.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/151.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/151.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17.0",
    "Mozilla/5.0 (X11; Linux x86_64) Chrome/151.0.0.0",
]

MASQ_SCRIPT = """
package.path = "%s/lua/?.lua;" .. package.path
local tlsfp = require "tlsfp"
tlsfp.load("%s")
for line in io.lines("%s") do
    local kind, arg1, arg2 = line:match("^(%%S+)\t([^\t]*)\t?(.*)$")
    if kind == "order" then
        local o = tlsfp.header_order(arg1)
        print("order\t" .. arg1 .. "\t" .. (o and table.concat(o, ",") or "-"))
    elseif kind == "sort" then
        local names = {}
        for w in arg2:gmatch("[^,]+") do names[#names + 1] = w end
        local r = tlsfp.sort_headers(arg1, names)
        print("sort\t" .. arg1 .. "\t" .. table.concat(r, ","))
    elseif kind == "value" then
        print("value\t" .. arg1 .. "|" .. arg2 .. "\t"
              .. tostring(tlsfp.header_value(arg1, arg2)))
    elseif kind == "plat" then
        local p, m = tlsfp.ua_platform(arg1)
        print("plat\t" .. arg1 .. "\t" .. tostring(p) .. "|" .. tostring(m))
    elseif kind == "uach" then
        print("uach\t" .. arg1 .. "\t"
              .. tostring(tlsfp.sec_ch_ua(arg1, tonumber(arg2))))
    end
end
print("DONE")
"""


def _lua(lua, script_src, rows):
    """跑一段 Lua，返回它打印的行；没打 DONE 视为失败。"""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(rows))
        vec = f.name
    with tempfile.NamedTemporaryFile("w", suffix=".lua", delete=False) as f:
        f.write(script_src % (ROOT, LIB, vec))
        script = f.name
    try:
        out = subprocess.run([lua, script], capture_output=True, text=True,
                             timeout=120, cwd=ROOT)
    finally:
        os.unlink(vec)
        os.unlink(script)
    lines = out.stdout.splitlines()
    if "DONE" not in lines:
        raise RuntimeError(f"Lua 脚本未正常结束：{out.stderr[:300]}")
    return [l for l in lines if l != "DONE"]


def _cli(exe, lines):
    out = subprocess.run([exe], input="\n".join(lines) + "\n",
                         capture_output=True, text=True, timeout=60)
    return out.stdout.splitlines()


def check_masquerade(lua):
    """伪装四层的 Lua 绑定逐品牌比一遍。返回 (问题列表, 比对条数)。"""
    brands = sorted(BRAND_ENGINE)
    names = ("accept", "accept-encoding", "upgrade-insecure-requests")
    rows = []
    for b in brands:
        rows.append(f"order\t{b}\t")
        rows.append(f"sort\t{b}\t" + ",".join(SORT_SAMPLE))
        rows += [f"value\t{b}\t{n}" for n in names]
        rows.append(f"uach\t{b}\t151")
    rows += [f"plat\t{ua}\t" for ua in PLAT_UAS]

    got = {}
    for line in _lua(lua, MASQ_SCRIPT, rows):
        kind, key, val = line.split("\t", 2)
        got[(kind, key)] = val

    # sec-ch-ua 的表是构建产物，权威在 C 侧（C 与 Python 的一致性归 test_uach）
    uachcli = os.path.join(ROOT, "csrc", "uachcli")
    c_uach = dict(zip(brands, _cli(uachcli, [f"{b} 151" for b in brands])))

    bad, n = [], 0
    for b in brands:
        want_order, _ = order_for(b)
        exp = ",".join(want_order) if want_order else "-"
        n += 1
        if got.get(("order", b)) != exp:
            bad.append(f"header_order({b}): Lua={got.get(('order', b))} "
                       f"Python={exp}")

        n += 1
        exp = ",".join(sort_headers(b, list(SORT_SAMPLE)))
        if got.get(("sort", b)) != exp:
            bad.append(f"sort_headers({b}): Lua={got.get(('sort', b))} "
                       f"Python={exp}")

        vals = values_for(b)
        for name in names:
            n += 1
            exp = vals.get(name)
            g = got.get(("value", f"{b}|{name}"))
            g = None if g == "nil" else g
            if g != exp:
                bad.append(f"header_value({b},{name}): Lua={g!r} Python={exp!r}")

        n += 1
        exp = c_uach.get(b, "-").strip()
        g = got.get(("uach", b))
        g = "-" if g == "nil" else g
        if g != exp:
            bad.append(f"sec_ch_ua({b}): Lua={g!r} C={exp!r}")

    for ua in PLAT_UAS:
        n += 1
        plat, mobile = platform_hint(ua)
        exp = f"{plat or 'nil'}|{mobile or 'nil'}"
        if got.get(("plat", ua)) != exp:
            bad.append(f"ua_platform({ua[:40]}…): Lua={got.get(('plat', ua))} "
                       f"Python={exp}")
    return bad, n


def find_luajit():
    for c in ("luajit", "resty"):
        p = shutil.which(c)
        if p:
            return p
    return None


def main():
    lua = find_luajit()
    if not lua:
        print("缺 luajit/resty，跳过（非失败）", file=sys.stderr)
        return 0
    # **门禁自己 make**：不然改坏 tlsfp.c 之后比的是上一次编出来的 .so，
    # 断言静默失灵（本项目第 5 次撞这个形态，见 test_c_parity 的同名说明）。
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"make 失败：{(r.stderr or r.stdout)[-300:]}", file=sys.stderr)
        return 2
    if not os.path.exists(LIB):
        print(f"缺 {LIB}；先在 csrc 下 make", file=sys.stderr)
        return 2

    with open(REGISTRY) as f:
        registry = json.load(f)

    rows = []
    for rec in registry:
        try:
            raw = build_client_hello(rec["tls"], sni=None)
        except Exception:
            continue
        rows.append(f"{raw.hex()}\t{fingerprint(raw)['ja4']}\t{rec['id']}")

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(rows))
        vec = f.name
    with tempfile.NamedTemporaryFile("w", suffix=".lua", delete=False) as f:
        f.write(LUA_SCRIPT % (ROOT, LIB, vec))
        script = f.name

    try:
        out = subprocess.run([lua, script], capture_output=True, text=True,
                             timeout=120, cwd=ROOT)
    finally:
        os.unlink(vec)
        os.unlink(script)

    lines = out.stdout.splitlines()
    if "DONE" not in lines:
        print(f"Lua 脚本未正常结束：{out.stderr[:300]}", file=sys.stderr)
        return 1
    bad = [l for l in lines if l.startswith("MISMATCH")]
    _n_compared = len(rows)
    print(f"三方差分 {len(rows)} 个 profile："
          f"{len(rows) - len(bad)} 一致，{len(bad)} 不符")
    for l in bad[:8]:
        _, pid, want, got = l.split("\t")
        print(f"  ✗ {pid}\n      Python/C {want}\n      Lua      {got}")
    # 比对集为空时上面每一项都会"通过" —— 实测过：清空
    # profiles.json 后本门禁照样退出码 0，打印"0 一致，0 不符"。
    if _n_compared < MIN_PROFILES:
        print(f"  ✗ 只比对了 {_n_compared} 条（下限 "
              f"{MIN_PROFILES}）—— 注册表被截断或读空了？")
        return 1

    # 第二段：伪装另外三层的 Lua 绑定
    try:
        mbad, mn = check_masquerade(lua)
    except Exception as e:
        print(f"伪装层比对跑不起来：{type(e).__name__}: {str(e)[:200]}",
              file=sys.stderr)
        return 1
    print(f"伪装层三方差分 {mn} 项：{mn - len(mbad)} 一致，{len(mbad)} 不符")
    for m in mbad[:10]:
        print(f"  ✗ {m}")
    if mn < MIN_MASQ:
        print(f"  ✗ 伪装层只比了 {mn} 项（下限 {MIN_MASQ}）—— 品牌表读空了？")
        return 1
    return 1 if (bad or mbad) else 0


if __name__ == "__main__":
    raise SystemExit(main())
