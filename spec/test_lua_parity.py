"""Lua FFI 绑定的差分门禁 —— Python / C / Lua 三方必须一致。

C 版已由 test_c_parity 对齐 Python。但 FFI 绑定层还有独立的出错空间：结构体
布局不匹配、字符串所有权、transport 参数传错等，都会在不崩溃的情况下给出错误
结果。所以 Lua 侧要单独比一遍，而不是"C 对了 Lua 就一定对"。

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

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LIB = os.path.join(ROOT, "csrc", "libtlsfp.so")
REGISTRY = os.path.join(HERE, "profiles.json")

# 防平凡通过：注册表被截断或读空时，"0 一致，0 不符"看着是绿的 —— 实测过，
# 清空 profiles.json 后本门禁照样退出码 0。下限**不是棘轮**，它只回答
# "比对集是不是还在"，所以取一个远低于真实值（81）又远高于零的数。
MIN_PROFILES = 50

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

    return 1 if bad else 0



if __name__ == "__main__":
    raise SystemExit(main())
