"""Lua 的 by_ua() 与 Python / C 的差分门禁。

**这是生产实际调用的入口**。网关在 CDN 之后拿不到 ClientHello，只能按 UA 选
指纹，走的就是 `browserfp.by_ua(brand, version)` —— 而 test_lua_parity 只比
ClientHello 解析（ja4 / identify），by_ua 一直没被任何 Lua 侧门禁覆盖过。

FFI 绑定层有独立的出错空间：confidence 的 out 参数、NULL 返回的判定、结构体
字段偏移，任何一处错了都会在不崩溃的情况下给出错误结果。C 对了不代表 Lua 对。

口径与 test_c_ua_parity 一致，两个都比：
  生产 UA 口径   必须 0 分歧 —— 今天就在用的路径
  全版本口径     用棘轮 —— 与 C 侧同一个水位，因为 Lua 直接调 C

跑：python -m spec.test_lua_ua_parity
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.covscan import NEVER_RELEASED, TARGETS            # noqa: E402
from oracle.uamap import UAMapper, parse_ua                   # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LIB = os.path.join(ROOT, "csrc", "libbrowserfp.so")
FIXTURES = os.path.join(HERE, "fixtures", "prod_user_agents.json")

# 与 test_c_ua_parity 同一个水位：Lua 直接调 C，两者分歧数应当一致。
# 若 Lua 的分歧数与 C 不同，那就是 FFI 绑定层自己出了问题。
FULL_RANGE_BASELINE = 0

LUA_SCRIPT = """
package.path = "%s/lua/?.lua;" .. package.path
local browserfp = require "browserfp"
browserfp.load("%s")
for line in io.lines("%s") do
    local brand, ver = line:match("^(%%S+)%%s+(%%d+)$")
    if brand then
        local r, err, conf = browserfp.by_ua(brand, tonumber(ver))
        if r then
            print(brand .. "\\t" .. ver .. "\\t" .. r.id .. "\\t" .. r.confidence)
        else
            print(brand .. "\\t" .. ver .. "\\t-\\t" .. tostring(conf))
        end
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


def run_lua(lua, cases):
    """把 (brand, version) 列表送进 Lua，返回 [(id, confidence)]。"""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(f"{b} {v}" for b, v in cases))
        vec = f.name
    with tempfile.NamedTemporaryFile("w", suffix=".lua", delete=False) as f:
        f.write(LUA_SCRIPT % (ROOT, LIB, vec))
        script = f.name
    try:
        out = subprocess.run([lua, script], capture_output=True, text=True,
                             timeout=180)
        rows = []
        for line in out.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) == 4:
                rows.append((parts[2], parts[3]))
        if "DONE" not in out.stdout:
            print(f"Lua 未正常结束：{out.stderr[:300]}", file=sys.stderr)
        return rows
    finally:
        for p in (vec, script):
            try:
                os.unlink(p)
            except OSError:
                pass


def main():
    lua = find_luajit()
    if not lua:
        print("缺 luajit/resty，跳过（非失败）", file=sys.stderr)
        return 0
    if not os.path.exists(LIB):
        print(f"缺 {LIB}；先在 csrc 下 make", file=sys.stderr)
        return 2

    mapper = UAMapper()

    # 口径一：生产 UA
    with open(FIXTURES) as f:
        rows = json.load(f)
    prod_cases, prod_want = [], []
    for row in rows:
        brand, ver = parse_ua(row["ua"])
        if not brand:
            continue
        r = mapper.lookup(row["ua"])
        prod_cases.append((brand, ver))
        prod_want.append((r.get("profile") or "-", r["confidence"]))
    prod_got = run_lua(lua, prod_cases)
    prod_bad = [(c, e, g) for c, e, g in zip(prod_cases, prod_want, prod_got)
                if e != g]

    # 口径二：全版本 × 全品牌
    full_cases, full_want = [], []
    for brand, (tpl, lo, hi) in TARGETS.items():
        skip = NEVER_RELEASED.get(brand, set())
        for v in range(lo, hi + 1):
            if v in skip:
                continue
            r = mapper.lookup(tpl.format(v=v))
            full_cases.append((brand, v))
            full_want.append((r.get("profile") or "-", r["confidence"]))
    full_got = run_lua(lua, full_cases)
    full_bad = [(c, e, g) for c, e, g in zip(full_cases, full_want, full_got)
                if e != g]

    print(f"生产 UA 口径   {len(prod_cases)} 条："
          f"{len(prod_cases) - len(prod_bad)} 一致，{len(prod_bad)} 不符")
    for c, e, g in prod_bad[:8]:
        print(f"  ✗ {c[0]} {c[1]}   Python {e}   Lua {g}")
    print(f"全版本口径     {len(full_cases)} 条："
          f"{len(full_cases) - len(full_bad)} 一致，{len(full_bad)} 不符")
    for c, e, g in full_bad[:8]:
        print(f"  ✗ {c[0]} {c[1]}   Python {e}   Lua {g}")

    if len(full_bad) > FULL_RANGE_BASELINE:
        print(f"\n全版本差分 {len(full_bad)} 处，超过水位 {FULL_RANGE_BASELINE}"
              " —— Lua 的分歧数应与 C 侧一致，多出来的就是 FFI 绑定层自己的问题")

    failed = bool(prod_bad) or len(full_bad) > FULL_RANGE_BASELINE
    print(f"\n{'Lua 与 Python 语义一致' if not failed else '存在分歧'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
