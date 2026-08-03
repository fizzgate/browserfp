"""生产接口发出去的公钥必须是**调用方注入的那把**，不是采集机上那把。

这一条以前没有任何门禁看着，而它是"接口做不了接口该做的事"那一类：
`browserfp.client_hello()` 组装出来的字节，所有指纹字段都对、JA4/JA3 全绿、
test_openresty 的逐字段比对也全绿 —— 因为 **JA4 和 JA3 都不看 key_share 的
公钥内容**。唯一会发现问题的是服务端，它拿这把公钥算共享密钥，而我们没有对应
私钥，于是握手在 Finished 阶段失败，报错指向"解密失败"，与真因隔着两层。

实测过：修之前 Lua 发的 0x001d 公钥与 golden 逐字节相同。

正面一条：每个非 GREASE 组发的都是注入值，GREASE 那条不受影响。

反面八条，都是"错了必须当场响"的边界。**只断言"返回了 nil"不够** —— 底下那层
C 对其中两条也会拒，但它报的是"组装失败（缓冲区不足或 profile 缺重建字段）"，
指向一个完全无关的原因；查这种错和查没报错一样费时间。所以连报错内容一起验：

  不给 key_shares / 传字符串 / 传数字   报错须提 key_shares（不能抛异常）
  给空表 / 少给一组                     报错须提"缺组"
  公钥长度不对                          报错须指出该多少字节
  多给一个 profile 里没有的组           报错须报出那个组号
  试图注入 GREASE 组                    同上 —— 它的内容按 RFC 8701 由库自己填
  键写成字符串而不是组号                报错须说清键的形状（否则 %04x 直接抛）

最后两条尤其容易被写成"静默丢掉"。**"以为注入了、其实没有"是最难查的形态**：
字节合法、指纹全绿，只有服务端算共享密钥时才炸。

跑：python -m spec.test_lua_keyshare
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.clienthello import is_grease, parse_client_hello   # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LIB = os.path.join(ROOT, "csrc", "libbrowserfp.so")

FILL = 0xAB

# 四个引擎各一条 —— key_share 的组构成各不相同（Firefox 多一条 P-256），
# 只验一个引擎等于只验了一种形状
CASES = [("chrome", 151), ("firefox", 153),
         ("safari-mobile", 27), ("chrome-mobile", 134)]

LUA = r"""
package.path = "%s/lua/?.lua;" .. package.path
local browserfp = require "browserfp"
assert(browserfp.load("%s"))
local function hex(s)
    return (s:gsub(".", function(c) return string.format("%%02x", c:byte()) end))
end
for line in io.lines("%s") do
    local brand, ver = line:match("^(%%S+)\t(%%d+)$")
    local gs, gerr = browserfp.key_share_groups(brand, tonumber(ver))
    if not gs then
        print(brand .. "\t" .. ver .. "\tGROUPS_ERR\t" .. tostring(gerr))
    else
        local ks, sizes = {}, {}
        for _, g in ipairs(gs) do
            ks[g.group] = string.rep(string.char(%d), g.len)
            sizes[#sizes + 1] = string.format("%%04x:%%d", g.group, g.len)
        end
        local rec, prof = browserfp.client_hello(brand, tonumber(ver), "example.com", ks)
        if not rec then
            print(brand .. "\t" .. ver .. "\tBUILD_ERR\t" .. tostring(prof))
        else
            print(brand .. "\t" .. ver .. "\tOK\t" .. table.concat(sizes, ",")
                  .. "\t" .. hex(rec))
        end
        -- 四条拒绝路径。**返回 nil 只是及格线** —— 底下那层 C 对其中两条
        -- 也会拒，但它报的是"组装失败（缓冲区不足或 profile 缺重建字段）"，
        -- 指向一个完全无关的原因。所以下面连报错内容一起验。
        local function call(v)
            local ok, r, e = pcall(browserfp.client_hello, brand, tonumber(ver),
                                   "example.com", v)
            if not ok then return "THREW", tostring(r) end   -- 抛异常不算拒绝
            return tostring(r == nil), tostring(e)
        end
        local short, extra, greased = {}, {}, {}
        for g, v in pairs(ks) do
            short[g] = v:sub(1, #v - 1)
            extra[g] = v
            greased[g] = v
        end
        extra[0x0100] = string.rep("z", 32)      -- profile 里没有的组
        greased[0x0a0a] = string.rep("z", 32)    -- GREASE 组，库自己填的那条
        local badkey = {}
        for g, v in pairs(ks) do badkey[g] = v end
        badkey["0x001d"] = "写成字符串的组号"    -- 键不是数字
        local out = {brand, ver, "REJECT"}
        local a0, b0 = call(nil)                     -- nil 进不了 ipairs，单列
        out[#out + 1] = a0 .. "§" .. b0
        for _, v in ipairs({{}, short, "不是表", 12345, extra, greased, badkey}) do
            local a, b = call(v)
            out[#out + 1] = a .. "§" .. b
        end
        print(table.concat(out, "\t"))
    end
end
"""


def find_luajit():
    for c in ("luajit", "resty"):
        p = subprocess.run(["which", c], capture_output=True, text=True)
        if p.returncode == 0:
            return p.stdout.strip()
    return None


def main():
    lua = find_luajit()
    if not lua:
        print("缺 luajit/resty，跳过（非通过）", file=sys.stderr)
        return 0
    if not os.path.exists(LIB):
        r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            print(f"make 失败：{(r.stderr or r.stdout)[-200:]}")
            return 1

    # 输入写临时文件，不落在 spec/cache —— 变异测试里那个目录是软链回真仓的，
    # 往里写等于让门禁污染被测源码树。
    import tempfile
    fd, inp = tempfile.mkstemp(prefix="lua_ks_", suffix=".tsv")
    with os.fdopen(fd, "w") as f:
        for b, v in CASES:
            f.write(f"{b}\t{v}\n")
    script = LUA % (ROOT, LIB, inp, FILL)
    try:
        r = subprocess.run([lua, "-"], input=script, capture_output=True,
                           text=True, timeout=180)
    finally:
        os.unlink(inp)
    if r.returncode != 0:
        print(f"luajit 退出 {r.returncode}：{(r.stderr or '')[-300:]}")
        return 1

    bad, checked, groups_seen = [], 0, 0
    for line in r.stdout.strip().splitlines():
        parts = line.split("\t")
        tag = parts[2] if len(parts) > 2 else "?"
        who = f"{parts[0]} {parts[1]}"
        if tag in ("GROUPS_ERR", "BUILD_ERR"):
            bad.append(f"{who}: {tag} {parts[3]}")
            continue
        if tag == "REJECT":
            # (列, 场景, 报错里必须出现的词) —— 只看"返回了 nil"是不够的：
            # 底下那层 C 对后两条也会拒，但报的是"组装失败（缓冲区不足或
            # profile 缺重建字段）"。**指向错原因的报错和不报错一样费时间**，
            # 这个项目里已经为此多绕过好几次，所以把真因一起当判据。
            for i, name, want in ((3, "不给 key_shares", "key_shares"),
                                  (4, "给空表", "缺组"),
                                  (5, "公钥短一字节", "字节"),
                                  (6, "传字符串", "key_shares"),
                                  (7, "传数字", "key_shares"),
                                  (8, "多给一个不存在的组", "0x0100"),
                                  (9, "试图注入 GREASE 组", "0x0a0a"),
                                  (10, "键写成字符串", "必须是组号")):
                got = parts[i].split("§", 1)
                if got[0] == "THREW":
                    bad.append(f"{who}: {name} 时直接抛异常（{got[1][:60]}）—— "
                               "接口约定是返回 nil, err，抛出去会打穿调用方")
                elif got[0] != "true":
                    bad.append(f"{who}: {name} 时仍然出了字节 —— "
                               "凑合出来的字节握不上手，必须当场报错")
                elif want not in got[1]:
                    bad.append(f"{who}: {name} 的报错没提「{want}」，实际是"
                               f"「{got[1][:70]}」—— 指向了别的原因")
            print(f"  拒绝路径 {who:22s} 8 条全按真因报错")
            continue

        sizes = dict(x.split(":") for x in parts[3].split(","))
        raw = bytes.fromhex(parts[4])
        hb = parse_client_hello(raw)["extension_bodies"].get(0x0033)
        if hb is None:
            bad.append(f"{who}: 构造的字节里没有 key_share 扩展")
            continue
        body = bytes.fromhex(hb)
        i, n_real, n_grease = 2, 0, 0
        while i + 4 <= len(body):
            g = int.from_bytes(body[i:i + 2], "big")
            ln = int.from_bytes(body[i + 2:i + 4], "big")
            pub = body[i + 4:i + 4 + ln]
            if is_grease(g):
                n_grease += 1
                if pub == bytes([FILL]) * ln and ln:
                    bad.append(f"{who}: GREASE 组 0x{g:04x} 被注入值覆盖了 —— "
                               "它的内容该由库自己填")
            else:
                n_real += 1
                if str(g) not in sizes and f"{g:04x}" not in sizes:
                    bad.append(f"{who}: 组 0x{g:04x} 没出现在 key_share_groups() "
                               "的返回里 —— 调用方无从知道要为它生成密钥")
                if pub != bytes([FILL]) * ln:
                    bad.append(f"{who}: 组 0x{g:04x} 发的不是注入的公钥"
                               f"（前 8 字节 {pub[:8].hex()}）—— "
                               "这是采集机那把，我们没有它的私钥")
            i += 4 + ln
        if n_real == 0:
            bad.append(f"{who}: 一个非 GREASE 组都没有，上面的比对等于没比")
        groups_seen += n_real
        checked += 1
        print(f"  ✅ {who:22s} 注入 {n_real} 组 + GREASE {n_grease} 组")

    if checked < len(CASES):
        bad.append(f"只验到 {checked}/{len(CASES)} 个引擎 —— key_share 的组构成"
                   "逐引擎不同，差一个就是差一种形状没验")
    if groups_seen < len(CASES) + 1:
        bad.append(f"总共只比了 {groups_seen} 组公钥，少于引擎数 —— "
                   "至少有一个引擎的 key_share 是空的")

    print(f"\n注入生效 {checked}/{len(CASES)} 个引擎，共 {groups_seen} 组公钥")
    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'生产接口发的是调用方的公钥' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
