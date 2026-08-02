-- 把 Lua 侧每个公开入口用恶劣输入喂一遍。
-- 判据：**不得抛出未捕获的错误**（在 content_by_lua_block 里那就是 500），
-- 也不得让 LuaJIT 崩掉。返回 nil+err 是合格的。
package.path = "lua/?.lua;" .. package.path
local tlsfp = require "tlsfp"
tlsfp.load("csrc/libtlsfp.so")

local big = string.rep("A", 70000)
local vals = {nil, "", " ", "chrome", big, "chrome-mobile", "\255\254",
              0, -1, 1.5, 151, 65535, 1e9, true, {}, function() end}
local n, bad = 0, {}

local function try(name, fn, ...)
  n = n + 1
  local ok, err = pcall(fn, ...)
  if not ok then
    bad[#bad + 1] = name .. ": " .. tostring(err):sub(1, 90)
  end
end

-- vals 里有 nil，用显式长度遍历，否则 ipairs 会提前停
local N = 16
for i = 1, N do
  local a = vals[i]
  for j = 1, N do
    local b = vals[j]
    try("by_ua", tlsfp.by_ua, a, b)
    try("client_hello", tlsfp.client_hello, a, b, "x")
    try("h2_preface", tlsfp.h2_preface, a, b)
    try("sec_ch_ua", tlsfp.sec_ch_ua, a, b)
    try("header_value", tlsfp.header_value, a, b)
  end
  try("header_order", tlsfp.header_order, a)
  try("ua_platform", tlsfp.ua_platform, a)
  try("identify_h2", tlsfp.identify_h2, a)
  try("identify", tlsfp.identify, a)
  try("ja4", tlsfp.ja4, a)
  try("sort_headers", tlsfp.sort_headers, a, {"Accept", a, 1})
  try("coherence", tlsfp.coherence, a, a, a)
  try("coherence-table", tlsfp.coherence, a, a, {a, "accept"})
end

-- 截断的 TLS record 逐长度喂给识别器
local rec = string.rep("\0", 400)
for k = 0, 300 do try("identify-trunc", tlsfp.identify, rec:sub(1, k)) end
local hdr = "\22\3\1\255\255" .. string.rep("\0", 300)
for k = 5, 300 do try("identify-lie", tlsfp.identify, hdr:sub(1, k)) end

print(n)
for i = 1, math.min(#bad, 8) do print("BAD " .. bad[i]) end
os.exit(#bad > 0 and 1 or 0)
