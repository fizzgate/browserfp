-- tlsfp —— ClientHello 指纹识别的 LuaJIT FFI 绑定。
--
-- 设计约束（这条是整个集成的前提）：
--   libtlsfp.so 里所有函数都是**内存进内存出、非阻塞**的，不做 socket/文件 I/O、
--   不 sleep。因此可以在 nginx worker 里直接调用而不会阻塞事件循环。网络 I/O 一律
--   由 Lua 侧的 cosocket 承担，在等待时 yield 给事件循环。
--
--   反例：若把网络 I/O 放进 FFI，一次阻塞调用会冻死整个 worker —— 实测一个 9s 的
--   阻塞调用能让同 worker 上的并发请求卡住 8.88s。
--
-- 典型用法（入站识别，OpenResty 的 ssl_client_hello_by_lua*）：
--   local tlsfp = require "tlsfp"
--   local ssl_clt_hello = require "ngx.ssl.clienthello"
--   local raw = ssl_clt_hello.get_client_hello_raw()   -- 需 OpenResty 支持
--   local r = tlsfp.identify(raw)
--   if r then ngx.log(ngx.INFO, "client=", r.id, " ja4=", r.ja4)
--   else       ngx.log(ngx.WARN, "unknown TLS fingerprint") end

local ffi = require "ffi"

ffi.cdef [[
typedef struct {
    uint16_t items[64];
    size_t   len;
} tlsfp_u16list;

typedef struct {
    uint16_t      client_version;
    uint8_t       session_id_len;
    tlsfp_u16list ciphers;
    tlsfp_u16list extensions;
    tlsfp_u16list curves;
    tlsfp_u16list sig_algs;
    tlsfp_u16list supported_versions;
    int           has_grease;
    int           has_sni;
    char          alpn_first[16];
    size_t        alpn_count;
} tlsfp_hello;

typedef struct {
    const char     *id;
    const char     *ja4;
    const char     *h2_akamai;
    const char     *mode;
    const uint16_t *ciphers;   size_t n_ciphers;
    const uint16_t *exts;      size_t n_exts;
    const uint16_t *curves;    size_t n_curves;
    const uint16_t *sigalgs;   size_t n_sigalgs;
} tlsfp_profile;

int  tlsfp_parse_client_hello(const uint8_t *record, size_t len, tlsfp_hello *out);
const tlsfp_profile *tlsfp_lookup_ua(const char *brand, uint16_t version, int *confidence);
int  tlsfp_ja4(const tlsfp_hello *h, char transport, char *out, size_t outlen);
int  tlsfp_build_client_hello(const tlsfp_profile *p, const char *sni,
                              const uint8_t *random32, const uint8_t *session_id,
                              uint8_t *out, size_t outlen);
const tlsfp_profile *tlsfp_profile_at(size_t idx);
const tlsfp_profile *tlsfp_lookup_ja4(const char *ja4);
size_t tlsfp_profile_count(void);
]]

local _M = { _VERSION = "0.1" }

local lib
do
    -- 依次尝试常见位置；调用方也可先设 package.cpath 或用 tlsfp.load(path)
    local candidates = {
        "libtlsfp.so", "./libtlsfp.so", "csrc/libtlsfp.so",
        "/usr/local/lib/libtlsfp.so",
    }
    for _, p in ipairs(candidates) do
        local ok, handle = pcall(ffi.load, p)
        if ok then lib = handle break end
    end
end

function _M.load(path)
    lib = ffi.load(path)
    return lib
end

-- 复用同一块 buffer，避免每请求分配（nginx worker 里这条很重要）
local hello_buf = ffi.new("tlsfp_hello")
local ja4_buf   = ffi.new("char[40]")

--- 解析 ClientHello 并算 JA4。
-- @param record  完整 TLS record（含 5 字节头）的字符串
-- @param transport  "t"（TCP，默认）或 "q"（QUIC）
-- @return ja4 字符串；失败返回 nil, err
function _M.ja4(record, transport)
    if not lib then return nil, "libtlsfp.so 未加载" end
    if type(record) ~= "string" or #record < 5 then return nil, "record 太短" end

    local rc = lib.tlsfp_parse_client_hello(record, #record, hello_buf)
    if rc ~= 0 then return nil, "解析失败 rc=" .. tonumber(rc) end

    local t = (transport == "q") and 113 or 116   -- 'q' / 't'
    if lib.tlsfp_ja4(hello_buf, t, ja4_buf, 40) ~= 0 then
        return nil, "ja4 计算失败"
    end
    return ffi.string(ja4_buf)
end

--- 识别 ClientHello 对应的已知 profile。
-- **未命中时返回 nil 而不是"最接近的那个"**：把陌生指纹安静地归到某个已知
-- profile，比认不出更糟——它让盲区永远不可见。
-- @return table{id, ja4, h2, mode} 或 nil, ja4（未知时把算出的 ja4 一并返回，
--         便于调用方记日志、后续补录）
function _M.identify(record, transport)
    local ja4, err = _M.ja4(record, transport)
    if not ja4 then return nil, err end

    local p = lib.tlsfp_lookup_ja4(ja4)
    if p == nil then return nil, ja4 end

    return {
        id   = ffi.string(p.id),
        ja4  = ja4,
        h2   = p.h2_akamai ~= nil and ffi.string(p.h2_akamai) or nil,
        mode = ffi.string(p.mode),
    }
end

-- C 侧的 confidence 取值：0/1/2 是可用档，负值表示"没给 profile"但原因不同。
-- **NULL 返回时也要把 confidence 带出去**：fallback（存在跨段的最近版本，只是
-- 严格模式不许用，该记进补录清单）与 no-brand（表里根本没这个品牌）是两件事，
-- 合并成一个 nil 会让调用方分不清，也让差分门禁把两侧判成不一致。
local conf_names = {
    [0] = "exact", [1] = "same-seg", [2] = "fallback",
    [-1] = "no-brand", [-2] = "no-version",
}
local conf_buf = ffi.new("int[1]")

--- 按 UA 的品牌与主版本选出该用的指纹（生产主入口）。
-- 网关在 CDN 之后拿不到 ClientHello，只能按 UA 选。
-- **默认严格**：只有 exact / same-seg 才返回 profile；没有精确指纹时返回 nil，
-- 调用方应放弃伪装。拿最近版本的指纹冒充另一个版本正是 split-brain 的来源。
-- @return table{id, ja4, h2, confidence} 或 nil, err
function _M.by_ua(brand, version)
    if not lib then return nil, "libtlsfp.so 未加载" end
    if type(brand) ~= "string" or type(version) ~= "number" then
        return nil, "brand/version 类型错误"
    end
    conf_buf[0] = -1
    local p = lib.tlsfp_lookup_ua(brand, version, conf_buf)
    local conf = conf_names[conf_buf[0]] or "unknown"
    if p == nil then
        -- 第三个返回值给出 confidence：调用方据此区分"该补录"与"本就没有"
        return nil, "该品牌/版本无可用 profile", conf
    end
    return {
        id   = ffi.string(p.id),
        ja4  = ffi.string(p.ja4),
        h2   = p.h2_akamai ~= nil and ffi.string(p.h2_akamai) or nil,
        confidence = conf,
    }
end

-- 复用缓冲区，避免每请求分配（nginx worker 里这条很重要）
local ch_buf   = ffi.new("uint8_t[16384]")
local rnd_buf  = ffi.new("uint8_t[32]")
local sid_buf  = ffi.new("uint8_t[32]")

--- 按 UA 选出指纹并组装 ClientHello 字节，供 cosocket 直接发出。
-- **伪装链的最后一环**：查表只拿到 profile，得把它变成真正的字节。
--
-- random 与 session_id 每次调用都重新生成 —— 照抄 golden 里那份会让所有连接的
-- ClientHello 逐字节相同，比不伪装还容易被判。这里用 resty.random 取强随机；
-- 不在 OpenResty 环境时退回 math.random（仅供离线自测，**不要用于生产**）。
--
-- @param brand    品牌，移动端传 "<brand>-mobile"
-- @param version  主版本；Chromium 系衍生浏览器传 UA 里 Chrome/ 的版本号
-- @param sni      目标域名，必须给 —— 少了它多租户站点直接 handshake_failure
-- @return record 字符串, profile 信息表；失败返回 nil, err
function _M.client_hello(brand, version, sni)
    if not lib then return nil, "libtlsfp.so 未加载" end
    if type(sni) ~= "string" or sni == "" then
        return nil, "必须提供 sni：多租户站点缺 SNI 会直接 handshake_failure"
    end
    local prof, err, conf = _M.by_ua(brand, version)
    if not prof then return nil, err or "无可用 profile" end

    local strong = nil
    local ok_rand, rnd = pcall(require, "resty.random")
    if ok_rand and rnd and rnd.bytes then strong = rnd.bytes(64, true) end
    if strong and #strong >= 64 then
        ffi.copy(rnd_buf, strong, 32)
        ffi.copy(sid_buf, strong:sub(33, 64), 32)
    else
        -- 离线自测退路：math.random 不是密码学随机，生产必须走 resty.random
        for i = 0, 31 do
            rnd_buf[i] = math.random(0, 255)
            sid_buf[i] = math.random(0, 255)
        end
    end

    local p = lib.tlsfp_lookup_ua(brand, version, conf_buf)
    if p == nil then return nil, "profile 已失效" end
    local n = lib.tlsfp_build_client_hello(p, sni, rnd_buf, sid_buf,
                                           ch_buf, ffi.sizeof(ch_buf))
    if n < 0 then return nil, "组装失败（缓冲区不足或 profile 缺重建字段）" end
    return ffi.string(ch_buf, n), prof
end

function _M.profile_count()
    if not lib then return 0 end
    return tonumber(lib.tlsfp_profile_count())
end

return _M
