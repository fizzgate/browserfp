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
int  tlsfp_ja4(const tlsfp_hello *h, char transport, char *out, size_t outlen);
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

function _M.profile_count()
    if not lib then return 0 end
    return tonumber(lib.tlsfp_profile_count())
end

return _M
