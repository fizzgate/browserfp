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
typedef struct {
    const uint32_t *settings; size_t n_settings;
    uint32_t        window;
    const uint32_t *prio;     size_t n_prio;
    const char     *pseudo;
    const char     *akamai;
    const char     *engine;
    uint16_t        ver_lo, ver_hi;
} tlsfp_h2;

const tlsfp_h2 *tlsfp_lookup_h2(const char *brand, uint16_t version);
const tlsfp_h2 *tlsfp_identify_h2(const char *akamai);
const char *tlsfp_engine_of_headers(const char *order_csv, int *n_match);
int tlsfp_coherence(const char *ja4, const char *akamai, const char *order_csv,
                    const char **tls_engine, const char **h2_engine,
                    const char **hdr_engine);
int  tlsfp_build_h2_preface(const tlsfp_h2 *h, uint8_t *out, size_t outlen);
const char *tlsfp_h2_pseudo(const tlsfp_h2 *h);
const char *tlsfp_header_order(const char *brand, int *attested);
const char *tlsfp_sec_ch_ua(const char *brand, uint16_t version);
const char *tlsfp_header_value(const char *brand, const char *name);
int tlsfp_ua_platform(const char *ua, const char **platform, const char **mobile);
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
local h2_buf = ffi.new("uint8_t[?]", 8192)
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

-- HTTP/2 连接开场：PREFACE + SETTINGS + WINDOW_UPDATE + PRIORITY。
--
-- **按 (品牌, 版本) 独立查，不从 TLS profile 上读**。注册表按 TLS 指纹去重，
-- 而 h2 参数与 ClientHello 各改各的：两个版本 TLS 相同、h2 不同是常态，实测
-- chrome 106-117 共 9 个版本曾因搭车拿到没有任何一个库归给它们的 h2。
-- 伪装是分层的，TLS 像 Chrome、h2 不像任何浏览器，是现实中不存在的组合。
--
-- 版本口径与 by_ua 一致：Chromium 系衍生浏览器传**内核** Chrome 版本。
--
-- HEADERS 不在返回值里：内容依赖具体请求，本库只给伪头**顺序**（第二个返回值）。
--
-- @return string 开场字节, string 伪头序   或  nil, err
function _M.h2_preface(brand, version)
    if not lib then return nil, "libtlsfp.so 未加载" end
    if type(brand) ~= "string" or type(version) ~= "number" then
        return nil, "brand 必须是字符串、version 必须是数字"
    end
    local h = lib.tlsfp_lookup_h2(brand, version)
    -- 查不到就明确失败。**不能退回一组默认 SETTINGS** —— 那等于发一个不属于
    -- 任何浏览器的 h2 指纹。调用方该走 HTTP/1.1，或换一个有数据的版本。
    if h == nil then return nil, "该品牌/版本没有 h2 数据，不能构造开场" end
    local n = lib.tlsfp_build_h2_preface(h, h2_buf, ffi.sizeof(h2_buf))
    if n < 0 then return nil, "组装失败（缓冲区不足）" end
    local ps = lib.tlsfp_h2_pseudo(h)
    return ffi.string(h2_buf, n), ps ~= nil and ffi.string(ps) or nil
end

-- 请求头的相对顺序。伪装是三层的：TLS、h2 开场、请求头顺序 —— 前两层对了、
-- 头按自己的顺序发，照样能被判。
--
-- 只回答"这些头之间谁在前"：实际发哪些头由调用方决定（导航请求与子资源请求
-- 带的头不同），本库不替它决定。第二个返回值 attested 为 true 表示该品牌有
-- 真机实采背书，false 表示按引擎推断（移动端全是推断）。
--
-- @return table 顺序数组, boolean 是否实采背书   或  nil, err
function _M.header_order(brand)
    if not lib then return nil, "libtlsfp.so 未加载" end
    if type(brand) ~= "string" then return nil, "brand 必须是字符串" end
    local p = lib.tlsfp_header_order(brand, conf_buf)
    if p == nil then return nil, "不认识的品牌" end
    local out = {}
    for h in ffi.string(p):gmatch("[^,]+") do out[#out + 1] = h end
    return out, conf_buf[0] == 1
end

-- 按该品牌的顺序排调用方给的头名。顺序里没有的排在最后并保持原序 ——
-- 不认识的头不能丢掉，也不能塞到中间。
function _M.sort_headers(brand, names)
    if type(names) ~= "table" then return names end
    local order = _M.header_order(brand)
    if not order then return names end
    local pos = {}
    for i, h in ipairs(order) do pos[h] = i end
    local known, unknown = {}, {}
    for _, h in ipairs(names) do
        -- **非字符串元素要原样放行，不能 h:lower()**：调用方的头名列表里
        -- 混进一个数字就会抛未捕获的错误，在 worker 里那是 500。
        if type(h) == "string" and pos[h:lower()] then
            known[#known + 1] = h
        else
            unknown[#unknown + 1] = h
        end
    end
    table.sort(known, function(a, b) return pos[a:lower()] < pos[b:lower()] end)
    for _, h in ipairs(unknown) do known[#known + 1] = h end
    return known
end

-- sec-ch-ua 的值。手写必然错 —— 里面的 GREASE 品牌按主版本号确定性生成
-- （既非固定串也非随机串），而它就摆在请求头里。
-- 版本口径同 by_ua：衍生浏览器传内核 Chrome 版本。
-- Opera 没有：它的嵌入层会再加自己的品牌项，本项目没有 Opera 实采，不猜。
function _M.sec_ch_ua(brand, version)
    if not lib then return nil, "libtlsfp.so 未加载" end
    if type(brand) ~= "string" or type(version) ~= "number" then
        return nil, "brand 必须是字符串、version 必须是数字"
    end
    local p = lib.tlsfp_sec_ch_ua(brand, version)
    if p == nil then return nil, "该品牌/版本没有 sec-ch-ua 数据" end
    return ffi.string(p)
end

-- 由**浏览器**决定的头取值（accept / accept-encoding /
-- upgrade-insecure-requests）。不由浏览器决定的返回 nil。
--
-- **accept-language 不在其中**：它取决于系统 locale 与用户设置，抄采集环境的
-- 值等于把那台机器的 locale 泄漏出去 —— 该由调用方按自己的场景给。
-- sec-fetch-* 同理，取决于请求类型。
function _M.header_value(brand, name)
    if not lib then return nil, "libtlsfp.so 未加载" end
    if type(brand) ~= "string" or type(name) ~= "string" then
        return nil, "brand 与 name 都必须是字符串"
    end
    local p = lib.tlsfp_header_value(brand, name:lower())
    return p ~= nil and ffi.string(p) or nil
end

-- UA → sec-ch-ua-platform / sec-ch-ua-mobile。两处必须与 UA 里声明的系统
-- 同源 —— 一处照抄 UA、另一处硬编码，会出现"UA 说 Windows、platform 说
-- macOS"这种一眼假的组合。iOS 与认不出的系统返回 nil（那一族不发 UA-CH）。
local plat_buf = ffi.new("const char*[1]")
local mob_buf = ffi.new("const char*[1]")
function _M.ua_platform(ua)
    if not lib then return nil, "libtlsfp.so 未加载" end
    if type(ua) ~= "string" then return nil, "ua 必须是字符串" end
    if lib.tlsfp_ua_platform(ua, plat_buf, mob_buf) == 0 then return nil end
    return ffi.string(plat_buf[0]), ffi.string(mob_buf[0])
end

-- 按观测到的 akamai 指纹反查（入站识别）。
--
-- **认得出引擎，认不出版本**：实测 644 个 (品牌,版本) 只归成 19 个 akamai，
-- 最常见的一个覆盖 223 个组合。但没有一个 akamai 跨引擎，所以 engine 是确定的；
-- ver_lo/ver_hi 只是该指纹覆盖的版本范围，不要当成"就是这个版本"。
--
-- @return table{engine, ver_lo, ver_hi, akamai} 或 nil
function _M.identify_h2(akamai)
    if not lib then return nil, "libtlsfp.so 未加载" end
    if type(akamai) ~= "string" then return nil, "akamai 必须是字符串" end
    local h = lib.tlsfp_identify_h2(akamai)
    if h == nil then return nil end
    return {engine = ffi.string(h.engine), ver_lo = h.ver_lo,
            ver_hi = h.ver_hi, akamai = ffi.string(h.akamai)}
end

-- 三层各自认出的引擎是否自洽。检测方正是这么查的：TLS 说 Chromium 而 h2 说
-- Gecko，一眼就假。也可以拿它自查自己拼出来的伪装。
--
-- 任一参数传 nil 表示该层没有观测。返回 (verdict, 各层引擎)：
--   verdict = "ok"      有观测的那些层一致
--             "mismatch" 矛盾
--             "unknown"  可用信息不足（少于两层认得出来）
-- 第二个返回值是 {tls=…, h2=…, headers=…}，认不出的为 nil ——
-- 报"哪一层不一致"比只报一个布尔有用得多。
local e1, e2, e3 = ffi.new("const char*[1]"), ffi.new("const char*[1]"), ffi.new("const char*[1]")
function _M.coherence(ja4, akamai, header_order)
    if not lib then return nil, "libtlsfp.so 未加载" end
    -- **三个参数都必须是字符串或 nil**。FFI 遇到数字/布尔会抛
    -- "cannot convert 'number' to 'const char *'" —— 未捕获就是 500。
    -- 传表时也只收其中的字符串项：混进一个 nil，table.concat 会直接报错。
    local function str_or_nil(v)
        return type(v) == "string" and v or nil
    end
    local csv
    if type(header_order) == "table" then
        local parts = {}
        for _, h in ipairs(header_order) do
            if type(h) == "string" then parts[#parts + 1] = h end
        end
        csv = #parts > 0 and table.concat(parts, ",") or nil
    else
        csv = str_or_nil(header_order)
    end
    ja4, akamai = str_or_nil(ja4), str_or_nil(akamai)
    e1[0], e2[0], e3[0] = nil, nil, nil
    local r = lib.tlsfp_coherence(ja4, akamai, csv, e1, e2, e3)
    local function str(b) return b[0] ~= nil and ffi.string(b[0]) or nil end
    return (r == 0 and "ok") or (r == 1 and "mismatch") or "unknown",
           {tls = str(e1), h2 = str(e2), headers = str(e3)}
end

function _M.profile_count()
    if not lib then return 0 end
    return tonumber(lib.tlsfp_profile_count())
end

return _M
