/* tlsfp —— ClientHello 解析与 JA4 计算（C 实现）
 *
 * 定位：与 the Python reference (clienthello.py) 逐字段等价的 C 版本。Python 那份是权威，
 * 本实现的验收标准是「在全部 golden 样本上与 Python 输出完全一致」，
 * 而不是「看起来实现了规范」——规范的模糊处（GREASE 剔除、JA4 各段的占位与
 * 排序）已经在 Python 侧被真机数据校准过，照抄那份行为即可。
 *
 * 只做解析与识别所需的确定性字段，不含 TLS 栈：出站伪装另有实现。
 */
#ifndef TLSFP_H
#define TLSFP_H

#include <stddef.h>
#include <stdint.h>

/* 库内所有函数都是**内存进内存出、非阻塞**的：不做 socket I/O、不做文件 I/O、
 * 不 sleep。宿主（OpenResty 的 cosocket）负责搬字节并在等待时 yield。
 * 若在这里做阻塞 I/O，会冻死整个 nginx worker —— 实测一个 9s 的阻塞调用能让
 * 同 worker 上的并发请求卡住 8.88s。 */

/* HTTP/2 连接开场。**独立于 tlsfp_profile 按 (品牌,版本) 查**，不挂在 TLS
   profile 上：注册表按 TLS 指纹去重，而 h2 参数改在 Chromium 的
   net/http/http_network_session.cc，与 BoringSSL 那边各改各的。两个版本 TLS
   相同、h2 不同是常态 —— 实测 chrome 106-117 共 9 个版本因为搭车拿到的 h2
   没有任何一个库把它归给这些版本。 */
typedef struct {
    const uint32_t *settings; size_t n_settings;   /* 扁平 (id,value) 对 */
    uint32_t        window;                        /* 0 = 不发 WINDOW_UPDATE */
    const uint32_t *prio;     size_t n_prio;       /* 扁平四元组 */
    const char     *pseudo;                        /* 伪头序，如 "m,a,s,p" */
    const char     *akamai;
} tlsfp_h2;

typedef struct {
    const char     *id;
    const char     *ja4;
    const char     *h2_akamai;
    const char     *mode;
    const uint16_t *ciphers;   size_t n_ciphers;
    const uint16_t *exts;      size_t n_exts;
    const uint16_t *curves;    size_t n_curves;
    const uint16_t *sigalgs;   size_t n_sigalgs;

    /* 重建 ClientHello 用的原始形态。比对字段剔了 GREASE、也没有每个扩展的
       具体内容，拿它拼出来的握手与真实浏览器不是一回事，所以另存一份：
         rawciph / rawext  保序且含 GREASE
         extblob           所有扩展体平铺，按 rawext 顺序
         extoff / extlen   每个扩展体在 extblob 里的偏移与长度 */
    const uint16_t *rawciph;   size_t n_rawciph;
    const uint16_t *rawext;    size_t n_rawext;
    const uint8_t  *extblob;
    const uint16_t *extoff;
    const uint16_t *extlen;
    uint16_t client_version;
    uint16_t session_id_len;

} tlsfp_profile;

typedef struct {
    const char *brand;      /* chrome / firefox / safari / edge / opera / tor */
    uint16_t    version;    /* 主版本号 */
    uint16_t    profile;    /* 下标，指向 tlsfp_profiles[] */
    uint16_t    fp_group;   /* 指纹分组号：相同即指纹一致 */
    uint16_t    src_mask;   /* 来源库位掩码：判同段时要求两端有交集 */
    uint16_t    from_seg;   /* 1 = 由源码段表补齐（报 same-seg 而非 exact） */
} tlsfp_ua_entry;

#define TLSFP_CONF_EXACT     0
#define TLSFP_CONF_SAME_SEG  1
#define TLSFP_CONF_FALLBACK  2

/* UA → profile。生产在 CDN 之后拿不到 ClientHello，只能按 UA 选指纹伪装。
 * **默认严格**：只在 exact / same-seg 命中时返回 profile。拿最近版本的指纹去
 * 冒充另一个版本正是 split-brain 的来源——UA 说 Chrome 78、TLS 却是 Chrome 83
 * 的形态，比完全不伪装更容易被判。要伪装就必须精确。
 *
 * confidence 输出：
 *   0 exact     该主版本有直接对应的 profile
 *   1 same-seg  同一来源库内相邻版本指纹一致，可安全替代
 *   2 fallback  只有跨段的最近版本 —— **返回 NULL**，调用方应放弃伪装
 *  -1 no-brand   表里没有该品牌的任何条目
 *  -2 no-version 有该品牌但没有可用版本
 * 后两者都返回 NULL，分开是为了与 Python 侧的 confidence 命名一致——差分门禁
 * 逐字符比对两侧输出，笼统报一个 none 会让真正的分歧藏在同一个词底下。
 * 判"同段"要求两端出自同一来源库：实测同一版本在不同库里指纹就不同
 * （29 个多库收录版本中 17 个有分歧），跨库比较没有意义。
 *
 * relaxed 非 0 时才在 fallback 档返回最近的 profile，仅供覆盖率分析，勿在生产使用。 */
const tlsfp_profile *tlsfp_lookup_ua(const char *brand, uint16_t version,
                                     int *confidence);
const tlsfp_profile *tlsfp_lookup_ua_ex(const char *brand, uint16_t version,
                                        int *confidence, int relaxed);

/* 按 JA4 查内置 profile；未命中返回 NULL（**不做近似匹配** —— 把陌生指纹
 * 归到最近的已知 profile 会让盲区永远不可见）。 */
const tlsfp_profile *tlsfp_lookup_ja4(const char *ja4);
size_t tlsfp_profile_count(void);
/* 按下标取 profile —— 供差分测试遍历全库，生产用 lookup_* 系列 */
const tlsfp_profile *tlsfp_profile_at(size_t idx);

/* 按 profile 组装一条完整的 TLS record（含 5 字节头），供 cosocket 直接发出。
 *
 * **这是伪装链的最后一环**：查表拿到 profile 之后，得把它变成真正的字节。
 * random 与 session_id 每次连接都必须重新生成 —— 照抄 golden 里那份会让所有
 * 连接的 ClientHello 逐字节相同，比不伪装还容易被判。
 *
 * sni 为 NULL 时保留 golden 里的 server_name 扩展体（多用于自测）；给了域名
 * 则重写该扩展 —— 真实请求必须带正确的 SNI，否则多租户站点直接
 * handshake_failure。
 *
 * 返回写入的字节数；out 空间不足或 profile 缺重建字段时返回 -1。
 * 与库里其他函数一样是**内存进内存出、非阻塞**的，可直接在 nginx worker 里调。 */
/* HTTP/2 连接开场：PREFACE + SETTINGS + WINDOW_UPDATE + PRIORITY。
 * 这一段完全由 profile 决定，与请求无关，所以能一次性构造出来。
 * HEADERS 不在其中 —— 它的内容依赖具体请求，调用方按 h2_pseudo 的顺序自己发。
 * 返回写入字节数；缓冲不够或 profile 无 h2 数据返回 -1。 */
int tlsfp_build_h2_preface(const tlsfp_h2 *h, uint8_t *out, size_t outlen);

/* (品牌, 版本) → h2 记录；没有该版本的 h2 数据时返回 NULL。
 * 版本口径与 tlsfp_lookup_ua 一致：Chromium 系衍生浏览器传内核 Chrome 版本。 */
const tlsfp_h2 *tlsfp_lookup_h2(const char *brand, uint16_t version);

/* 伪头序（缩写形式，如 "m,a,s,p"）。做成函数而不是让调用方直接读结构体字段：
 * Lua 侧的 ffi.cdef 里结构体是截断声明，按偏移读后面的字段会读到垃圾。 */
const char *tlsfp_h2_pseudo(const tlsfp_h2 *h);

/* 请求头的相对顺序，逗号分隔（如 "sec-ch-ua,...,priority"）。
 * 伪装是三层的：TLS、h2 开场、请求头顺序。前两层对了、头按自己的顺序发，
 * 照样能被判。
 * 只回答"这些头之间谁在前" —— 实际发哪些头由调用方决定（导航请求与子资源
 * 请求带的头不同），本库不替它决定。
 * attested 非空时回填 1/0：1 = 该品牌有真机实采背书，0 = 按引擎推断
 * （移动端全是推断，本项目的真机采集都是桌面浏览器）。 */
const char *tlsfp_header_order(const char *brand, int *attested);

int tlsfp_build_client_hello(const tlsfp_profile *p, const char *sni,
                             const uint8_t *random32, const uint8_t *session_id,
                             uint8_t *out, size_t outlen);

#define TLSFP_MAX_ITEMS 64
#define TLSFP_JA4_LEN   40

typedef struct {
    uint16_t items[TLSFP_MAX_ITEMS];
    size_t   len;
} tlsfp_u16list;

typedef struct {
    uint16_t        client_version;
    uint8_t         session_id_len;
    tlsfp_u16list ciphers;          /* 已剔除 GREASE */
    tlsfp_u16list extensions;       /* 已剔除 GREASE，保持线上顺序 */
    tlsfp_u16list curves;
    tlsfp_u16list sig_algs;
    tlsfp_u16list supported_versions;
    int             has_grease;
    int             has_sni;
    char            alpn_first[16];   /* ALPN 第一项，用于 JA4 的 a/b 位 */
    size_t          alpn_count;
} tlsfp_hello;

/* 返回 0 成功，负数为错误码 */
int tlsfp_parse_client_hello(const uint8_t *record, size_t len,
                               tlsfp_hello *out);

/* 计算 JA4；transport 传 't'(TCP) 或 'q'(QUIC)。out 需 >= TLSFP_JA4_LEN */
int tlsfp_ja4(const tlsfp_hello *h, char transport, char *out, size_t outlen);

/* GREASE 判定（RFC 8701）：0x0a0a、0x1a1a … 0xfafa */
static inline int tlsfp_is_grease(uint16_t v) {
    return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff);
}

#endif
