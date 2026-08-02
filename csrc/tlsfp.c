/* ClientHello 解析与 JA4 计算。行为以 the Python reference (clienthello.py) 为准。 */
#include "tlsfp.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/sha.h>

#include "profiles.inc"

const tlsfp_profile *tlsfp_lookup_ja4(const char *ja4) {
    if (!ja4) return NULL;
    for (size_t i = 0; i < TLSFP_PROFILE_COUNT; i++)
        if (strcmp(tlsfp_profiles[i].ja4, ja4) == 0) return &tlsfp_profiles[i];
    return NULL;
}

size_t tlsfp_profile_count(void) { return TLSFP_PROFILE_COUNT; }

#define ERR_SHORT      -1
#define ERR_NOT_HS     -2
#define ERR_NOT_CH     -3
#define ERR_TRUNCATED  -4

static void list_push(tlsfp_u16list *l, uint16_t v) {
    if (l->len < TLSFP_MAX_ITEMS) l->items[l->len++] = v;
}

#ifdef TLSFP_FUZZ_COUNTERS
unsigned long tlsfp_ext_hits[6];         /* SNI/groups/sigalgs/alpn/versions/其它 */
/* **计数必须放在每个 case 的体内**，不能放在 switch 之前：放前面计的是
   "看见了这个扩展"，而不是"解析体真的执行了" —— 实测把四个 case 的体改空之后，
   放在 switch 前的计数器照样满额，断言完全失灵。这与并发检查那次"比错字段"
   是同一类错误：测了一个相邻但不等价的东西。 */
#define TLSFP_EXT_SEEN(i) (tlsfp_ext_hits[i]++)
#else
#define TLSFP_EXT_SEEN(id) ((void)0)
#endif

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

/* 解析 supported_groups / signature_algorithms 这类「2 字节长度 + u16 数组」的扩展。
 * skip_grease 仅对 curves 有意义：Chrome 会在 supported_groups 里塞 GREASE。 */
static void parse_u16_vector(const uint8_t *body, size_t len,
                             tlsfp_u16list *out, int skip_grease) {
    if (len < 2) return;
    size_t n = rd16(body);
    if (n + 2 > len) n = len - 2;
    for (size_t i = 0; i + 1 < n; i += 2) {
        uint16_t v = rd16(body + 2 + i);
        if (skip_grease && tlsfp_is_grease(v)) continue;
        list_push(out, v);
    }
}

int tlsfp_parse_client_hello(const uint8_t *rec, size_t len,
                               tlsfp_hello *out) {
    memset(out, 0, sizeof(*out));
    if (len < 5) return ERR_SHORT;
    if (rec[0] != 0x16) return ERR_NOT_HS;

    size_t body_len = rd16(rec + 3);
    if (body_len + 5 > len) return ERR_TRUNCATED;
    const uint8_t *b = rec + 5;
    size_t o = 0;

    if (body_len < 4 || b[0] != 0x01) return ERR_NOT_CH;
    o = 4;                                   /* handshake type + 3 字节长度 */
    if (o + 2 + 32 + 1 > body_len) return ERR_TRUNCATED;
    out->client_version = rd16(b + o);
    o += 2 + 32;                             /* version + random */

    out->session_id_len = b[o];
    o += 1 + out->session_id_len;
    if (o + 2 > body_len) return ERR_TRUNCATED;

    size_t cs_len = rd16(b + o);
    o += 2;
    if (o + cs_len > body_len) return ERR_TRUNCATED;
    for (size_t i = 0; i + 1 < cs_len; i += 2) {
        uint16_t c = rd16(b + o + i);
        if (tlsfp_is_grease(c)) { out->has_grease = 1; continue; }
        list_push(&out->ciphers, c);
    }
    o += cs_len;

    if (o >= body_len) return ERR_TRUNCATED;
    o += 1 + b[o];                           /* compression methods */
    if (o + 2 > body_len) return 0;          /* 无扩展，合法 */

    size_t ext_total = rd16(b + o);
    o += 2;
    size_t end = o + ext_total;
    if (end > body_len) end = body_len;

    while (o + 4 <= end) {
        uint16_t eid = rd16(b + o);
        size_t elen = rd16(b + o + 2);
        o += 4;
        if (o + elen > end) break;
        const uint8_t *ebody = b + o;

        if (tlsfp_is_grease(eid)) {
            out->has_grease = 1;
        } else {
            list_push(&out->extensions, eid);
            /* 只在健壮性构建里计数：用来断言变异**真的走到了**每一个分支。
               "没崩"若是因为某个 case 从没被执行过，那是平凡通过 ——
               本项目在别处（h2 的 PRIORITY、sec-ch-ua 的两项分支）栽过同样
               的坑，所以这里把它变成可断言的数字。生产构建里整段消失。 */
            switch (eid) {
            case 0x0000:                     /* server_name */
                TLSFP_EXT_SEEN(0);
                out->has_sni = 1;
                break;
            case 0x000a:                     /* supported_groups */
                TLSFP_EXT_SEEN(1);
                parse_u16_vector(ebody, elen, &out->curves, 1);
                break;
            case 0x000d:                     /* signature_algorithms */
                TLSFP_EXT_SEEN(2);
                parse_u16_vector(ebody, elen, &out->sig_algs, 0);
                break;
            case 0x0010:                     /* ALPN：只取第一项 */
                TLSFP_EXT_SEEN(3);
                if (elen >= 3) {
                    size_t l = ebody[2];
                    if (l > 0 && 3 + l <= elen) {
                        size_t cp = l < sizeof(out->alpn_first) - 1
                                        ? l : sizeof(out->alpn_first) - 1;
                        memcpy(out->alpn_first, ebody + 3, cp);
                        out->alpn_first[cp] = '\0';
                        out->alpn_count = 1;
                    }
                }
                break;
            case 0x002b:                     /* supported_versions */
                TLSFP_EXT_SEEN(4);
                if (elen >= 1) {
                    /* **长度字段要夹到扩展体之内**：n 来自报文（1 字节，
                       最大 255），不夹的话恶意 ClientHello 声称 255 就能读到
                       扩展外、缓冲外。这条是 ASan + 精确大小堆缓冲才暴露出来的
                       —— 之前用固定大小的静态数组喂，越界落在数组内部，
                       看不见。入站识别的输入完全由对方控制，这里是真漏洞。 */
                    size_t n = ebody[0];
                    if (n + 1 > elen) n = elen - 1;
                    for (size_t i = 0; i + 1 < n; i += 2) {
                        uint16_t v = rd16(ebody + 1 + i);
                        if (!tlsfp_is_grease(v))
                            list_push(&out->supported_versions, v);
                    }
                }
                break;
            default:
                break;
            }
        }
        o += elen;
    }
    return 0;
}

static int cmp_u16(const void *a, const void *b) {
    uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;
    return (x > y) - (x < y);
}

/* sha256 前 12 个十六进制字符；空输入按规范记 12 个 '0' */
static void hash12(const char *s, char *out) {
    if (!s || !*s) { memcpy(out, "000000000000", 12); out[12] = '\0'; return; }
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)s, strlen(s), d);
    for (int i = 0; i < 6; i++) sprintf(out + i * 2, "%02x", d[i]);
    out[12] = '\0';
}

int tlsfp_ja4(const tlsfp_hello *h, char transport, char *out, size_t outlen) {
    /* **空指针必须挡在门口**：这些函数跑在 nginx worker 里，解引用一个 NULL
       不是"这个请求失败"，是整个 worker 挂掉。实测 ASan 下
       tlsfp_ja4(NULL, …) 直接 SEGV。 */
    if (!h || !out || outlen == 0) return -1;
    if (outlen < TLSFP_JA4_LEN) return -1;

    /* 版本取 supported_versions 的最大值，没有该扩展则退回 client_version
     * —— 与 Python 侧一致；TLS1.3 客户端的 legacy_version 恒为 0x0303。 */
    uint16_t ver = h->client_version;
    for (size_t i = 0; i < h->supported_versions.len; i++)
        if (h->supported_versions.items[i] > ver) ver = h->supported_versions.items[i];
    const char *vs = ver == 0x0304 ? "13" : ver == 0x0303 ? "12"
                   : ver == 0x0302 ? "11" : ver == 0x0301 ? "10" : "00";

    size_t nc = h->ciphers.len > 99 ? 99 : h->ciphers.len;
    size_t ne = h->extensions.len > 99 ? 99 : h->extensions.len;

    char alpn[3] = {'0', '0', '\0'};
    if (h->alpn_count && h->alpn_first[0]) {
        size_t l = strlen(h->alpn_first);
        alpn[0] = h->alpn_first[0];
        alpn[1] = h->alpn_first[l - 1];
    }

    /* ja4_b：cipher 排序后拼接 */
    uint16_t tmp[TLSFP_MAX_ITEMS];
    memcpy(tmp, h->ciphers.items, h->ciphers.len * sizeof(uint16_t));
    qsort(tmp, h->ciphers.len, sizeof(uint16_t), cmp_u16);
    char buf[TLSFP_MAX_ITEMS * 5 + 1];
    size_t p = 0;
    for (size_t i = 0; i < h->ciphers.len; i++)
        p += sprintf(buf + p, i ? ",%04x" : "%04x", tmp[i]);
    buf[p] = '\0';
    char hb[13];
    hash12(h->ciphers.len ? buf : "", hb);

    /* ja4_c：扩展排序后拼接（**排除 SNI 0x0000 与 ALPN 0x0010**），
     * 再接 "_" 与按原序的 sig_algs。规范如此，两处都容易写错。 */
    size_t m = 0;
    for (size_t i = 0; i < h->extensions.len; i++) {
        uint16_t e = h->extensions.items[i];
        if (e == 0x0000 || e == 0x0010) continue;
        tmp[m++] = e;
    }
    qsort(tmp, m, sizeof(uint16_t), cmp_u16);
    char cbuf[TLSFP_MAX_ITEMS * 10 + 2];
    p = 0;
    for (size_t i = 0; i < m; i++)
        p += sprintf(cbuf + p, i ? ",%04x" : "%04x", tmp[i]);
    if (h->sig_algs.len) {
        p += sprintf(cbuf + p, "_");
        for (size_t i = 0; i < h->sig_algs.len; i++)
            p += sprintf(cbuf + p, i ? ",%04x" : "%04x", h->sig_algs.items[i]);
    }
    cbuf[p] = '\0';
    char hc[13];
    hash12(m ? cbuf : "", hc);

    snprintf(out, outlen, "%c%s%c%02zu%02zu%s_%s_%s",
             transport, vs, h->has_sni ? 'd' : 'i', nc, ne, alpn, hb, hc);
    return 0;
}

/* UA → profile。语义与 Python 侧 oracle/uamap.py 完全一致（由差分门禁保证）。 */
const tlsfp_profile *tlsfp_lookup_ua(const char *brand, uint16_t version,
                                     int *confidence) {
    return tlsfp_lookup_ua_ex(brand, version, confidence, 0);
}

/* Chromium 系衍生浏览器：指纹由内核决定，调用方传进来的 version 必须已经是
   UA 里 Chrome/ 的版本号（oracle/uamap.py 的 parse_ua 就是这么解析的）。
   自家表查不到时回落到内核表 —— Opera 110 的内核是 Chromium 125，而
   opera 表里不会有 125 这个号。

   **必须先剥 -mobile 再判**：移动端品牌是 edge-mobile / opera-mobile，
   拿它去和 "edge" / "opera" 逐字比永远不等，Android 版会一条都认不出来。
   Python 侧的 chromium_engine() 是同一条规则，两边必须一致。 */
static const char *chromium_engine(const char *brand) {
    if (strcmp(brand, "edge") == 0 || strcmp(brand, "opera") == 0)
        return "chrome";
    if (strcmp(brand, "edge-mobile") == 0 || strcmp(brand, "opera-mobile") == 0)
        return "chrome-mobile";
    return NULL;
}

const tlsfp_profile *tlsfp_lookup_ua_ex(const char *brand, uint16_t version,
                                        int *confidence, int relaxed) {
    if (!brand) return NULL;
    /* 区分"表里没有该品牌"与"有品牌但没有可用版本"：两者都返回 NULL，但
       confidence 不同，好与 Python 侧的命名对齐（差分门禁逐字符比对）。 */
    int brand_seen = 0;
    const tlsfp_ua_entry *exact = NULL, *lo = NULL, *hi = NULL;
    const char *engine = chromium_engine(brand);

    /* Python 侧的语义是"把内核表并进自家表后再统一查"（own 覆盖 engine），
       不是"自家表查不到再去内核表查一遍"。两者在 lo/hi 跨表时会分歧：
       自家表只有 100、内核表只有 120，查 110 时合并语义能判 100..120 同段，
       分两趟查则各自都缺一端而弃权。所以这里在**一趟遍历**里同时收两个
       品牌的条目，并在版本号撞车时让自家表优先。 */
    for (size_t i = 0; i < TLSFP_UA_COUNT; i++) {
        const tlsfp_ua_entry *e = &tlsfp_ua_table[i];
        int own = strcmp(e->brand, brand) == 0;
        int eng = engine && strcmp(e->brand, engine) == 0;
        if (!own && !eng) continue;
        if (own) brand_seen = 1;

        /* 撞车时的取舍：**只有**"当前这条不是自家、新来的是自家"才替换。
           写成 `own` 就替换会退化成"取最后一条"，而原实现是命中即返回、
           即"取第一条" —— 同一 (品牌,版本) 在表里出现多次时两者结果不同，
           实测这么写会让 chrome 120/123、firefox 133 等本来正确的版本翻车。 */
        if (e->version == version) {
            if (!exact || (own && strcmp(exact->brand, brand) != 0)) exact = e;
            continue;
        }
        if (e->version < version) {
            if (!lo || e->version > lo->version) lo = e;
            else if (e->version == lo->version && own
                     && strcmp(lo->brand, brand) != 0) lo = e;
        } else {
            if (!hi || e->version < hi->version) hi = e;
            else if (e->version == hi->version && own
                     && strcmp(hi->brand, brand) != 0) hi = e;
        }
    }

    if (exact) {
        /* 由源码段表补齐的条目报 same-seg：它是段内替代而非直接采到的，
           调用方有权知道这个区别。 */
        if (confidence)
            *confidence = exact->from_seg ? TLSFP_CONF_SAME_SEG
                                          : TLSFP_CONF_EXACT;
        return &tlsfp_profiles[exact->profile];
    }

    /* same-seg 需两端指纹同组**且**来源库有交集 —— 跨库的"相同"是巧合，
     * 实测 29 个多库收录的版本里 17 个存在跨库分歧。 */
    if (lo && hi && lo->fp_group == hi->fp_group && (lo->src_mask & hi->src_mask)) {
        if (confidence) *confidence = TLSFP_CONF_SAME_SEG;
        return &tlsfp_profiles[hi->profile];
    }

    const tlsfp_ua_entry *near = hi ? hi : lo;
    if (!near) {
        /* 衍生品牌即便自家表为空，只要内核表在就不该报 no-brand */
        if (confidence) *confidence = (brand_seen || engine) ? -2 : -1;
        return NULL;
    }
    if (confidence) *confidence = TLSFP_CONF_FALLBACK;
    /* 严格模式（默认）：跨指纹段的最近版本**不返回** —— 用它伪装等于制造
     * split-brain。调用方据 confidence 得知存在最近版本，但拿不到 profile。 */
    return relaxed ? &tlsfp_profiles[near->profile] : NULL;
}


const tlsfp_profile *tlsfp_profile_at(size_t idx) {
    return idx < TLSFP_PROFILE_COUNT ? &tlsfp_profiles[idx] : NULL;
}

/* ---- HTTP/2 连接开场组装 ------------------------------------------------- */

/* 定长数组塞不下字符串字面量的结尾 NUL，会触发
   -Wunterminated-string-initialization；用 sizeof-1 的惯用写法回避。 */
static const char H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_PREFACE_LEN (sizeof(H2_PREFACE) - 1)

static size_t put_u24(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v;
    return 3;
}

static size_t put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
    return 4;
}

/* 帧头 9 字节：长度(24) 类型(8) 标志(8) 流 ID(31，最高位保留必须为 0) */
static size_t put_frame_head(uint8_t *p, uint32_t len, uint8_t type,
                             uint8_t flags, uint32_t sid) {
    size_t n = put_u24(p, len);
    p[n++] = type;
    p[n++] = flags;
    n += put_u32(p + n, sid & 0x7FFFFFFFu);
    return n;
}

/* 与 oracle/uach.py 的 PLATFORM_BY_UA 同一张表、同一个顺序。
   顺序有讲究：iPhone/iPad 要排在 Mac 前（iOS 的 UA 里写着 like Mac OS X），
   Android 要排在 Linux 前（Android 的 UA 里也写着 Linux）。 */
static const struct { const char *token; const char *platform; } tlsfp_ua_plat[] = {
    {"iPhone", NULL}, {"iPad", NULL}, {"iPod", NULL},
    {"Android", "\"Android\""},
    {"Windows NT", "\"Windows\""},
    {"Macintosh", "\"macOS\""},
    {"Mac OS X", "\"macOS\""},
    {"X11", "\"Linux\""},
    {"Linux", "\"Linux\""},
};

int tlsfp_ua_platform(const char *ua, const char **platform, const char **mobile) {
    if (!ua) return 0;
    for (size_t i = 0; i < sizeof(tlsfp_ua_plat) / sizeof(tlsfp_ua_plat[0]); i++) {
        if (!strstr(ua, tlsfp_ua_plat[i].token)) continue;
        if (!tlsfp_ua_plat[i].platform) return 0;      /* iOS：不发 UA-CH */
        if (platform) *platform = tlsfp_ua_plat[i].platform;
        if (mobile)
            *mobile = (strcmp(tlsfp_ua_plat[i].platform, "\"Android\"") == 0
                       && strstr(ua, "Mobile")) ? "?1" : "?0";
        return 1;
    }
    return 0;
}

const char *tlsfp_header_value(const char *brand, const char *name) {
    if (!brand || !name) return NULL;
    for (size_t i = 0; i < TLSFP_HV_COUNT; i++) {
        const tlsfp_hv_entry *e = &tlsfp_hv_table[i];
        if (strcmp(e->brand, brand) == 0 && strcmp(e->name, name) == 0)
            return e->value;
    }
    return NULL;
}

const char *tlsfp_sec_ch_ua(const char *brand, uint16_t version) {
    if (!brand) return NULL;
    for (size_t i = 0; i < TLSFP_UACH_COUNT; i++) {
        const tlsfp_uach_entry *e = &tlsfp_uach_table[i];
        if (e->version == version && strcmp(e->brand, brand) == 0)
            return e->value;
    }
    return NULL;
}

const char *tlsfp_header_order(const char *brand, int *attested) {
    if (!brand) return NULL;
    for (size_t i = 0; i < TLSFP_HDR_COUNT; i++) {
        if (strcmp(tlsfp_hdr_table[i].brand, brand) == 0) {
            if (attested) *attested = tlsfp_hdr_table[i].attested;
            return tlsfp_hdr_table[i].order;
        }
    }
    return NULL;
}

/* order_csv 是不是 full 的子序列（保序，可跳过） */
static int tlsfp_is_subseq(const char *order_csv, const char *full) {
    const char *p = order_csv;
    size_t at = 0;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        /* 在 full 里从 at 之后找这一项 */
        int found = 0;
        const char *q = full + at;
        while (*q) {
            const char *c2 = strchr(q, ',');
            size_t l2 = c2 ? (size_t)(c2 - q) : strlen(q);
            if (l2 == len && strncmp(q, p, len) == 0) {
                at = (size_t)(q - full) + l2;
                found = 1;
                break;
            }
            if (!c2) break;
            q = c2 + 1;
        }
        if (!found) return 0;
        if (!comma) break;
        p = comma + 1;
    }
    return 1;
}

const char *tlsfp_engine_of_headers(const char *order_csv, int *n_match) {
    if (n_match) *n_match = 0;
    if (!order_csv || !*order_csv) return NULL;
    const char *hit = NULL;
    int n = 0;
    for (size_t i = 0; i < TLSFP_HDR_COUNT; i++) {
        const char *eng = tlsfp_hdr_table[i].engine;
        /* 每个引擎只算一次 */
        int seen = 0;
        for (size_t j = 0; j < i; j++)
            if (strcmp(tlsfp_hdr_table[j].engine, eng) == 0) { seen = 1; break; }
        if (seen) continue;
        if (tlsfp_is_subseq(order_csv, tlsfp_hdr_table[i].order)) {
            n++;
            hit = eng;
        }
    }
    if (n_match) *n_match = n;
    return n == 1 ? hit : NULL;
}

int tlsfp_coherence(const char *ja4, const char *akamai, const char *order_csv,
                    const char **tls_engine, const char **h2_engine,
                    const char **hdr_engine) {
    const char *t = NULL, *h = NULL, *d = NULL;
    if (ja4) {
        const tlsfp_profile *p = tlsfp_lookup_ja4(ja4);
        if (p && p->engine && *p->engine) t = p->engine;
    }
    if (akamai) {
        const tlsfp_h2 *x = tlsfp_identify_h2(akamai);
        if (x) h = x->engine;
    }
    if (order_csv) d = tlsfp_engine_of_headers(order_csv, NULL);
    if (tls_engine) *tls_engine = t;
    if (h2_engine) *h2_engine = h;
    if (hdr_engine) *hdr_engine = d;

    const char *seen = NULL;
    int n = 0;
    const char *all[3] = {t, h, d};
    for (int i = 0; i < 3; i++) {
        if (!all[i]) continue;
        n++;
        if (!seen) seen = all[i];
        else if (strcmp(seen, all[i]) != 0) return 1;   /* 矛盾 */
    }
    return n >= 2 ? 0 : -1;      /* 至少两层有观测才谈得上一致 */
}

const tlsfp_h2 *tlsfp_identify_h2(const char *akamai) {
    if (!akamai) return NULL;
    for (size_t i = 0; i < TLSFP_H2_RECORD_COUNT; i++)
        if (strcmp(tlsfp_h2_records[i].akamai, akamai) == 0)
            return &tlsfp_h2_records[i];
    return NULL;
}

const char *tlsfp_h2_pseudo(const tlsfp_h2 *h) {
    return h ? h->pseudo : NULL;
}

/* (品牌, 版本) → h2 记录。表按 (品牌, 版本) 建，与 TLS 的 profile 表分开 ——
   h2 与 TLS 的变更点不是同一批，绑在一起就会出现"TLS 对、h2 错"。 */
const tlsfp_h2 *tlsfp_lookup_h2(const char *brand, uint16_t version) {
    if (!brand) return NULL;
    for (size_t i = 0; i < TLSFP_H2_COUNT; i++) {
        const tlsfp_h2_entry *e = &tlsfp_h2_table[i];
        if (e->version == version && strcmp(e->brand, brand) == 0)
            return &tlsfp_h2_records[e->rec];
    }
    return NULL;
}

int tlsfp_build_h2_preface(const tlsfp_h2 *p, uint8_t *out, size_t outlen) {
    if (!p || !out) return -1;
    /* 查不到 h2 数据时调用方拿到的是 NULL，走不到这里；这里再挡一层空记录，
       免得凭空造出一个不属于任何浏览器的开场。 */
    if (!p->n_settings && !p->window && !p->n_prio) return -1;

    size_t need = H2_PREFACE_LEN
                + 9 + p->n_settings * 6
                + (p->window ? 9 + 4 : 0)
                + p->n_prio * (9 + 5);
    if (outlen < need) return -1;

    size_t o = 0;
    memcpy(out + o, H2_PREFACE, H2_PREFACE_LEN);
    o += H2_PREFACE_LEN;

    /* SETTINGS：每项 6 字节（id 16 位 + value 32 位），流 ID 恒为 0。
       即便一项都没有也要发这个空帧 —— 协议要求 PREFACE 之后紧跟 SETTINGS。 */
    o += put_frame_head(out + o, (uint32_t)(p->n_settings * 6), 4, 0, 0);
    for (size_t i = 0; i < p->n_settings; i++) {
        uint32_t id = p->settings[i * 2], val = p->settings[i * 2 + 1];
        out[o++] = (uint8_t)(id >> 8);
        out[o++] = (uint8_t)id;
        o += put_u32(out + o, val);
    }

    /* 连接级 WINDOW_UPDATE（流 ID 0）。0 表示这个浏览器不发，不能补一个默认值。 */
    if (p->window) {
        o += put_frame_head(out + o, 4, 8, 0, 0);
        o += put_u32(out + o, p->window & 0x7FFFFFFFu);
    }

    /* PRIORITY：Firefox 会在开场发一组优先级树，Chrome 系一般不发。
       载荷 5 字节 = 依赖流(31) + 独占位(1) + 权重(8)。
       线上权重比实际值小 1（RFC 7540 §6.3），而 h2probe 解析时 +1 还原，
       所以这里必须减回去 —— 不减会让权重逐轮漂移。 */
    for (size_t i = 0; i < p->n_prio; i++) {
        uint32_t sid = p->prio[i * 4], dep = p->prio[i * 4 + 1];
        uint32_t excl = p->prio[i * 4 + 2], wt = p->prio[i * 4 + 3];
        o += put_frame_head(out + o, 5, 2, 0, sid);
        o += put_u32(out + o, (dep & 0x7FFFFFFFu) | (excl ? 0x80000000u : 0u));
        out[o++] = (uint8_t)(wt ? wt - 1 : 0);
    }
    return (int)o;
}

/* ---- ClientHello 组装 ---------------------------------------------------- */

static size_t put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return 2;
}

int tlsfp_build_client_hello(const tlsfp_profile *p, const char *sni,
                             const uint8_t *random32, const uint8_t *session_id,
                             uint8_t *out, size_t outlen) {
    if (!p || !out || !p->rawciph || !p->rawext) return -1;
    if (!random32 || (p->session_id_len && !session_id)) return -1;

    /* 先拼扩展块，因为握手体长度要回填 */
    uint8_t ext[8192];
    size_t e = 0;

    /* **库里的 golden 绝大多数采自无 SNI 场景**（81 条里只有 2 条带
       server_name），所以不能只做"替换"——那样 sni 参数会被静默忽略，构造出
       的握手压根没有 SNI，多租户站点直接 handshake_failure。需要在正确位置
       **插入**：真实浏览器把 server_name 排在首个 GREASE 之后、其余扩展之前。 */
    int sni_done = 0;
    for (size_t i = 0; i < p->n_rawext; i++) {
        if (p->rawext[i] == 0x0000) { sni_done = 1; break; }
    }
    size_t sni_at = 0;
    if (!sni_done && sni) {
        /* 首个 GREASE 之后；没有 GREASE 就放最前 */
        if (p->n_rawext && tlsfp_is_grease(p->rawext[0])) sni_at = 1;
    }

    for (size_t i = 0; i < p->n_rawext; i++) {
        if (!sni_done && sni && i == sni_at) {
            size_t n = strlen(sni);
            if (n > 4096 || e + 9 + n > sizeof(ext)) return -1;
            e += put_u16(ext + e, 0x0000);
            e += put_u16(ext + e, (uint16_t)(n + 5));
            e += put_u16(ext + e, (uint16_t)(n + 3));
            ext[e++] = 0x00;
            e += put_u16(ext + e, (uint16_t)n);
            memcpy(ext + e, sni, n); e += n;
            sni_done = 1;
        }
        uint16_t id = p->rawext[i];
        const uint8_t *body = p->extblob + p->extoff[i];
        uint16_t blen = p->extlen[i];

        if (id == 0x0000 && sni) {
            /* 重写 SNI：真实请求必须带正确域名，否则多租户站点直接拒绝。
               结构 = list_len(2) + type(1) + name_len(2) + name */
            size_t n = strlen(sni);
            if (n > 4096 || e + 9 + n > sizeof(ext)) return -1;
            e += put_u16(ext + e, id);
            e += put_u16(ext + e, (uint16_t)(n + 5));
            e += put_u16(ext + e, (uint16_t)(n + 3));
            ext[e++] = 0x00;
            e += put_u16(ext + e, (uint16_t)n);
            memcpy(ext + e, sni, n); e += n;
            continue;
        }
        if (e + 4 + blen > sizeof(ext)) return -1;
        e += put_u16(ext + e, id);
        e += put_u16(ext + e, blen);
        if (blen) { memcpy(ext + e, body, blen); e += blen; }
    }

    size_t body_len = 2 + 32 + 1 + p->session_id_len
                    + 2 + p->n_rawciph * 2 + 2 + 2 + e;
    size_t total = 5 + 4 + body_len;
    if (total > outlen) return -1;

    size_t o = 0;
    out[o++] = 0x16;                              /* handshake */
    o += put_u16(out + o, 0x0301);                /* record 版本恒 TLS1.0 */
    o += put_u16(out + o, (uint16_t)(4 + body_len));
    out[o++] = 0x01;                              /* client_hello */
    out[o++] = (uint8_t)(body_len >> 16);
    o += put_u16(out + o, (uint16_t)body_len);
    o += put_u16(out + o, p->client_version);
    memcpy(out + o, random32, 32); o += 32;
    out[o++] = (uint8_t)p->session_id_len;
    if (p->session_id_len) {
        memcpy(out + o, session_id, p->session_id_len);
        o += p->session_id_len;
    }
    o += put_u16(out + o, (uint16_t)(p->n_rawciph * 2));
    for (size_t i = 0; i < p->n_rawciph; i++) o += put_u16(out + o, p->rawciph[i]);
    out[o++] = 0x01;                              /* compression 长度 */
    out[o++] = 0x00;                              /* null */
    o += put_u16(out + o, (uint16_t)e);
    memcpy(out + o, ext, e); o += e;
    return (int)o;
}
