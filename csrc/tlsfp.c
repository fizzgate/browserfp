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
            switch (eid) {
            case 0x0000:                     /* server_name */
                out->has_sni = 1;
                break;
            case 0x000a:                     /* supported_groups */
                parse_u16_vector(ebody, elen, &out->curves, 1);
                break;
            case 0x000d:                     /* signature_algorithms */
                parse_u16_vector(ebody, elen, &out->sig_algs, 0);
                break;
            case 0x0010:                     /* ALPN：只取第一项 */
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
                if (elen >= 1) {
                    size_t n = ebody[0];
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
   自家表查不到时回落到 chrome 表 —— Opera 110 的内核是 Chromium 125，而
   opera 表里不会有 125 这个号。 */
static int is_chromium_derived(const char *brand) {
    return strcmp(brand, "edge") == 0 || strcmp(brand, "opera") == 0;
}

const tlsfp_profile *tlsfp_lookup_ua_ex(const char *brand, uint16_t version,
                                        int *confidence, int relaxed) {
    if (!brand) return NULL;
    /* 区分"表里没有该品牌"与"有品牌但没有可用版本"：两者都返回 NULL，但
       confidence 不同，好与 Python 侧的命名对齐（差分门禁逐字符比对）。 */
    int brand_seen = 0;
    const tlsfp_ua_entry *lo = NULL, *hi = NULL;

    for (size_t i = 0; i < TLSFP_UA_COUNT; i++) {
        const tlsfp_ua_entry *e = &tlsfp_ua_table[i];
        if (strcmp(e->brand, brand) != 0) continue;
        brand_seen = 1;
        if (e->version == version) {
            /* 由源码段表补齐的条目报 same-seg：它是段内替代而非直接采到的，
               调用方有权知道这个区别。 */
            if (confidence)
                *confidence = e->from_seg ? TLSFP_CONF_SAME_SEG
                                          : TLSFP_CONF_EXACT;
            return &tlsfp_profiles[e->profile];
        }
        if (e->version < version && (!lo || e->version > lo->version)) lo = e;
        if (e->version > version && (!hi || e->version < hi->version)) hi = e;
    }

    /* same-seg 需两端指纹同组**且**来源库有交集 —— 跨库的"相同"是巧合，
     * 实测 29 个多库收录的版本里 17 个存在跨库分歧。 */
    if (lo && hi && lo->fp_group == hi->fp_group && (lo->src_mask & hi->src_mask)) {
        if (confidence) *confidence = TLSFP_CONF_SAME_SEG;
        return &tlsfp_profiles[hi->profile];
    }

    /* 自家表没命中：Chromium 系衍生浏览器回落到 chrome 表再查一次。放在这里
       而不是入口，是为了让自家实采到的条目优先于内核推断。 */
    if (is_chromium_derived(brand)) {
        for (size_t i = 0; i < TLSFP_UA_COUNT; i++) {
            const tlsfp_ua_entry *e = &tlsfp_ua_table[i];
            if (strcmp(e->brand, "chrome") != 0) continue;
            if (e->version == version) {
                if (confidence)
                    *confidence = e->from_seg ? TLSFP_CONF_SAME_SEG
                                              : TLSFP_CONF_EXACT;
                return &tlsfp_profiles[e->profile];
            }
        }
    }

    const tlsfp_ua_entry *near = hi ? hi : lo;
    if (!near) {
        if (confidence) *confidence = brand_seen ? -2 : -1;
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
