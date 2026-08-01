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

const tlsfp_profile *tlsfp_lookup_ua_ex(const char *brand, uint16_t version,
                                        int *confidence, int relaxed) {
    if (!brand) return NULL;
    const tlsfp_ua_entry *lo = NULL, *hi = NULL;

    for (size_t i = 0; i < TLSFP_UA_COUNT; i++) {
        const tlsfp_ua_entry *e = &tlsfp_ua_table[i];
        if (strcmp(e->brand, brand) != 0) continue;
        if (e->version == version) {
            if (confidence) *confidence = TLSFP_CONF_EXACT;
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

    const tlsfp_ua_entry *near = hi ? hi : lo;
    if (!near) return NULL;
    if (confidence) *confidence = TLSFP_CONF_FALLBACK;
    /* 严格模式（默认）：跨指纹段的最近版本**不返回** —— 用它伪装等于制造
     * split-brain。调用方据 confidence 得知存在最近版本，但拿不到 profile。 */
    return relaxed ? &tlsfp_profiles[near->profile] : NULL;
}
