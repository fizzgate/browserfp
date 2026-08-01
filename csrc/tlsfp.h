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

typedef struct {
    const char *brand;      /* chrome / firefox / safari / edge / opera / tor */
    uint16_t    version;    /* 主版本号 */
    uint16_t    profile;    /* 下标，指向 tlsfp_profiles[] */
    uint16_t    fp_group;   /* 指纹分组号：相同即指纹一致 */
    uint16_t    src_mask;   /* 来源库位掩码：判同段时要求两端有交集 */
} tlsfp_ua_entry;

#define TLSFP_CONF_EXACT     0
#define TLSFP_CONF_SAME_SEG  1
#define TLSFP_CONF_FALLBACK  2

/* UA → profile。生产在 CDN 之后拿不到 ClientHello，只能按 UA 选指纹伪装。
 * confidence 输出三档之一，调用方**必须**据此决策：
 *   0 exact     该主版本有直接对应的 profile
 *   1 same-seg  同一来源库内相邻版本指纹一致，可安全替代
 *   2 fallback  跨指纹段取最近 —— 有 split-brain 风险，宜记录并考虑放弃伪装
 * 未命中返回 NULL。判"同段"要求两端出自同一来源库：实测同一版本在不同库里
 * 指纹就不同（29 个多库收录版本中 17 个有分歧），跨库比较没有意义。 */
const tlsfp_profile *tlsfp_lookup_ua(const char *brand, uint16_t version,
                                     int *confidence);

/* 按 JA4 查内置 profile；未命中返回 NULL（**不做近似匹配** —— 把陌生指纹
 * 归到最近的已知 profile 会让盲区永远不可见）。 */
const tlsfp_profile *tlsfp_lookup_ja4(const char *ja4);
size_t tlsfp_profile_count(void);

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
