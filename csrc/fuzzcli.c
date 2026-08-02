/* 把每个公开入口用恶劣输入喂一遍：NULL、空串、超长串、越界下标、零缓冲、
   缓冲刚好差一字节。这些函数跑在 nginx worker 里 —— 一次越界就是整个 worker
   挂掉，而不是一个请求失败。
   本程序不判断"结果对不对"，只判断"活着回来且不越界"；越界由 ASan 报。 */
#include "tlsfp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 喂给解析器的缓冲**必须按实际长度堆分配**，不能用固定大小的静态数组：
   越界读若落在"逻辑长度之外、物理数组之内"，ASan 根本看不见 —— 实测就是
   这么漏掉的：去掉 tlsfp_parse_client_hello 里那句 record 长度检查，静态数组
   版本照样全绿，换成精确大小的堆缓冲立刻报 heap-buffer-overflow。 */
static int feed_parser(const uint8_t *data, size_t n, tlsfp_hello *out) {
    uint8_t *exact = (uint8_t *)malloc(n ? n : 1);
    if (!exact) return -1;
    if (n) memcpy(exact, data, n);
    int r = tlsfp_parse_client_hello(exact, n, out);
    free(exact);
    return r;
}


static int calls = 0;
#define CALL(expr) do { (void)(expr); calls++; } while (0)

int main(void) {
    static char big[70000];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = 0;
    uint8_t out[64];
    const char *p = NULL, *m = NULL;
    int conf = 0, natt = 0;

    const char *strs[] = {NULL, "", " ", "chrome", big, "\xff\xfe", "a,b,c",
                          ",,,", "chrome-mobile"};
    const size_t NS = sizeof(strs) / sizeof(strs[0]);
    const uint16_t vers[] = {0, 1, 151, 65535};

    for (size_t i = 0; i < NS; i++) {
        for (size_t v = 0; v < 4; v++) {
            CALL(tlsfp_lookup_ua(strs[i], vers[v], &conf));
            CALL(tlsfp_lookup_ua(strs[i], vers[v], NULL));
            CALL(tlsfp_lookup_ua_ex(strs[i], vers[v], &conf, 1));
            CALL(tlsfp_lookup_h2(strs[i], vers[v]));
            CALL(tlsfp_sec_ch_ua(strs[i], vers[v]));
        }
        CALL(tlsfp_lookup_ja4(strs[i]));
        CALL(tlsfp_identify_h2(strs[i]));
        CALL(tlsfp_engine_of_headers(strs[i], &natt));
        CALL(tlsfp_engine_of_headers(strs[i], NULL));
        CALL(tlsfp_header_order(strs[i], &natt));
        CALL(tlsfp_header_order(strs[i], NULL));
        CALL(tlsfp_ua_platform(strs[i], &p, &m));
        CALL(tlsfp_ua_platform(strs[i], NULL, NULL));
        for (size_t j = 0; j < NS; j++)
            CALL(tlsfp_header_value(strs[i], strs[j]));
        for (size_t j = 0; j < NS; j++)
            CALL(tlsfp_coherence(strs[i], strs[j], strs[(i + j) % NS],
                                 &p, &m, &p));
    }

    /* 越界与边界下标 */
    CALL(tlsfp_profile_at((size_t)-1));
    CALL(tlsfp_profile_at(tlsfp_profile_count()));
    CALL(tlsfp_profile_at(tlsfp_profile_count() + 1000));

    /* 构造器：NULL、零缓冲、差一字节的缓冲 */
    for (size_t i = 0; i < tlsfp_profile_count(); i++) {
        const tlsfp_profile *prof = tlsfp_profile_at(i);
        uint8_t rnd[32] = {0}, sid[32] = {0};
        CALL(tlsfp_build_client_hello(NULL, "x", rnd, sid, out, sizeof(out)));
        CALL(tlsfp_build_client_hello(prof, NULL, rnd, sid, out, 0));
        CALL(tlsfp_build_client_hello(prof, "x", NULL, sid, out, sizeof(out)));
        CALL(tlsfp_build_client_hello(prof, big, rnd, sid, out, sizeof(out)));
        CALL(tlsfp_build_client_hello(prof, "x", rnd, sid, NULL, 99999));
    }
    for (size_t i = 0; i < 4; i++) {
        const tlsfp_h2 *h = tlsfp_lookup_h2("chrome", (uint16_t)(150 + i));
        CALL(tlsfp_build_h2_preface(h, out, sizeof(out)));   /* 缓冲太小 */
        CALL(tlsfp_build_h2_preface(h, out, 0));
        CALL(tlsfp_build_h2_preface(NULL, out, sizeof(out)));
        CALL(tlsfp_h2_pseudo(h));
        CALL(tlsfp_h2_pseudo(NULL));
    }

    /* 解析器：截断的、全零的、超长的 record */
    tlsfp_hello hello;
    static uint8_t rec[70000];
    memset(rec, 0, sizeof(rec));
    CALL(tlsfp_parse_client_hello(NULL, 0, &hello));
    CALL(feed_parser(rec, 0, &hello));
    for (size_t n = 1; n < 300; n++)
        CALL(feed_parser(rec, n, &hello));
    rec[0] = 0x16; rec[1] = 3; rec[2] = 1; rec[3] = 0xff; rec[4] = 0xff;
    for (size_t n = 5; n < 400; n++)
        CALL(feed_parser(rec, n, &hello));
    CALL(feed_parser(rec, sizeof(rec), &hello));

    /* **结构化变异**：拿真实 ClientHello 逐字节改。全零与截断只能覆盖
       "一眼就不合法"的输入，而真实攻击面是"看起来合法、内部长度撒谎"的记录 ——
       扩展块声称 60000 字节、cipher 列表长度是奇数、会话 ID 超过 32 字节
       这类，解析器要靠自己的边界检查挡住。 */
    {
        static uint8_t base[16384];
        uint8_t rnd2[32] = {1}, sid2[32] = {2};
        for (size_t i = 0; i < tlsfp_profile_count(); i++) {
            const tlsfp_profile *prof = tlsfp_profile_at(i);
            int n = tlsfp_build_client_hello(prof, "a.io", rnd2, sid2,
                                             base, sizeof(base));
            if (n <= 0) continue;
            /* 每条 profile 取若干个位点，各试几种恶意值 */
            const uint8_t vals[] = {0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff};
            /* **每个位点都要试**。原来 off += 7 只覆盖 1/7 的位置 ——
               长度字段往往就那么一两个字节，跳着走很容易正好跨过去。
               全覆盖也只多花零点几秒。 */
            for (size_t off = 0; off < (size_t)n; off++) {
                for (size_t v = 0; v < sizeof(vals); v++) {
                    static uint8_t mut[16384];
                    memcpy(mut, base, (size_t)n);
                    mut[off] = vals[v];
                    CALL(feed_parser(mut, (size_t)n, &hello));
                    /* 同时试"长度字段说得比实际多/少"的情况 */
                    if ((size_t)n > 8) {
                        CALL(feed_parser(mut, (size_t)n - 1, &hello));
                        CALL(feed_parser(mut, (size_t)n / 2, &hello));
                    }
                    /* **双字节变异**：长度字段是 2 字节的，只改一个字节
                       常常还落在合法范围里；真实攻击也不会只动一处。
                       与相邻字节、以及固定几个偏移各配一次。 */
                    if (off + 1 < (size_t)n) {
                        uint8_t save = mut[off + 1];
                        mut[off + 1] = vals[(v + 3) % sizeof(vals)];
                        CALL(feed_parser(mut, (size_t)n, &hello));
                        mut[off + 1] = save;
                    }
                }
            }
        }
    }

    char ja4[64];
    memset(&hello, 0, sizeof(hello));
    CALL(tlsfp_ja4(&hello, 't', ja4, sizeof(ja4)));
    CALL(tlsfp_ja4(&hello, 't', ja4, 0));
    CALL(tlsfp_ja4(&hello, 'q', ja4, 1));
    CALL(tlsfp_ja4(NULL, 't', ja4, sizeof(ja4)));

    printf("%d\n", calls);
    return 0;
}
