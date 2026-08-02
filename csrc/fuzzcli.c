/* 把每个公开入口用恶劣输入喂一遍：NULL、空串、超长串、越界下标、零缓冲、
   缓冲刚好差一字节。这些函数跑在 nginx worker 里 —— 一次越界就是整个 worker
   挂掉，而不是一个请求失败。
   本程序不判断"结果对不对"，只判断"活着回来且不越界"；越界由 ASan 报。 */
#include "tlsfp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    CALL(tlsfp_parse_client_hello(rec, 0, &hello));
    for (size_t n = 1; n < 300; n++)
        CALL(tlsfp_parse_client_hello(rec, n, &hello));
    rec[0] = 0x16; rec[1] = 3; rec[2] = 1; rec[3] = 0xff; rec[4] = 0xff;
    for (size_t n = 5; n < 400; n++)
        CALL(tlsfp_parse_client_hello(rec, n, &hello));
    CALL(tlsfp_parse_client_hello(rec, sizeof(rec), &hello));

    char ja4[64];
    memset(&hello, 0, sizeof(hello));
    CALL(tlsfp_ja4(&hello, 't', ja4, sizeof(ja4)));
    CALL(tlsfp_ja4(&hello, 't', ja4, 0));
    CALL(tlsfp_ja4(&hello, 'q', ja4, 1));
    CALL(tlsfp_ja4(NULL, 't', ja4, sizeof(ja4)));

    printf("%d\n", calls);
    return 0;
}
