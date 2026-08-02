/* 从 stdin 读 "<profile_id>\t<sni>\t<group>:<pubhex>,…"（后两段可空），
   按 profile 重建 ClientHello 并把注入的 key_share 公钥用上，hex 打到 stdout。
   构造失败（含形状不符、分组不存在）打 "ERR"。

   按 id 而不是下标取 profile：下标会随注册表增删漂移，而门禁是按 id 遍历的。 */
#include "tlsfp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KS 8
#define MAX_PUB 4096

static int hex2bin(const char *h, uint8_t *out, size_t cap, size_t *n) {
    size_t len = strlen(h);
    if (len % 2 || len / 2 > cap) return -1;
    for (size_t i = 0; i < len; i += 2) {
        unsigned v;
        if (sscanf(h + i, "%2x", &v) != 1) return -1;
        out[i / 2] = (uint8_t)v;
    }
    *n = len / 2;
    return 0;
}

static const tlsfp_profile *by_id(const char *id) {
    for (size_t i = 0; i < tlsfp_profile_count(); i++) {
        const tlsfp_profile *p = tlsfp_profile_at(i);
        if (p && p->id && strcmp(p->id, id) == 0) return p;
    }
    return NULL;
}

int main(void) {
    static char line[65536];
    static uint8_t out[16384], pubs[MAX_KS][MAX_PUB];
    uint8_t rnd[32], sid[32];

    /* **每行取新鲜随机**。库内没有 RNG，出网口径下 GREASE / ECH 长度全部从
       random32 派生 —— 写死 random32 就等于把随机性关掉，取样时看到的会是
       "C 侧不变"，而那是取样装置的问题不是实现的问题。生产每连接都给新的。 */
    FILE *ur = fopen("/dev/urandom", "rb");
    if (!ur) return 1;

    while (fgets(line, sizeof(line), stdin)) {
        if (fread(rnd, 1, 32, ur) != 32 || fread(sid, 1, 32, ur) != 32) return 1;
        line[strcspn(line, "\r\n")] = 0;
        char *tab = strchr(line, '\t');
        if (!tab) { printf("ERR\n"); fflush(stdout); continue; }
        *tab = 0;
        /* id 前缀 "!" = 出网口径（ECH 长度随机、padding 按长度重算）；
           不带前缀 = 重建口径。只加一个字符，省得再动一次输入契约 ——
           上次动它就漏了调用方，test_keyshare 的 C 侧当场 70 条全失败。 */
        /* **不带前缀 = 出网口径**，与 C/Python 的默认一致；"=" 前缀才是重建。
           原来反着定（不带前缀=重建），与库的默认不一致 —— 同一套代码里两种
           默认，迟早有人按另一边的直觉调错。 */
        unsigned flags = 0;
        char *idp = line;
        if (*idp == '=') { flags = TLSFP_BUILD_VERBATIM; idp++; }
        const tlsfp_profile *p = by_id(idp);
        if (!p) { printf("ERR\n"); fflush(stdout); continue; }
        char *sni = tab + 1;
        char *tab2 = strchr(sni, '\t');
        if (!tab2) { printf("ERR\n"); fflush(stdout); continue; }
        *tab2 = 0;
        if (!*sni) sni = NULL;

        tlsfp_keyshare ks[MAX_KS];
        size_t n_ks = 0;
        char *spec = tab2 + 1, *tok = strtok(spec, ",");
        int bad = 0;
        while (tok && n_ks < MAX_KS) {
            char *colon = strchr(tok, ':');
            if (!colon) { bad = 1; break; }
            *colon = 0;
            size_t plen = 0;
            if (hex2bin(colon + 1, pubs[n_ks], MAX_PUB, &plen) != 0) { bad = 1; break; }
            ks[n_ks].group = (uint16_t)strtoul(tok, NULL, 16);
            ks[n_ks].pub = pubs[n_ks];
            ks[n_ks].pub_len = plen;
            n_ks++;
            tok = strtok(NULL, ",");
        }
        if (bad) { printf("ERR\n"); fflush(stdout); continue; }

        int n = tlsfp_build_client_hello_ex(p, sni, rnd, sid,
                                            n_ks ? ks : NULL, n_ks, flags,
                                            out, sizeof(out));
        if (n < 0) { printf("ERR\n"); fflush(stdout); continue; }
        for (int k = 0; k < n; k++) printf("%02x", out[k]);
        printf("\n");
        fflush(stdout);
    }
    return 0;
}
