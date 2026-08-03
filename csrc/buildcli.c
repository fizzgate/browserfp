/* 从 stdin 读 profile 下标，把构造出的 ClientHello 以 hex 打到 stdout */
#include "tlsfp.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    /* 行缓冲：错误分支用 continue 跳过了 fflush，缓冲住会让交互式调用方挂死。 */
    setvbuf(stdout, NULL, _IOLBF, 0);
    char line[64];
    uint8_t out[16384], rnd[32], sid[32];
    for (int i = 0; i < 32; i++) { rnd[i] = (uint8_t)(i * 7 + 1); sid[i] = (uint8_t)(i * 3 + 2); }
    while (fgets(line, sizeof(line), stdin)) {
        /* 行首带 '=' 表示走**出网口径**（会打乱扩展顺序），否则照采集那条重建。
           三方差分要能比"打乱之后"，否则 C 侧的置换没有任何判据看着。
           这段必须在第一次 sscanf 之前 —— "=0" 用 %d 解析会失败，直接 continue，
           于是那一行悄悄没有任何输出（第一版就是这么错的）。 */
        const char *q = line;
        while (*q == ' ' || *q == '\t') q++;
        unsigned flags = TLSFP_BUILD_VERBATIM;
        if (*q == '=') { flags = 0; q++; }
        /* 既接下标也接 profile id。**下标不能跨表用**：C 表的顺序与
           spec/profiles.json 的数组顺序不同（生成时会去重排序），拿 json 的
           下标喂进来会安静地取到另一条 profile —— 第一版就是这么比出"四条
           全不一致"的。 */
        int idx = -1;
        if (sscanf(q, "%d", &idx) != 1) {
            char id[128];
            size_t n = 0;
            while (q[n] && q[n] != '\n' && n + 1 < sizeof(id)) { id[n] = q[n]; n++; }
            id[n] = 0;
            while (n && (id[n-1] == ' ' || id[n-1] == '\r')) id[--n] = 0;
            for (size_t k = 0; k < tlsfp_profile_count(); k++) {
                if (!strcmp(tlsfp_profile_at(k)->id, id)) { idx = (int)k; break; }
            }
            if (idx < 0) { printf("-\n"); continue; }
        }
        if (idx < 0 || (size_t)idx >= tlsfp_profile_count()) { printf("-\n"); continue; }
        const tlsfp_profile *p = tlsfp_profile_at((size_t)idx);
        int n = tlsfp_build_client_hello_ex(p, NULL, rnd, sid, NULL, 0,
                                    flags, out, sizeof(out));
        if (n < 0) { printf("-\n"); continue; }
        for (int k = 0; k < n; k++) printf("%02x", out[k]);
        printf("\n");
    }
    return 0;
}
