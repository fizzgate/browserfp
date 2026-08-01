/* 从 stdin 读 profile 下标，把构造出的 HTTP/2 连接开场以 hex 打到 stdout。
   另在 tab 后附上 h2_pseudo —— 伪头序不在开场字节里（它属于 HEADERS 帧），
   但它同样是 profile 的一部分，验证时要一起比。 */
#include "tlsfp.h"
#include <stdio.h>
int main(void) {
    char line[64];
    uint8_t out[8192];
    while (fgets(line, sizeof(line), stdin)) {
        int idx = -1;
        if (sscanf(line, "%d", &idx) != 1) continue;
        if (idx < 0 || (size_t)idx >= tlsfp_profile_count()) { printf("-\t-\n"); continue; }
        const tlsfp_profile *p = tlsfp_profile_at((size_t)idx);
        int n = tlsfp_build_h2_preface(p, out, sizeof(out));
        if (n < 0) { printf("-\t-\n"); continue; }
        for (int k = 0; k < n; k++) printf("%02x", out[k]);
        printf("\t%s\n", p->h2_pseudo ? p->h2_pseudo : "");
    }
    return 0;
}
