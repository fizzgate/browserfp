/* 从 stdin 读 "品牌 版本"，把构造出的 HTTP/2 连接开场以 hex 打到 stdout。
   另在 tab 后附上伪头序 —— 它不在开场字节里（属于 HEADERS 帧），但同样是
   该版本 h2 指纹的一部分，验证时要一起比。
   查不到 h2 数据时打 "-\t-"，调用方据此走 HTTP/1.1，而不是发一个不属于任何
   浏览器的开场。 */
#include "tlsfp.h"
#include <stdio.h>
int main(void) {
    char line[128], brand[64];
    unsigned ver;
    uint8_t out[8192];
    while (fgets(line, sizeof(line), stdin)) {
        if (sscanf(line, "%63s %u", brand, &ver) != 2) continue;
        const tlsfp_h2 *h = tlsfp_lookup_h2(brand, (uint16_t)ver);
        int n = h ? tlsfp_build_h2_preface(h, out, sizeof(out)) : -1;
        if (n < 0) { printf("-\t-\n"); continue; }
        for (int k = 0; k < n; k++) printf("%02x", out[k]);
        printf("\t%s\n", tlsfp_h2_pseudo(h) ? tlsfp_h2_pseudo(h) : "");
    }
    return 0;
}
