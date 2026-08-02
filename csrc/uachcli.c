/* 从 stdin 读 "品牌 版本"，打出 sec-ch-ua（没有则打 "-"） */
#include "tlsfp.h"
#include <stdio.h>
int main(void) {
    char line[128], brand[64];
    unsigned ver;
    while (fgets(line, sizeof(line), stdin)) {
        if (sscanf(line, "%63s %u", brand, &ver) != 2) continue;
        const char *v = tlsfp_sec_ch_ua(brand, (uint16_t)ver);
        printf("%s\n", v ? v : "-");
    }
    return 0;
}
