/* 从 stdin 读品牌名，打出 "顺序<TAB>是否实采背书" */
#include "tlsfp.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    char line[64];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0]) continue;
        int att = -1;
        const char *o = tlsfp_header_order(line, &att);
        printf("%s\t%d\n", o ? o : "-", att);
    }
    return 0;
}
