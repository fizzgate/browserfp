/* 从 stdin 读 UA（每行一条），打出 "platform<TAB>mobile"，没有则 "-\t-" */
#include "tlsfp.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    char line[1024];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0]) continue;
        const char *p = NULL, *m = NULL;
        if (tlsfp_ua_platform(line, &p, &m)) printf("%s\t%s\n", p, m);
        else printf("-\t-\n");
    }
    return 0;
}
