/* 从 stdin 读 "ja4<TAB>akamai<TAB>order_csv"（空段用 -），打出
   "verdict<TAB>tls<TAB>h2<TAB>hdr" */
#include "tlsfp.h"
#include <stdio.h>
#include <string.h>
/* **分隔符必须用 TAB 不能用竖线**：akamai 指纹本身就是竖线分段的
   （settings|window|priority|pseudo），拿竖线切会把它切碎，表现是 h2 那层
   恒认不出、整批判 unknown。 */
static char *cut(char **p) {
    char *s = *p, *bar = strchr(s, '\t');
    if (bar) { *bar = 0; *p = bar + 1; } else *p = s + strlen(s);
    return (strcmp(s, "-") == 0 || !*s) ? NULL : s;
}
int main(void) {
    char line[2048];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0]) continue;
        char *p = line;
        char *ja4 = cut(&p), *ak = cut(&p), *od = cut(&p);
        const char *t = NULL, *h = NULL, *d = NULL;
        int r = tlsfp_coherence(ja4, ak, od, &t, &h, &d);
        printf("%s\t%s\t%s\t%s\n",
               r == 0 ? "ok" : r == 1 ? "mismatch" : "unknown",
               t ? t : "-", h ? h : "-", d ? d : "-");
    }
    return 0;
}
