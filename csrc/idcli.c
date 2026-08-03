/* 从 stdin 读 akamai 指纹，打出 "engine<TAB>lo<TAB>hi"，认不出打 "-" */
#include "browserfp.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    char line[512];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0]) continue;
        const browserfp_h2 *h = browserfp_identify_h2(line);
        if (h) printf("%s\t%u\t%u\n", h->engine, h->ver_lo, h->ver_hi);
        else printf("-\n");
    }
    return 0;
}
