/* 读 "brand<TAB>version" 每行一条，输出 "profile_id<TAB>confidence"。
   供与 Python 侧 oracle/uamap.py 做差分。 */
#include "tlsfp.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        char brand[32]; unsigned ver;
        if (sscanf(line, "%31s %u", brand, &ver) != 2) continue;
        int conf = -1;
        const tlsfp_profile *p = tlsfp_lookup_ua(brand, (uint16_t)ver, &conf);
        static const char *names[] = {"exact", "same-seg", "fallback"};
        if (p) printf("%s\t%s\n", p->id, conf >= 0 && conf <= 2 ? names[conf] : "?");
        else   printf("-\tnone\n");
    }
    return 0;
}
