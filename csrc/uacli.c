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
        /* profile 为 NULL 时 confidence 仍要如实上报：fallback（存在跨段的
           最近版本，只是不许用）与 none（该品牌根本没有可比版本）是两件事，
           前者进补录清单、后者不进。合并成 "none" 会让清单凭空少掉一批。 */
        const char *cname = (conf >= 0 && conf <= 2) ? names[conf]
                          : (conf == -2) ? "no-version"
                          : (conf == -1) ? "no-brand" : "none";
        printf("%s\t%s\n", p ? p->id : "-", cname);
    }
    return 0;
}
