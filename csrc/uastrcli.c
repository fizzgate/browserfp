/* uastrcli —— 每行一条 User-Agent，输出 "brand<TAB>version" 或 "-"。
   供与 Python 侧 oracle/uamap.py 的 parse_ua 做全量差分。 */
#include "tlsfp.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    static char line[4096], brand[64];
    while (fgets(line, sizeof(line), stdin)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        uint16_t ver = 0;
        if (tlsfp_parse_ua(line, brand, sizeof(brand), &ver))
            printf("%s\t%u\n", brand, ver);
        else
            printf("-\n");
    }
    return 0;
}
