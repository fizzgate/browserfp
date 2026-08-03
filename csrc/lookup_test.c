#include "browserfp.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    printf("内置 profile 数: %zu\n", browserfp_profile_count());
    for (int i = 1; i < argc; i++) {
        const browserfp_profile *p = browserfp_lookup_ja4(argv[i]);
        if (p) printf("  %s → %s (mode=%s) h2=%s\n", argv[i], p->id, p->mode,
                      p->h2_akamai[0] ? p->h2_akamai : "-");
        else   printf("  %s → unknown（不做近似匹配）\n", argv[i]);
    }
    return 0;
}
