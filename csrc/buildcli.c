/* 从 stdin 读 profile 下标，把构造出的 ClientHello 以 hex 打到 stdout */
#include "tlsfp.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    char line[64];
    uint8_t out[16384], rnd[32], sid[32];
    for (int i = 0; i < 32; i++) { rnd[i] = (uint8_t)(i * 7 + 1); sid[i] = (uint8_t)(i * 3 + 2); }
    while (fgets(line, sizeof(line), stdin)) {
        int idx = -1;
        if (sscanf(line, "%d", &idx) != 1) continue;
        if (idx < 0 || (size_t)idx >= tlsfp_profile_count()) { printf("-\n"); continue; }
        const tlsfp_profile *p = tlsfp_profile_at((size_t)idx);
        int n = tlsfp_build_client_hello(p, NULL, rnd, sid, out, sizeof(out));
        if (n < 0) { printf("-\n"); continue; }
        for (int k = 0; k < n; k++) printf("%02x", out[k]);
        printf("\n");
    }
    return 0;
}
