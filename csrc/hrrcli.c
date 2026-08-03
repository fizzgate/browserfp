/* hrrcli —— 每行 "<ch1hex> <group> <pubhex>"，输出重建出的 CH2 的 hex。 */
#include "browserfp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int unhex(const char *s, size_t n, uint8_t *out, size_t cap) {
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(s + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return (int)(n / 2);
}

int main(void) {
    /* 行缓冲：错误分支用 continue 跳过了 fflush，缓冲住会让交互式调用方挂死。 */
    setvbuf(stdout, NULL, _IOLBF, 0);
    static char line[131072];
    static uint8_t ch1[16384], pub[4096], out[16384];
    while (fgets(line, sizeof(line), stdin)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *s1 = strchr(line, ' ');
        if (!s1) { printf("ERR\n"); continue; }
        *s1 = 0;
        char *s2 = strchr(s1 + 1, ' ');
        if (!s2) { printf("ERR\n"); continue; }
        *s2 = 0;
        int n1 = unhex(line, strlen(line), ch1, sizeof(ch1));
        unsigned g = (unsigned)strtoul(s1 + 1, NULL, 0);
        int np = unhex(s2 + 1, strlen(s2 + 1), pub, sizeof(pub));
        if (n1 < 0 || np < 0) { printf("ERR\n"); continue; }
        int n = browserfp_rebuild_hrr(ch1, (size_t)n1, (uint16_t)g, pub, (size_t)np,
                                  out, sizeof(out));
        if (n < 0) { printf("ERR\n"); continue; }
        for (int i = 0; i < n; i++) printf("%02x", out[i]);
        printf("\n");
    }
    return 0;
}
