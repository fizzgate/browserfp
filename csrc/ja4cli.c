/* 读十六进制 ClientHello（每行一条），输出 JA4。供与 Python 差分比对。 */
#include "tlsfp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char transport = (argc > 1 && argv[1][0] == 'q') ? 'q' : 't';
    static char line[1 << 20];
    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strlen(line);
        while (n && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';
        if (!n) continue;
        size_t blen = n / 2;
        uint8_t *buf = malloc(blen);
        for (size_t i = 0; i < blen; i++) {
            unsigned v; sscanf(line + i*2, "%2x", &v); buf[i] = (uint8_t)v;
        }
        tlsfp_hello h;
        char ja4[TLSFP_JA4_LEN];
        if (tlsfp_parse_client_hello(buf, blen, &h) == 0 &&
            tlsfp_ja4(&h, transport, ja4, sizeof(ja4)) == 0)
            printf("%s\n", ja4);
        else
            printf("ERROR\n");
        free(buf);
    }
    return 0;
}
