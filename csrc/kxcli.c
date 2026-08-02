/* kxcli —— 把 tlsfp_kx 暴露给门禁。
 *
 * 每行一条指令：
 *   gen <group>                       → <pubhex> <handle>
 *   derive <handle> <peerhex>         → <secrethex>
 *   version                           → OpenSSL 版本串
 * 句柄是本进程内的下标，**只在一次进程生命周期内有效** —— 门禁要在同一个
 * 进程里先 gen 再 derive，否则私钥早没了。
 */
#include "tlsfp_kx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXH 64
static void *H[MAXH];
static int nh;

static int unhex(const char *s, unsigned char *out, size_t cap) {
    size_t n = strlen(s);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(s + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (unsigned char)v;
    }
    return (int)(n / 2);
}

static void puthex(const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
}

int main(int argc, char **argv) {
    const char *lib = argc > 1 ? argv[1] : NULL;
    if (tlsfp_kx_init(lib) != 0) {
        fprintf(stderr, "解析 libcrypto 符号失败\n");
        return 2;
    }
    /* **行缓冲**：下面几个错误分支都用 continue 跳过了循环底部的 fflush，
     * 于是 "ERR" 留在 stdio 缓冲里、对端读不到，表现是门禁挂死而不是报错。
     * 管道喂完即退的手工测试看不出来 —— 进程退出时会统一 flush。 */
    setvbuf(stdout, NULL, _IOLBF, 0);
    static char line[8192];
    static unsigned char buf[4096], sec[256], peer[4096];
    while (fgets(line, sizeof(line), stdin)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (!strcmp(line, "version")) {
            printf("%s\n", tlsfp_kx_openssl_version());
        } else if (!strncmp(line, "gen ", 4)) {
            unsigned g = (unsigned)strtoul(line + 4, NULL, 0);
            void *ctx = NULL;
            int n = tlsfp_kx_keygen((uint16_t)g, buf, sizeof(buf), &ctx);
            if (n < 0 || nh >= MAXH) { printf("ERR\n"); continue; }
            H[nh] = ctx;
            puthex(buf, n);
            printf(" %d\n", nh++);
        } else if (!strncmp(line, "derive ", 7)) {
            char *sp = strchr(line + 7, ' ');
            if (!sp) { printf("ERR\n"); continue; }
            *sp = 0;
            int idx = atoi(line + 7);
            int pn = unhex(sp + 1, peer, sizeof(peer));
            if (idx < 0 || idx >= nh || pn < 0) { printf("ERR\n"); continue; }
            int n = tlsfp_kx_derive(H[idx], peer, (size_t)pn, sec, sizeof(sec));
            if (n < 0) { printf("ERR\n"); continue; }
            puthex(sec, n);
            printf("\n");
        } else {
            printf("ERR\n");
        }
        fflush(stdout);
    }
    for (int i = 0; i < nh; i++) tlsfp_kx_free(H[i]);
    return 0;
}
