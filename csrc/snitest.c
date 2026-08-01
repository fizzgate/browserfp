#include "tlsfp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    uint8_t out[16384], rnd[32], sid[32];
    for (int i=0;i<32;i++){rnd[i]=(uint8_t)(i*11+3); sid[i]=(uint8_t)(i*5+7);}
    int conf=-1;
    const tlsfp_profile *p = tlsfp_lookup_ua(argv[1], (uint16_t)atoi(argv[2]), &conf);
    if (!p) { fprintf(stderr,"no profile\n"); return 1; }
    int n = tlsfp_build_client_hello(p, argv[3], rnd, sid, out, sizeof(out));
    if (n<0) { fprintf(stderr,"build failed\n"); return 1; }
    for (int k=0;k<n;k++) printf("%02x", out[k]);
    printf("\n");
    fprintf(stderr, "%s\n", p->id);
    return 0;
}
