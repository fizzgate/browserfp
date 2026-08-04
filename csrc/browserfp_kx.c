#include "browserfp_kx.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#define X25519_GROUP   0x001D
#define P256_GROUP     0x0017
#define P384_GROUP     0x0018
#define MLKEM_GROUP    0x11EC
#define KYBER_GROUP    0x6399     /* X25519Kyber768Draft00 */

#define MLKEM_EK_LEN   1184
#define MLKEM_CT_LEN   1088
#define MLKEM_SS_LEN     32
#define X25519_LEN       32

/* 只声明用得到的那几个 EVP 入口。**不 include openssl 的头** —— 打包机上的
 * 头文件版本与运行时那份未必一致，而我们只需要函数签名。 */
typedef void *(*fn_ctx_new_from_name)(void *, const char *, const char *);
typedef void *(*fn_ctx_new)(void *, void *);
typedef int (*fn_keygen_init)(void *);
typedef int (*fn_generate)(void *, void **);
typedef int (*fn_set_group_name)(void *, const char *);
typedef int (*fn_get_raw_pub)(const void *, unsigned char *, size_t *);
typedef int (*fn_get_octet_param)(const void *, const char *, unsigned char *,
                                  size_t, size_t *);
typedef unsigned long (*fn_err_get)(void);
typedef void (*fn_err_str)(unsigned long, char *, size_t);
typedef void *(*fn_new_raw_pub_ex)(void *, const char *, const char *,
                                   const unsigned char *, size_t);
typedef void *(*fn_pkey_new)(void);
typedef int (*fn_copy_params)(void *, const void *);
typedef int (*fn_set1_encoded_pub)(void *, const unsigned char *, size_t);
typedef int (*fn_derive_init)(void *);
typedef int (*fn_derive_set_peer)(void *, void *);
typedef int (*fn_derive)(void *, unsigned char *, size_t *);
typedef int (*fn_decap_init)(void *, void *);
typedef int (*fn_decap)(void *, unsigned char *, size_t *,
                        const unsigned char *, size_t);
typedef void (*fn_pkey_free)(void *);
typedef void (*fn_ctx_free)(void *);
typedef const char *(*fn_version)(int);
typedef void *(*fn_md_fetch)(void *, const char *, const char *);
typedef void (*fn_md_free)(void *);
typedef void *(*fn_mdctx_new)(void);
typedef void (*fn_mdctx_free)(void *);
typedef int (*fn_digest_init)(void *, const void *, void *);
typedef int (*fn_digest_update)(void *, const void *, size_t);
typedef int (*fn_digest_final)(void *, unsigned char *, unsigned int *);
typedef int (*fn_digest_xof)(void *, unsigned char *, size_t);

static struct {
    int loaded;
    fn_ctx_new_from_name ctx_new_from_name;
    fn_ctx_new           ctx_new;
    fn_keygen_init       keygen_init;
    fn_generate          generate;
    fn_set_group_name    set_group_name;
    fn_get_raw_pub       get_raw_pub;
    fn_get_octet_param   get_octet_param;
    fn_new_raw_pub_ex    new_raw_pub_ex;
    fn_pkey_new          pkey_new;
    fn_copy_params       copy_params;
    fn_set1_encoded_pub  set1_encoded_pub;
    fn_derive_init       derive_init;
    fn_derive_set_peer   derive_set_peer;
    fn_derive            derive;
    fn_decap_init        decap_init;
    fn_decap             decap;
    fn_pkey_free         pkey_free;
    fn_ctx_free          ctx_free;
    fn_version           version;
    fn_md_fetch          md_fetch;
    fn_md_free           md_free;
    fn_mdctx_new         mdctx_new;
    fn_mdctx_free        mdctx_free;
    fn_digest_init       digest_init;
    fn_digest_update     digest_update;
    fn_digest_final      digest_final;
    fn_digest_xof        digest_xof;
    /* 诊断用，可选：缺了不影响主流程，但 keygen 失败就查不出所以然 */
    fn_err_get           err_get;
    fn_err_str           err_str;
} S;

/* 私钥句柄。混合组要拿两把。 */
typedef struct {
    uint16_t group;
    void *a;            /* X25519 / EC / ML-KEM */
    void *b;            /* 混合组的 X25519 */
} kx_ctx;

#define SYM(field, name)                                        \
    do {                                                        \
        void *p = h ? dlsym(h, name) : dlsym(RTLD_DEFAULT, name); \
        if (!p) return -1;                                      \
        S.field = (fn_##field)p;                                \
    } while (0)

/* 与 browserfp.c 的 SHA-256 同一套兜底：**这个 .so 不再链 libcrypto**（为了能交叉
 * 编译），所以不能指望 RTLD_DEFAULT 里现成就有 EVP 符号 —— 那只在宿主自己链了
 * libcrypto 时成立（OpenResty 是，纯 LuaJyIT 进程不是）。
 * 2026-08-03 实测：只留 RTLD_DEFAULT 的话 test_kx / test_hrr / test_lua_keyshare
 * 一起红，而在 OpenResty 里跑却是好的 —— 典型的「本机能跑不等于没坏」。 */
static const char *const KX_CRYPTO_SONAMES[] = {
    /* Linux 优先（生产就是它）：进程里通常已经加载，dlopen 只是兜底 */
    "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so",
    /* macOS：**必须给绝对路径**。裸名 "libcrypto.dylib" 会命中系统那份
     * LibreSSL，而它被 dlopen 时主动 abort：
     *     WARNING: … is loading libcrypto in an unsafe way
     *     SIGABRT
     * 在 OpenResty 里碰不到（进程已链好 libcrypto，走 RTLD_DEFAULT 就命中），
     * 但 Go 绑定 / 离线 CLI 这类**自己没链 libcrypto 的宿主**一试就崩。
     * 2026-08-04 写 Go 绑定时撞到。 */
    "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
    "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib",
    "/opt/homebrew/lib/libcrypto.3.dylib",
    "/usr/local/lib/libcrypto.3.dylib",
    "libcrypto.3.dylib", "libcrypto.1.1.dylib",
    NULL
};

int browserfp_kx_init(const char *libcrypto_path) {
    if (S.loaded) return 0;
    void *h = NULL;
    if (libcrypto_path) {
        h = dlopen(libcrypto_path, RTLD_NOW | RTLD_GLOBAL);
        if (!h) return -1;
    } else if (!dlsym(RTLD_DEFAULT, "EVP_PKEY_CTX_new_from_name")) {
        /* 宿主没加载 libcrypto ⇒ 自己找一个 */
        for (int i = 0; KX_CRYPTO_SONAMES[i]; i++) {
            h = dlopen(KX_CRYPTO_SONAMES[i], RTLD_NOW | RTLD_GLOBAL);
            if (h) break;
        }
        if (!h) return -1;
    }
    SYM(ctx_new_from_name, "EVP_PKEY_CTX_new_from_name");
    SYM(ctx_new,           "EVP_PKEY_CTX_new");
    SYM(keygen_init,       "EVP_PKEY_keygen_init");
    SYM(generate,          "EVP_PKEY_generate");
    SYM(set_group_name,    "EVP_PKEY_CTX_set_group_name");
    SYM(get_raw_pub,       "EVP_PKEY_get_raw_public_key");
    SYM(get_octet_param,   "EVP_PKEY_get_octet_string_param");
    SYM(new_raw_pub_ex,    "EVP_PKEY_new_raw_public_key_ex");
    SYM(pkey_new,          "EVP_PKEY_new");
    SYM(copy_params,       "EVP_PKEY_copy_parameters");
    SYM(set1_encoded_pub,  "EVP_PKEY_set1_encoded_public_key");
    SYM(derive_init,       "EVP_PKEY_derive_init");
    SYM(derive_set_peer,   "EVP_PKEY_derive_set_peer");
    SYM(derive,            "EVP_PKEY_derive");
    SYM(decap_init,        "EVP_PKEY_decapsulate_init");
    SYM(decap,             "EVP_PKEY_decapsulate");
    SYM(pkey_free,         "EVP_PKEY_free");
    SYM(ctx_free,          "EVP_PKEY_CTX_free");
    SYM(version,           "OpenSSL_version");
    /* ERR_* 是**可选**的（老/裁剪版可能没有），所以不走 SYM —— 那个宏缺符号就
     * 返回 -1，会把整个初始化拖垮。没有它时 keygen 失败只剩"返回非 0"，
     * 2026-08-04 在 macOS + Go 宿主上就是卡在这一点上查不下去。 */
    S.err_get = (fn_err_get)(h ? dlsym(h, "ERR_get_error") : dlsym(RTLD_DEFAULT, "ERR_get_error"));
    S.err_str = (fn_err_str)(h ? dlsym(h, "ERR_error_string_n") : dlsym(RTLD_DEFAULT, "ERR_error_string_n"));
    /* SHA3-256 / SHAKE256：Kyber768Draft00 的那层包装要用，见 kyber_wrap() */
    SYM(md_fetch,          "EVP_MD_fetch");
    SYM(md_free,           "EVP_MD_free");
    SYM(mdctx_new,         "EVP_MD_CTX_new");
    SYM(mdctx_free,        "EVP_MD_CTX_free");
    SYM(digest_init,       "EVP_DigestInit_ex");
    SYM(digest_update,     "EVP_DigestUpdate");
    SYM(digest_final,      "EVP_DigestFinal_ex");
    SYM(digest_xof,        "EVP_DigestFinalXOF");
    S.loaded = 1;
    return 0;
}

const char *browserfp_kx_openssl_version(void) {
    return S.loaded ? S.version(0) : NULL;
}

size_t browserfp_kx_pub_len(uint16_t group) {
    switch (group) {
    case X25519_GROUP: return X25519_LEN;
    case P256_GROUP:   return 65;
    case P384_GROUP:   return 97;
    case MLKEM_GROUP:  return MLKEM_EK_LEN + X25519_LEN;
    case KYBER_GROUP:  return X25519_LEN + MLKEM_EK_LEN;
    default:           return 0;
    }
}

size_t browserfp_kx_secret_len(uint16_t group) {
    switch (group) {
    case X25519_GROUP: return 32;
    case P256_GROUP:   return 32;
    case P384_GROUP:   return 48;
    case MLKEM_GROUP:  return MLKEM_SS_LEN + X25519_LEN;
    case KYBER_GROUP:  return X25519_LEN + MLKEM_SS_LEN;
    default:           return 0;
    }
}

/* Kyber768Draft00 的共享密钥 = SHAKE-256(K || SHA3-256(ct), 32)，K 是 ML-KEM
 * 的解封装输出。
 *
 * **这一族不需要另一份密码学实现**。ML-KEM 相对 Kyber 第三轮只去掉了最后一步
 * 哈希，补回来就是 Kyber v3 —— Go 标准库与 utls 都是这么做的（见 utls 的
 * u_key_schedule.go）。本仓拿 CIRCL 的真·第三轮实现验过：它对我们生成的
 * ML-KEM 公钥做封装，我们按上式解出来的共享密钥与它逐字节相同。
 *
 * 判据在 spec/test_kx.py 里，不是"看着像"。 */
static int kyber_wrap(const uint8_t *K, const uint8_t *ct, size_t ctlen,
                      uint8_t *out) {
    void *sha3 = S.md_fetch(NULL, "SHA3-256", NULL);
    void *shake = S.md_fetch(NULL, "SHAKE-256", NULL);
    void *c1 = S.mdctx_new(), *c2 = S.mdctx_new();
    int ok = 0;
    uint8_t h[32];
    unsigned int hn = 0;
    if (sha3 && shake && c1 && c2
        && S.digest_init(c1, sha3, NULL) == 1
        && S.digest_update(c1, ct, ctlen) == 1
        && S.digest_final(c1, h, &hn) == 1 && hn == 32
        && S.digest_init(c2, shake, NULL) == 1
        && S.digest_update(c2, K, MLKEM_SS_LEN) == 1
        && S.digest_update(c2, h, 32) == 1
        && S.digest_xof(c2, out, MLKEM_SS_LEN) == 1) {
        ok = 1;
    }
    if (c1) S.mdctx_free(c1);
    if (c2) S.mdctx_free(c2);
    if (sha3) S.md_free(sha3);
    if (shake) S.md_free(shake);
    return ok ? 0 : -1;
}

static void *gen_named(const char *name) {
    void *c = S.ctx_new_from_name(NULL, name, NULL);
    if (!c) return NULL;
    void *pk = NULL;
    if (S.keygen_init(c) != 1 || S.generate(c, &pk) != 1) pk = NULL;
    S.ctx_free(c);
    return pk;
}

static void *gen_ec(const char *curve) {
    void *c = S.ctx_new_from_name(NULL, "EC", NULL);
    if (!c) return NULL;
    void *pk = NULL;
    if (S.keygen_init(c) != 1 || S.set_group_name(c, curve) != 1
        || S.generate(c, &pk) != 1) pk = NULL;
    S.ctx_free(c);
    return pk;
}

static int raw_pub(void *pk, uint8_t *out, size_t cap) {
    size_t n = cap;
    if (S.get_raw_pub(pk, out, &n) != 1) return -1;
    return (int)n;
}

static int ec_pub(void *pk, uint8_t *out, size_t cap) {
    size_t n = 0;
    if (S.get_octet_param(pk, "encoded-pub-key", out, cap, &n) != 1) return -1;
    return (int)n;
}

int browserfp_kx_keygen(uint16_t group, uint8_t *pub, size_t publen, void **out) {
    if (!S.loaded || !out) return -1;
    size_t need = browserfp_kx_pub_len(group);
    if (!need || publen < need) return -1;

    kx_ctx *k = calloc(1, sizeof(*k));
    if (!k) return -1;
    k->group = group;
    int n = -1;

    switch (group) {
    case X25519_GROUP:
        k->a = gen_named("X25519");
        if (k->a) n = raw_pub(k->a, pub, publen);
        break;
    case P256_GROUP:
    case P384_GROUP:
        k->a = gen_ec(group == P256_GROUP ? "prime256v1" : "secp384r1");
        if (k->a) n = ec_pub(k->a, pub, publen);
        break;
    case KYBER_GROUP:
        /* **顺序与 X25519MLKEM768 相反**：draft-tls-westerbaan-xyber768d00 是
         * X25519 在前、Kyber 在后。Go 标准库 handshake_client.go 与 utls 的
         * handshake_client_tls13.go 都是这个顺序（两份独立实现互相印证）。
         * 记混的表现是长度完全正确、握手却在 Finished 阶段失败。 */
        k->b = gen_named("X25519");
        k->a = gen_named("ML-KEM-768");
        if (k->a && k->b) {
            int x = raw_pub(k->b, pub, publen);
            int m = (x == X25519_LEN)
                    ? raw_pub(k->a, pub + X25519_LEN, publen - X25519_LEN) : -1;
            if (m == MLKEM_EK_LEN) n = x + m;
        }
        break;
    case MLKEM_GROUP:
        /* 顺序按 draft-ietf-tls-ecdhe-mlkem：ML-KEM 在前，X25519 在后。
         * 与参考实现 oracle/tls13.py 同一顺序 —— 它已经能跟真站点握上手。 */
        k->a = gen_named("ML-KEM-768");
        k->b = gen_named("X25519");
        if (k->a && k->b) {
            int m = raw_pub(k->a, pub, publen);
            int x = (m == MLKEM_EK_LEN)
                    ? raw_pub(k->b, pub + MLKEM_EK_LEN, publen - MLKEM_EK_LEN) : -1;
            if (x == X25519_LEN) n = m + x;
        }
        break;
    default:
        break;
    }

    if (n != (int)need) { browserfp_kx_free(k); return -1; }
    *out = k;
    return n;
}

static int derive_ecdh(void *priv, const char *rawname,
                       const uint8_t *peer, size_t peerlen,
                       uint8_t *out, size_t cap) {
    void *pk = NULL;
    if (rawname) {
        pk = S.new_raw_pub_ex(NULL, rawname, NULL, peer, peerlen);
    } else {
        pk = S.pkey_new();
        if (pk && (S.copy_params(pk, priv) != 1
                   || S.set1_encoded_pub(pk, peer, peerlen) != 1)) {
            S.pkey_free(pk); pk = NULL;
        }
    }
    if (!pk) return -1;

    void *c = S.ctx_new(priv, NULL);
    int n = -1;
    if (c && S.derive_init(c) == 1 && S.derive_set_peer(c, pk) == 1) {
        size_t len = cap;
        if (S.derive(c, out, &len) == 1) n = (int)len;
    }
    if (c) S.ctx_free(c);
    S.pkey_free(pk);
    return n;
}

int browserfp_kx_derive(void *ctx, const uint8_t *peer, size_t peerlen,
                    uint8_t *secret, size_t seclen) {
    kx_ctx *k = (kx_ctx *)ctx;
    if (!S.loaded || !k) return -1;
    size_t need = browserfp_kx_secret_len(k->group);
    if (!need || seclen < need) return -1;

    switch (k->group) {
    case X25519_GROUP:
        if (peerlen != X25519_LEN) return -1;
        return derive_ecdh(k->a, "X25519", peer, peerlen, secret, seclen);
    case P256_GROUP:
    case P384_GROUP:
        return derive_ecdh(k->a, NULL, peer, peerlen, secret, seclen);
    case KYBER_GROUP: {
        if (peerlen != X25519_LEN + MLKEM_CT_LEN) return -1;
        int x = derive_ecdh(k->b, "X25519", peer, X25519_LEN, secret, seclen);
        if (x != X25519_LEN) return -1;
        void *c = S.ctx_new(k->a, NULL);
        if (!c) return -1;
        uint8_t K[MLKEM_SS_LEN];
        size_t n = MLKEM_SS_LEN;
        int ok = (S.decap_init(c, NULL) == 1
                  && S.decap(c, K, &n, peer + X25519_LEN, MLKEM_CT_LEN) == 1
                  && n == MLKEM_SS_LEN);
        S.ctx_free(c);
        if (!ok) return -1;
        if (kyber_wrap(K, peer + X25519_LEN, MLKEM_CT_LEN,
                       secret + X25519_LEN) != 0) return -1;
        return (int)need;
    }
    case MLKEM_GROUP: {
        if (peerlen != MLKEM_CT_LEN + X25519_LEN) return -1;
        void *c = S.ctx_new(k->a, NULL);
        if (!c) return -1;
        size_t n = MLKEM_SS_LEN;
        int ok = (S.decap_init(c, NULL) == 1
                  && S.decap(c, secret, &n, peer, MLKEM_CT_LEN) == 1
                  && n == MLKEM_SS_LEN);
        S.ctx_free(c);
        if (!ok) return -1;
        int x = derive_ecdh(k->b, "X25519", peer + MLKEM_CT_LEN, X25519_LEN,
                            secret + MLKEM_SS_LEN, seclen - MLKEM_SS_LEN);
        return x == X25519_LEN ? (int)need : -1;
    }
    default:
        return -1;
    }
}

void browserfp_kx_free(void *ctx) {
    kx_ctx *k = (kx_ctx *)ctx;
    if (!k) return;
    if (S.loaded) {
        if (k->a) S.pkey_free(k->a);
        if (k->b) S.pkey_free(k->b);
    }
    free(k);
}


/* 最近一条 OpenSSL 错误并清空队列。没有 ERR_* 符号时返回 0。 */
unsigned long browserfp_kx_last_error(char *out, size_t outlen) {
    if (!S.err_get) return 0;
    unsigned long e = S.err_get();
    if (out && outlen) {
        out[0] = 0;
        if (e && S.err_str) S.err_str(e, out, outlen);
    }
    return e;
}
