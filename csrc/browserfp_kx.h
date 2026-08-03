/* browserfp_kx —— key_share 用的密钥交换。
 *
 * 为什么在这里而不是 Lua 侧：`browserfp.client_hello()` 现在要求调用方把每一组的
 * 公钥交进来，而调用方要能产出这些密钥。X25519 好办，X25519MLKEM768 不好办 ——
 * 生产 UA 里 64.9% 落在需要它的 profile 上。
 *
 * 为什么不自己实现 ML-KEM：**OpenResty 自带的就是 OpenSSL 3.5.7**，里面有
 * ML-KEM-768。（曾经量错过一次：容器里 `openssl version` 报 3.0.20，那是 Debian
 * 的系统二进制，不是 OpenResty 链的那份 —— 后者在 /usr/local/openresty/openssl3/。
 * **先确认数据出自哪一层**，否则会得出"必须自己写密码学"这种反向结论。）
 *
 * 符号在**运行时**解析，不在链接期绑定：worker 里 libcrypto 早就加载好了，
 * dlsym(RTLD_DEFAULT) 拿到的就是 OpenResty 那一份。链接期绑一个 Debian 的
 * libcrypto.so.3 会在同一个进程里出现两份 OpenSSL —— 那是很难查的一类故障。
 */
#ifndef TLSFP_KX_H
#define TLSFP_KX_H

#include <stddef.h>
#include <stdint.h>

/* 解析 libcrypto 的符号。path 给 NULL 表示"用进程里已经加载的那份"（worker 里
 * 就该这样）；离线跑 CLI 时才需要显式给一个 .so/.dylib 路径。
 * 返回 0 成功，-1 失败。可重复调用，只做一次。 */
int browserfp_kx_init(const char *libcrypto_path);

/* 已解析到的 OpenSSL 版本串；未初始化时返回 NULL。**要记进日志** —— 版本不同
 * 意味着能不能做 ML-KEM 不同。 */
const char *browserfp_kx_openssl_version(void);

/* 该组的 key_share 公钥字节数 / 共享密钥字节数；不支持的组返回 0。 */
size_t browserfp_kx_pub_len(uint16_t group);
size_t browserfp_kx_secret_len(uint16_t group);

/* 生成一对密钥。pub 写的是 key_share 里那一段的**线上格式**：
 *   0x001d X25519            32 字节裸公钥
 *   0x0017 secp256r1         65 字节未压缩点
 *   0x0018 secp384r1         97 字节未压缩点
 *   0x11ec X25519MLKEM768    ML-KEM 封装密钥(1184) || X25519 公钥(32) = 1216
 * 返回写入 pub 的字节数，失败返回 -1。*out 拿到私钥句柄，用完必须 free。 */
int browserfp_kx_keygen(uint16_t group, uint8_t *pub, size_t publen, void **out);

/* 拿服务端那一段算共享密钥。X25519MLKEM768 的入参是
 * ML-KEM 密文(1088) || X25519 公钥(32)，出参是 ML-KEM 共享(32) || X25519 共享(32)。
 * 返回写入 secret 的字节数，失败返回 -1。 */
int browserfp_kx_derive(void *ctx, const uint8_t *peer, size_t peerlen,
                    uint8_t *secret, size_t seclen);

void browserfp_kx_free(void *ctx);

#endif
