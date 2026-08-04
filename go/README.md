# browserfp Go 绑定

```go
import browserfp "github.com/fizzgate/browserfp/go"

p, err := browserfp.SelectUA(userAgent)   // 认不出就报错，**绝不顶替**
if err != nil { return err }

keys, err := p.Keygen()                    // 私钥留在句柄里
defer keys.Close()
hello, _ := p.ClientHello("example.com", keys)  // 完整 TLS record，可直接写 socket
preface, pseudoOrder, _ := p.H2Preface()        // h2 开场字节 + 伪头序
```

与 Lua 绑定共用 `../csrc` 的同一份实现和同一份 profile 表，两边不会漂移。

## 构建

cgo 直接编译 C 源，`go build` 一步到位，不需要先 make 出 `.so`。
但 `csrc/profiles.inc` 是 `gen_profiles.py` 生成的、**不入库**，首次要先：

```sh
make -C ../csrc profiles.inc
```

## C 侧返回值约定（最容易踩的一处）

`browserfp_*` 的整型返回**不是** C 惯例的 0=成功：

| 函数 | 成功 | 失败 |
|---|---|---|
| `browserfp_parse_ua` | **1** | 0 |
| `browserfp_kx_keygen` | **公钥长度**（32 / 65 / 1216…） | -1 |
| `browserfp_kx_derive` | **共享密钥长度** | -1 |
| `browserfp_build_client_hello_ex` | **record 长度** | -1 |

Lua 绑定判的是 `n ~= len`。按 `!= 0` 写会把每次成功都当失败 —— 写这个绑定时连着
踩了两次，还一度误诊成「macOS + Go 宿主的已知限制」写进文档，直到用**纯 C + 同样
只靠 dlopen** 的对照实验（rc=32/65/1216 全成功）才打掉那个错判。

## ClientHello 的两个必填参数

`random`(32B) 与 `session_id` 都必须给（C 侧 `!random32 || (session_id_len &&
!session_id)` 直接返回 -1），而且**每次调用都要重新生成** —— 照抄一份固定值会让
所有连接的 ClientHello 逐字节相同，比不伪装还容易被判。本绑定用 `crypto/rand`。

## cgo 指针规则

传给 C 的 Go 内存里不能再含 Go 指针（`keyshare.pub` 指向 Go 切片就是这种），
否则运行时 panic `cgo argument has Go pointer to unpinned Go pointer`。
本绑定用 `runtime.Pinner` 钉住，比 `C.malloc` 拷一份省事且不会漏 free。

## macOS 上的 libcrypto

系统 `libcrypto.dylib` 是 LibreSSL，被 dlopen 时**主动 abort**
（`loading libcrypto in an unsafe way` + SIGABRT）。所以 `csrc` 的候选列表只用
绝对路径、不用裸名 —— 改那个列表时别把裸名加回去。

需要指定别的 libcrypto 时用 `InitCrypto("/path/to/libcrypto...")`，
**必须在任何 Keygen 之前调用**。

## 与 Lua 绑定的一致性

两边共用同一份 C 实现与 profile 表。`TestSameRegistryAsLuaBinding` 断言同一
profile 的注册表 JA4 与 akamai 逐字节相同 —— 漂移了的话，用一边验过的指纹就不能
代表另一边发出去的字节。
