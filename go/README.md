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

## 已知限制：macOS 上 Keygen 不可用

Go 宿主本身不链 libcrypto，只能 `dlopen`。而 dlopen 来的那份在 EVP keygen 上会失败
（符号全部解析成功、`OpenSSL_version` 也调得通，但 `EVP_PKEY_generate` 返回错误），
X25519 / P-256 / ML-KEM **全部**如此。同一份 `.so` 在 OpenResty 里是好的。

- 未在 Linux 上复现；生产（Linux + OpenResty）走 `RTLD_DEFAULT` 那条路，不受影响。
- 受影响的只有 `Keygen` 及依赖它的 `ClientHello` / `JA4For`；
  `SelectUA` / `H2Preface` / `JA4` / `Coherence` / `LookupJA4` 正常。
- 测试遇到时会 **SKIP 并打印原因**，不会假装通过。
- 可以用 `InitCrypto("/path/to/libcrypto.dylib")` 显式指定一份试试。

⚠ 另：macOS 的系统 `libcrypto.dylib` 是 LibreSSL，被 dlopen 时**主动 abort**
（`loading libcrypto in an unsafe way` + SIGABRT）。所以 `csrc` 里的候选列表
只用绝对路径，不用裸名 —— 改那个列表时别把裸名加回去。
