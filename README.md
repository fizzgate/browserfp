# browserfp

Browser network fingerprints — **build them, identify them, and prove they're right.**

A C library (+ Lua binding) that reproduces what a real browser looks like on the
wire: the TLS 1.3 ClientHello and the HTTP/2 opening frames. Given a User-Agent
string, it emits the exact bytes that browser would send.

The second half of that sentence is the point. Fingerprint work fails in a
specific way: JA4 matches, tests are green, and the bytes on the wire still
differ from a real browser in one place that matters. Every claim in this repo
has to be backed by something that can fail.

## Coverage

| | |
|---|---|
| Unique fingerprints | **82** (deduped from 321 target names by 13 deterministic fields) |
| (brand, version) pairs that can emit a fingerprint | **644** / 650 |
| Brands | Chrome, Firefox, Safari, Edge, Opera + their mobile variants |
| Distinct byte forms **confirmed by a third party** | **44 / 44** |
| Key exchange | X25519, P-256, P-384, X25519MLKEM768, X25519Kyber768Draft00 |
| Layers | TLS 1.3 (incl. HRR, RFC 8879 cert compression), HTTP/2 preface + Akamai fingerprint |

Not covered: QUIC/HTTP-3 construction (identify-only — see *Scope* below).

## How it's verified

This is the part worth reading.

**Third-party echo, with a ledger.** 644 combinations collapse to 44 distinct byte
forms. Each one has been sent to a public fingerprint-echo service and confirmed
against 8 axes (JA4 both halves, JA3, extension order, ALPN, supported_versions,
PSK modes, cert compression, HTTP/2 Akamai). The ledger records *when* each was
last confirmed; an offline gate fails if any form has never been confirmed, has
gone stale, or no longer exists.

**Real production User-Agents.** "644/650" is a number about a set *we* enumerated.
It says nothing about live traffic — users don't hand you a version number, they
hand you a UA string, and `parse_ua` sits in between. A separate gate measures
coverage against 60 deduplicated production UAs, splitting two things that must
not be averaged together: *non-browsers we correctly refuse* (scanners, health
checks, truncated UAs — impersonating a browser for those would be wrong) versus
*browsers we can't emit* (a real gap).

**Mutation testing.** Every assertion is checked by breaking the thing it guards
and confirming it goes red. Assertions that can't fail have been found here more
than once — a padding check that never triggered, a byte-for-byte comparison
where both sides used the same default seed, an extension-order metric fooled by
rotating GREASE values.

**Negative controls.** A gate that only ever sees the happy path proves nothing.
Certificate decompression is verified against a server that *actually compresses*
— and the gate asserts that it did, because otherwise "the handshake succeeded"
only proves the uncompressed path still works.

51 offline gates run without network. Network-dependent ones are opt-in
(`LIVE=1`) so a normal test run never touches a public service.

## Quick start

```lua
local bfp = require("browserfp")

local p = bfp.select({ kind = "browser", ua = "Mozilla/5.0 (Windows NT 10.0; " ..
                       "Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " ..
                       "Chrome/131.0.0.0 Safari/537.36" })
if not p then return end                     -- unknown UA → don't guess

local keys  = p:keygen()                     -- private keys stay in the handle
local hello = p:client_hello("example.com", keys)   -- complete TLS record
local preface, pseudo_order = p:h2_preface()
```

`select()` returns `nil` when the UA is unrecognised or that version has no
profile. **It does not fall back to a different browser.** Sending Safari's UA
with Chrome's TLS fingerprint is worse than not impersonating at all — that
mismatch is exactly what fingerprint checks look for.

## Build

```sh
cd csrc && make            # libbrowserfp.so
```

No link-time OpenSSL dependency: SHA-256 and the EVP key-exchange functions are
resolved at runtime via `dlsym`, preferring whatever libcrypto the host process
already loaded. Two consequences, both deliberate:

- **Cross-compiles cleanly.** `zig cc -target x86_64-linux-gnu` produces a Linux
  `.so` from macOS with no sysroot setup.
- **No second OpenSSL in the process.** Linking one in would mean two copies
  inside an OpenResty worker, which already bundles its own.

## Scope

Primarily browsers; runtimes (bun, rust) are being added — the profile registry
already carries entries sourced from `curl_cffi`, `utls`, `tls-client` and
`wreq`, though those are *where the data came from*, not impersonation targets.

**QUIC/HTTP-3 is identify-only, deliberately.** Emitting it means writing a QUIC
transport from scratch (packet and header protection, loss recovery, congestion
control, flow control) plus HTTP/3 and QPACK — an order of magnitude more code
than the entire TLS stack here, for 3 profiles versus 644 over HTTP/2. Measured,
not assumed: iOS Safari doesn't send UDP at all in the cases checked.

**This is not a full browser emulator.** It covers TLS and the HTTP/2 opening —
not HTTP semantics, not JavaScript, not Canvas or WebGL fingerprints.

---

## 中文

浏览器的**网络指纹**：构造、识别，以及**证明它是对的**。

给一条 User-Agent，输出那个浏览器会发的 TLS ClientHello 与 HTTP/2 开场字节。

重点在第三件事。指纹这类工作最容易出的问题是「看起来对了」—— JA4 一致、测试
全绿，实际发出去的字节和真浏览器差着关键一处。所以这里每个结论都要求一个**能红
的判据**：

- **第三方回显 + 台账**：644 个组合去重成 44 种字节形态，逐个打公开回显服务，
  按 8 个轴比对；台账记录每种最后确认的日期，离线门禁会因「从未确认 / 过期 /
  已不存在」而红。
- **真实生产 UA**：644/650 是我们自己枚举的集合，回答不了线上的问题 —— 用户发的
  是 UA 字符串，中间隔着 `parse_ua`。另一条门禁拿 60 条去重后的线上 UA 量，并把
  两件事**分开**：认不出扫描器是**对的**（给爬虫套浏览器指纹才是错的），认不出
  浏览器才是缺口。
- **变异测试**：每条断言都要被「改坏它守的东西」验证过能变红。「断言打不到」在
  这个仓里抓到过不止一次。
- **阴性对照**：只走通顺路径的门禁什么也证明不了。证书压缩那条会断言**对端确实
  压缩了** —— 否则「握手成功」只证明了没压缩的路径还能用。

51 条离线门禁不联网；联网的要显式 `LIVE=1`。

`select()` 认不出 UA 时返回 `nil`，**不会拿别的浏览器顶替** —— 拿 Chrome 的 TLS
指纹配 Safari 的 UA，比不伪装更显眼。

不链接期依赖 OpenSSL（SHA-256 与 EVP 都走运行时 `dlsym`），因此能干净地交叉编译，
也不会在 OpenResty 进程里多塞一份 OpenSSL。

QUIC/HTTP-3 **只识别不构造**：构造意味着从零写 QUIC 传输层再加 h3/QPACK，量级是
这里整个 TLS 栈的十倍以上，而收益是 3 条 profile（对比 h2 的 644 个组合）。
