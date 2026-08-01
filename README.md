# fizztls — 浏览器 TLS/HTTP2 指纹覆盖与验证

目标两条：**覆盖市面主流浏览器指纹**，以及**有办法证明覆盖是对的**。

后一条是重点。指纹这类工作最容易出的问题是"看起来对了"——JA4 一致、测试全绿，
实际发出去的字节和真浏览器差着关键一处。本项目的每个结论都要求可复现的实测支撑。

## 现状

| 指标 | 数值 |
|---|---|
| 唯一指纹 | **74**（来自 305 个 target 名，按 13 个确定性字段去重） |
| 连接形态 | 首连 59 + 会话恢复 15 |
| 来源 | 开源表 67 + 真机采集 7 |
| 含 h2 层 | 50/74 |
| 重建门禁 | 74/74 |
| 可用性门禁 | 66/68（34 profile × 2 真实站点） |

### 用途决定了要覆盖什么

本项目服务的是**入站识别**（进来一个指纹，认出它是谁），不是出站伪装。这个区别
决定了覆盖标准：伪装只需几个能用的指纹，识别却要求覆盖**一切可能进来的形态**，
漏一个就是"不认识"。

因此有两条与直觉不同的要求：

1. **同一浏览器有两种形态**。首次连接与会话恢复（ClientHello 带 `pre_shared_key`）
   的指纹**完全不同** —— 实测 31 个 target 的恢复态 JA4 无一与首连相同。浏览器
   打开站点后的后续请求基本都走会话复用，只有首连表等于认不出大部分真实流量。
2. **穷举版本不可持续**，改用源码审计（见下）确定"可能出现的全集"。

交付物是 `spec/profiles.json` —— 每条含 `id` / `aliases` / `provenance` / `tls` / `h2`。
下游引擎读它即可产出正确的 ClientHello，**不需要再去 curl-impersonate 的 C 源码抄表**。

## 为什么需要四个来源

| 来源 | 数量 | Chrome | Firefox | Safari | Edge | Opera |
|---|---|---|---|---|---|---|
| curl_cffi 0.13.0 | 31 | ≤136 | ≤135 | 26.0 | **101** | — |
| bogdanfinn/tls-client 1.14.0 | 76 | ≤146 | ≤147 | 16.0 | **101** | 91 |
| 0x676e67/wreq（Rust） | 134 | ≤149 | ≤151 | 26_4 | **148** | 131 |
| refraction/utls v1.8.3-dev | 36 | 58–133 | 55–148 | 16.0 / **26_3** | 85–106 | — |
| 真机采集 | 4 | 151 | 149 | 27 | — | — |

wreq 补上了前两家最大的缺口：**Edge 在 curl_cffi 与 tls-client 都停在 2022 年的
101，wreq 到 148**。它还独有几个维度：`FirefoxPrivate`（隐私模式）、
`FirefoxAndroid`、`SafariIpad`。

utls 上游的价值不在最新版，而在**别处没有的老版本与国产浏览器**：Chrome 58/62/70/72、
Firefox 55/56/63/65、QQ 11.1、360 7.5/11.0 —— 它 36 个变体贡献了 15 个新唯一指纹，
比 wreq 的 133 个贡献 5 个还多。另有两个填空洞的：`HelloSafari_26_3`（JA4 与真机
Safari 27 完全相同）与 `HelloFirefox_148`（`record_size_limit=16385`，与真机
Firefox 149 一致，而 curl_cffi:firefox135 是 4001）。

构建注意：utls v1.8.3-dev 依赖 `crypto/mlkem`（Go 1.24+ 标准库）。**不要设
`GOTOOLCHAIN=local`** —— 本机 `/usr/local/go` 是 1.23.1 会编译失败，默认工具链
1.25.7 可用。

wreq 要求 Python ≥3.11，而主 venv 是系统 Python 3.9（curl_cffi 在其上工作正常，
不动它），故单独建 `.venv-wreq`（anaconda 3.12）。

**多张开源表合起来也覆盖不了当前浏览器版本**：真机 Chrome 151 的 `sig_algs` 含
ML-DSA（`0x0904/0905/0906`），连 `tls_client:chrome_146` 都没有。所以架构必须是
**开源表打底 + 真机采集补最新**，只靠任何一张表都不够。

## 架构

```
采集 ─┬─ oracle/collect.py     curl_cffi 31 个（带/不带 SNI 两套）
      ├─ oracle/gocollect.py   tls-client 67 个（Go 采集器发真实 ClientHello）
      ├─ oracle/wreqcollect.py wreq 133 个（须用 .venv-wreq/bin/python 跑）
      ├─ oracle/utlscollect.py refraction utls 36 个（老版本 + QQ/360）
      ├─ oracle/goh2collect.py tls-client 71 个的 h2 层
      ├─ oracle/browsers.py    真机浏览器 TLS 层
      └─ oracle/h2collect.py   真机浏览器 h2 层
                │
观测 ─┬─ oracle/sniffer.py     L1：裸 TCP 收第一条 record，不握手、不要证书
      ├─ oracle/h2probe.py     L2：真 TLS + ALPN h2，抓 SETTINGS/WINDOW_UPDATE/头序
      └─ oracle/tapproxy.py    透明转发，抓客户端打**真实站点**时发的 ClientHello
                │
解析 ──  oracle/clienthello.py 自实现 JA3/JA4 + 逐扩展明细（GREASE 按 RFC8701 剔除）
                │
合成 ──  oracle/registry.py    三源合并去重 → spec/profiles.json
                │
识别 ──  oracle/match.py       ClientHello → 已知 profile 或明确的 unknown
                │
消费 ─┬─ oracle/chbuild.py     profile → ClientHello 字节
      ├─ oracle/tls13.py       TLS 1.3 握手（含 X25519MLKEM768）
      └─ oracle/h2client.py    HTTP/2（SETTINGS/伪头顺序照 profile）
```

## 三道门禁

```bash
python -m spec.test_rebuild            # 数据自洽：profile → 字节 → 解析 → 逐字段比
python -m spec.test_live_handshake     # 真实可用：34 profile × 2 站点，真握手 + h2
python -m spec.test_match              # 识别器：认得出 + 认不出必须报 unknown
python -m spec.test_cf_discrimination  # 指纹是否被区别对待（三臂对照）
python -m oracle.coverage              # 开源表对真机的覆盖矩阵
python -m oracle.srcaudit              # 源码审计：还有哪些扩展我们从没见过
```

自洽 ≠ 可用：字节拼得出、解析回来一致，不代表服务端会接受。两者必须分开验。

## 识别器

`oracle/match.py` 是整条链路的落点：输入 ClientHello，输出已知 profile 或 unknown。

| 档位 | 含义 |
|---|---|
| `exact` | 13 个确定性字段逐项相同 |
| `exact-no-pad` | 忽略 padding(0x15) 后相同（HRR 前后的真实差异） |
| `unknown` | 都不满足；同时给出最接近者与差异字段，供补录 |

**认不出时必须报 unknown，不许硬套最近的**——把陌生流量安静归到某个已知 profile
比认不出更糟，它让盲区永远不可见。`spec/test_match.py` 的重点因此是阴性对照：

```
自识别                    54/54 exact
变异必须 unknown          5/5（改 sig_algs / ciphers / curves / 扩展 / alpn）
容忍 padding              12/12
真实 HRR 端到端            chrome136:exact  safari184:exact-no-pad
```

最后一项是真触发一次 HelloRetryRequest 后识别第二个 ClientHello——safari184 正是
靠 `exact-no-pad` 命中的，padding 容忍在真实场景中确实起了作用。

## 关键方法论

**判据不能用 JA4。** 14 个 chrome target 只产生 4 个不同的 JA4，safari170 与
safari172_ios 完全相同。断言必须走 13 个确定性字段的逐项比对，用 JA4 会假绿。

**去重要数唯一指纹，不数名字。** `tls_client` 里 safari_ios_15_5/15_6/16_0/17_0
是同一指纹的四个名字，按名字数会虚高。

**门禁必须打多个站点。** 曾经只打 cloudflare.com，34 条全绿，掩盖了"根本没发
SNI"——cloudflare.com 有默认证书不介意，claude.ai 多租户直接 handshake_failure。
单站点的绿是假绿。

**真机 profile 不能用来证明开源表的覆盖率。** 用真机指纹匹配真机必然 0 差异，
是循环论证。`provenance` 字段把两类分开，`coverage.py` 判覆盖率时只读开源表。

**padding(0x15) 是长度驱动的噪声，性质同 GREASE。** 它按 ClientHello 总长度动态
添加（RFC 7685）：HRR 之后 key_share 从 X25519(32B) 换成 P-384(97B)，总长度变了，
padding 就跟着变——safari184/155/260_ios 在 HRR 后 padding 直接消失，扩展集合因此
与首连不同。严格匹配会把同一个客户端的两次握手判成两个指纹。实测忽略 padding 只
让唯一指纹 54→53（仅合并 1 对），代价很小，识别器应容忍它。

**偶发红先量再解释。** 遇到一次 timeout 不要当网络抖动放过——重试 5 次×2 站点
确认偶发之后，才加重试；且只重试网络类异常，`TLSError` 一律不重试，否则会把
稳定缺陷洗成偶发绿。

## 踩坑记录

| 现象 | 真因 |
|---|---|
| 打 claude.ai 恒 `handshake_failure(40)`，打 cloudflare.com 正常 | profile 来自 no-SNI 采集，`raw_extensions` 无 `0x0000`，**根本没发 SNI**。曾误归因到 ECH |
| Chrome 151 自签证书握手直接 EOF | 151 起 `--ignore-certificate-errors` 不够，须加 `--ignore-certificate-errors-spki-list`；Chromium 142 不需要 |
| Firefox 回 `SSLV3_ALERT_BAD_CERTIFICATE` | 不接受同一张自签证书既当信任锚又当服务器证书，须 CA + leaf 两级 |
| `--host-resolver-rules` 在 Chrome 151 完全失效 | headless/有头 × 裸规则/显式端口/关 DoH/`--host-rules` 六种组合实测全不生效，只能直连 IP 采集 |
| h2probe 只能 TLS 1.2 | macOS 系统 Python 3.9 链接 LibreSSL 2.8.3，不支持 TLS 1.3 |
| ML-KEM `decapsulate` 报 Invalid ciphertext | `encapsulate()` 返回 `(shared_secret, ciphertext)`，不是 `(ct, ss)` |
| PSK 形态永远采不到 | 观测点跑在 LibreSSL 2.8.3 上（系统 Python 3.9），`HAS_TLSv1_3=False`，发不出 NewSessionTicket。须用 anaconda 的 python（OpenSSL 3.4.1）。gocollect 当初 9 个 `_PSK` profile 全失败就是这个原因，当时误判成"首连无票据、可解释"放过了 |
| 单独采 Safari 后覆盖矩阵少算 | 直接写 results 清空了其他样本，须读回合并。**同类 bug 出现过两次**（`browsers.py` 与 `h2collect.py`），少算样本不报错，是纯假绿 |
| Safari 回 `SSLV3_ALERT_CERTIFICATE_UNKNOWN`（CA 已注入钥匙串） | 观测点只发 leaf 没发链。Firefox 能用库里的 CA 补全，Safari 不会，须发 `fullchain.pem` |
| `security add-trusted-cert` 卡住 | 实测要 8s、偶发更久（曾撞 60s 超时）；且 CA 已在钥匙串时重复添加会触发确认流程。须放宽超时 + 先查再加 |

## 与同类工具的字段交叉验证

拿 `0x676e67/pingly`（同作者的 TLS/HTTP 分析服务端）的字段定义与我们的
`clienthello.py` 对照，检查解析器自身有没有盲区：

| pingly 解析的 | 我们 | 结论 |
|---|---|---|
| cipher_suites / extensions / compression / session_id / tls_version | ✅ 有 | — |
| PskKeyExchangeModes / ECH / cert_compression / ALPN | ✅ 有 | — |
| **KeyShare 组列表** | ❌ 判据里没有 | **实测不增加区分度**：加入后唯一指纹仍是 59（+0） |
| StatusRequest 内容、OidFilter | ❌ 没解 | 服务端侧扩展，对客户端识别无用 |
| **TCP 层**（ja4t / satori / TTL 跳数 / MTU） | ❌ 整层没有 | 结构性缺口，见下 |
| **HTTP/3 与 QUIC** | ❌ 整层没有 | 结构性缺口，见下 |

key_share 那条是有价值的阴性结果：它证明现有 13 字段判据**已足够区分当前全部
59 个指纹**，不必为此扩判据。但这是在当前样本上的结论，新增来源后应重测。

## 版本覆盖与真实缺口

按品牌统计（只算首连形态；版本号→指纹后压缩成"指纹段"）：

| 品牌 | 有数据版本 | 压缩后指纹段 | 我们最高 | 市面 | 状态 |
|---|---|---|---|---|---|
| Chrome | 55 | 22 | 151 | 151 | 已追平 |
| Firefox | 31 | 16 | 151 | 149 | 已追平 |
| Safari | 6 | 4 | 27 | 27 | 已追平 |
| Opera | 19 | 2 | 131 | 131 | 已追平 |
| **Edge** | 22 | 6 | **148** | **151** | **差 3 个大版本** |

「55 个版本压缩成 22 个指纹段」再次说明版本数不等于指纹数。

**真实缺口（按可补性排序）**：

1. **Chrome 150** —— 唯一"有证据无实采"的：surf 源码显示它含 ML-DSA 且与真机 151
   同序，但 surf 要求 go≥1.27（本机 1.25.7）编译不了，注册表里没有独立条目。
   ML-DSA 的引入点因此只能确定在 (146, 150]，无法再收窄。
2. **Edge 149–151** —— 四个源最高都只到 148，是**真缺口**。

   曾推测"Edge 是 Chromium 系，与同代 Chrome 同指纹，风险低于表象"。**实测证伪
   了这个推测**：20 对同代版本里 18 对相同，但 Edge134 与 Edge146 不同。差异是
   实质性的：

   ```
   Edge134   扩展含 17613 (0x44CD, ALPS 新)，app_settings = []
   Chrome134 扩展含 17513 (0x4469, ALPS 旧)，app_settings = ['h2']
   ```

   **Edge 比同代 Chrome 更早切换 ALPS codepoint**，不是简单跟随。加之 Edge 全球
   市占率约 5%，这个缺口必须实采补齐，不能靠"大概率相同"推断。
3. **版本号空洞** —— 各品牌都有（Chrome 31 个、Firefox 58 个、Edge 35 个、
   Opera 24 个），指两端指纹不同、中间可能藏变更点的区间。但这只是**上界**：
   多数空洞里指纹并未变化。

⚠ 分析这类空洞时**不能假设版本号连续**：Safari 从 18 直接跳到 26（Apple 2025 年
改用年份命名），19–25 根本不存在，早期版本的自动分析曾把它们误报成高风险空洞。

## 已知缺口

- **chrome124 不可用**：服务端选 `X25519Kyber768Draft00 (0x6399)`，被 ML-KEM 取代的
  废弃草案，cryptography 未实现。刻意不加豁免表，让它每次都报出来。
- **5 个纯 TLS1.2 profile 未覆盖**：cloudscraper / confirmed_android / mesh_android_2 /
  okhttp4_android_7 / okhttp4_android_8。参考实现只做 TLS 1.3。
- **wreq 的 h2 采不到**：wreq 坚持校验服务端证书，`verify=False` /
  `danger_accept_invalid_certs` / `cert_store=CertStore.from_pem_stack(ca)` 均无效
  （前者疑似被静默忽略）。L1 不受影响是因为 sniffer 不完成握手。`wreqh2collect.py`
  逻辑已就绪，待找到正确的信任配置。
- **utls 那批刻意不采 h2**：utls 是纯 TLS 库，profile 里没有 h2 定义。套一个 Go 的
  http2 客户端能采到 SETTINGS，但那是 `golang.org/x/net/http2` 的默认值——**是 Go 的
  指纹不是浏览器的**，入库会污染数据且事后极难发现（它看起来完全合理）。
- **24 个缺 h2 层**（wreq 与 utls 两源只采了 TLS 层，未采 h2）。原先的 4 个：cloudscraper / mesh_android_2 / mms_ios / mms_ios_2 ——
  **均为非浏览器 app profile，浏览器侧无缺口**（四个真机浏览器全部三层齐全）。
- **CF 挑战未验证**：claude.ai 根路径本就不设防（三种指纹结果一致、无 `cf-mitigated`），
  要验 managed challenge 需要一个真正会触发的端点。
- **TCP 层指纹整层缺失**（ja4t、TCP options 顺序、TTL 推断跳数、MTU）。我们的观测点
  用普通 socket，拿不到 TTL/窗口等 IP/TCP 头字段——需要 raw socket 或 eBPF。同类
  工具 pingly 有 `src/tcp/fingerprint.rs` 覆盖这层。
- **HTTP/3 与 QUIC 整层缺失**：现有观测点只做 TCP 上的 TLS，QUIC 走 UDP 且 TLS
  握手内嵌在 QUIC 帧里，需要另一套观测点。`srcaudit` 报出的 `0x0039`/`0xffa5`
  （quic_transport_parameters）盲区即源于此。
- **12 个扩展从未观测到**（`srcaudit` 实测）：BoringSSL 声明 31 个，我们见过 19 个。
  其中 `0x002a early_data`（0-RTT）、`0x0039`/`0xffa5`（QUIC）是真实会遇到的，仍是
  识别盲区。`0x002c cookie` 已试图触发：HRR 确实发生了，但 Go 服务端未下发 cookie
  （该扩展对服务端是可选的），需要一个会发 cookie 的服务端才能采到。
- **HRR 形态已验证，基本不构成盲区**：Chrome136/131、Firefox135 在 HelloRetryRequest
  之后重发的 ClientHello 与首连 13 字段差异为 0、JA4 相同，用首连表即可识别。唯一
  例外是 Safari，差异来自 padding（见上节方法论）。
- **Safari 没有恢复态，这是 WebKit 的行为而非我们的采集问题**（已查证，见下节）。

## 一个可用的伪装破绽：Safari 从不发 pre_shared_key

实测真 Safari 27 连续 6 次连接全部全新握手，不发 `session_ticket(0x23)`，也从不
发 `pre_shared_key(0x29)`。起初怀疑是我们的采集场景（IP 地址 + 临时信任的自签
CA）导致，**查证后否定了这个推测**：

Apple 开发者论坛 thread/796184 有人做了同样的对照实验——同一个本地 OpenSSL
服务器、自签证书、localhost：Chrome 有 `pre_shared_key`，Safari 没有。结论是与
自签证书/localhost/IP 均无关，是 Safari/WebKit 网络栈的根本限制。Apple DTS
工程师 Quinn 确认问题存在、"比看起来更复杂"，仍在调查中；影响 macOS 15.6 与 iOS。

由此得到一条识别判据：

| 观测 | 判定 |
|---|---|
| Safari 指纹 + 带 `pre_shared_key` | **不是真 Safari** |

curl_cffi 的 10 个 safari target（safari153/155/170/180/184/260 及 _ios 变体）
**全部**能采到 PSK 形态，真 Safari 一个都没有——curl-impersonate 只复刻了
ClientHello 的形状，没有复刻 WebKit 不做会话恢复这一行为。

## 真机采集的四条信任路径

L2 必须完成真握手，所以客户端得信任观测点的自签证书。四种客户端四条路，都已打通：

| 客户端 | 方式 | 副作用 |
|---|---|---|
| curl_cffi | `SSL_VERIFYPEER=0` | 无 |
| Chromium 系 | `--ignore-certificate-errors`（151 起还须 `-spki-list`） | 无 |
| Firefox | `certutil` 注入**临时 profile** 的 cert9.db | 无（临时目录，用完删） |
| Safari | 注入**用户**钥匙串，`finally` 里即删并核对残留 | 改钥匙串 + 弹真实窗口，故设 `--safari` 显式开关 |

Safari 那条是唯一有副作用的，默认不跑。观测点必须发**完整链**（`fullchain.pem`）：
只发 leaf 时 Safari 回 `CERTIFICATE_UNKNOWN`——Firefox 能用库里的 CA 补全，Safari 不会。

## 环境依赖

```bash
python3 -m venv .venv && .venv/bin/pip install curl_cffi hpack cryptography
brew install nss                      # certutil，给 Firefox 注入信任 CA
cd oracle/gotls && go build -o fizztls-probe .        # 采 tls-client 76 个 profile
go build -o hrrserver/hrrserver ./hrrserver           # HelloRetryRequest 观测服务端
```

注意本机 `http_proxy` 指向 reclaude（见仓库根 CLAUDE.md），所有采集命令须
`env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY`，否则流量被
中间代理改写，采到的指纹是代理的而不是客户端的。
