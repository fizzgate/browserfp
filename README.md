# tlsfp — 浏览器 TLS / HTTP2 / QUIC 指纹覆盖与验证

目标两条：**覆盖市面主流浏览器指纹**，以及**有办法证明覆盖是对的**。

后一条是重点。指纹这类工作最容易出的问题是"看起来对了"——JA4 一致、测试全绿，
实际发出去的字节和真浏览器差着关键一处。本项目的每个结论都要求可复现的实测支撑。

## 现状

| 指标 | 数值 |
|---|---|
| 唯一指纹 | **81**（来自 319 个 target 名，按 13 个确定性字段去重） |
| 连接形态 | 首连 61 + 会话恢复 15 + QUIC 1 |
| 来源 | 开源表 67 + 真机采集 15 |
| 含 h2 层 | 56/78；含 h3 层 1（QUIC 形态）|
| 重建门禁 | 77/77 |
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
      ├─ oracle/dockercollect.py Linux 版浏览器（容器内，补非 macOS 平台）
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

## 伪装链：从 UA 到可发送的字节

网关拿到 UA 之后，整条链是：

```
UA → parse_ua → 段表/等价关系选 profile → tlsfp_build_client_hello() → cosocket 发出
```

C 侧的构造器 `tlsfp_build_client_hello()` 与库里其他函数一样是**内存进内存出、
非阻塞**的，可直接在 nginx worker 里调。Lua 侧一步到位：

```lua
local rec, prof = tlsfp.client_hello("chrome", 151, "example.com")
-- rec 是可直接 sock:send() 的完整 TLS record
```

两个设计要点：

**random 与 session_id 每次调用都重新生成**。照抄 golden 里那份会让所有连接的
ClientHello 逐字节相同 —— 那比不伪装还容易被判。Lua 侧走 `resty.random`，C 侧
由调用方传入。

**SNI 支持插入而不只是替换**。库里 81 条 golden 只有 2 条带 `server_name`（都采
自无 SNI 场景），只做替换的话 `sni` 参数会被静默忽略。这个缺陷差点被掩盖：
cloudflare.com 有默认证书、没 SNI 照样通过，只有 example.com 会回
`handshake_failure(40)` —— **只测一个站点就会误以为没问题**。

验证两层，缺一不可：

| 门禁 | 验什么 | 为什么不够 |
|---|---|---|
| `test_build_parity` | C 构造 80 条 → Python 解析 → 与 golden 逐字段比 | 这是**自洽性**：字段全对，但 record 长度回填错一位、扩展块少两字节，解析器能忍、服务器不会忍 |
| `test_build_live` | 字节真发出去，看回 ServerHello 还是 Alert | 这是**可用性**，当前 12/12（4 个 profile × 3 站点）|

`test_build_live` 必须打多站点：SNI 插入那个缺陷曾差点被掩盖 —— cloudflare.com
有默认证书、缺 SNI 照样回 ServerHello，只有严格校验 SNI 的站点才回
`handshake_failure(40)`。**只测一个站点得出的绿是假绿**。

## 一条命令看全部状态

验证入口散在 20 多个门禁 + covscan + live_handshake 里，想知道"现在到底什么
状态"得自己拼一遍，拼漏一项就会得出过于乐观的结论。

```
python -m spec.verify_all          # 静态门禁 + 覆盖度（不联网）
python -m spec.verify_all --live   # 再加端到端（对外发真实请求）
```

分三层，越往下越接近真实网络：

| 层 | 查什么 | 联网 |
|---|---|---|
| 1 静态门禁 | 数据自洽、Python/C/Lua 三方语义一致、文档不僵尸 | 否 |
| 2 覆盖度 | 生产 UA 口径与全版本口径分别缺多少 | 否 |
| 3 端到端与生产形态 | 每个 profile 能不能真握手；C 模块在真实 OpenResty worker 里是否与 Python 一致 | 是，默认跳过 |

**第 3 层默认不跑**：它对外发真实请求、还要拉镜像起容器，不该在每次改动后无脑
跑。但它查得出前两层查不出的东西：

· 派生 profile 缺 h2 层那次，字段级门禁全绿，只有真去握手才暴露
· `test_openresty` 第一次跑就撞到 `invalid ELF header` —— 本机编译的
  `libtlsfp.so` 是 macOS 的 Mach-O，而生产跑在 Linux OpenResty 上，这条链
  此前**从未在 Linux 上编译并加载过**。裸 luajit 的差分门禁验得了 FFI 语义，
  验不到平台/ABI 匹配与 nginx worker 内的加载时机。

## 三道门禁

```bash
python -m spec.test_rebuild            # 数据自洽：profile → 字节 → 解析 → 逐字段比
python -m spec.test_live_handshake     # 真实可用：34 profile × 2 站点，真握手 + h2
python -m spec.test_match              # 识别器：认得出 + 认不出必须报 unknown
python -m spec.test_real_stability     # 真机反复连接，每次都须认出（含充分性断言）
python -m spec.test_collector_merge    # 采集器必须合并写（防止只采子集冲掉其余样本）
python -m spec.test_ja4t               # TCP 层 JA4T 解析器（构造向量，不需抓包权限）
python -m spec.test_golden_orphans     # golden 不得有"采了却没人读"的孤儿文件
python -m spec.test_c_parity           # C 实现与 Python 逐字符一致
python -m spec.test_lua_parity         # Lua FFI 绑定与 Python/C 一致
python -m spec.test_ua_mapping         # UA 映射质量（真实生产 UA 分布为测试集）
python -m spec.test_alias_lookup       # 禁止"只比 id 不查 aliases"的查找
python -m spec.test_cross_source       # 跨库分歧规模 + same-seg 仅同库成立
python -m spec.test_c_ua_parity        # C 侧 UA 映射与 Python 一致（真实 UA 输入）
python -m spec.test_quic               # QUIC：RFC 9001 官方向量 + 真机端到端
.venv-wreq/bin/python -m spec.test_h3  # HTTP/3：GREASE 剔除 + 跨连接稳定性
python -m spec.test_cf_discrimination  # 指纹是否被区别对待（三臂对照）
python -m oracle.coverage              # 开源表对真机的覆盖矩阵
python -m oracle.srcaudit              # 源码审计：还有哪些扩展我们从没见过
```

自洽 ≠ 可用：字节拼得出、解析回来一致，不代表服务端会接受。两者必须分开验。

**识别稳定性是第三件独立的事**。注册表里每个 profile 是**某一次**握手的快照，而真机
每次握手都不同。`test_match` 拿注册表自己喂自己，永远发现不了"只在采集那一次能认出"
这种失效。实测（每浏览器 5 次连接）：

```
chrome   151  exact×5   JA4 取值=1   扩展顺序取值=5
chromium 142  exact×5   JA4 取值=1   扩展顺序取值=5
edge     151  exact×5   JA4 取值=1   扩展顺序取值=5
firefox  149  exact×5   JA4 取值=1   扩展顺序取值=1
```

Chromium 系每次连接扩展顺序都不同（RFC 8701 permutation）、GREASE 10 种取值、
ClientHello 长度在 1707/1739/1771/1803 间浮动，而识别始终命中 —— 这才说明稳定性
是真的。**门禁因此额外断言"Chromium 系扩展顺序取值数 > 1"**：若某次跑出取值恒为 1，
说明这轮验证根本没覆盖到变化，属于平凡通过，必须报失败。Firefox 不乱序也不发
GREASE，其稳定属平凡，故充分性只对 Chromium 系断言。

## 识别器

`oracle/match.py` 是整条链路的落点：输入 ClientHello，输出已知 profile 或 unknown。

| 档位 | 含义 |
|---|---|
| `exact` | 13 个确定性字段逐项相同 |
| `exact-no-pad` | 忽略 padding(0x15) 后相同（HRR 前后的真实差异） |
| `unknown` | 都不满足；同时给出最接近者与差异字段，供补录 |

识别结果同时返回该指纹的 h2（Akamai）与 h3（h3_text）应用层特征——**若实际观测到
的应用层与之不符，就是 TLS 层与协议栈对不上的 split-brain**。

QUIC 形态作为**独立条目**入库而非 TCP 那条的附加字段：实测 Chrome 151 的 QUIC 版
10 个扩展、TCP 版 15 个，用首连表去认 QUIC 连接一个都认不出。识别器实测能正确
区分（`real_quic:edge` / `real:edge` 是两条记录）。

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

## C 模块与 OpenResty 集成

```
csrc/tlsfp.{h,c}      ClientHello 解析 + JA4 计算 + 内置 profile 查表
csrc/gen_profiles.py  把 spec/profiles.json 编译成 C 静态数组（构建期常量）
lua/tlsfp.lua         LuaJIT FFI 绑定
```

**架构约束（集成的前提）**：库内所有函数都是**内存进内存出、非阻塞**的——不做
socket I/O、不做文件 I/O、不 sleep。网络 I/O 一律由 Lua 侧的 cosocket 承担，
在等待时 yield 给事件循环。若把阻塞 I/O 放进 FFI，一次调用就会冻死整个 nginx
worker（实测一个 9s 的阻塞调用能让同 worker 上的并发请求卡住 8.88s）。

profile 编译进只读段而非运行时解析 JSON：数据是构建期常量，这样既快又少一类
解析漏洞。只编入 76 条默认配置形态。查表**不做近似匹配**，未命中返回 NULL/nil。

**验收标准是四方差分，不是"看起来实现了规范"**。规范的模糊处（GREASE 剔除、
JA4 各段排序与占位、ja4_c 排除 SNI/ALPN）已在 Python 侧被真机数据与 RFC 官方
向量校准，C/Lua 照抄其行为：

```
Python  ←→  C CLI       77/77 一致
Python  ←→  luajit FFI  77/77 一致
真实 OpenResty worker 内实测：profiles=76，识别 real:edge 正确
```

FFI 绑定层有独立的出错空间（结构体布局、字符串所有权、参数传递），不会崩溃只会
给错结果，所以 Lua 侧单独比一遍，而不是"C 对了 Lua 就一定对"。

## UA → profile 映射（生产实际用法）

网关在 CDN 之后**拿不到客户端的 ClientHello**，只能看到 UA。所以出站代理浏览器
流量时，是按 UA 挑一个匹配的指纹去伪装——挑错就成了"UA 说是 Chrome 150、TLS 却
是别的形态"的 split-brain，比不伪装更容易被判。

三层实现语义一致（由差分门禁保证）：Python `oracle/uamap.py` 是权威，
C `tlsfp_lookup_ua()` 与 Lua `tlsfp.by_ua()` 供生产使用。

```lua
local r = tlsfp.by_ua("chrome", 150)
-- r.id="real:edge"  r.confidence="exact"  r.ja4=...  r.h2=...
-- confidence 必须检查：fallback 表示跨指纹段取的最近版本，有 split-brain 风险
```

分三档并**永远显式告知用的是哪一档**：

| 档位 | 含义 |
|---|---|
| `exact` | 该主版本有直接对应的 profile |
| `same-seg` | 落在同一指纹段内（可安全替代），两种证据都算：同库两端指纹一致，或**源码段表**证明同段 |
| `fallback` | 只能跨段取最近 —— **默认不返回 profile**，宁可不伪装 |

**严格模式是默认**：`fallback` 档一律返回 None/NULL。拿相邻版本的指纹冒充另一个
版本正是 split-brain 的来源——UA 说 Chrome 78、TLS 却是 Chrome 83 的形态，比完全
不伪装更容易被判，因为两者互相矛盾本身就是强信号。要伪装就必须精确。

**判据必须看条目的全部 aliases，不能只看 id** —— 这条在项目里踩过好几次，最后
一处是 `versions` 路径：`real:edge` 是本机 Chrome 151 与 Edge 151 的实采，按指纹
去重后 id 恰为 `real:edge`，而 aliases 里含 `real:chrome`。只从 id 推品牌会让
chrome 151 进不了 chrome 表，只能绕道段表报 `same-seg` —— 而它明明是直接采到的。
修完 Python 与 C/Lua 的全版本差分从 1 处降到 **0 处**。

跨品牌检查同理：注册表按
指纹去重，id 只是众多别名之一——`curl_cffi:tor145` 的 aliases 里含 `wreq:Firefox128`
（Tor 基于 Firefox ESR，指纹本就相同），`curl_cffi:chrome119` 含 `wreq:Edge122`。
只看 id 会把这些**正确**的映射误判成跨品牌而拒绝。真正要拒绝的是无同品牌依据的
套用（如把纯 Chrome 条目给 Edge 用）。

### 真实流量验证

测试集取自生产 access.log（`spec/fixtures/prod_user_agents.json`，60 种 UA /
14026 次请求），这是唯一能回答"库够不够用"的口径：

```
exact       82.3%
same-seg     9.9%     ← 可安全伪装合计 92.2%
fallback     0.0%     ← 主流品牌缺口已全部清零
unparsed     7.8%     ← 非浏览器 UA（扫描器、UC 浏览器、残缺 UA 等）
```

**主流品牌（Chrome / Firefox / Safari / Edge / Opera，含移动端）在生产流量口径下
已无缺口**。剩余 7.8% 是非浏览器 UA，按设计就该返回无指纹。

### 全版本扫描：生产口径之外还缺什么

生产 UA 只有 60 种，`fallback=0` 只说明**那批样本**没缺口。要知道真实覆盖边界，
得对每个品牌逐版本构造 UA 走一遍映射：

```
python -m oracle.covscan            # 全品牌
python -m oracle.covscan firefox    # 单品牌，附每个缺漏版本所属段的理由
```

扫描结果（这些版本生产流量里没出现过），合计缺 3 个：

| 品牌 | 已发布版本数 | 缺 | 成因 |
|---|---|---|---|
| chrome | 83 | — | 已全覆盖 |
| chrome-mobile | 83 | — | 已全覆盖 |
| firefox | 76 | — | 已全覆盖（78/83/111/121 四份 Linux 容器实采作锚）|
| firefox-mobile | 76 | — | 已全覆盖（桌面等价回落 + 145–153 派生）|
| safari | 9 | 12–14 | 无段表（闭源），且 iOS ≡ macOS 的证据只覆盖 15+ |
| safari-mobile | 9 | — | 已全覆盖（11–18, 26–27）|

### 覆盖棘轮：缺漏数只许降不许升

缺漏数只在手工跑 `covscan` 时才看得到，改坏了映射逻辑没有任何东西会报警。
`spec/test_coverage_ratchet.py` 把当前水位记下来，只在**变差**时失败：

```
品牌                   缺漏     水位
chrome                2      2
firefox               6      6
safari-mobile         0      0
合计缺漏 19 个版本（水位合计 19）
```

用棘轮而不是固定阈值，是因为缺漏数会随两件事变化：补进新 golden 会降、新版本
发布会升。固定阈值要么松到失效，要么每次都得手改。

**水位降下来后要手动改小，这一步刻意不自动化** —— 自动收紧会把"某次意外变好"
固化成新基线，而那次变好可能只是判据被放宽了。本项目就出现过两次这种情况
（把 ext_order 纳入判段、按全品牌出现率找"数据不全"记录），都是引入错误后回退的。

门禁本身做过变异测试：把一个可替代段标成不可替代，缺漏从 6 升到 10，门禁确实
报错并列出了具体版本号。

### 派生 profile：规则被验证过才用

`firefox-mobile 145–153` 那一段没有任何实采 golden，但**桌面有**，而源码明确
指出该区间两平台只差一处（Android 不发 SCT）。`oracle/derive.py` 据此从桌面
golden 派生移动端形态。

**h2 层也要一并派生**。只有 TLS 层的 profile 在生产里用不完整 —— 伪装浏览器
流量必然要发 HTTP/2，没有 SETTINGS 帧一看就露。实测 Android Firefox 的 h2 与
桌面不同（HEADER_TABLE_SIZE 65536→4096、INITIAL_WINDOW_SIZE 131072→32768，
移动端用更小的缓冲区），其余字段完全一致，所以整体取锚点的移动端 h2 而不是
自己编一组数值。派生结果做过端到端验证：对 cloudflare.com 与 example.com
TLS1.3 + h2 都通（HTTP 301 / 200）。

这不算"造样本"（README 上文的 covers_versions 一节讲过不塞推导样本），区别在于
**规则先在有实采 golden 的锚点版本上验证过**：

```
桌面 wreq:Firefox135  减去 SCT 与 MLKEM
= 实采 wreq:FirefoxAndroid135        逐字段一致
```

而且**每次派生都会重跑这个验证，不通过就拒绝派生** —— 规则的前提哪天不成立了，
派生出来的就是错的，那时应该报错而不是静默产出。派生结果的 `provenance` 单列
`source-derived`，不混进 real-capture 的统计。

派生时必须重算 ja4：删掉扩展后计数变了，不重算会得到一份自相矛盾的 profile ——
ja4 首段写着 16 个扩展、字段里只有 15 个，识别时按 ja4 查表永远命不中自己。

`spec/test_derive.py` 盯住这条链的三件事：规则在锚点版本上仍成立、库里每条
派生 profile 都能从记录的来源**重新派生出同样的结果**、`source-derived` 没有
混进 real-capture 统计。第二条是核心 —— 派生产物是推导结果而非观测，一旦它的
输入变了却没重新派生，库里那份就成了无人负责的陈旧数据。门禁做过变异测试：
篡改派生结果、删掉 `derived_from`，两种都能抓到。

**"文件不存在"与"feature 不存在"要分开**。2018 年的 Chromium 还没有
`net/base/features.cc`，抽取器若在取不到时返回 `None`，就会与后来版本的 `False`
判成不同值 —— chrome 71 正是这么被从段 70 切出去的，而两者真实差异只有
`channel_id`。同理"feature 消失即已转正"这条规则只在该 feature **曾经存在过**
的年代成立：M71/M72 的 features.cc 只有 700 多字节、通篇没有 ECH 概念，却因这条
规则被判成发 ECH。年代下界必须实测 —— 第一版按 95 猜，把 91–94 从原本可替代的
段里切了出来，缺漏反而从 5 涨到 11；逐版本查过 85–99 才定到 M97。

**扫描上界要跟着已发布版本走**。本机 Safari 已是 27.0，而扫描上界一度停在 26 —— 
那个区间出问题也发现不了。改到 27 后立刻暴露一个真实缺口：`real:safari` 是本机
Safari 27 的实采、其 iOS 别名只到 26，于是桌面有 27 而 `safari-mobile` 缺 27，
**同一条记录、同一份指纹，两侧覆盖范围却不同**。修法是：条目若同时带移动端别名，
说明该指纹在两个平台都被观测到，桌面 `versions` 里的版本号也该注册给移动端。

**从未发布的版本不计入缺漏**，否则会凭空多出一串永远补不上的"缺口"：
Chrome 82（2020 年疫情期间从 81 直接跳到 83）、Safari 19–25（2025 年 Safari
从 18 直接跳到 26，跟随 OS 版本号）。这两条写在 `oracle/covscan.py` 的
`NEVER_RELEASED` 里。

成因分两类，处理方式不同：

1. **段内没有任何实采 golden** —— 源码能定段边界，但定不出段内该用哪份指纹，
   需要至少一份实采作锚。补齐靠实采。
2. **段内实采数据互相矛盾** —— 不是判段维度不足。实测 chrome 段 97–118 里
   wreq 的 ECH 排开看是「105 有、106–114 无、116 又有」，没有哪个版本演进能长
   这样，只能是抓包时落在不同 Finch 实验组。

   这类分歧按**库内分组规模**判：若最大组覆盖的版本数超过其余组之和，取多数
   （chrome 段 97–118 的 wreq 是 9:2:2，且 curl_cffi 7 个版本、tls_client
   11 个版本都各自一致，三家里两家无分歧）；1:1 这种平局不算多数，段保持
   不可替代 —— **段内证据势均力敌时，"不伪装"比"挑一个用"正确**。

   **跨库共识可以压过单库内部的分歧**。同一版本在不同库里指纹常常不同，所以
   跨库"不同"没有意义；但跨库**相同**是强证据 —— 采集噪声不会让几家独立抓的
   包凑成同一份指纹。实测段 108–111：补进 Linux 容器实采的 firefox 111 后，
   `linux:111` / `tls_client:108` / `wreq:109` 三个独立来源指纹完全一致，只有
   `tls_client:110` 一条孤立不同（缺 `0x23`、`0x2d`），判据因此改为"三家以上
   一致且多于少数派"时取共识。

### Chrome 的 ECH 与 ALPS codepoint：源码默认值 ≠ 实际行为

这两个维度都受 Finch 运行期覆盖，源码只给出默认值：

| 维度 | 源码 | 实采 |
|---|---|---|
| `kUseNewAlpsCodepointHttp2` | M126–133 全 DISABLED | 四家一致显示 M132+ 已改发 `0x44cd` |
| `kEncryptedClientHello` | M119 起 ENABLED | wreq 的 105/116 提前发了 |

所以它们**只在自洽的数据上可用于判段**：curl_cffi 的 `chrome99_android`(无 ECH)
与 `chrome131_android`(有 ECH) 是干净的一对，据此切 `chrome-mobile` 段站得住；
拿同一维度去解释 wreq 内部的跳跃则必然失败。

**服务范围：只覆盖主流品牌**（Chrome / Firefox / Safari / Edge / Opera，含各自的
移动端），其余一律返回"无指纹"而不是找个近似的顶上。OkHttp 栈、UC 浏览器、各类
扫描器都属此列 —— 库里虽有 okhttp4_android_*、nike_android_mobile 这些条目（对
**入站识别**有用），但它们不参与出站的 UA→profile 映射。

**safari 12–14 是唯一没有路径的缺口**，原因值得写清楚，免得以后有人误以为能靠
iOS 侧的数据补上：

`safari-mobile` 确实有 11–14 的实采（utls 的 `IOS_11_1/12_1/13/14`），而
"iOS ≡ macOS Safari" 这条关系也确实成立 —— 注册表里 4 条 profile 同时含两侧
别名。但把两者接起来需要**同号对应**，而实测对应关系是：

```
iOS 14        ↔  桌面 Safari 15      ← 偏移一位
iOS 15/16/17/18/26  ↔  桌面同号
```

同号对应从 15 起才成立，12–14 那个年代（2018–2020）没有任何桌面侧证据能锚住。
拿 iOS 12 的指纹去服务桌面 Safari 12 的 UA，既没有等价证据、版本号对应也可疑，
正是本项目一直在防的那种"看起来合理"的替代。**保持缺口比编一个映射诚实**。

**utls 的 iOS 条目命名不带品牌名**（`IOS_11_1` / `IOS_12_1` / `IOS_13` /
`IOS_14`），别名解析若要求以品牌名开头就会漏掉它们 —— `safari-mobile` 表因此
一度凭空少了 11–14 四个版本。它们确实是 iOS Safari 的指纹（11/12 还是 TLS 1.2
时代的 `t12i`），补上解析形态后 `safari-mobile` 已全覆盖。

**iOS 上的第三方浏览器按 Safari 处理**。App Store 政策强制所有 iOS 浏览器使用
系统 WKWebView，自己不带 TLS 栈，所以 FxiOS / EdgiOS / CriOS / OPiOS 发出的
ClientHello 就是 iOS Safari 的。版本要按 **iOS 版本**取而非它们自己的版本号——
生产里有 `FxiOS/128.4` 跑在 iOS 15 上，用 128 去查 safari 表只会张冠李戴。
这一条覆盖了 147 次请求。

**移动端与桌面分开计**。生产里 569 次（4.1%）是移动端 UA，其中 287 次曾被映射到
纯桌面 profile —— UA 说 Android Firefox 115、TLS 却是桌面 Firefox 102 的形态，
正是本项目一直在防的 split-brain。修正后这些请求在严格模式下拒绝伪装，覆盖率
因此从 91.2% 回落到 88.2%。**那 3% 是过去被算进"可安全伪装"的错误映射**，不是
能力倒退。

另外 282 次移动端请求的映射是**对的**：注册表按指纹去重后，`curl_cffi:safari155`
的别名里同时含桌面与 `safari_ios_15_5`，说明这两者指纹本就相同。判据因此不是
"移动端一律拒绝"，而是"命中的 profile 必须带移动端别名"。

这条规则的证据基础是注册表里 6 条同时含两侧别名的 profile（Safari 占 4 条，
iOS ≡ macOS 覆盖 153/155/180/26）。`test_ua_mapping` 断言该数不少于 3 —— 推断
类规则不配门禁的话，前提悄悄消失了也没人知道。

**移动端数据密度远不如桌面**，这是当前最大的实际缺口：

| 品牌 | 已有版本 | 生产需要但缺 |
|---|---|---|
| `safari-mobile` | 15, 16, 17, 18, 26 | —（已全覆盖）|
| `chrome-mobile` | 99, 131（+ 源码段表覆盖 97–132）| 134 |
| `firefox-mobile` | 135（+ 源码段表覆盖 124–144）| 115 |
| `edge-mobile` | — | —（按 UA 内核版本走 chrome 表）|
| `edge-mobile` | — | 120 |

源码推导对 **Android Firefox 可用**：它与桌面共享 NSS，差异全在 StaticPrefList
的 `ANDROID` 分支里 —— 实测 135 版只差两处，都能由 pref 解释（不发 SCT，因为
CT mode 在 `#if defined(ANDROID)` 下是 0；不发 MLKEM，因为
`enable_kyber = @IS_NOT_ANDROID@`）。按 android 平台求值后推导出的形态与
`wreq:FirefoxAndroid135` 三项逐字段吻合，据此建了 `firefox-mobile` 段表。

**但这条链的验证基础远弱于桌面**：桌面 Firefox 的 SCT 维度有 47 条实采比对，
Android 只有 1 条（FirefoxAndroid135，单版本单来源）。段表 5 个段里 4 个段内
没有任何 golden，所以只有 124–144 段真正可用。要提高置信度只能补更多 Android
实采。

**Android Chrome 同样可推导**。差异同源于硬编码的平台分支：

```c
BASE_FEATURE(kPostQuantumKyber, "PostQuantumKyber",
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
             base::FEATURE_DISABLED_BY_DEFAULT);   // 移动端默认关
#else
             base::FEATURE_ENABLED_BY_DEFAULT);
```

而 `PostQuantumKeyAgreementEnabled()` 就是 `IsEnabled(kPostQuantumKyber)`。据此
建的 `chrome-mobile` 段表，边界与实采吻合（`chrome131_android` 落在启用 MLKEM
之前的段、确实没有 `0x11ec`）。再补上 ECH 维度（`kEncryptedClientHello` 在 M119
翻成 ENABLED、M124 起转正为默认行为）后，97–118 与 119–132 两段各自内部一致，
覆盖了生产里 chrome-mobile 的四个缺口版本。

iOS Safari 闭源，这条仍用不上 —— 但 iOS 上所有浏览器共用系统 WebKit，
`safari-mobile` 靠实采 golden 已全覆盖。

**剩余两个缺口只能实采**。已逐库核对过四家的移动端变体清单，没有一家收录：

| 库 | 移动端变体 |
|---|---|
| wreq | 10 个：`FirefoxAndroid135` + 9 个 Safari iOS/iPad |
| curl_cffi | `chrome99_android`、`chrome131_android`、`safari*_ios` |
| tls_client | 多为 App 的 OkHttp 栈（`okhttp4_android_*`、`nike_*`、`zalando_*`）|
| utls | `Android_11_OkHttp`、`IOS_11_1/12_1/13/14` |

`firefox-mobile 115` 与 `chrome-mobile 134` 所在的段内一条 golden 都没有 ——
不是判段维度没抓到，而是没有任何来源观测过那个区间。补齐需要 Android 真机或
模拟器实采。
四个开源库里的 android 变体（okhttp4_android_*、nike_android_mobile 等）绝大多数
是 **App 的 OkHttp 栈**而非浏览器，不能拿来服务浏览器 UA。

fallback 一度是 7.4%，靠三件事降到 0.3%：

1. **源码段表**（下节）—— 从产生 ClientHello 的源码推导版本区间，回答了抓包答
   不了的问题（两端分属不同来源库时本就不可比）
2. **Chromium 系按 UA 里的内核版本映射** —— Opera 110 的 UA 里写着 `Chrome/125`，
   OPR 版本与内核版本差了 15，按 OPR 号查表必然张冠李戴；Edge 的 `Edg/` 与
   `Chrome/` 则完全一致（150/148/125/126 四种全对得上）
3. **逐个查清段内不一致的成因** —— 见"从差异字段回溯源码翻转点"一节

顺带厘清了流量构成：**浏览器只占全部请求的 4.9%**（Codex 47%、claude-cli 15.6%、
OpenAI SDK 12.2%、Go client 10.9%）。只有浏览器流量需要 TLS 指纹伪装，其余不需要
——这个边界决定了本项目的服务范围。

### 源码段表：不跑浏览器也能判版本异同

真实用户的浏览器版本极其分散，拿相邻版本顶就会发出 UA 与 TLS 矛盾的握手。要对
任意版本给出确定答案，必须知道每个指纹段从哪个版本起、到哪个版本止。抓包做不到
这点——历史版本要下上百 MB 二进制、还未必跑得起来，两端分属不同来源库时更是无从
比较。

改读源码：ClientHello 的构成由若干张表与开关决定，按 tag 取几个文件就有。

| | Firefox | Chrome |
|---|---|---|
| 源 | hg.mozilla.org 按 release tag | jsDelivr 上的 chromium/chromium 与 google/boringssl |
| 决定性表 | NSS 的 cipherSuites / defaultSignatureSchemes / clientHelloSendersTLS | BoringSSL 的 kExtensions / kSignSignatureAlgorithms |
| 还须读 | gecko 的 namedGroups[]、StaticPrefList.yaml | Chromium 的 kCurves/kGroups、kVerifyPrefs、cipher 排除项、features.cc |
| 段数 | 11（78–152 全覆盖） | 12（70–153，M82 从未发布） |

产物在 `spec/segments/*.json`，每段带 `substitutable` 与判定理由。**逐段判定而非
品牌级开关**：同一品牌里有的段实采 golden 一致（可替代），有的段同一来源库内就
分歧（段划粗了，不可替代）。

### 从差异字段回溯源码翻转点

段内两条 golden 不一致时，不去猜，而是把差异字段拿出来回源码找那个字段是**哪个
版本、哪行代码**翻转的。四个缺口都是这么解掉的：

| 缺口 | 差异字段 | 源码翻转点 |
|---|---|---|
| chrome 78 | `0x7550` Channel ID | Chromium M72 删掉使用它的代码（M70 有 35 处引用、M72 起 0 处）|
| chrome 95 | `0x4469` ALPS | `kAlpsForHttp2` 自 M92 出现即 `ENABLED`，M91 及以前无此符号 |
| firefox 115 | `0xfe0d` ECH | `network.dns.echconfig.enabled` 在 119 起才是 `true` |
| firefox 126/127/134 | `0x001b` 等 | NSS `clientHelloSendersTLS` 表在 124 新增 |

每一条都能落到具体代码，且实采两侧都对得上——不是推断。

### covers_versions：用已验证的等价关系，而不是造样本

生产第一大浏览器 UA 是 Chrome 150，而我们只实采了 151。**没有**为此往库里塞推导
样本，而是记录"这条实采指纹经验证同时适用哪些版本"：surf 源码写明
`HelloChrome_150 = HelloChrome_144 + 前置 ML-DSA`，据此推导的 Chrome150 与真机
Chrome151 实测 **13 字段差异为 0**。该标注只在有硬证据时添加。

## 跨库比较不可作为版本演进的证据

实测同一版本在不同来源库里的指纹就不一致：

```
Firefox133  wreq vs tls_client   差 2 项（extensions_ordered, psk_modes）
Firefox135  wreq vs curl_cffi    差 1 项（record_size_limit）
Firefox120  tls_client vs utls   差 2 项
```

规模：**29 个版本被多库同时收录，其中 17 个存在跨库分歧（59%）**。各库抓包的
环境、时间、feature 配置不同，跨库比出来的"相同/不同"都没有意义。

这条曾导致真实误判：先前拿 `tls_client:firefox_123` 与 `wreq:Firefox128` 比较，
得出"Firefox 123↔128 差 3 项、中间必有变更点"，进而把 Firefox 124–127 判为
"不能安全替代的缺口"——而那个差异有多少来自版本演进、多少来自库间建模差异，
根本无从区分。

正确做法是**在同一个库内部**看版本演进，结论完全不同：

```
wreq 内部：      135 → 136 → 139 → 142 … → 151   全部相同（16 个版本一个指纹）
tls_client 内部： 102–108 相同；108→110→117→120→123 每档都变
```

`uamap` 的 `same-seg` 判定因此要求两端**既指纹相同、又出自同一来源库**，
由 `spec/test_cross_source.py` 断言。

## 关键方法论

**判据不能用 JA4。** 14 个 chrome target 只产生 4 个不同的 JA4，safari170 与
safari172_ios 完全相同。断言必须走 13 个确定性字段的逐项比对，用 JA4 会假绿。

**去重要数唯一指纹，不数名字。** `tls_client` 里 safari_ios_15_5/15_6/16_0/17_0
是同一指纹的四个名字，按名字数会虚高。

**门禁必须打多个站点。** 曾经只打 cloudflare.com，34 条全绿，掩盖了"根本没发
SNI"——cloudflare.com 有默认证书不介意，多租户站点直接 handshake_failure。
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
| 打多租户站点恒 `handshake_failure(40)`，打默认证书站点正常 | profile 来自 no-SNI 采集，`raw_extensions` 无 `0x0000`，**根本没发 SNI**。曾误归因到 ECH |
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
| Edge | 23 | 7 | **151** | 151 | 已追平（真机实采）|

「55 个版本压缩成 22 个指纹段」再次说明版本数不等于指纹数。

**真实缺口（按可补性排序）**：

1. **Chrome 150** —— 有源码证据、无实采。surf 编译不了（要求 go≥1.27，本机 1.25.7），
   但其源码注释写明 `HelloChrome_150 mirrors HelloChrome_144 but prepends the ML-DSA
   signature schemes`。据此从 chrome_144 推导出 150 的指纹，与真机 Chrome 151
   **13 字段差异为 0** —— 即 Chrome 150 与 151 同指纹，**ML-DSA 引入点确定在
   (146, 150]**。该推导仅用于分析，**未入库**（注册表只收实采数据）。
2. ~~Edge 149–151~~ **已补齐**：装真机 Edge 151.0.4129.59 实采（TLS + h2 + 恢复态）。

   过程中修正了一个推测。曾判"Edge 属 Chromium 系、与同代 Chrome 同指纹，风险低于
   表象"，实测**证伪**：20 对同代版本里 18 对相同，但 Edge134 与 Edge146 不同，
   且差异实质：

   ```
   Edge134   扩展含 17613 (0x44CD, ALPS 新)，app_settings = []
   Chrome134 扩展含 17513 (0x4469, ALPS 旧)，app_settings = ['h2']
   ```

   Edge 比同代 Chrome 更早切换 ALPS codepoint。但实采 151 后又发现：**Edge 151 与
   Chrome 151 在 TLS 13 字段、h2 Akamai 指纹、HTTP 头序三层完全相同**。

   即 **Edge 的独立性是间歇的**——134/146 分叉、151 合并。既不能假设它总跟随
   Chrome，也不能假设它总是独立，只能持续实采验证。
3. **版本号空洞** —— 各品牌都有（Chrome 31 个、Firefox 58 个、Edge 35 个、
   Opera 24 个），指两端指纹不同、中间可能藏变更点的区间。但这只是**上界**：
   多数空洞里指纹并未变化。

⚠ 分析这类空洞时**不能假设版本号连续**：Safari 从 18 直接跳到 26（Apple 2025 年
改用年份命名），19–25 根本不存在，早期版本的自动分析曾把它们误报成高风险空洞。

## 平台维度是真实的区分点

用已采数据裁决了一个此前存疑的问题——**同版本浏览器在不同平台上指纹确实不同**：

| 对比 | 差异字段数 | 差在哪 |
|---|---|---|
| Firefox135 vs FirefoxAndroid135 | 2 | extensions_ordered, curves |
| Firefox136 vs FirefoxPrivate136 | 2 | extensions_ordered, psk_modes |
| Safari26_4 vs SafariIos26 | **4** | ciphers, extensions_ordered, curves, supported_versions |

这同时纠正了先前对 `enetx/surf` 的一处解读：它的 Firefox 移动端变体自陈是
placeholder（与桌面相同），**那是该库自己的简化，不代表平台维度不存在**。
wreq 的 `FirefoxAndroid135` 就是真实不同的。隐私模式同理，也是独立形态。

**差异在两层的表现并不一致**，单看任一层都会漏判：

| 对比 | TLS 层 | h2 层 |
|---|---|---|
| Firefox 桌面 vs Android | ❌ 不同 | ❌ **也不同**（`1:4096,4:32768` vs `1:65536,4:131072`）|
| Firefox 桌面 vs 隐私模式 | ❌ 不同 | ✅ 相同 |
| Safari 桌面 vs iOS | ❌ 不同（差 4 字段）| ✅ 相同 |

移动端改的是 h2 SETTINGS 的缓冲区大小（内存受限的合理结果），而隐私模式与
iOS Safari 只在 TLS 层有别。**所以识别必须同时看两层**——这也是 `identify()`
返回 h2/h3 特征的原因：TLS 认出来是 Firefox，h2 却是桌面形态而非 Android 形态，
就说明对不上。

当前平台标注分布（75 个指纹）：

```
未标注平台 38 · iOS 16 · Android 13 · macOS(真机) 8 · 隐私模式 1 · QUIC 1
```

「未标注」那 38 个是开源库对桌面 Chrome/Firefox 只给一份、未区分
Windows/Linux/macOS 的结果。**我们的真机采集也全部来自 macOS**——所以
Windows/Linux 桌面版是否与 macOS 同指纹，目前**没有直接证据**。Chrome 系跨平台
共用 BoringSSL，大概率相同；Firefox 走 NSS 且已证明 Android 版不同，桌面各平台
之间更值得实测。

## 已知缺口

- **chrome124 不可用**：服务端选 `X25519Kyber768Draft00 (0x6399)`，被 ML-KEM 取代的
  废弃草案，cryptography 未实现。刻意不加豁免表，让它每次都报出来。
- **5 个纯 TLS1.2 profile 未覆盖**：cloudscraper / confirmed_android / mesh_android_2 /
  okhttp4_android_7 / okhttp4_android_8。参考实现只做 TLS 1.3。
- ~~wreq 的 h2 采不到~~ **已解**：正确参数是 `tls_verify=False`。`verify` /
  `danger_accept_invalid_certs` / `cert_verification` 都会被**静默忽略**（构造不报错
  但仍校验证书），极易误判成"库不支持"。已采齐 133/133。
- **utls 那批刻意不采 h2**：utls 是纯 TLS 库，profile 里没有 h2 定义。套一个 Go 的
  http2 客户端能采到 SETTINGS，但那是 `golang.org/x/net/http2` 的默认值——**是 Go 的
  指纹不是浏览器的**，入库会污染数据且事后极难发现（它看起来完全合理）。
- **19 个缺 h2 层**，已分类且都不是遗漏：15 个来自 utls（纯 TLS 库无 h2 定义，
  刻意不采）；4 个来自 tls_client 且**本来就不走 h2** —— cloudscraper 与
  mesh_android_2 协商到 http/1.1，mms_ios / mms_ios_2 根本不发 ALPN。原先的 4 个：cloudscraper / mesh_android_2 / mms_ios / mms_ios_2 ——
  **均为非浏览器 app profile，浏览器侧无缺口**（四个真机浏览器全部三层齐全）。
- **CF 挑战未验证**：该端点本就不设防（三种指纹结果一致、无 `cf-mitigated`），
  要验 managed challenge 需要一个真正会触发的端点。
- **TCP 层：解析器已就绪，数据只能在生产入口采**。`oracle/ja4t.py` 可从 SYN 包算出
  JA4T（`window_size_options_MSS_windowscale`），已用构造向量验证（含"非 SYN 包必须
  报错"的阴性对照）。但**本地采不到数据**，且这不只是权限问题：

  1. ja4t 四项里只有 MSS 能经 socket API（`TCP_MAXSEG`）拿到，options 顺序与
     window scale **只存在于 SYN 包**，socket API 完全看不到；
  2. macOS 上 `/dev/bpf` 是 `crw------- root:wheel`，抓包必须 root；
  3. **即使有 root，回环上采到的也是失真值** —— 实测回环 `TCP_MAXSEG=4024`
     （loopback MTU 16384），真实网卡是 1460。TCP 指纹取决于客户端 OS 栈**加网络
     路径**（MTU、中间设备 MSS clamping），本地造不出来。

  故正确落点是在生产入口用 tcpdump/pcap 采 SYN 包再喂给解析器，而不是本地补。

  占位规则与参考实现 `0x676e67/pingly` 的 `src/tcp/fingerprint.rs` **逐条核对过**
  ——初版三处全写错（空 options / MSS 缺失 / window scale 缺失都写成 `0`，规范是
  `00`；且 **wscale 等于 0 也要当缺失处理**，pingly 用 `.filter(|v| *v != 0)`）。
  这类偏差不会报错，只会产出与其他工具对不上的 JA4T。**先查开源实现再动手，比
  自己照规范文字实现可靠。**

  pingly 另有三个我们尚未实现的 TCP 层维度：`SatoriFingerprint`（含 quirks）、
  `NetworkEstimate`（TTL 推断跳数）、`LinkEstimate`（MTU 估计）。
- **QUIC 的 ClientHello 已覆盖，H3 应用层待做**。`oracle/quic.py` + `quicprobe.py`
  可从 UDP 上的 Initial 包解出 ClientHello：QUIC Initial 的密钥由**公开 salt +
  客户端自选 DCID** 派生（RFC 9001 §5.2），旁路观测无需服务端私钥。密钥派生已对齐
  RFC 9001 Appendix A.1 官方向量（key/iv/hp 三项逐字节一致）。

  **QUIC 与 TCP 是两套指纹**，不能互相顶替——实测 Chrome 151：

  ```
  QUIC  q13i0310h3_55b375c5d22e_653d80c3fe9d  10 个扩展  ALPN=[h3]
  TCP   t13i1515h2_8daaf6152771_806a8c22fdea  15 个扩展  ALPN=[h2,http/1.1]
  ```

  QUIC 版含 `0x39 quic_transport_parameters` —— 正是 `srcaudit` 长期报"从未观测到"
  的盲区之一，至此消除。已采 chromium 系三个浏览器（chrome/chromium/edge 指纹一致）。

  **H3 应用层也已覆盖**：`oracle/h3probe.py` 用 aioquic 起 QUIC 服务端完成真握手，
  取客户端控制流的 SETTINGS 与请求的伪头顺序。实测 chrome/chromium/edge 三者一致：

  ```
  1:65536,6:262144,7:100,51:1|m,a,s,p
  ```

  **与参考实现有一处有意分歧：GREASE 设置项必须剔除，不能只排到末尾。**
  pingly 的 `sort_by_key(|s| (s.is_grease(), s.id))` 保留了 GREASE，而实测 Chrome
  连续 3 次的 GREASE 项 id 与 value **每次都随机**（4286499706/128806768986/
  96762675253…），保留它 h3_text 就三次三个值、根本不能当指纹；剔除后三次同值。
  这与 TLS 层按 RFC 8701 剔 GREASE 同理。剔除的同时保留 `has_grease_setting`
  布尔——发不发 GREASE 本身是区分点。

  **QUIC/H3 目前只覆盖 chromium 系**（chrome/chromium/edge）。Firefox 已尝试三种
  方式驱动其走 h3，均超时未建立 QUIC 连接：

  ```
  alt-svc-mapping-for-testing = "127.0.0.1;h3=\":port\""        ❌
  alt-svc-mapping-for-testing = "127.0.0.1:port;h3=\":port\""   ❌
  域名方式（network.dns.localDomains + tlsfp.test）              ❌
  ```

  需强调这是**采集侧的限制，不是实现缺失**：`quicprobe`/`h3probe` 处理的是任意
  客户端的 QUIC，只是"让 Firefox 主动对本地观测点发起 QUIC"这一步没成功
  （Chromium 有 `--origin-to-force-quic-on`，Firefox 没有等价的命令行开关）。
  Safari 更无此类入口。真实流量里的 Firefox/Safari QUIC 一样能被解析。
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
cd oracle/gotls && go build -o tls-probe .        # 采 tls-client 76 个 profile
go build -o hrrserver/hrrserver ./hrrserver           # HelloRetryRequest 观测服务端
```

注意本机 `http_proxy` 指向 reclaude（见仓库根 CLAUDE.md），所有采集命令须
`env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY`，否则流量被
中间代理改写，采到的指纹是代理的而不是客户端的。
