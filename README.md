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
| 重建门禁 | 80/80 |
| 可用性门禁 | 132/132（66 profile × 2 真实站点，2026-08-01 实测） |
| 伪装可用性 | 12/12（4 profile × 3 真实站点，2026-08-01 实测） |

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
| `test_h2_build` | C 构造 h2 开场 → h2probe 解析 → 与表逐字段比 | h2 的**自洽性**，644 条 |
| `test_h2_live` | h2 开场真发给服务器，看回响应头还是 GOAWAY | h2 的**可用性**，当前 10/10（5 种形态 × 2 站点）|

`test_build_live` 必须打多站点：SNI 插入那个缺陷曾差点被掩盖 —— cloudflare.com
有默认证书、缺 SNI 照样回 ServerHello，只有严格校验 SNI 的站点才回
`handshake_failure(40)`。**只测一个站点得出的绿是假绿**。

而"这批站点里有严格校验 SNI 的"这句话**不能只写在注释里**：站点策略会变（换
CDN、加默认证书），全变宽松了也没人知道，那时门禁看着还在跑、实际上已经测不出
"SNI 没发"这个缺陷。所以选站要求当场验 —— `check_hosts()` 逐个探"无 SNI 会不会
被拒"，没有严格站点或没有宽松对照都直接判失败。

github.com 已从站点表里换掉：本机对它是**持续性阻断**而非瞬时抖动，openssl 直连
三次里两次也失败（真实客户端对照）。留着它这条门禁会周期性假红，而假红久了就会
被无视。换成同样严格且可达的 www.iana.org。

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
| 3 端到端与生产形态 | 每个 profile 能不能真握手；C 模块在真实 OpenResty worker 里是否与 Python 一致；**扫描上限有没有落后于上游最新版** | 是，默认跳过 |

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
exact       81.9%
same-seg    10.3%     ← 可安全伪装合计 92.2%
fallback     0.0%     ← 主流品牌缺口已全部清零
unparsed     7.8%     ← 非浏览器 UA（扫描器、UC 浏览器、残缺 UA 等）
```

**主流品牌（Chrome / Firefox / Safari / Edge / Opera，含移动端）在生产流量口径下
已无缺口**。剩余 7.8% 是非浏览器 UA，按设计就该返回无指纹。

### h2 层：伪装是分层的，覆盖率也得分层算

TLS 层覆盖 99.5%，**h2 层 99.1%**。两层剩下的缺口现在是**同一批**：safari
12–14（见下文"唯一没有路径的缺口"），别的全部覆盖到了。
把两层合成一个数字会把后者藏起来，而"TLS 像 Chrome、h2 不像任何浏览器"恰恰是
最容易被判的组合 —— 它显示出一个现实中不存在的形态，比不伪装更可疑。

此前这一层根本没有构造器：C 只导出 `h2_akamai` **字符串**。那是识别用的标识
符，出站伪装拿它没用 —— 调用方还得自己反解析才知道该发什么 SETTINGS。现在
补齐了对称的一套：

```
TLS 层   tlsfp_build_client_hello()   → ClientHello 字节
h2 层    tlsfp_build_h2_preface()     → PREFACE + SETTINGS + WINDOW_UPDATE + PRIORITY
```

HEADERS 不在其中：它的内容依赖具体请求，本库只给出伪头**顺序**
（`tlsfp_h2_pseudo()`，形如 `m,a,s,p`）。

**没有 h2 数据的 profile 一律拒绝构造**，不退回一组默认 SETTINGS —— 那等于
发一个不属于任何浏览器的 h2 指纹。24 条 profile 属此列，门禁逐条断言它们确实
被拒绝了。

验证是真闭环，且**解析器必须复用 `oracle/h2probe.py` 的那份**：

```
C 构造字节 → h2probe 的帧解析器读回来 → 重算 akamai → 与 golden 逐段比
```

另写一份"验证用解析器"是拿自己的理解验自己的理解，两边一起错就一起绿。
h2probe 那套是真机采集时用来读浏览器帧的，它读得懂真浏览器，才有资格判我们
造的像不像。

门禁另外卡**分支覆盖下限**（`settings≥50 / window_update≥50 / priorities≥4`）：
priorities 只有 Firefox 系会发，全库仅 4 条，数字小但不能为 0 —— 为 0 意味着
构造器里 PRIORITY 那段（含 RFC 7540 §6.3 的权重减一）根本没被执行过，它的
正确性就只是一句没验过的声明。三个变异测试各自产生不同的红，证明门禁有效。

#### h2 必须按版本独立解析，不能搭 TLS 去重的车

最早 h2 是挂在 profile 上的，而 profile 按 **TLS 指纹**去重。两个版本 TLS 相同
而 h2 不同是常态 —— Chrome 的 h2 参数改在 `net/http/http_network_session.cc`，
与 BoringSSL 那边的 ClientHello 各改各的。实测后果：

```
curl_cffi:chrome100 这一条记录的 36 个别名带着三种不同的 h2，只存下一种
全库 8/81 条 profile 有这个问题，53 个别名拿到的不是自己那份
UA 口径下 chrome 106-117 共 9 个版本拿到的 h2，没有任何一个库把它归给这些版本
```

现在 h2 由 `spec/h2table.json` 按 (品牌, 版本) 解析，判据优先级：

1. **该版本自己的库条目**，多库须一致
2. **源码推导**（`oracle/chromiumh2.py`，见下）
3. **跨平台/跨品牌归一**，每条都有实证且每次建表都重验前提

归一规则与其实证：

| 规则 | 实证 |
|---|---|
| Chromium 系（chrome/edge/opera，含 -mobile）用桌面 Chrome 的推导 | curl_cffi 的 `chrome99_android ≡ chrome99`、`chrome131_android ≡ chrome131` |
| `safari-mobile` 取同版本桌面 | wreq 的 `SafariIos26 ≡ Safari26`、`SafariIPad18 ≡ Safari18` |
| **firefox-mobile 没有这条规则** | wreq 的 `FirefoxAndroid135` 与 `Firefox135` 实测不同（HEADER_TABLE_SIZE 4096 vs 65536、INITIAL_WINDOW_SIZE 32768 vs 131072） |

最后一行是重点：**一条规则在 Chromium 上成立不代表在 Gecko 上也成立**。前提重验
里因此还放了一条反向断言 —— firefox 两端必须仍然不同，哪天一样了，说明数据或
解析变了，那条判断要重新审而不是继续躺着。

#### 从 Chromium 源码推 h2

判据链比 TLS 那边还直接：

```
net/http/http_network_session.cc  AddDefaultHttp2Settings()   决定发哪些键
net/http/http_network_session.h   kSpdyMaxHeaderTableSize = 64*1024      → 1:65536
                                  kSpdyMaxHeaderListSize  = 256*1024     → 6:262144
                                  kSpdyMaxConcurrentPushedStreams = 1000 → 3:1000
net/http/http_network_session.cc  kSpdyStreamMaxRecvWindowSize = 6*1024*1024 → 4:6291456
                                  kSpdySessionMaxRecvWindowSize = 15*1024*1024
WINDOW_UPDATE = 15728640 - 65535 = 15663105
```

**键集随版本变，这正是源码强于猜测的地方**：

```
M100     {1,3,4,6}      推送还在，发 MAX_CONCURRENT_STREAMS，不发 ENABLE_PUSH
M106-116 {1,2,3,4,6}    推送移除，显式发 ENABLE_PUSH=0，仍发 MAX_CONCURRENT_STREAMS
M117+    {1,2,4,6}      不再发 MAX_CONCURRENT_STREAMS
```

**顺序不是我们定的**：`spdy::SettingsMap` 是 `std::map`，迭代按键号升序 ——
不能按源码里的书写顺序发（M120 源码里 `ENABLE_PUSH` 写在最前，线上却排第二）。

按 Safari coreTLS 那次立下的规矩先验证再使用：`test_chromium_h2` 拿各库对每个
版本自报的 h2 当基准，**44/44 逐字节吻合**。

#### 从 Gecko 源码推 h2

同样的办法在 Firefox 上也走通了，而且判据更完整 —— 连 PRIORITY 树都是写死的：

```
Http2Session::SendHello()   SETTINGS 按**源码书写顺序**写（不是 std::map 升序）
  1 HEADER_TABLE_SIZE = pref default-hpack-buffer
  if !allow-push:  2 ENABLE_PUSH = 0
                   3 MAX_CONCURRENT = 0     ← 门是后加的，见下
  4 INITIAL_WINDOW  = pref push-allowance
  5 MAX_FRAME_SIZE  = kMaxFrameData = 0x4000
  if disableRFC7540Priorities && send_NO_RFC7540_PRI:  9 = 1
WINDOW_UPDATE = pref pull-allowance - 65535
PRIORITY：CreatePriorityNode 的六个固定分组，只在 UseH2Deps() 时发
```

两处非平凡的判据：

**MAX_CONCURRENT 的门是后加的**。128 的源码在 `!allow_push` 分支里**无条件**写
它，132 之后才包进 `send-push-max-concurrent-frame`。所以不能只看 pref ——
pref 不存在时按"关"处理会让 128 少发一项。判据取源码结构：分支里有没有这条
写入、写入是不是被 pref 包着。

**Android 的差异不在 StaticPrefList 里**。实测 `FirefoxAndroid135` 与
`Firefox135` 差两处（HEADER_TABLE_SIZE 4096 vs 65536、INITIAL_WINDOW 32768 vs
131072），而 StaticPrefList 里这两个 pref 的桌面与 Android 求值**完全相同** ——
差异在 `mobile/android/app/geckoview-prefs.js` 的覆盖里：

```
pref("network.http.http2.default-hpack-buffer", 4096);
pref("network.http.http2.push-allowance", 32768);
```

TLS 那边的 `nsssrc.py` 用平台构建标记就够了，h2 这边不够 —— 同一套基础设施，
不同的坑。门禁因此**必须两个平台都验**：只验桌面的话，Android 推错了也全绿。

验证 28/28 吻合，其中 12 条带 PRIORITY 树（本项目的 `linux:firefox-111-linux`
实采是唯一能验到那棵树的样本）。

**wreq 的 `Firefox128` 其实是 Tor Browser**，必须排除。它在注册表里与
`curl_cffi:tor145` 同属一条 profile；Tor 会关掉 `allow-push`，于是发出
`ENABLE_PUSH=0` 与 `MAX_CONCURRENT=0`，而原版 Firefox 128 的 allow-push 默认是
`true`，那个分支根本不执行。**不能按名字判** —— 名字里没有 tor，判据得取注册表
分组。`uamap` 建版本表时早就排除 tor / private 了，这里同理。排除表本身也有断言：
它必须真的排除到东西，否则说明命名或分组变了、规则已失效。

**Firefox 78-99 那段的 pref 换过名字也换过文件**：

```
Firefox 100 起   StaticPrefList.yaml   network.http.http2.*
Firefox 78-99    all.js                network.http.spdy.*
```

只查 StaticPrefList 的 `http2` 名字，这 22 个版本整段推不出来。而且两个文件的
语法完全不同（YAML 的 `- name:` / `value:` vs JS 的 `pref("name", value);`），
拿 StaticPrefList 的解析器去读 all.js 的表现是"文件取到了、值恒为 None" ——
看起来像"这个版本没有这个 pref"。

**布尔开关的判据必须取源码结构，不能取"有没有 StaticPrefs:: 引用"**。78-99 读
pref 走的是 `gHttpHandler->AllowPush()` 这类访问器，压根不出现 `StaticPrefs::`；
按引用判会把 `allow_push` 判成假，于是给那段版本错发 `ENABLE_PUSH=0` —— 而它们
的 allow-push 默认恰恰是 `true`。

**`disableRFC7540Priorities` 那句表达式本身随版本变**，不能写死：132 起是
`!enabled_deps() || !CriticalRequestPrioritization()`，128 还多一项
`|| priority_header_enabled()`。它同时决定发不发 PRIORITY、以及 `9:` 那项的值，
所以是从源码里把表达式抠出来求值的。顺带一个反推不回去的坑：StaticPrefs 符号把
pref 名里的 `.` 和 `-` 一律压成 `_`，而 `network.http.priority_header.enabled`
两种分隔符都有 —— 只能正向匹配（把文件里的 pref 名归一后与符号比）。

#### 反过来：按 h2 指纹认浏览器

本项目一直是双向的 —— 出站按 UA 造指纹，入站按指纹认浏览器。TLS 侧早有
`identify()`（按 ja4 查），h2 侧的数据一直都在（记录里就带 akamai），却没有反查
接口。

**先量识别力，再定接口形态**：

```
644 个 (品牌,版本)  →  只有 19 个不同的 akamai
最常见的一条覆盖 223 个组合、6 个品牌
但**没有一个 akamai 跨引擎**
```

所以这一层能确定回答的是**引擎**，不是版本。接口据此返回 `engine` 加一个版本
区间，而不是假装能给出确切版本 —— 调用方不该拿 `ver_lo` 当"就是这个版本"用。

门禁三条：644/644 闭环（每条自己的指纹反查回来，引擎相符、版本落在区间内）；
"没有一个 akamai 跨引擎"这条前提仍成立（它是反查有意义的**唯一**理由）；
以及一条**反向断言** —— 最粗的那条必须真的很粗（当前 50 个组合），若哪天每条
akamai 只对应一两个版本，说明数据变了，"只能认引擎"这句保守话该重新审。

#### 四层要合起来验一次

每层都有自己的门禁，但**层与层之间的耦合分层测试恰好都测不到**：头顺序表里有
`sec-ch-ua`，取值却要从另一个按 (品牌, 版本) 查的接口拿；伪头序来自 h2 层、普通
头顺序来自头顺序层，HEADERS 帧里必须先伪后普。`test_masquerade_live` 把四层输出
真的拼成一个请求发出去。

**它当场抓出一个跨采集的上下文错配。** `upgrade-insecure-requests` 不是纯浏览器
属性，它看目标协议：

```
明文 HTTP（localhost 采集）      五个浏览器全发
HTTPS / h2（h2 实采）           Chromium 与 Gecko 发，**WebKit 不发**
```

本项目的伪装出网是 HTTPS，拿明文 HTTP 的采集去填 https 请求，Safari 伪装就会多出
一个真 Safari 在 https 上不会发的头 —— 与 UA-CH 那条"多发也是异常"同一类问题。
`values_for()` 因此带协议参数，默认 https。

**"服务端收不收"验不了头顺序。** 变异测试实证：把顺序整个反排，三个站点依然
全绿 —— HTTP/2 不在乎头的先后，顺序只影响"像不像浏览器"。所以这条性质另配一个
**独立 oracle**：拼出来的顺序必须与真机实采一致（取交集比对）。不能拿
`order_for()` 自比，compose() 本来就是按它排的，那是循环论证。

同一个方法在本项目里已经用过两次 —— sec-ch-ua 的洗牌方向也是"实采验不到、
改用源码断言"。**一条性质如果现有手段验不了，就换一个能验它的 oracle，
而不是把它当成验过了。**

#### 第四层：头的取值（`sec-ch-ua`）

顺序对了、值不对照样露馅。`sec-ch-ua` 是其中最要命的一项：里面有一个**按主版本号
确定性生成的 GREASE 品牌**，既非固定串也非随机串 —— 手写必然对不上，而它就明晃晃
摆在请求头里。

算法全在 `components/embedder_support/user_agent_utils.cc`，只依赖主版本号：

```
greasey_brand = "Not" + chars[v%11] + "A" + chars[(v+1)%11] + "Brand"
                chars = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"]
greasey_ver   = ["8", "99", "24"][v%3]
列表 = [greasey, {"Chromium", v}, {品牌, v}]，按 orders[v%6] 洗牌
```

表本身也从源码抠，不写死 —— `greasey_chars` 改过一次，写死会在老版本上算错。

**先验证再使用**：拿本机三个真实浏览器实采比对，刻意覆盖三条不同分支：

```
chrome-151     三项 + 品牌 "Google Chrome"                    ✅
chromium-142   两项 —— CHROMIUM_BRANDING 构建无品牌项          ✅
edge-151       同 151 的 GREASE 品牌，只换品牌名                ✅
```

采集用本地 HTTP 服务就够：UA-CH 只在安全上下文发送，而 **localhost 算安全上下文**。

**变异测试暴露了一条实采验不到的性质。** 把洗牌从散射
（`shuffled[order[i]] = list[i]`）改成收集，三条实采**依然 3/3 全绿** —— 因为本机
能拿到的版本置换恰好全是自逆的（151%6=1 是对换、142 走两项分支是恒等）。要区分得
有 `major%6 ∈ {3,4}` 的版本，本机没有、Chrome for Testing 的下载源又连不上。改成
**从源码断言赋值方向**，把"实采验不到"变成"源码变了就会红"。

只跑正向测试的话，这个错会以"一半版本对、一半错"的形式潜伏下去 —— 比全错更难发现。

代码形态换过一次而**算法实质没变**：132 起在 `GetRandomOrder()` 里，131 及更早
内联在 `GenerateBrandVersionList()` 里，置换表、`seed%6`、散射赋值一字不差。
第一版只认前者，把 97–131 整段判成"不支持"，而它们其实推得出来。当前覆盖 97–153
共 57 个版本；96 及更早的 GREASE 表还没出现，弃权。

**Opera 不推**：它的嵌入层会往列表里再加自己的品牌项，而本项目没有 Opera 实采 ——
加几项、叫什么名字都只能猜。

#### 检测方能主动出招：`Accept-CH`

前面几层都是"我们发什么"。但服务端可以**主动索要**：回一个 `Accept-CH`，看客户端
会不会像浏览器那样补发高熵提示。实测（服务端回 `Accept-CH` + `Critical-CH`）：

```
第 1 个请求      3 个低熵提示
              ↓  Critical-CH 让 Chrome **立刻重发同一个请求**
第 2 个请求      9 个（补齐 6 个高熵）
之后同源每个请求  9 个
```

补发的六项里，**只有一项推得出来**：

```
可推    sec-ch-ua-full-version-list
        与 sec-ch-ua 同一套算法，只是版本换成完整版本 —— 但 GREASE 那项要补
        ".0.0.0"（源码 GetProcessedGreasedBrandVersion：单段版本追加零段）。
        只差这一处，而这一处恰好最不像手写值。实采逐字节验过。

推不出  sec-ch-ua-platform-version   实采是 "27.0.0"（真实 macOS 版本），
                                     而 UA 缩减后恒为 10_15_7 —— 这是真正的
                                     额外熵，只能由调用方按场景给一个可信值
        sec-ch-ua-arch / -bitness    取决于伪装目标机器的 CPU，不是浏览器属性
        sec-ch-ua-model              桌面恒空串、移动端是机型，同上
```

这条边界写进 golden 的 `not_derivable` 并由门禁断言 —— 删掉它，后来人会默认
"这些也能推"，然后编一个值出来。

#### `sec-ch-ua-platform` / `-mobile` 必须与 UA 同源

真浏览器这两处同源：UA 字符串与 UA-CH 都由同一个平台判定生成。伪装时最容易的
出错方式是**一处照抄 UA、另一处硬编码** —— UA 说 Windows 而 platform 说 macOS，
是不用任何统计就能抓的交叉矛盾。所以这两项也由库推，不让调用方填：

```
Mozilla/5.0 (Windows NT 10.0; ...) Chrome/151     → "Windows"  ?0
Mozilla/5.0 (Linux; Android 14; Pixel 8) ...      → "Android"  ?1
Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 ...)      → 没有
```

平台串取自源码（`GetPlatformForUAMetadata`：macOS 写死 `"macOS"`、Android 是
`"Android"`、其余走 `GetOSType()`），门禁断言它们仍在源码里 —— 那段有 TODO
说想改名，改了就该红而不是继续发一个不存在的值。

**匹配顺序踩过两处**，都单独立了断言：

· `iPhone/iPad` 必须排在 `Mac` 前 —— iOS 的 UA 里写着 `like Mac OS X`，
  不先拦下来会给 iPhone 推出 `"macOS"`；而 iOS 上所有浏览器都是 WebKit、
  根本不发 UA-CH，正确答案是"没有"
· `Android` 必须排在 `Linux` 前 —— Android 的 UA 里也写着 `Linux`

C 与 Python 用的是两张独立的表，顺序又是关键，所以门禁逐条比对（10/10）。

#### UA-CH 什么时候该发、什么时候绝不能发

"少发"和"多发"是对称的两个坑，都实测过：

| 场景 | UA-CH 头 |
|---|---|
| Chrome / Chromium / Edge，https 或 localhost | `sec-ch-ua`、`sec-ch-ua-mobile`、`sec-ch-ua-platform` **三个都发** |
| Chrome，明文 HTTP 打 LAN IP（非安全上下文） | **一个都没有** |
| Safari 27 | 从不发（11 个头里没有任何 `sec-ch-ua-*`） |
| Firefox | 不实现 UA-CH |

本项目的伪装出网是 TLS + h2，也就是 https，**必然是安全上下文** —— 这种情况下
真 Chrome 一定发这三个头，少发本身就是异常。反过来伪装 Safari/Firefox 时绝不能
发。默认也只发这三个"低熵"提示，`-platform-version`、`-arch` 这些高熵项要服务端
先用 `Accept-CH` 索要（本次采集里确实只有三个）。

这条规则连同实测记在 `spec/golden/uach_real.json` 的 `_context_rule` 里，
门禁会断言它没被改动 —— 采到的结论若只写在文档里，改错了没人会发现。

#### 采集环境本身也要被验一遍

那五份实采是无头浏览器打本地 HTTP 采的（Safari 除外）。**无头会改变发出去的
头**，不查清楚就用，等于把采集环境当成浏览器行为。同机有头 vs 无头逐字段比：

```
被污染          user-agent（HeadlessChrome/…）、accept-language（新 profile 的
                locale）、cookie（新 profile 没有）
完全相同        头名顺序（交集 13 个）、accept、accept-encoding、
                upgrade-insecure-requests、sec-fetch-*、
                sec-ch-ua-mobile、sec-ch-ua-platform
```

结论：污染的三项**恰好都不在本项目实际使用的表里**（`accept-language` 早就因为
"是系统 locale 不是浏览器属性"被排除了，这次拿到了第二重证据 —— 有头是
`zh-CN,...`、无头是 `en-US,...`，同一台机器同一个浏览器）。

这条测量写进 `headers_real.json` 的 `_capture_note`，门禁断言它与取值表不相交，
并且断言 `user-agent` 确实被记在污染清单里 —— 那个字段看着最像"现成可用的
真实 UA"，最容易被后来人直接拿去用。

**污染的是取值，不是位置。** 门禁第一版查的是"被污染的头名有没有出现在顺序表
里"，把三条正常的顺序全判成有问题 —— `user-agent` 的位置本身没被污染，实测
有头与无头的交集顺序完全一致。

顺带白捡一个验证点：有头那次 `open -a` 复用了**更新前就在跑的 Chrome 150 进程**
（磁盘上的二进制已经是 151）。于是拿到了 M150 的真实 `sec-ch-ua`，推导逐字节
命中 —— 而且它是**有头**采的，交叉证明了无头不影响 `sec-ch-ua`。

#### 头的取值：只收浏览器决定的那几项

实采五个真实浏览器（Chrome 151 / Chromium 142 / Edge 151 / Firefox 153 /
Safari 27）之后，能进表的只有三项：

```
accept                      Chromium 长（带 image/avif、signed-exchange），
                            Gecko 与 WebKit 短
accept-encoding             Chromium 与 Gecko: gzip, deflate, br, zstd
                            **WebKit: gzip, deflate**    ← 强判别位
upgrade-insecure-requests   1
```

**`accept-language` 绝不能进表。** 它取决于系统 locale 与用户设置，不是浏览器
属性 —— 本次采集里 Firefox 显示 `zh-CN,...` 而其它是 `en-US`，那是新建 profile
取 locale 的差异。把它抄进去等于把采集环境的 locale 泄漏给每一个使用者。
`sec-fetch-*` 同理，取决于请求类型（导航/子资源/XHR），调用方比我们清楚。
门禁对这两条都有断言。

同引擎的多份采集在这几项上必须一致 —— chrome/chromium/edge 三份确实逐字节相同，
这本身就是"由浏览器决定"的验证；不一致就说明那一项不该留在表里。

#### 第三层：请求头顺序

伪装是**三层**的 —— TLS、h2 开场、请求头顺序。前两层都对了、头按自己的顺序发，
照样能被判。

```
tlsfp_build_client_hello()   ClientHello 字节
tlsfp_build_h2_preface()     PREFACE + SETTINGS + WINDOW_UPDATE + PRIORITY
tlsfp_header_order()         请求头的相对顺序          ← 本节
```

**库里那 240 条 `header_order` 不能用。** 它看着像现成数据，实际上是**各库
自己的发头顺序**，不是浏览器的。把所有观测当成偏序约束一检验就露馅：

```
chrome    79 条观测 → 顺序矛盾 398 处
          curl_cffi:chrome100 说 sec-fetch-dest 在 sec-fetch-mode 前，
          wreq:Chrome100 说反过来
firefox   33 条观测 → 矛盾 183 处
safari    28 条观测 → 矛盾 203 处
```

同一个浏览器同一个版本，两家库给出相反的先后 —— 那不可能都是浏览器的行为。
门禁里因此有一条**反向断言**：这些矛盾数必须保持在高位。它防的是"哪天有人看见
240 条数据觉得浪费、把它接回来"；真降到 0 才说明数据源变了，那时才该重新评估。

**实采则是干净的**，而且这一层按**引擎**建模、不按版本：

```
chromium   13 个头   ← chrome 151 / chromium 142 / edge 151 三份逐项相同
gecko      11 个头   ← firefox 149
webkit      8 个头   ← safari 27
```

Chromium 那三份相隔 9 个大版本仍然一致，是"引擎级且跨版本稳定"的实证。

**只回答相对顺序，不回答发哪些头。** 实际发哪些头由请求类型决定（导航请求有
`upgrade-insecure-requests` 与 `sec-fetch-user`，子资源请求没有）—— 库数据里那些
看似"品牌差异"的东西，多半就是请求类型不同造成的。调用方比我们清楚它要发什么，
本库只把认识的那些摆到对的位置，不认识的保持原序排在最后。

**移动端全部标成"按引擎推断"**：本项目的真机采集都是桌面浏览器。移动端的头名与
顺序大概率与桌面相同（`sec-ch-ua-mobile` 变的是值不是名），但"大概率"不是实证。
门禁断言移动端不得被标成实采背书 —— 标错会让调用方以为那份顺序是采到的。

#### h2 也要验"能不能用"，不只是"对不对"

TLS 层早就有"字节真发出去看服务端收不收"，h2 层此前只有自洽性检查 —— 构造出的
帧解析回来与表一致。**自洽不等于可用**：帧头长度写错一位、SETTINGS 项数与载荷
长度对不上、WINDOW_UPDATE 增量写成 0（RFC 7540 禁止），解析器能忍、服务器会回
GOAWAY。变异测试实证了这两种：

```
SETTINGS 帧头长度少 6 字节      → 0/5 通过
WINDOW_UPDATE 增量写成 0        → GOAWAY error_code=1（PROTOCOL_ERROR）
还原                            → 5/5 通过
```

**TLS 那一跳故意用 Python 自己的 ssl，不用我们构造的 ClientHello**。这是分层：
TLS 层有它自己的实网门禁，两层混在一起的话一次失败没法归因 —— 到底是握手被拒
还是 h2 被拒？分开之后这条门禁的红只可能来自 h2 层。

验到**响应头**才算通过，不是"没报错就算"：服务端回了 `:status`，说明它接受了
我们的 SETTINGS，也接受了按 profile 伪头序发出去的请求。

两个容易写错的细节：

· **首个请求流的 ID 取决于有没有 PRIORITY 分组**。Firefox 的开场用 3..13 建六个
  优先级节点，真实请求从 15 开始；Chrome 系没有分组，从 1 开始。发错会被服务端
  当协议错误，而那是我们自己的问题。
· **站点要可达且真能协商出 h2**。本机 Google 系域 DNS 能解析但连不上，拿它当
  第二站点会让门禁恒红 —— 那比没有门禁更糟。

用例按**形态**挑而不是随便选版本：`{1,2,4,6}`、`{1,2,3,4,6}`、`{1,4,5}+PRIORITY`、
`{1,2,4,5}`、`{2,3,4,9}`（Safari，伪头序也不同）。带 PRIORITY 那一档另有断言：
它必须真的通过过，否则等于没覆盖到风险最大的形态。

#### Safari：没有源码，靠三条判据补齐

Safari 闭源、coreTLS 已被证伪，但剩下的 11 个缺口里有 8 个并不需要源码：

**主版本内的小版本演进 vs 离群值，要分开处理。** 库里的条目名带小版本
（`safari184` = 18.4、`Safari17_4_1`、`safari_ios_18_5`），而表按主版本存，
一格只能放一份。判据是"按小版本排序后，各形态是否连续成段"：

```
safari 18   18.0/18.1.1/18.2/18.3/18.3.1 有 8:1，18.4/18.5 没有   → 干净分界
            取末尾形态。与本项目对 Chromium 的规则一致：同一主版本取最后一个
            patch，那是用户实际跑得最多的形态
safari 17   17.0/17.2.1 一种，17.4.1 另一种，17.5/17.6 又回到第一种 → 交错
            不是演进而是离群，按多数取（5:1）
```

**本项目自己的实采本该是最硬的来源，此前却排在最外面。** `observed()` 只读
`spec/golden/h2_*.json` 那几个库文件，而 `profiles.json` 里 `real:*` / `linux:*`
的真机采集同样带 h2、还带着确切版本号 —— `real:safari` 的 `versions` 就是
`['27.0']`，本机 macOS 27 上采的 Safari 27。漏掉的后果是 safari 27 被判成
"无库条目且源码取不到"，而那份数据一直躺在库里。补进来之后 safari 27 与
safari-mobile 27（经"移动端取同版本桌面"）一并解决。

剩余 6 个缺口是 safari 12–14 × 2 平台 —— 与 TLS 层是同一批，原因见下。

### 扫描范围本身也会过期

品牌是一个轴，**版本上限是另一个**。`TARGETS` 的上下界写死在源码里，于是有
两种过期方式，各配一道门禁：

| 过期方式 | 门禁 | 判据来源 |
|---|---|---|
| 库里补了超出扫描范围的数据 | `test_coverage_ratchet` 的 `check_scan_range` | 自洽：上限 >= 版本表与段表的最大版本号，不联网 |
| 浏览器发了新版、上限还停在旧号 | `test_version_ceiling`（第 3 层） | 上游发布源 |

后者只能联网判，而且**取不到的源按"跳过"处理**。本机实测 Mozilla 的
product-details 可达（firefox 153，与上限一致），Google 的三个版本源
（versionhistory / chromiumdash / chrome-for-testing）DNS 能解析但连不上 ——
chromiumdash 解析到 104.244.46.165，不是 Google 网段。把"取不到"判成失败，
这条门禁在这台机器上永远是红的，很快会被无视，那比没有门禁更糟；所以取不到
就明说"没查到，也不构成上限没落后的证据"。

### Chromium 系衍生品牌：认得 ≠ 覆盖到了

Edge / Opera 一直"支持"着 —— `CHROMIUM_DERIVED` 会把它们的 UA 里那个
`Chrome/` 内核版本拿去查 chrome 表。但全版本扫描器长期只有 6 个桶
（chrome/firefox/safari × 桌面/移动），**Edge 与 Opera 一个版本都没被扫过**。
补进扫描器的当天就暴露三个问题，没有一个是"少几条数据"这类小事：

| 问题 | 表现 | 根因 |
|---|---|---|
| Android 版完全不认 | edge-mobile / opera-mobile **全部 74/83 个版本 no-brand** | 移动端品牌是 `edge-mobile`，拿它去查 `CHROMIUM_DERIVED = {"edge","opera"}` 这个集合永远不命中 |
| 桌面缺 14 / 18 个版本 | 同版本 chrome 全部由 same-seg 正常覆盖 | 段表是从 Chromium 源码推出来的、只按内核品牌建，`segments["edge"]` 根本不存在，于是跳过 same-seg 直接掉进跨段回退并被拒 |
| Opera 版本号语义错配 | 查内核 116 会拿到 wreq 标为 "Opera 116"（实际内核 ~102）的指纹，还报 `exact` | 库里的 opera 别名用 OPR 发行号（`wreq:Opera116`），而查表用的是 UA 里的内核号，两套编号差十几位 |

前两个是同一个 `-mobile` 后缀吃掉判断的形态（本项目第二次撞到），归一函数
`chromium_engine()` 一并解决：先剥 `-mobile` 再判成员，再把段表、"移动端≡桌面"
等价段、别名品牌比对**全部**映射到内核品牌。

第三个的处理是**删掉那张表**，而不是修键。理由是它贡献的独有指纹数为 0 ——
所有 opera 别名都挂在 chrome 条目上（`curl_cffi:chrome131` 与 `chrome100`），
两个库都把 Opera 建模成纯 Chromium。删掉之后 Opera 统一走内核表，用 UA 里那个
`Chrome/` 版本查询，语义才对得上。生产口径的 `exact` 因此从 82.3% 降到 81.9%
（opera 125 从"错的 exact"变成"对的 same-seg"），可安全伪装合计不变。

**归一到内核不是近似替代，是有证据的**。扣掉 Chromium 自 M110 起的扩展乱序
噪声后逐字段比：

```
edge  49 组同版本比对 → 48 组与 chrome 完全相同，1 组差 app_settings
```

而自采数据始终优先：`lookup` 先查自家表，命中就用自家的，内核推断只在自家表
没有该版本时才介入 —— 上面 edge 134 那条差异就是这么被保住的。

**这轮的教训**：覆盖度扫描器漏掉一个品牌，等于那个品牌的所有缺陷都不存在。
三方一致性门禁也一样 —— 它的比对集就是扫描器的输出，扫描器不含 edge/opera，
C 与 Python 在这两个品牌上的分歧就永远不会被发现（补进去后立刻报出 160 处）。

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

而且"桌面 ≡ iOS"本身也不是普遍成立的。库里同版本成对出现的只有三组：

```
safari 18.0 桌面 vs _ios   同一指纹
safari 18.4 桌面 vs _ios   同一指纹
safari 26.0 桌面 vs _ios   ★不同（曲线差 X25519MLKEM768、扩展差 padding、
                              TLS1.3 三个套件的顺序也不同）
```

2/3 达不到本项目对"可替代"要求的强证据门槛（见"段内可替代性"）。

**源码路线也走过了，是死路**。Chrome/Firefox 的缺口都靠读源码补上了，Safari
试过同样的办法：Apple 确实在 opensource.apple.com 公开了 coreTLS，`sslCipherSpecs.c`
有套件表、`sslHandshakeHello.c` 的 `SSLEncodeClientHello` 有扩展写入顺序，形态
上正是需要的东西。**但它拿已有真值一比就废了**：

```
coreTLS-167 推出的扩展序   35, 0, 10, 11, 13, 13172, 16, 5, 18, 23, 21
实测 utls:IOS_11_1/12_1    65281, 23, 13, 5, 13172, 18, 16, 11, 10
coreTLS-167 的曲线表       secp256r1/384r1/521r1（无 x25519）
实测三代 Safari 的曲线     x25519, secp256r1, secp384r1, secp521r1
```

顺序毫无相似之处，曲线更是缺了实测必有的 x25519 —— 说明早在 iOS 11.1 时
Apple 就已经不走 coreTLS 了。而实际在用的那套（Network.framework / libnetwork
里的 BoringSSL 分支）没有开源：`tarballs/boringssl`、`tarballs/libnetwork`
都是 404，只有 `tarballs/coreTLS` 是 200。

**这一步的做法值得记**：源码表看起来对不等于它就是那个栈，必须先拿它重建一个
**已有真值**的版本。先验证再使用，这次因此省下了一整套基于错误源码的推断。

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

**超时不是"被拒绝"，分档要看服务端说了什么。** 服务端回 Alert 才说明它读懂了
我们的字节并拒绝；超时只说明这一跳没走通。`test_build_live` 曾把 github.com 的
4 次超时报成"构造出的字节被服务端拒绝"，那个结论会把人指向根本不存在的长度
回填 bug。**分清的办法是找一个真实客户端做对照**：

| | 我们的字节 | openssl（对照） |
|---|---|---|
| 连发 8 次无间隔 | 2/8 | 首次即超时 |
| 每次间隔 3s ×5 | 5/5 | 5/5 |

openssl 是真实客户端真实 TLS，它在同样节奏下一起挂——字节问题就此排除，
github.com 是在按速率丢连接。门禁因此结果分三档（OK / 服务端回 Alert /
这一跳没走通），只对后者重试一次，并加 3s 节流。

**总览的绿必须包含每一层。** `verify_all` 曾经第 3 层红着、返回码是 1，结尾却
打印"所有已跑的验证均通过"——失败只累加了计数、没进 failed 列表。改完加了阴性
对照：注入一个必失败的第 3 层门禁，确认总览如实报错才算修好。

**变异测试之后，还原可能是假的（macOS 系统 Python 专属陷阱）。**
本项目所有新门禁都要做变异测试 —— 改坏一处、确认门禁真的会红、再还原。但
这次还原完门禁**依然报红**，而文件里、`git diff` 里、`inspect.getsource()` 里
全都是还原后的正确值。追下去是字节码缓存：

```
sys.pycache_prefix = ~/Library/Caches/com.apple.python
c.__cached__ = ~/Library/Caches/com.apple.python/<源码绝对路径>/covscan.cpython-39.pyc
```

macOS 自带的 python3.9 把缓存放在**源码之外**，源码旁边根本不会出现
`__pycache__` —— 删本地 `__pycache__` 等于什么都没做（我删了，没用）。
而 Python 判缓存有效只看 `(mtime, size)` 两个数，变异测试恰好同时踩中两条：
把 `153` 改成 `150` 字节数不变，`cp` 还原又落在同一秒。于是执行的是变异版本、
读源码读到的却是还原后的。

排查时最省时间的一步是打印 `module.__cached__` —— 它直接说出字节码来自哪，
比逐个排除"是不是有第二份文件 / 是不是 .pth / 是不是 __init__ 干的"快得多。

修法不是"记得清缓存"，是让 `verify_all` 给每轮门禁指定一个**全新的**
`PYTHONPYCACHEPREFIX` 临时目录，陈旧缓存不可能被读到。阴性对照验过：

```
同秒同长度变异+还原后
  裸跑 python -m spec.test_coverage_ratchet   → 报 150（被骗）
  经 verify_all 的运行器                       → 覆盖未倒退（正确）
```

手工单跑某个门禁时仍可能中招，清一下即可：
`rm -rf ~/Library/Caches/com.apple.python/<项目绝对路径>`

**README 里的数字，凡是能算的都要有门禁查。** "重建门禁 77/77" 在库涨到 80 条
之后仍写着 77，烂了一阵没人发现——它不依赖外网，纯粹是没人查。依赖外网的数字
（握手成功数）查不了，那就标成"某日实测"，让读的人知道它不是当前值。

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
