# browserfp — 浏览器 TLS / HTTP2 / QUIC 指纹覆盖与验证

目标两条：**覆盖市面主流浏览器指纹**，以及**有办法证明覆盖是对的**。

后一条是重点。指纹这类工作最容易出的问题是"看起来对了"——JA4 一致、测试全绿，
实际发出去的字节和真浏览器差着关键一处。本项目的每个结论都要求可复现的实测支撑。

## 现状

| 指标 | 数值 |
|---|---|
| 唯一指纹 | **82**（来自 321 个 target 名，按 13 个确定性字段去重） |
| 连接形态 | 首连 65 + 会话恢复 15 + QUIC 2 |
| 来源 | 开源表 64 + 真机采集 17 + 源码派生 1 |
| 含 h2 层 | 56/82；含 h3 层 2（QUIC 形态）|
| 重建闭环（全部 profile） | 82/82 |
| 构造器比对（默认配置） | 81/81 |

**验证分六层，每层的判据都在项目之外**（不是"我们跟我们自己比"）：

| 层 | 判据来自 | 结果 |
|---|---|---|
| 算法 | FoxIO 的 JA4 规范官方向量 | 逐字符一致 |
| 构造 | 三份构造器互比 + 59 条代码变异 | 全绿 |
| 每连接变化 | 三个引擎的真机连采（逐扩展比内容） | 变化谱一致 |
| 线上可用 | 真实站点握手 | 104/104（52 profile × 2 站点，2026-08-02 实测）|
| 对端视角 | 第三方指纹回显服务 | 37/37；生产字节 8/8（2026-08-02 实测）|
| 与被模仿者 | curl_cffi / wreq 本尊 A/B | 23/23（2026-08-02 实测）|

（前三层由门禁在本地实时验，数字锚定在 `test_docs` 里；后三层依赖外网，
按本项目的规矩标注实测日期 —— **查不了的数字就得让读的人知道它不是当前值**。）

最后两层是**最硬的**：前面几层都在问"我们与我们自己算的一致吗"，只有它们在问
**"对端看到的是不是我们想冒充的那个"**、**"我们与被模仿的那个库一样吗"**。
本项目 7 处发货缺陷里有 3 处只有这两层能发现。

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
UA → parse_ua → 段表/等价关系选 profile → browserfp_build_client_hello() → cosocket 发出
```

C 侧的构造器 `browserfp_build_client_hello()` 与库里其他函数一样是**内存进内存出、
非阻塞**的，可直接在 nginx worker 里调。Lua 侧一步到位：

```lua
-- 先问这个 profile 要哪些组的密钥（组是 profile 决定的，逐版本不同）
local groups = browserfp.key_share_groups("chrome", 151)   -- {{group=0x11ec,len=1216},…}
local ks = {}
for _, g in ipairs(groups) do ks[g.group] = my_keygen(g.group) end

local rec, prof = browserfp.client_hello("chrome", 151, "example.com", ks)
-- rec 是可直接 sock:send() 的完整 TLS record
```

**`key_shares` 是必填的。** 不给、少给一组、长度不对、多给一个 profile 里没有的
组 —— 五种都当场返回 `nil, err`，不会"用默认值凑合"。原因见下面 key_share 那节：
凑合出来的字节所有指纹字段都对、JA4/JA3 全绿，只有服务端算共享密钥时才炸，而
报错指向"解密失败"，与真因隔着两层。`test_lua_keyshare` 把这 8 条边界逐个验，
并断言报错内容指向真因而不是底层那句"组装失败"。

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
  `libbrowserfp.so` 是 macOS 的 Mach-O，而生产跑在 Linux OpenResty 上，这条链
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
chrome   151  exact×4   JA4 取值=1   扩展顺序取值=4
chromium 142  exact×4   JA4 取值=1   扩展顺序取值=4
edge     151  exact×4   JA4 取值=1   扩展顺序取值=4
firefox  153  exact×4   JA4 取值=1   扩展顺序取值=1
safari    27  exact×4   JA4 取值=1   扩展顺序取值=1     ← SAFARI=1 才跑
```

**「扩展顺序取值」这个指标原来是含 GREASE 算的**，而 GREASE 每连接轮换 —— 于是
「顺序变了」会被 GREASE 的变化冒充，那条充分性断言分不出「真的乱序」和「只是
GREASE 换了值」。归一之后重测，上面这组数才是真的：Chromium 系确实每连接换一个
顺序，而 **Safari 不换**。后者此前只是假设（置换只开给 chromium），现在有真机
证据；本来可能是另一个答案。

Safari 默认不在清单里：它没有 headless、也不能用独立 profile，只能 `open -a`
唤起用户那个真实窗口，每次跑门禁都弹窗太扰人。但 **webkit 是三个引擎里唯一
没有真机识别证据的**，所以留了 `SAFARI=1` 这个开关。

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
csrc/browserfp.{h,c}      ClientHello 解析 + JA4 计算 + 内置 profile 查表
csrc/gen_profiles.py  把 spec/profiles.json 编译成 C 静态数组（构建期常量）
lua/browserfp.lua         LuaJIT FFI 绑定
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
Python  ←→  C CLI       82/82 一致
Python  ←→  luajit FFI  82/82 一致
真实 OpenResty worker 内实测：profiles=76，识别 real:edge 正确
```

FFI 绑定层有独立的出错空间（结构体布局、字符串所有权、参数传递），不会崩溃只会
给错结果，所以 Lua 侧单独比一遍，而不是"C 对了 Lua 就一定对"。

#### key_share：JA4 不看它，于是它错了很久也没人知道

JA4 **不哈希 key_share 的内容**，所以三方差分、重建闭环、真机握手（服务端只要
能算出共享密钥就不在乎你发了几组）全部照样绿。实测两侧都是错的，而且错得不一样：

```
Python  只给 curves[0] 发一个随机公钥
        chrome131 真机 GREASE(1)+X25519MLKEM768(1216)+X25519(32) → 重建只剩一条
C       照抄 golden 整段
```

也就是说 **C 与 Python 产出的字节形状长期不同**，同样没人发现 —— 因为所有门禁
比的都是 JA4 与解析回来的字段，没有一条比 key_share 的形状。

两个后果都很硬：**Chrome 恒发一个 GREASE key_share**，丢掉它本身就是破绽；而真
出网时照抄 golden 的公钥根本用不了 —— 那把私钥不在我们手里，算不出共享密钥，
症状会是"握手莫名其妙失败"，与 key_share 毫无表面关联。一把固定公钥反复出现，
更是比不伪装还显眼。

改法是**形状照抄、内容可注入**：分组、顺序、每条长度全部按 golden 走，公钥由
调用方给（`build_client_hello(..., key_shares={group: pub})` /
`browserfp_build_client_hello_ex`）。GREASE 那条不接受注入 —— 按 RFC 8701 它的内容
本来就是固定的。

**不合法的注入一律报错，不将就。** 长度不符会改变形状；分组在 profile 里不存在
则更危险 —— 调用方以为注入成功了，实际握手拿的是 golden 里那把旧公钥。
`test_keyshare` 首次跑就抓到 Python 犯了后一种（静默忽略未知分组）。

顺带一条门禁自身的教训：做阴性对照时，把形状退化成只剩 GREASE，构造器直接抛
`ValueError` 把整条门禁**打死**，后面的检查一条都没跑。**门禁应该报告，不该崩** ——
崩掉时你只看得到一个 traceback，看不到"哪几条不符"。

##### 修完之后，生产接口上并没有它

上面这些都做在 Python 与 C 的构造器里，`test_keyshare` 全绿。但 `lua/browserfp.lua`
的 `client_hello()` 调的是**不带注入参数的那个 C 入口** —— 于是生产接口发出去的
仍然是 golden 里那把采集机公钥。实测确认过：Lua 发的 `0x001d` 公钥与 golden
逐字节相同。

**这与 VERBATIM 默认值那次是同一类**（见"默认值要选错了会响的那个"）：能力做在
库里，出口没接上，而所有指纹门禁照样全绿 —— **JA4 和 JA3 都不看 key_share 的
公钥内容**。这一类的共同点是"改动落在实现上、没落在调用链上"，判据只能是
**从生产入口回打一遍**，不能看实现里写没写。

现在 Lua 侧多了 `key_share_groups()`（问该为哪些组生成密钥）与必填的
`key_shares` 参数，`test_lua_keyshare` 从生产入口出发验注入是否真落到线上字节里，
六个代码变异逐个确认它会红。

#### h2 那一层也要按 (品牌, 版本) 独立查

Lua 侧新增 `browserfp.h2_akamai(brand, version)`，给出这个版本应该呈现的 Akamai
指纹串。**不要拿 `by_ua().h2` 当这个用** —— 那是「采集这条 TLS 指纹时顺带看到
的 h2」，而注册表按 TLS 指纹去重：两个版本 TLS 相同、h2 不同是常态，还有一批
profile 那个字段干脆是空的。实测 firefox 153 就是空的，而第三方回显给出的是
`1:65536,2:0,4:131072,5:16384|12517377|0|m,p,a,s` —— 拿 profile 上那个字段
去比，会得出「我们没有目标值」这种毫无意义的结论。

#### QUIC / HTTP-3 的出网：不做

这条一直挂着没定，把成本量出来之后结论是明确的。

现状：**只识别、不构造** —— `oracle/quic.py` 只有 `parse_initial`，没有
builder；网关那侧有 UDP cosocket，但没有任何 QUIC 地基。

补出网意味着在 Lua 里从零写 QUIC 传输层（包保护与头保护、丢包恢复、拥塞控制、
流控）再加 h3/QPACK，量级是整个 TLS 栈的十倍以上。而收益：**QUIC 只有 3 条
profile，对比 h2 的 644 个 (品牌,版本) 组合**，且实测 iOS Safari 根本不发 UDP
（Cloudflare trace 报 `http=http/2`）。

所以记成 WONT_DO。识别侧的能力保留（`test_quic` / `test_h3` 照跑），哪天真需要
h3 出网，正确的做法也不是在 Lua 里写，而是换一个承载。

#### 第三方确认的台账

回显那条门禁要联网、要对公开服务节流（44 条连打会被限流到跑一次十几分钟），
所以它只在手工加 `LIVE=1` 时跑。**于是"全部指纹都被对端确认过"这个结论没有
任何常驻门禁看着** —— 它可以静静地烂掉：新增一条 profile 谁也不会注意到它从没
被外部验过；改了 h2 表让某个组合的指纹变了，台账里那条旧记录还挂着，看上去仍然
"已确认"。

现在验过就记一笔到 `spec/echo_ledger.json`（**只记这一轮全对的**），离线的
`test_echo_ledger` 每次都查三件事：有用例没记录、有记录没用例（profile 改名后的
残留会把"全部已确认"撑虚）、记录超过 90 天没复验。

用例集的定义抽到了 `oracle/echocases.py` —— 联网那条与离线那条**必须用同一份**，
写两份就会漂移，而漂移的表现正是上面那个"两个数永远对不上"。

#### 扩展顺序：真 Chrome 每连接换一个，我们此前恒定

同一族的第三处（前两处是 GREASE 取值、GREASE ECH 体长）。本仓自己的真机实测就
在上面那张表里：chrome / chromium / edge 各 5 次连接**出 5 种扩展顺序**，
Firefox 恒 1 种。而我们 12 次构造只出 1 种 —— **一个固定的扩展顺序是真
Chrome 110+ 永远产不出来的东西**，与照抄固定 GREASE 一样，不用比长度，看两次
连接就够。

规则取自 utls 的 `ShuffleChromeTLSExtensions`（本仓的 profile 就采自它）：
**GREASE / padding / pre_shared_key 位置钉住，其余全部打乱**。padding 要钉住是
因为它得留在末尾承担补齐，PSK 则是 RFC 8446 强制最后一个。

**置换从 random32 派生，不用系统随机** —— 否则三方差分立刻炸，同一条连接必须
排得出同一个顺序。这与 GREASE 取值同一个套路（C 侧的 `grease_at` 就是
`SHA256(random32 || 计数器)`）。

写门禁时有两条断言**根本打不到**，是变异测试翻出来的：

- 真 profile 太长（带 MLKEM 的 key_share 上千字节），padding 按长度重算的结果是
  **永远不出现**，于是"padding 位置钉住"在真 profile 上验不到。补了合成用例。
- verbatim 那条对照两次都不传 `random32`，用的是同一个默认种子，**就算真被打乱
  了也排出同一个顺序**。改成传两个不同的种子。

C 侧已跟上，且**由数据决定**：profile 表里本来就有 `engine` 字段（原本给两层
一致性检查用），出网口径下 `engine == "chromium"` 才打乱。判据是
`test_permute` 的跨实现段：同一个 `random32`，Python 与 C 必须排出**逐位相同**
的顺序 —— 对不上就说明派生算法或钉住规则有一侧写歪了。

写这段时又踩到"断言打不到"：C 侧的比对用例全是长 profile，出网口径下 padding
**永远不出现**，于是"padding 位置钉住"在 C 侧验不到（变异实测：把它从钉住名单
去掉，门禁照样全绿）。挑了一条在 buildcli 那个固定种子下会带 padding 的
profile 补进用例（82 条里有 21 条会）。

还有一处是工具本身的坑：`buildcli` 原来只接下标，而 **C 表的顺序与
profiles.json 的数组顺序不同**（生成时会去重排序），拿 json 的下标喂进去会
安静地取到另一条 profile —— 第一版就是这么比出"四条全不一致"的。现在它也接
profile id。

#### Kyber768Draft00（0x6399）：不用第二份密码学实现

27 个 (品牌,版本) 的 key_share 里有 X25519Kyber768Draft00。它**不是** ML-KEM-768
—— 是 Kyber 第三轮那版，OpenSSL 只有最终标准版。第一反应是得自己实现或者 vendor
一份参考实现（约 1000 行 C）。

实际不用。**ML-KEM 相对 Kyber 第三轮只去掉了最后一步哈希**，补回来就是：

```
Kyber_ss = SHAKE-256( ML-KEM_ss || SHA3-256(密文) , 32 )
```

这条是从**采集来源自己身上**看到的：本仓的 profile 有一批采自 utls，而 utls 的
`u_key_schedule.go` 就是这么做的（Go 标准库同款）。**先去看被模仿的那个实现怎么
做，比从草案文本往回推快得多，也可靠得多。**

线上布局与 X25519MLKEM768 **正好相反**：X25519 在前、Kyber 在后。两份独立实现
印证（Go 标准库 `handshake_client.go`、utls `handshake_client_tls13.go`）。
顺序记混的表现是长度完全正确、握手却在 Finished 阶段失败。

判据不是"看着像"：`test_kx` 拿 CIRCL 的 `kem/kyber/kyber768`（文档明确写着
"as submitted to round 3"，与它自己的 `kem/mlkem` 是两个包）对我们生成的公钥
做封装，两边的共享密钥必须逐字节相同。三条变异（顺序反了 / 少那层包装 /
包装少喂 SHA3(ct)）逐个确认会红。

#### HelloRetryRequest：第二条 ClientHello

服务端要一个我们没发过的组时必须补发 CH2，不补的表现是"某些站点连不上"。
参考实现早就会补，但 C 与 Lua 不会 —— 又一次"能力只在验证侧、发货侧没有"。

C 的做法与 Python 不同：**在 CH1 的字节上就地改写**，而不是照 profile 重新造。
RFC 8446 §4.1.2 要求 CH2 与 CH1 只差指定的几处，random / session_id / GREASE /
GREASE ECH 全都必须原样带回；重新造就得让调用方把这些随机量存下来再传进来，
多一个能出错的环节，就地改写让它们天然逐字节相同。要动的只有两处：key_share
换成服务端选的那一个组（GREASE 那条也不留），padding 按新长度重算 ——
key_share 从 1216 字节缩到几十字节，总长会掉进 [256,512) 这一档。

Lua 侧：

```lua
local pub  = browserfp.keygen(group).shares[group]     -- 服务端选的组多半不在 profile 里
local ch2  = browserfp.client_hello_hrr(ch1, group, pub)
```

判据是**与参考实现逐字节相同** —— 参考实现能跟真服务端完成 HRR，两条路殊途
同归才说明改写没漏东西。

这里的取样方式踩过一次：CH1 带不带 padding 取决于 GREASE ECH 的体长（每连接
在 {186,218,250,282} 里随机取），单次取样约 3/4 落在"不带"那一档。**于是"CH2
照抄 CH1 的 padding"这个变异第一次跑是绿的** —— 不是门禁漏，是那条路径压根没
被走到。现在每条 profile 取 10 次样、按 (带不带 padding, ECH 体长) 去重逐个比，
并断言"自带 padding 的 CH1"至少出现过一次。

#### 公钥从哪来：密钥交换

注入接口要求调用方交出每一组的公钥，调用方就得能产出它们。**生产 UA 里 64.9%
落在需要 X25519MLKEM768 的 profile 上**，只做 X25519 等于三分之二的真实 UA
伪装不了：

| 密钥交换 | 生产 UA 口径 | 全版本口径 |
|---|---|---|
| X25519MLKEM768 | 64.9% | 25.4% |
| 只 X25519 | 18.5% | 51.2% |
| Kyber768Draft00 | 5.6% | 4.2% |
| X25519 + P-256（Firefox） | 3.3% | 18.6% |

于是 `csrc/browserfp_kx.c` 提供四组：X25519 / secp256r1 / secp384r1 /
X25519MLKEM768，Lua 侧 `key_share_groups()` 告诉调用方该产哪几组。

**这里差点走上一条错路。** 容器里 `openssl version` 报 3.0.20，ML-KEM 要 3.5
才有，据此得出的结论是"得自己实现 ML-KEM-768"——大约 900 行密码学代码。实际
那是 **Debian 的系统二进制**，OpenResty 链的根本不是它，而是自带的
`/usr/local/openresty/openssl3/`，实测 **3.5.7，ML-KEM-768 就在里面**。
教训是老的那条：**先确认数据出自哪一层**，否则量到的是另一个东西。

符号在**运行时** `dlsym` 解析，不在链接期绑定：worker 里 libcrypto 早已加载，
拿到的就是 OpenResty 那一份；链接期绑一个别的版本会让同一个进程里出现两份
OpenSSL。`test_kx` 把解析到的版本打出来，并在版本低于 3.5 时**当场判红**——
悄悄跳过等于把"生产上这条根本不能用"藏起来。

Lua 侧一步到位：`browserfp.gen_key_shares(brand, version)` 按 profile 把每一组的
密钥都生成好，`keys.shares` 直接喂给 `client_hello()`，拿到 ServerHello 后用
`keys:derive(group, peer)` 算共享密钥。**私钥不出这个模块**，挂在 `ffi.gc` 上，
协程被 kill 掉也会回收。

判据是**两份实现算出同一个 32/64 字节**，对端用 `cryptography`（独立实现）。
门禁分两段：先验 C 那一层，再**从生产入口（Lua）整个过一遍** —— 中间隔着 FFI
的输出缓冲、句柄所有权与 ffi.gc，这些都能在不崩溃的情况下给出错误结果。
密钥交换错了不会报错：本地照样算得出一个共享密钥，只是与服务端算的不同，
症状是握手在 Finished 阶段失败、报"解密失败"，与真因隔着两层。混合组的拼接
顺序（ML-KEM 在前）单独做了阴性对照——顺序错时长度完全正确。

顺带两条门禁自身的教训，都是老坑的新实例：

- `kxcli` 的错误分支用 `continue` 跳过了循环底部的 `fflush`，"ERR" 留在 stdio
  缓冲里，交互式调用方读不到 → **门禁挂死 600s 而不是报错**。管道喂完即退的
  手工测试看不出来（退出时统一 flush）。现在几个 CLI 都改成行缓冲。
- 变异还原后 `make` 因**同秒 mtime** 判定不用重编，门禁跑的是变异版二进制，
  于是"源码里 grep 不到变异、门禁却按变异行为报错"。`test_kx` 现在自己先删
  产物再 make。

#### GREASE ECH：同一族的第二处，而且更险

`key_share` 那条修完，同一个形态在别处又出现一次 —— **GREASE ECH（0xFE0D）**。
`config_id` 只有 1 字节，照抄 golden 的固定值一旦撞上服务端真实的 ECH 配置，
服务端会拿自己的私钥去解 payload、失败，回 `handshake_failure(40)`。

参考实现 `oracle/tls13.py` **早就**每次新鲜生成，注释里写着实测原因；而**发货的
构造器（Python 与 C）一直在照抄**。34/81 条默认 profile 带这个扩展 —— 也就是绝
大多数 Chrome 形态都埋着这个雷。`test_build_live` 只打三个站点，撞不上就一直绿。

这里有个更值得记的教训：**同一份逻辑存在两处实现时，能干的那份会把不能干的那份
遮住**。真机端到端（`test_live_handshake`）用的是 `tls13.py` 那份，它补 SNI、
新鲜生成 ECH、跳过 `pre_shared_key`；发货那份三样都不做。于是"端到端全绿"证明
的是**测试用的构造器**能用，而不是**我们发货的构造器**能用。现在 `grease_ech()`
提到 `chbuild` 里由两侧共用，重复没了。

修法与 key_share 同族：**形状照抄、内容新鲜**。kdf/aead 与 enc/payload 的长度
全部取自 profile（payload 长度决定 ClientHello 总长度，是指纹的一部分），只有
`config_id`/`enc`/`payload` 的内容每次不同。C 侧没有内部 RNG（内存进内存出的
架构约束），随机性从调用方给的 `random32` 派生：`SHA256(random32 || 序号)` ——
每次连接都不同，而库本身仍然是确定性的、可差分比对的。

#### pre_shared_key：同一族的第三处，判据要按**用途**分开

`key_share`、GREASE ECH 之后，第三处是 `pre_shared_key`（0x0029）。15 条 profile
是会话恢复态，里面那 267 字节是**采集当时的票据**：发出去验不过，服务端会退回
完整握手 —— 一个"声称自己来过"却拿不出有效票据的客户端，比干净的首连更可疑。
真做恢复也不可能靠照抄：binder 是对整段 transcript 的 HMAC，换一个字节就得重算。

但这一处不能简单地"总是拒绝"，因为它有两种用途，要求正好相反：

```
重建验证   必须原样发 —— 不然重建闭环（test_rebuild / test_c_parity）验不了
真出网     必须拒绝 —— 发出去只会更可疑
```

区分信号选的是**调用方有没有注入 key_share**：注入了就说明它真要握手（不注入的
话它根本没有私钥，也就不可能真连）。两侧都按这条判，`by_ua` 本来就只返回
initial 态，这一层是给"直接按 profile id 调构造器"的调用方兜底。

#### 第四处：`sni=` 参数在 Python 侧对 80/82 条 profile 被静默忽略

前三处（key_share、GREASE ECH、pre_shared_key）都是"照抄了本该每次不同的东西"。
第四处形态不同，更露骨：**参数被静默忽略**。

80/82 条 profile 采自 nosni 场景（真机浏览器只能这么采），扩展里根本没有
`0x0000`，而 `chbuild` 只在**遍历到**该扩展时才写 SNI —— 于是
`build_client_hello(profile, sni=host)` 对 97.5% 的 profile 发出去**没有 SNI**。
打有默认证书的站点不报错，打多租户站点直接 `handshake_failure(40)`。

C 侧与 `oracle/tls13.py` 都早就在补。之所以谁也没发现：三方差分都用
`sni=None`、真机端到端走 tls13 那份、C 的 SNI 由 `snitest` 单独验 ——
**三条路恰好各自绕开了它**。

#### 于是把三份构造器钉在一起

`test_builder_parity` 按**结构**比 `chbuild` / C / `tls13` 三者的产物：扩展 id
顺序（含补进去的 SNI 的位置）、密码套件、压缩、`client_version`、key_share 的
(分组, 长度) 形状、SNI 的值必须相同；random / session_id / 公钥内容 / ECH 内容
则必须**不同**（相同才是缺陷）。

它当场抓到第五处：**`tls13` 的 key_share 只发首选那一条**，把 GREASE 条目与其余
分组全丢了 —— 与我刚在 `chbuild` 里修掉的是同一个 bug，而所有真机端到端测试
一直在用它。现在 `tls13` 改走同一个构造器，按 profile 的形状**逐组生成真密钥**
（X25519 / P-256 / X25519MLKEM768；Kyber768Draft00 生成不了，明确列为不支持）。

**这条门禁的第一版有个盲点，是靠阴性对照发现的**：把 `tls13` 改回"只发一条"，
门禁**不红** —— 因为形状是由构造器保证的（缺的分组填随机字节），少生成密钥在
结构上根本看不出来。真正的风险是"发了某组却没有对应私钥"，那要**直接断言**：
参考实现生成的分组集合必须覆盖 profile 里所有非 GREASE 分组（明确不支持的除外）。
补上这条之后同一个变异立刻红。

#### 最后一环：对端**实际看到的**指纹，是不是我们想冒充的那个

此前所有"端到端"验的都是**服务端接受了我们的握手**。**接受 ≠ 认成那个浏览器** ——
一条把 GREASE 全丢掉、密码套件顺序打乱的 ClientHello 照样能握上手，只是任何指纹
库都会把它归成"不是浏览器"。

而 JA4 一直是我们自己算的：Python 与 C 互校，golden 里的 `ja4` 字段也是采集时由
`oracle/clienthello.py` 算的。`test_ja4_vectors` 用规范官方向量补了**算法**这一层，
但那是一条合成输入 —— **真实流量在真实对端眼里长什么样，从来没验过**。

`test_echo_fingerprint` 把回路闭上：按 profile 出网打一个公开的指纹回显服务，
拿它回显的值与我们算的比。结果：

```
JA4✅ JA3✅ h2✅   real:chromium   t13d1516h2_8daaf6152771_d8a2da3f94cd
JA4✅ JA3✅ h2✅   real:firefox    t13d1717h2_5b57614c22b0_3cbfd9057e0d
JA4✅ JA3✅ h2✅   real:safari     t13d2013h2_a09f3c656075_7f0f34a4126d
```

三条链路（TLS 的 JA4/JA3、h2 的 akamai 指纹）全部与第三方独立实现一致。阴性对照：
把 `clienthello.py` 里一处 `sorted()` 换成 `list()`，两条立刻报出"我们算的"与
"对端看到的"不同 —— 而**其余所有门禁仍然全绿**，因为它们比的都是我们自己算的值。

**扩到 20 条之后，"假警报"才是主要工作量。** 覆盖面从 3 条提到跨四类引擎的
20 条，冒出四处"不符"，逐条查下来**没有一处是我们的指纹错了**，全是两边记法不同：

| 分歧 | 对端 | 我们与三家库 |
|---|---|---|
| SETTINGS 分隔符 | `2:0;3:100` | `2:0,3:100` |
| PRIORITY 之间 | `,` | `\|` |
| PRIORITY 权重 | 有效权重 202 | 线上字节 201（RFC 7540：线上值加一才是权重） |
| 未知设置 id | 渲染成空 `;:1;` | `8:1` |
| ja4_c 里的 padding | **排除** 0x0015 | 计入（规范只排除 SNI/ALPN） |

最后一条尤其要说清：**FoxIO 的规范没有排除 padding，是回显服务偏离了规范**
（`test_ja4_vectors` 用官方向量验过我们这一侧）。这对伪装**无害** —— 我们发的
字节与真浏览器相同，任何一个确定性实现算两边都会得到同一个值；它只影响"拿我们
表里的 ja4 去比对某个公开库"这种用法。实测对应关系是干净的：**含 padding 的
profile 全部不符、不含的全部相符**，所以门禁按段比 `ja4_r`，**只**豁免这一处，
并且还要断言"扣除 padding 之后确实一致"。

这几处的处理方式是一致的：**逐条建模，不做笼统忽略**。"两边都排序后比集合"能让
所有差异消失，但顺序本身就是指纹 —— 那种绿等于把门禁关掉。

#### 与被模仿者 A/B：抓"自洽地错着"

前面所有档次问的都是同一件事的不同侧面 —— **我们与我们自己算的一致**。再加一档
换个问法：同一个 target，**我们发的字节与 curl_cffi 本尊发的字节，在对端眼里是不是
同一个指纹**。它同时验两件事：语料里那条 profile 记得对不对，构造器复现得对不对。

阴性对照最能说明它的位置：把语料里 `curl_cffi:chrome131` 删掉一个密码套件，
**第一档仍然是绿的**（我们与我们自己算的当然还一致），只有 A/B 变红。

**它当场抓到一个真缺陷，而且是前面四处的第五个同族**：`curl_cffi:chrome119`
我们发出去是 17 个扩展，本尊是 16 个 —— 多的正是 **padding（0x0015）**。

**padding 不是固定成分，它按报文长度算。** BoringSSL 把 ClientHello 补齐到
**512 字节**（含 4 字节握手头），超过就整个不发。证据一直躺在我们自己的语料里：
同一 target 的带 SNI 与 nosni 两份采集，padding 长度恰好差 18 字节（正是那个 SNI
扩展的大小），而 chrome119 带 SNI 时根本没有 padding：

```
              去pad体长   golden pad   合计
chrome100        284         224       512
chrome119        506           2       512
safari153        298         210       512
safari180        291         217       512
```

所以照抄是错的，两侧都改成按实际长度重算。这意味着 **JA4 会随 SNI 长度变化** ——
那正是真浏览器的行为，不是缺陷。改完 A/B 立刻对上。

#### A/B 换一家库，立刻又抓到反方向的同一个缺陷

curl_cffi 只覆盖 13 条 profile，另有 10 条只有 wreq 别名 —— **只用一家库做 A/B，
另一家建模的那批就没有"与被模仿者比"这一层**。wreq 是 Python 库（装在
`.venv-wreq`，走子进程），补上它之后 23 条里立刻红了 3 条，形态与 padding 那次
一模一样、方向相反：**本尊多发一个扩展，我们少发**。

根因是 padding 规则**缺了下界**。BoringSSL 只在 `256 ≤ 长度 < 512` 时补齐，而我
第一版只写了上界，并且**只在 profile 里记录了 padding 时才补**。OkHttp 系的语料
是在 nosni（体长 251）下采的，低于下界所以没记 padding —— 换成真实 SNI（体长
268）落进区间，本尊补而我们不补。

**这正好是下界的直接证据**：同一个客户端，251 字节时不补、268 字节时补。全语料
82 条零反例（22 条在区间且补了、17 条 <256 未补、43 条 ≥512 未补），六条 Firefox
正好 512 且带 padding —— **NSS 同样补，这条规则不是 BoringSSL 专有的**。所以改成
**按长度统一判，不看 profile 里有没有记录**。

改完 `test_ja4_vectors` 红了，而它红得对：**官方向量描述的是一条给定的
ClientHello，不是让我们按长度重算的 profile**。给构造器加了一个窄口子
`recompute_padding=False`，只给这一类调用方用。

#### 别再一个个撞了：把"哪些东西每连接会变"系统扫一遍

前六处都是**逐个撞出来的** —— 每次靠一条 A/B 不符再回溯。有了本地 sniffer 之后
可以换个做法：**让真客户端连采 8 次，逐扩展比内容，看哪些在变**；再拿我们自己
构造 8 次做同样的比对。差集就是下一处。

```
真机 curl_cffi chrome119   会变：000a  0015  002b  0033  fe0d  以及**所有 GREASE 扩展 id**
我们构造                   会变：      0015        0033  fe0d
```

差集一眼可见：**GREASE**。我们的 GREASE 恒为 `0x4a4a`/`0x5a5a`（扩展）与 `0xeaea`
（密码套件），而真客户端每次都换。**GREASE 的全部意义就是每连接随机**（RFC 8701）
—— 一个 GREASE 永不变化的"Chrome"，比前六处更容易被发现：不用比长度，看两次连接
就够。

规格也一并测了（6~10 次采样，结论一致），够直接实现：

| 槽位 | 行为 |
|---|---|
| 两个扩展 id | 每次随机，**且恒不相同**（0/10 相同） |
| 密码套件 | 独立随机 |
| supported_groups 首项 | 随机，**且 key_share 里那条与它相同**（6/6） |
| supported_versions 首项 | 独立随机 |

**方法比这一处更值钱**：前六处花了好几轮各撞一次，这一次一轮就把"还有什么在变"
问完了。**能列举的轴，就别靠撞。**

#### 三个引擎各扫一遍：变化谱完全不同

上面那次扫描只做了 **chromium 一个引擎**。把同样的方法用到另外两个真机上，结果
彼此毫无共同点：

| 引擎 | 每连接会变的 | GREASE | 扩展序列 |
|---|---|---|---|
| chromium | `0x0a` `0x2b` `0x33` `0xfe0d` | 每次换 | 8/8 各不相同 |
| gecko | 只有 `0x33` `0xfe0d` | **一个都不发** | 6/6 恒定 |
| webkit | `0x0a` `0x2b` `0x33` | 每次换 | 6/6 各不相同，**不发 ECH** |

我们三个引擎的行为与真机**逐项一致**，这一轮没找到新缺陷 —— **一个有价值的否定
结果**：GREASE 那次改动是按 Chromium 的观测做的，而它没有污染另外两个栈。

固化成 `test_variation`，**逐引擎**断言。Gecko 那条方向是反的、也最容易被好心改坏：
**如果哪天有人"顺手"给 Firefox 也加上 GREASE 随机，那是把它变成一个不存在的
浏览器** —— 阴性对照验过，给 gecko profile 塞一个 GREASE 立刻红。

阴性对照里还暴露了这条门禁自己的边界：把 ECH 的**长度**改成固定，它不红 ——
因为它查的是"内容在不在变"，而 config_id/enc 仍然新鲜。长度那条归
`test_keyshare` 的 `ECH_BODY_LENS` 管。**两条门禁各管一半，得知道自己管的是哪半。**

#### 七处修复在**生产路径上全是死的**

上面那条门禁只查了 Python 侧。而生产走的是 C/Lua —— 顺手用 Lua 绑定取四次字节
一看：

```
第1..4次  GREASE=['0x4a4a', '0x5a5a']  ECH体=218      （四次完全一样）
```

**全部七处修复在发货那条路上一次都没生效。** 根因是我自己埋的：C 的旧签名
`browserfp_build_client_hello` 当时默认 `VERBATIM`，理由是"不动既有调用方"，而
**Lua 绑定用的正是这个签名**。为门禁图方便，把修复在生产上关掉了。

**默认值要选"错了会响"的那个。** 重建门禁忘了传 `VERBATIM` 会当场比对失败
（看得见）；生产忘了传出网标志是静默地发固定字节（看不见）。所以把默认反过来 ——
plain 名 = 出网口径（与 Python 一致），重建工具 `buildcli` / `snitest` 显式传标志。
`kscli` 的前缀约定也一并对齐：**不带前缀 = 出网**，`=` 前缀才是重建 —— 同一套代码
里两种默认，迟早有人按另一边的直觉调错。

门禁也补上了：`test_variation` 现在**在发货那条路上取样**。"写了但没接"这一类，
只能这么发现 —— 前面每一条断言都通过了，因为它们全都只看 Python 侧。

补的过程里还撞了两处**取样装置**的问题，都不是实现的毛病：`kscli` 的 `random32`
写死，于是"C 侧不变"；而 gecko 的 `key_share` 在发货路径上本来就该恒定 ——
**库内不产密钥，公钥由调用方注入**，那是架构约束。两条都写进了判据注释，
免得下次被当成缺陷。

而上一处是**靠手动去戳 Lua 才发现的** —— 门禁那时查的是 C CLI，它走的是另一个
入口，已经在变了。所以又补一档：**直接从 Lua FFI 取样**，那才是生产真正调的那层。

```
Python   变=[0x33 0xfe0d]   序列 8/8
C CLI    变=[0x33 0xfe0d]   序列 8/8
Lua      变=[0x33 0xfe0d]   序列 8/8      ← 生产真正调的
```

阴性对照把上一处缺陷精确复现了：**只把 C 的 plain 名默认改回 `VERBATIM`**，
Python 与 C CLI 两档照常绿，只有 Lua 那档红 —— 与当初的现场一模一样。

一层一层往发货那端补，是因为**每多一层包装就多一次分叉的机会**：
Python↔C 分叉过（五处构造器差异）、C↔Lua 分叉过（默认口径反了）。
**断言要贴着最终发货的那个面做**，中间层全绿说明不了终点。

#### h2 层扫完了：三个引擎全都恒定，于是把"不许变"也钉住

同一套方法用到 h2 开场上，三个引擎各连采 6~8 次：

```
settings / window_update / priorities / 伪头序 / 帧序 / akamai 指纹
chromium 8 次、gecko 6 次、webkit 6 次 —— **没有一项在变**
```

所以我们发固定值是对的，**这一层没有第 8 处**。但把这条**反过来钉住**：哪天有人
照着 TLS 层的经验"顺手"给 h2 也加随机，那是把它变成一个不存在的浏览器 —— 与
"gecko 不发 GREASE"那条同理。至此三层（TLS 内容、TLS 变化谱、h2 恒定性）都扫过了。

**这次阴性对照连做三版才成立**，本身是个教训：

```
第一版  改动引用了后面才声明的函数 → 编译失败
        门禁是红了，但红的是构建 —— 不算数
第二版  用 time(NULL)&1 → 四次调用都在同一秒，值根本没变
        门禁绿 —— 而我要验的条件压根没被制造出来
第三版  用 getpid() → 每个进程不同，四次得到 2 种 → 门禁红
```

**阴性对照必须真的制造出那个条件**，否则"没红"说明不了断言不灵，只说明实验没做成。

#### 带 ECH 的 profile 本来就有两个 JA4，A/B 因此会抖

HRR 改完重跑真机，`test_live_handshake` 104/104 没问题，而 A/B 那档报了
`chrome119` 不一致 —— 上一次跑它是绿的。**这不是缺陷，是门禁自己在抖**：

ECH 体长每连接从 `{186,218,250,282}` 随机取，它进总长、总长决定 padding 补不补，
于是扩展数在 16/17 之间跳。**同一个客户端本来就有两个 JA4**（真机 16 次实测 10:6）。
A/B 各取一个样本，约一半概率对不上。

**抖动的门禁比没有更糟** —— 它会被当成噪声无视，然后某天真的坏了也没人信。按已知
机理精确豁免：**两个哈希段必须完全相同**，只允许扩展计数差 1，且该 profile 确实
带 ECH。边界逐条测过：

```
扩展数差 1、哈希全同        放过   ← 唯一放过的情形
扩展数差 2 / 密码套件数不同  红
哈希段不同 / ALPN 不同      红
SNI 标志不同                红
不带 ECH 的 profile 差 1    红
```

**豁免要窄到只覆盖那一个已知机理**，宽一点就等于把这条最硬的判据关掉了。

#### HelloRetryRequest：CH2 的约束比想象中多，每违反一条都被拒

参考实现原来不支持 HRR。表现不是"报错说不支持"，而是**在算共享密钥时报一个与真因
毫无关系的错** —— HRR 与 ServerHello 长得一模一样，只有 random 那 32 字节
（`SHA-256("HelloRetryRequest")`）能区分。真浏览器都会补发第二个 ClientHello；
我们不补的表现是"某些站点连不上"。

判据现成：`oracle/gotls/hrrserver` 只接受客户端不会首发的 P-384，必定触发 HRR。

RFC 8446 §4.1.2 说 CH2 与 CH1 **只差指定的几处**。实测下来每违反一条都会被拒，
而告警**不会告诉你是哪一条**：

| 约束 | 违反后的表现 |
|---|---|
| `key_share` 换成服务端选的那一个组 | （这是允许改的） |
| `random` / `session_id` 与 CH1 相同 | Alert |
| GREASE 沿用 CH1 抽到的那组 | 两条 CH 的 GREASE 对不上 |
| GREASE ECH 原样带回 | Alert |
| **记录层版本必须 0x0303**（首条才是 0x0301） | `protocol_version` |
| transcript 先把 CH1 换成 `message_hash`（§4.4.1） | Finished 校验失败 |

最后那条记录层版本我最后才想到：告警说 `protocol_version`，而我先怀疑了三处扩展。
**告警码指向的是"哪一类"，不是"哪一处"** —— 真正定位靠的是**把 CH1 与 CH2 逐字段
diff**，一眼看见只有 `key_share` 与 `0xfe0d` 不同，其余全同，于是问题只可能在
扩展之外。三个引擎现在 3/3 协商到 P-384，阴性对照（版本改回 0x0301）0/3。

顺带补上 P-256 / P-384 的密钥交换 —— HRR 常常就是为了换到这两条曲线。

#### 上游源被挡时，"最重要的品牌永远查不到"

`test_version_ceiling` 查的是"我们的扫描上限有没有落后于真实发布的版本" —— 覆盖度
说"全覆盖"时，覆盖的可能是一个已经过时的版本区间。它的判据只能来自上游发布源。

本机实测：Mozilla 的源可达，**Google 的三个源全部连不上** —— `curl` 也取不到，
所以不是我们的装置问题。于是**最重要的那个品牌（Chrome）永远是"没查到"**。
"取不到不算失败"的判法是对的（否则这条门禁在这台机器上永远红，很快会被无视），
但代价是它对 Chrome 什么都不说。

补一个**可达的下界**：本机已装浏览器的版本。它回答不了"上游最新是多少"，但能回答
**"有没有落后于一台真实存在的浏览器"** —— 用户的 Chrome 自动更新到我们表外的版本
时，这条会先发现。阴性对照验过：把上限压到 140，它立刻报"chrome 已发布到 151"。

**取不到判据时，先找一个够得着的弱判据，而不是让那一格永远空着。**

修法按上表随机化，两侧都做；`verbatim=True` 时保持 golden 的 GREASE 值（重建验证
要的是采集那条报文）。接进来之后 `test_builder_parity` 立刻红了 6 处 —— **它在比
GREASE 的具体值**，而那本来就该每次不同。比结构时把 GREASE 归一成一个记号，
**只归一取值、位置照比**：位置错了仍然要红。

做阴性对照时撞出实现里一个真隐患：我原来用 `while ext_a == ext_b:` 重试来保证两个
扩展 id 不同，变异把条件改坏之后**直接变成死循环，门禁挂死 10 分钟**。改成取一个
偏移量绕过去，**构造上就不可能相同**（3000 次抽样 0 次相同）—— "靠重试保证不变式"
在取值域退化时就是这个下场。

还有一处是门禁自己的：把 GREASE 换成 0 之后，我那条"两个 id 不能相同"的断言
**什么都没查到就绿了** —— 它只在"GREASE 集合"里比，而集合已经空了。补上"GREASE
还在不在"这一条才红。**先查还在不在，再查对不对**，这与"零处不符先拆跳过"同族。

改完照例重跑真机 —— 这一处直接改变上线字节，只跑离线门禁等于没验：

```
系统扫描   我们的"会变集合"与真机一致（0xa/0x15/0x2b/0x33/0xfe0d + GREASE id），
           扩展 id 序列 8/8 各不相同
真机握手   104/104（52 profile × 2 站点）
回显比对   37/37 · C 路径 8/8 · 与被模仿者 A/B 23/23，零处不符
```

**A/B 那 23/23 尤其说明问题**：我们与 curl_cffi/wreq 本尊的 GREASE 各自随机、
具体值必然不同，而对端算出的 JA4 仍然逐条相同 —— 因为 JA4 按 RFC 8701 剔除
GREASE。**"该随机的随机了，而不该受影响的没受影响"**，两件事一次验到。

#### 同族第 6 处：GREASE ECH 的长度**每次连接随机**，于是 JA4 本来就不唯一

A/B 修完 padding 再跑，`chrome119` 仍然不符，**但方向翻了**。本地 sniffer 抓本尊
的真实字节逐扩展比长度，第一反应是"ECH 长度随 SNI 变"—— 但同一条件下连采两次
得到 218 与 282，**同一个输入两个结果**，那就不是长度函数。

连采 16 次，答案很干脆：

```
ECH 体长  186×6  218×4  250×5  282×1     两两相差 32
CH  体长  512（补 padding）/ 538 / 570
JA4       t13i1516h2_…_b1ff8ab2d16f ×10
          t13i1515h2_…_02713d6af862 ×6
```

**GREASE ECH 的体长每次连接从一个固定集合里随机取**；它进总长，总长决定
padding 补不补，于是**同一个客户端打同一个目标会产生两个不同的 JA4**。
这类 profile 的"那个 JA4"本来就不存在 —— 我们注册表里存的是其中一个。

两层后果都要紧：照抄 golden 的长度 ⇒ 我们**每次连接一模一样**，而真客户端在变，
**一个 JA4 永不变化的"Chrome"在聚合统计里很显眼**。改成同样随机之后，我们构造
24 次得到的 ECH 体长、CH 体长与 JA4 取值集合，与真机实测**逐项吻合**。

**集合是按 TLS 栈分的，不能通用。** 第一版把 BoringSSL 那组套给了所有 profile，
门禁当场报出 Firefox 被改成了不属于它的长度：Firefox 的 golden 是 249/281/569
（模 32 余 25），而 BoringSSL 那组是余 26 —— **两个族**。

后来把 NSS 那族也实测了：真机 Firefox 连开 6 次，**ECH 体长恒为 281、CH 体长恒为
1887**。所以这不是"我们没测所以保守"，而是**两个栈的行为本来就不同** —— BoringSSL
每次抽，NSS 固定。给 NSS 套上 BoringSSL 的集合，等于让 Firefox 发出一个真 Firefox
从不发的长度，**比照抄还糟**。`ech_family()` 就是这条界线。

语料本身也印证它：curl_cffi / tls_client / wreq 的 firefox 形态落在
`{186,218,250,282}` —— 它们是用 BoringSSL/utls **模拟** Firefox，GREASE ECH 走的
是自己那套；而 `real:firefox153` / `real_quic:firefox` 这些**真机**采集是
249/281/569。**"Firefox 的指纹"取决于是谁在发。**

顺带撞出一处一直没人发现的死代码：`capture_browser` 的 Firefox 分支
**从来没被走到过** —— `BROWSERS` 表里根本没有 firefox，`capture("firefox")` 恒报
`not found at None`，"装了却用不上"。补进表之后才发现它也不工作：Firefox 正常启动
但 45s 内一个 ClientHello 都不到，而换成 `https://localhost:<port>/`（不依赖 DNS
覆盖）立刻抓到 —— 是 `network.dns.localDomains` 没生效，不是采集链路坏了。
**分层定位比反复调参有用**：一个替代路径就把"DNS 层"与"采集层"分开了。

**判据也要按用途分开**，与 `pre_shared_key` 同一个道理：重建验证要"照采集那条"
（`verbatim=True`），真出网要"每次新鲜"。默认值给的是**出网口径** —— 忘了传参时
退化成固定字节，比退化成重建不上危险得多。

#### 全量跑一遍，又逼出一处实现分歧 —— 以及我自己一句误导的诊断

把回显比对从 20 条提到**全部 37 条可联网验证的 profile**，冒出一条
`tls_client:chrome_133`，我的诊断信息写着"三段都相同却哈希不同 —— 哈希算法本身
有问题"。**那句话是错的**：两个哈希段确实完全相同，差的是**前缀里的 ALPN 两位**
（我们 `h3`、对端 `h2`），而我的诊断压根**没有比过前缀**。

> 诊断信息比结论更容易骗人：它用肯定的语气报出一个我根本没测的东西。

真因查清了，而且证据是对端自己给的：该 profile 提供 `h3, h2, http/1.1`，回显里
明明记着 `"protocols": ["h3","h2","http/1.1"]`，JA4 却写 `h2` —— 那正是 TCP 上
协商出来的协议。规范说取 ClientHello 里 ALPN 列表的**首项**，所以**又是回显服务
偏离规范**，与 padding 同类，对伪装同样无害。

判定要求**对端自己记录的 ALPN 首项与我们一致**才算这处分歧，不是见到 ALPN 不同
就放过 —— 只有一条 profile 是 h3 打头，样本量为 1，不能只靠"听起来合理"。

#### 还差一半：验的是参考实现发的字节，生产发的是 C 那份

上面那一档全绿，但它验的是 **Python 参考实现**发出去的字节。**生产走的是 C 那条
路** —— 两者一旦分叉，这一档全绿也说明不了生产没问题，而本项目已经栽过五次
"两份实现悄悄分叉"。

key_share 注入（`browserfp_build_client_hello_ex`）正好让这件事可做：让 **C 构造器出
ClientHello**、把我们生成的公钥注进去，Python 只负责完成握手与密钥调度。于是上线
的字节就是生产那份。断言是最直接的性质：

```
C 路径（生产发的字节）8/8 条，覆盖引擎 ['chromium', 'gecko', 'webkit', '其它']
  C✅  curl_cffi:chrome119   与参考实现同一指纹
  C✅  curl_cffi:firefox135  与参考实现同一指纹
  C✅  curl_cffi:safari180   与参考实现同一指纹
```

**同一条 profile，两条路径在对端眼里必须是同一个指纹**，而且都等于我们自己算的。

这里也自摆了一道：C 那一档第一版**直接比哈希**，于是含 padding 的四条全部报错 ——
同一个已知分歧在两处各判一次、判法还不同，等于自己给自己造假警报。改成与上一档
**共用同一个 `ja4r_diff`**。

**扩面还抓到一个真缺陷**：`linux:firefox-111-linux` 的 profile 写着 6 条 PRIORITY
帧，对端却看到 `0` —— 我们的 `H2Client` **根本不发 PRIORITY 帧**。C 侧的
`browserfp_build_h2_preface` 一直在发，**又是一处两份实现的分叉**，而此前所有 h2
端到端只看 ServerHello 与 `:status`，没有一条去问"对端看到的 h2 指纹是什么"。

#### 改完必须重跑真机，否则只是"离线门禁绿了"

前面五处改动全部落在**真机端到端所依赖的那条路**上（`tls13.py` 换了构造器与密钥
生成，C 侧改了 ECH 与 PSK），只跑离线门禁等于什么都没验。重跑两条真机链路：

```
test_live_handshake   52 profile × 2 站点 → 104/104 可用
test_build_live       C 构造的字节 × 4 品牌 × 3 站点 → 12/12 收到 ServerHello
```

这次的 104/104 比之前那次**更有分量**：以前发的是单条 key_share，现在发的是
浏览器保真的形状（GREASE + X25519MLKEM768 + X25519 三条），服务端照样接受 ——
说明保真的形状在真实网络上是可用的，不是"只在纸面上正确"。

**15 条会话恢复态从"通过"变成了"显式跳过"，那是修正不是退步。** 旧行为是把
`pre_shared_key` 扩展整个丢掉再握手，于是它们一直是绿的 —— 但那验的不是这条
profile，是一个被改过的形态。没有有效票据就承认验不了，比拿一个改过的形态换
一个绿勾诚实。

#### 门禁自己崩掉，就看不见它本该报告的东西

这三处改动里，最花时间的不是判据本身，而是**门禁在阴性对照下崩溃**：某条 profile
让构造器抛异常 → 整条门禁当场死掉 → 后面几段一条都没跑。同一个形态在
`test_keyshare` 里撞了**三次**（形状比对循环、注入那段、ECH 那段），每次我都只
补了当处的 `try`，下一次换个位置又来。

崩掉时终端只有一个 traceback：看不到哪几条不符，也看不到还有没有别的问题 ——
**一个崩掉的门禁与一个报"1 处问题"的门禁，给出的信息量差了一个数量级**。
最后不再逐处补，只留一个 `py_build()` 入口，构造失败一律记成发现。

#### 但三方一致证明不了"这份理解是对的"

上面那句"已被 RFC 官方向量校准"，长期是**一句没有门禁支撑的话**。真实情况是
JA4 从头到尾只跟自己比过：Python↔C、C↔Lua。三方一致只说明**三份实现抄的是同一份
理解**。更隐蔽的是 golden 里的 `ja4` / `ja3` 字段 —— 它们看着像外部数据，实际是
采集时由 `oracle/clienthello.py` 算的（见 `oracle/collect.py` 的 import），
拿它们当参照是**自我确认**。

于是一整类缺陷可以在全绿的情况下存活：排序规则搞反、截断取 12 位取成 16 位、
`ja4_c` 少排除一个 SNI —— 只要三份实现错得一致，没有任何门禁会响，而真实检测方
算出来的指纹与我们发的对不上。**这正是本项目最不能出错的地方，却是唯一没有外部
参照的地方。**

`test_ja4_vectors` 补上这一环，判据取自 FoxIO 的 JA4 规范
（`technical_details/JA4.md`）给出的完整向量。两段：

```
算法级   规范给的输入字符串 → SHA256 前 12 位，四个哈希当场重算
         （抄错一位与实现错一位表现完全一样，所以不照抄结论）
端到端   按向量字段拼一条真 ClientHello → Python 与 C 各算一遍
         两边都必须是 t13d1516h2_8daaf6152771_e5627efa2ab1
```

**首次跑就逐字符通过**，包括 `-o`（原序）那两个哈希。顺带解释了一件旧事：上一轮
做代码变异时"cipher 不排序"得到的 `acb858a92679`，正是规范里 JA4_o 的密码套件
哈希 —— 当时只当它是个随机变化的值，其实它一直在说"你把排序去掉就退化成原序"。

这条门禁**不读任何 golden**：输入全是规范里的常量。它是全项目唯一一条与自家语料
完全无关的判据，也正因如此才能抓住"三份实现错得一致"。阴性对照三种都会红：
C 去掉 cipher 排序、C 不排除 SNI、Python 把一处 `sorted()` 换成 `list()`。

## UA → profile 映射（生产实际用法）

网关在 CDN 之后**拿不到客户端的 ClientHello**，只能看到 UA。所以出站代理浏览器
流量时，是按 UA 挑一个匹配的指纹去伪装——挑错就成了"UA 说是 Chrome 150、TLS 却
是别的形态"的 split-brain，比不伪装更容易被判。

三层实现语义一致（由差分门禁保证）：Python `oracle/uamap.py` 是权威，
C `browserfp_lookup_ua()` 与 Lua `browserfp.by_ua()` 供生产使用。

```lua
local r = browserfp.by_ua("chrome", 150)
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
TLS 层   browserfp_build_client_hello()   → ClientHello 字节
h2 层    browserfp_build_h2_preface()     → PREFACE + SETTINGS + WINDOW_UPDATE + PRIORITY
```

HEADERS 不在其中：它的内容依赖具体请求，本库只给出伪头**顺序**
（`browserfp_h2_pseudo()`，形如 `m,a,s,p`）。

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

#### 三层一致性：检测方查什么，库就得能自查什么

检测方不会只看一层 —— TLS 指纹说 Chromium 而 h2 说 Gecko，一眼就假。所以库自己
也得能查：使用者能拿它自审伪装，我们能拿它守住"库产出的三层永远同源"。

```
browserfp_coherence(ja4, akamai, header_order, &tls_eng, &h2_eng, &hdr_eng)
    0 = 有观测的那些层一致    1 = 矛盾    -1 = 信息不足
```

返回的是**各层认出的引擎**而不是一个布尔 —— 报"哪一层不一致"才有用。

前提是引擎在三层都良定义，这条实测过：**81 条 TLS profile 无一跨引擎**，
19 个 akamai 无一跨引擎，三个引擎的头顺序互不相同。生成器里有硬断言，
跨了就直接构建失败。

头顺序按**子序列**匹配（真实请求只发完整顺序的一部分），实测 600 个随机子序列
里 549 个能唯一定位引擎，短子集（3 个头）容易多解 —— **那时必须报"认不出"
而不是硬选一个**。

门禁两侧都验，只验一侧都是半个门禁：

```
正向  库为每个 (品牌,版本) 产出的三元组必须判 ok      644/644
反向  故意跨引擎拼的三元组必须判 mismatch             6/6
```

反向那一半是关键：只验正向的话，一个**恒返回 ok 的实现也能全绿** —— 而那正是
最坏的情况，使用者以为自审过了。

#### 会话恢复态绝不能进伪装路径

库里有 15 条 `resumed` 形态的 profile（入站识别要用），它们带
`pre_shared_key`(41) —— 里面是**采集当时的会话票据**，合成不出来。发一个带陈旧
binder 的恢复态握手，服务端验不过会退回完整握手，**比干净的首连更可疑**。

`oracle/uamap.py` 显式过滤了 `mode != "initial"`，`test_coherence` 断言
`by_ua` 在全版本范围内一条恢复态都不返回。

**这条断言的可达性单独验过**：只去掉那个过滤**不会**让它变红 —— 版本表用
`setdefault`，先注册的 initial 条目已经占住了版本号。要同时改动注册顺序才会漏
（去过滤 + 反转顺序 → 红；只反转顺序 → 绿）。所以它守的是"双重保护同时失效"，
不是摆设，但也别指望单点变异能触发它 —— **写下这一点，免得后人以为它是个永不
触发的摆设而删掉**。

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

#### 范围边界：请求头不归我们管

伪装曾经做过四层：TLS 字节、h2 开场、请求头顺序、头取值（含 `sec-ch-ua`）。
**后两层已整层删除**，理由来自使用场景：本库服务的是网关转发，请求头是真实
浏览器发来的、原样转出去 —— 我们既不排序也不添加，于是也没有"我们这一侧的
头顺序"需要伪造。自己合成 `sec-ch-ua` 只会凭空多出一处可能与来访请求对不上的
东西，那是给自己造破绽。

删掉的是：C 的 `browserfp_header_order` / `browserfp_header_value` / `browserfp_sec_ch_ua` /
`browserfp_ua_platform` / `browserfp_engine_of_headers` 与配套 CLI，Lua 的同名绑定，
oracle 下的 `headerorder.py` / `uach.py` / `hdrcollect.py`，
spec 下的 `uach.json` 与 golden 里的 `headers_real.json` / `uach_real.json`，
以及 `test_header_order` / `test_uach` / `test_uach_platform` /
`test_masquerade_live` 四条门禁。（这些名字下面不带路径前缀是有意的 ——
文档门禁会核对 `oracle/…` 形式的路径是否存在，而它们已经不存在了。）

`browserfp_coherence` 从三层降为**两层**（TLS 与 h2）。它仍是有价值的：TLS 说
Chromium 而 h2 说 Gecko，一眼就假 —— 那两层都是**连接握手**的一部分，由我们
自己发出，与请求头不是一回事。

留下的边界要记清楚，免得下次又混：**h2 的 SETTINGS、WINDOW_UPDATE、PRIORITY、
伪头序（`:method/:scheme/:path/:authority`）仍然是指纹**，它们构成 Akamai
指纹，属于我们要伪造的范围；被删掉的是**普通请求头**的顺序与取值。

#### 移动端第一份真机实采：h2 与 TLS 的结论正好相反

移动端此前一份实采都没有，而"移动端与桌面大概率相同"这句猜测**方向是反的**。
iOS 模拟器里的 Safari 是真的 iOS WebKit 构建，从它采到的 h2 与 macOS Safari
**在三个轴上同时不同**：

| | macOS Safari 27 | iOS Safari 17.4 |
|---|---|---|
| SETTINGS 顺序 | `2:0,3:100,4:2097152,9:1` | `2:0,4:2097152,3:100` |
| WINDOW_UPDATE | 10420225 | 10485760 |
| 伪头序 | `m,s,a,p` | `m,s,p,a` |

**模拟器算不算真机，不靠推断。** 本次采到的 akamai 指纹与 curl_cffi /
tls_client / wreq **三家独立库**记录的 Safari iOS 17 逐字节一致（4 条）——
三家各自采自真机的数据同时对上，模拟器假象解释不了。另做了两组对照：
iOS 17.4 与 17.5、iPhone 与 iPad 各采一次，结果完全相同。

采集固化成 `oracle/simcollect.py`（TLS 与 h2 两层，CA 只装进**模拟器**的信任库
`simctl keychain add-root-cert`，不碰用户钥匙串），**"模拟器等于真机"那条论证
也固化成了门禁** `test_simulator`。这一步不是形式主义：那条论证是会过期的 ——
库更新一版、golden 被改一次，依据就可能不成立，而那份 iOS 数据仍会以"实采背书"
的身份被 h2 与注册表继续用下去。门禁不重新采集（重采要人盯着模拟器），验的是
**入库那份仍与三家独立库一致**。阴性对照：把 golden 里的 iOS h2 指纹改成桌面的
值，门禁立刻红。

写 `verify()` 时还自摆了一道：比对对象最初写成"任何带 ios 的 curl_cffi Safari
别名"，抓到的是 **iOS 18** 那条，于是报"JA4 不再相同" —— 而那本来就该不同。
**比对对象挑错，看起来和真的回归一模一样。** 改成按采到的版本精确匹配。

已知缺口写在 golden 的 `_provenance` 里：本机只有 iOS 17.4/17.5 两个 runtime，
iOS 18+ 与 26/27 没有实采。

#### TLS 层上 iOS 与桌面 Safari 是同一个指纹，分歧只在 HTTP 层

同一台模拟器再采一次 ClientHello，结论与 h2 那边正好相反：**iOS Safari 17.4 的
JA4 与注册表里的 `curl_cffi:safari172_ios` 完全相同** ——
`t13i2013h2_a09f3c656075_14788d8d241b`，9 个字段逐项一致，扩展序列剔除 GREASE
后也一致，GREASE 位置相同。

采 nosni 版靠的是**改用 IP 地址访问**（Safari 因此不发 SNI），而不是事后把 SNI
扩展删掉 —— 后者是合成，不是采集。带 SNI 的那次也单独采了一遍：两个哈希段同样
一致，只差 SNI 标志 `i→d` 与随之多出的一个扩展，说明差异只来自 SNI 本身。

所以这份实采并进注册表时**没有新增一条指纹**，而是并入已有 profile，成了
`real:safari-ios`，带着 27 个别名 —— 横跨 curl_cffi / tls_client / wreq / utls
记录的 Safari 桌面 15.6–18 与 iOS 15.5–18.1。

**而这恰好触发了注册表一个一直存在的缺陷。** 注册表按 TLS 指纹去重，h2 只是
搭车；同一条 profile 下的 27 个别名 TLS 相同但 h2 不同，而合并时挂哪份 h2 是
**先到先得**（`if h2 and not rec["h2"]`）。实测后果：我们自己采的
`real:safari-ios` 被挂上了**桌面 Safari 15/16 的 h2**，然后被 `h2table` 当成
"实采"读走。**错值挂在最可信的来源名下，比库之间互相矛盾更难查** —— 而此前
没有任何门禁会发现，因为没人比过"注册表里那份实采的 h2，是不是我们采到的那份"。

改成实采优先，并把"TLS 相同而 h2 不同"这件事在建表时打出来。门禁补了一条：
凡是 `real:*` / `linux:*` 且在 `h2_real_browsers.json` 里有对应采集的，注册表挂
的 h2 必须与采集逐字节相同。阴性对照（改回先到先得并重建）确认它会红。

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

**而"移动端取同版本桌面"这条规则本身是错的，它的前提检查给了假绿。**
`check_premises()` 每次建表都复验规则前提，看起来很严 —— 但它只挑了两个版本比
（18 和 26），而版本 18 因库内分歧被**静默跳过**，于是整条前提实际上只剩版本 26
一个点在比，它恰好相同。逐版本全扫立刻露馅：**iOS 15 与 16 与桌面明确不同**
（`4:2097152` vs `4:4194304`），这条前提从来就没成立过。

这与"零处不符先拆跳过"是同一族：**先看比到了几个点，再看结论。** 现在
`check_premises` 逐版本全扫，并且断言比对点数不足本身就是失败。

规则换成**同平台最近较低版本**：平台轴已实证有分歧，版本轴则实测稳定
（桌面 26→27 无变化），两条腿都在 `check_premises` 里复验。原来那条改成
**反向断言** —— iOS 与桌面必须仍然不同，哪天处处相同了要重新评估，
而不是让一条用不上的规则继续躺着。

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

## QUIC/h3 层：Firefox 那份是"试着采一次"才采出来的

这一层长期只有 **1 条**指纹（三份 Chromium 实采去重后同一条），采集器的注释里
写着"Firefox 走 about:config，需要预置 prefs，**暂未支持**"。真去做才发现，
不支持的原因不是 prefs：

Firefox 确实有等价开关 —— `network.http.http3.alt-svc-mapping-for-testing`
（`"host;h3=:port"`），作用同 Chromium 的 `--origin-to-force-quic-on`：不必等
服务端广播 Alt-Svc 就直接走 h3。加上它，Firefox **立刻就发出了 QUIC Initial**。

真正卡住的是探针里一个**只有 Firefox 才触发得到的缺陷**：

```
完整性判据写的是"已收到的片段之间没有空洞"
但"没有空洞"不等于"收齐了" —— 末尾片段还没到时，已收到的部分同样没有空洞
```

Chromium 把整条 ClientHello 塞进一个 Initial，所以这条判据一直够用；Firefox 会
拆成多个 Initial，第一个包单独看就是"无空洞、但只有 1209 字节，而消息声称 1405"。
于是重组"成功"返回一条**被截断的 ClientHello** —— 这次是解析报错才暴露，
换个长度它完全可能悄悄产出一条错的指纹。

改成拿握手消息自己的长度字段（第 1..3 字节）当收齐判据之后，采到了
`q13i0314h3_…`，与 Chromium 那条明显不同（14 个扩展 vs 10、5 条曲线 vs 4）。

Safari 仍然没有 —— 它没有等价的强制开关，采集器会明确跳过并说明理由。

### QUIC/h3 的覆盖度此前是隐形的

这两层一直不在 `verify_all` 的覆盖度报告里 —— **没有覆盖度的层等于隐形**，
悄悄退化也看不出来。它们与 TLS/h2 不同：profile 不进 UA 版本表（`mode` 不是
`initial`），只服务入站识别，所以按**引擎**报最诚实：

```
QUIC chromium:142,151  gecko:153
h3   chromium:142,151  gecko:153
缺 webkit（Safari）—— 无强制开关；证书信任已解决，但它就是不发 QUIC（见下）
```

配了引擎级棘轮（`QUIC_ENGINES`）：少一个引擎就红。变异验过 —— 删掉
`real_quic:firefox` 会红，只抹掉它的 `h3` 字段也会红（两层分别记）。

Safari 那条**采不到**。最初的理由是"自签 CA 要改用户/系统信任设置，属侵入性
操作"，后来这条理由消失了：iOS 模拟器能单独装 CA（`simctl keychain
add-root-cert`），只影响模拟器。装好之后实测的结果是它**根本不发 QUIC** ——
Alt-Svc 送达、页面加载 47 次、UDP 数据报 0 个。详见下文。

### h3 层：Firefox 采到了，卡点是一条"检测到自装根证书就禁用 h3"的开关

上一轮定位到"卡在 alt-svc 存储就绪时序"，照那条路做完之后又冒出两层，
每一层的表面症状都是同一句 `未收到 H3 请求头`：

**第一层 —— 探针只服务 UDP。** 加了并行的 TCP/TLS 端，响应带
`Alt-Svc: h3=":port"`（真站点让浏览器升级 h3 的正规方式，顺带摆脱测试专用
pref）。日志确认 Firefox 收到并建立了映射：`AltSvcMapping created npnToken=h3`。

**第二层 —— Alt-Svc 只对后续请求生效**，而页面只有一个请求且已在 TCP 上完成。
补了子资源与一次 meta refresh 触发新导航之后，Firefox 真的开始建 HTTP/3 会话
（`Http3Session::Init` 出现 35 次）。

**第三层才是真正的墙**，日志写得很清楚：

```
Http3Session::CallCertVerification
Http3Session::Authenticated [hasThirdPartyRoots=1, servCertHashesSucceeded=0]
Http3Session::Close → ConnectionClosed error=804b…
```

同一张证书在 TCP 上验证是**通过**的。差别在于 Firefox 有一条专门的策略：
检测到用户自装根证书就禁用 HTTP/3（为躲开中间人设备）。在 `XUL` 里搜 pref 名
直接找到了它 —— `network.http.http3.disable_when_third_party_roots_found`。
关掉它，h3 立刻握上手。

采到的结果与 Chromium 明显不同，**连伪头序都不一样**：

```
chromium   1:65536,6:262144,7:100,51:1                     | m,a,s,p
firefox    1:65536,7:20,8:1,51:1,16765559:1,727725890:0    | m,s,a,p
```

（后两个是 GREASE 设置，`test_h3` 的剔除逻辑对它们同样生效。另外注意
Firefox 的 h3 伪头序 `m,s,a,p` 与它自己的 **h2** 伪头序 `m,p,a,s` 不同 ——
同一个浏览器，两个协议两套顺序。）

**Safari 仍然没有，但"缺的只是证书信任"这句话已经不成立了。**

证书信任那一步后来解决了：iOS 模拟器可以用 `xcrun simctl keychain <udid>
add-root-cert` 单独装 CA，只影响模拟器、不碰用户钥匙串（同一条路已经让 h2 与
TLS 两层的 iOS 实采落了地）。装好之后重跑，结果是：

```
TCP 请求 47 次: ['/', '/sub.png', '/favicon.ico', '/', '/sub.png', '/']
UDP 数据报  0 个: []
```

**Alt-Svc 送到了、页面被反复加载了 47 次，而 iOS Safari 一个 UDP 数据报都没发。**
所以拦路的从来不是证书 —— 换掉信任这一步之后它照样不走 QUIC。试过把
`HTTP3Enabled` / `WebKitHTTP3Enabled` / `WebKitExperimentalHTTP3Enabled` 三个键
写进 `com.apple.mobilesafari` 与 `com.apple.WebKit.WebContent` 再重启 Safari，
UDP 仍然是 0。

候选解释还没分辨清楚（都未经证实）：iOS 的 HTTP/3 是需要在设置里手动打开的
实验特性、Safari 不对 loopback 走 QUIC、或只在 443 端口认 Alt-Svc（绑 443 要
root）。**把"证书信任"当成剩余障碍写在文档里是错的** —— 那会让下一个人朝着
已经解决的方向再走一遍。

这三层每一层的表面症状都一样。只看 `未收到 H3 请求头` 会得出"Firefox 不支持"
的结论 —— 而真相是三个互不相关的原因叠在一起，**每一层都要靠浏览器自己的日志
才定位得到**。

QUIC Initial 采到了，**h3 的 SETTINGS 还没有** —— 那一层要完成握手才读得到。
Firefox 这条卡在哪，已经定位清楚，不是"没试过"：

两件准备工作都做对了 —— pref 确实生效（MOZ_LOG 里看得到
`AltSvcMapping ctor … npnToken=h3` 建出来了），CA 也用 certutil 装进了 profile
证书库（要装 **`ca.pem`** 不是 `fullchain.pem`，后者第一张是叶证书，装成叶再标
`CT,,` 语义就错了）。卡在第三件事：

```
AltSvcCache::LookupMapping … skip when storage is not ready
```

alt-svc 缓存的存储是异步加载的，**首个请求发出时还没就绪**，于是 Firefox 按普通
https 走 TCP —— 而探针只服务 UDP，那条 TCP 直接失败且不会重试。Chromium 没这
问题：`--origin-to-force-quic-on` 从第一个请求就强制 QUIC，根本不查 alt-svc 缓存。

往下走的路很明确：让探针**同时起一个 TCP/TLS 端**，在响应里带
`Alt-Svc: h3=":port"` —— 那才是真实站点让浏览器升级到 h3 的方式，顺带还能摆脱
这个测试专用 pref。工作量在 `h3probe` 那边。

**结论写进代码而不是留一句"不支持"**：下一个人接手时该看到的是"卡在
alt-svc 存储就绪时序，路在 h3probe 加 TCP 端"，而不是重新试一遍 pref。

## 模块级共享缓冲：单线程测试永远看不出来

`lua/browserfp.lua` 有 9 个 `ffi.new` 出来的模块级缓冲（`ch_buf` / `h2_buf` /
`e1..e3` …），一个 worker 里所有协程共用。安全的前提只有一条 —— **写进去和
`ffi.string` 读出来之间不能有让出点**。此前所有 Lua 验证都是单线程的，这条前提
从没被验过。

`test_openresty` 现在会 16 路并发打 5 个品牌，把返回的**字节**解析回来与该品牌
应有的指纹逐字段比。

**第一版比错了字段**：比的是响应里的 profile id —— 而那个 id 来自 Lua 表、不在
共享缓冲里，串了也不会变。阴性对照（在 build 与 `ffi.string` 之间插一个真让出
点）因此照样全绿。改成比字节之后，同一个阴性对照立刻触发：

```
并发 12/60 个请求各自对得上
  ✗ firefox 135: 拿到的字节与 curl_cffi:firefox135 差 [ciphers, extensions_ordered, curves]
  ✗ safari 26:   字节解析失败 ParseError
```

**这条对照同时证明了两件事**：风险是真的；而当前代码安全是因为那段路径上确实
没有让出点，不是因为"大概不会有事"。这个结论写在了那几行缓冲声明的正上方 ——
往后面加代码的人该在那里看到它。

## 恶劣输入：一次越界不是一个请求失败，是整个 worker 挂掉

这些函数跑在 nginx worker 里，同 worker 上的并发请求共命运。所以健壮性单独一条
门禁，判据不是"结果对不对"，而是"活着回来且没踩内存"。

**必须带 ASan + UBSan**：不带的话"没崩"只说明这次没踩到 —— 越界读发生在只读的
静态表上时常常无声无息，而那种最难查。

第一次跑就抓到 `browserfp_ja4(NULL, …)` 直接 SEGV（少一个空指针检查）。

喂进去的：NULL、空串、单空格、70KB 超长串、非 UTF-8 字节、全逗号、越界与
`(size_t)-1` 下标、零长缓冲、差一字节的缓冲、**截断到每一个长度**的 TLS record、
长度字段撒谎的 record。当前 1543 次调用全部安全返回。

**结构化变异 + 精确大小的堆缓冲，抓到一个真漏洞。** 拿库里每条 profile 真实
构造出的 ClientHello 逐位点改（每位点 6 种恶意值，再配"长度说得比实际多/少"
两种截断），20 万次调用，0.15 秒跑完。它当场报出未变异代码里的
heap-buffer-overflow：

```
browserfp.c: supported_versions 用 n = ebody[0] 当列表长度，不检查 n 是否超出扩展体
恶意 ClientHello 声称 255 字节 → 读到扩展外、缓冲外
```

入站识别的输入完全由对方控制，这是真漏洞。**关键是缓冲要按实际长度堆分配**：
此前用固定 16384 的静态数组喂，越界落在"逻辑长度之外、物理数组之内"，
ASan 根本看不见 —— 换成精确大小立刻报出来。

调用次数本身也有下限断言 —— 程序若因编译宏或早退只跑了几次，"没崩"证明不了
任何事。变异验过：去掉 `browserfp_ja4` 的空指针检查、让 `lookup_ua` 不挡 NULL brand、
去掉 record 长度截断检查、放宽 u16 列表边界、去掉 cipher 列表边界、去掉刚修的
`supported_versions` 夹紧 —— 六种全部变红。

**"没崩"还得配一句"真的走到了"。** 解析器里 5 个扩展 `case` 全都出现在我们
82 条 profile 里，所以变异确实能走到 —— 但这话得是个数字而不是推理。健壮性构建
里给每个 case 加了计数器，门禁断言每个都被走到过（当前最少的
`supported_versions` 是 88 万次）。

**计数器放错位置会让断言完全失灵**：第一版放在 `switch` 之前，计的是"看见了
这个扩展"而不是"解析体真的执行了" —— 把四个 case 的体改空，计数照样满额，
断言纹丝不动。移进 case 体内之后，同一个变异立刻红。这与并发检查那次
"比错字段"是同一类错误：**测了一个相邻但不等价的东西**，而它看起来完全合理。

加强之后是**全位点 + 双字节**：原来 `off += 7` 只覆盖 1/7 的位置，而长度字段
往往就那么一两个字节，跳着走很容易正好跨过去；单字节变异也常常还落在合法范围
里，所以再配一次与相邻字节的组合。189 万次调用，1 秒跑完。

**另一个解析器不做同等投入**：`oracle/quic.py` 的 `parse_initial` 是 Python 且
只在采集/测试里用，不在生产路径 —— Python 内存安全，最坏是异常，而探针已经捕获。
唯一值得担心的是死循环（会卡住探针线程），单独验过 3005 次随机/截断输入全部快速
抛错、无一超过 2 秒。**风险面在哪就把力气花在哪**，不为对称而对称。

**这轮还栽在"陈旧产物让测试说谎"上第四次**：门禁原本只看
`os.path.exists(fuzzcli)`，不看 `make` 的返回码。我把 `feed_parser` 误插到
`#include` 之前导致编译失败，而临时副本里带着一份复制来的旧二进制 —— 于是三个
"去掉边界检查"的变异全部"通过"，跑的根本是没变异的那份。现在门禁先删产物、
构建失败直接判红。前三次分别是：pyc 缓存、make 的秒级 mtime、`git commit`
带 pathspec。

**Lua 那层要单独验：C 挡住了 NULL，不等于 Lua 挡住了错类型。** 同一批恶劣输入
喂给 Lua 接口，第一次跑抓到三处未捕获的错误 —— 每一处在
`content_by_lua_block` 里都是 500：

```
coherence 收数字        FFI 抛 cannot convert 'number' to 'const char *'
coherence 收含 nil 的表 table.concat 报错
sort_headers 收非字符串 h:lower() 报错
```

判据是"返回 nil+err 合格，抛错不合格"。修完 2005 次调用无一抛错，同样有次数
下限与变异验证（去掉 `sort_headers` 的类型判断、`coherence` 不再过滤非字符串，
两次都变红）。

## 关键方法论

**干净克隆要单独验。** 开发机上攒着两类不进版本控制的东西 —— `spec/cache/`
（40MB 源码缓存）与 `csrc/` 下的编译产物。它们让本机看起来一切正常，新克隆的人
却会撞墙。`test_clean_clone` 用 `git archive HEAD` 导出一份纯净副本，在里面跑
不联网的门禁。第一次跑就抓出三个：

```
test_build_parity   缺 csrc/snitest —— Makefile 里**根本没有它的构建规则**，
                    本机那个是早年手工编的，所以一直没人发现
test_h2_table       冷缓存下要为 650 个版本逐个取源，**超时挂死**（退出码 124）
                    而不是优雅跳过 —— try/except 拦得住异常，拦不住慢
test_match          缺 hrrserver（Go 二进制），判失败而不是跳过
```

三种都不是"数据不对"，是**打包与降级路径**的问题，只有换个干净环境才看得见。

它验的是 **HEAD 而不是工作区** —— 干净克隆拿到的就是 HEAD。所以修完要先提交才
能让它转绿，这一点是有意的。

**"跳过"必须显示出来，而且不能全跳过。** `test_match` 现在缺 Go 时报跳过而非
失败（与"无 docker 跳过"同一口径 —— 判失败的话它在那种环境里永远是红的，很快
会被无视），但会打印原因并计入"N 项跳过"；全跳过则判失败，那说明这台机器什么
都没验到。

**"平凡通过"要靠改坏数据源来查，不能靠读代码。** 清空 `spec/profiles.json` 再
把全部门禁跑一遍，结果是**四个骨干门禁照样绿**：

```
test_c_parity      差分比对 0 个 profile：0 一致，0 不符      退出码 0
test_lua_parity    三方差分 0 个 profile：0 一致，0 不符      退出码 0
test_rebuild       重建 0 个 profile：0 通过，0 失败          退出码 0
test_build_parity  构造器与 golden 一致                       退出码 0
```

三方一致性与重建正是整个项目的骨干 —— 注册表哪天被截断或读空，它们会异口同声
地说"一切正常"。现在四个都有了下限断言，空表与半截断（10 条）都会红。

**下限不是棘轮**：它只回答"比对集是不是还在"，所以取一个远低于真实值（81）又
远高于零的数，不随数据增长而调。

同一次扫描里另有 7 个门禁空注册表仍绿，但那是**合理的** ——
`test_golden_orphans` 查的是 golden 与 registry.py 源码、`test_h2_identify` 读的
是 h2 表（自己有 644 条的下限）、`test_quic` / `test_h3` 各有自己的数据源。
分清"该红没红"与"本来就不该受影响"，比一律加断言重要。

第五个是**意外抓到的**：一次后台 `--live` 恰好跑在把注册表清空的时段，
`test_live_handshake` 报了 `0/0 组合可用` 并打绿勾。它也补了下限。

这里有两条教训：

**这套扫描现在是一条门禁**（`test_trivial_pass`），在临时副本里逐个清空数据源，
断言至少有一个门禁会变红。当前 **12/12** 个源都有把守。

**那张"不是数据源"的豁免表我自己写错过。** 曾把 `h3_real_browsers.json` 与
`quic_real_browsers.json` 声明成"采完没人读"，理由写的是"`golden_orphans` 里也
这么说的" —— 但那份文档说的是"**曾经**没并入注册表"（过去时），而
`registry.py` 一直在读它们。实测一比就露馅：清空 quic 那份，`test_registry_fresh`
变红；清空 h3 那份，**照样绿**。

后半句才是真问题：h3 那份确实被读，却没有任何门禁看着它 —— 因为
`test_registry_fresh` 只比"指纹身份"（id + 别名 + 13 个 TLS 字段），h2/h3 载荷
不在比对集里。现在把载荷也纳进去，三份实采都有了把守。

教训是**豁免表的理由不能靠印象**：写"这个没人读"的时候，得真去清空它跑一遍。
自己写的豁免最容易变成没人查的洞。

#### "已确认无路径"要与"还没做"分开记

覆盖率棘轮一直用一个数字记缺口（`safari: 3`），但那个数字不区分**还没做**与
**做不了**。代价很具体：一条"待补"会让后来人（包括我自己）反复去试同一条死路。

现在多一张 `WONT_DO` 表，每条必须写清**试过什么、观测到什么**，不接受"做不了"
这种没有观测支撑的说法：

```
tls/h2  safari 12-14   coreTLS 闭源无段表；三家库都没建模过；真机侧拿不到那么旧的
                       Safari（系统绑定，无独立安装包）
h3      webkit         iOS Safari 根本不发起 QUIC。装好 CA 后 Alt-Svc 送达、页面
                       加载 47 次、UDP 0 个；写三个 HTTP3Enabled 键重启仍是 0；
                       换非回环的局域网 IP 也是 0；访问 Cloudflare trace 自报
                       http=http/2 —— 对任何站点都不用 h3
```

并且**两张表必须对得上**：`WONT_DO` 记的缺口数与棘轮水位不一致就报错。分头维护
一定会漂 —— 棘轮降了而 `WONT_DO` 还写着"无路径"，或者反过来。哪天条件变了
（新的库、新的采集手段），删掉对应条目即可，那是一次显式的决定。

### 另一半：把**代码**改坏，看门禁响不响

清空数据源只管住一半。另一半是**判据本身被改坏时，断言会不会红** —— 这半边
不是假想风险，本项目连着栽过两次，两次的断言看起来都完全合理：

| 断言 | 为什么不会红 |
|---|---|
| 并发检查 | 比的是 profile id，而 id 根本不在共享缓冲里；往解析中间注入 `ngx.sleep` 制造真实踩踏，照样 60/60 绿 |
| 分支覆盖 | 计数器放在 `switch` **之前**，计的是"看见了这个扩展"而不是"解析体执行了"；把四个 case 的体掏空，计数照样满额 |

两次都是靠临时手搓一次阴性对照抓出来的，抓完那次对照就随手扔了。现在固化成
`test_mutation`：一份变异清单，每条都是**语义**改动（不是改注释、改空白），
在临时副本里逐条改坏，断言至少有一个门禁变红。当前 **10/10** 条都有把守。

第一次跑，10 条里 **6 条没人红**。逐条查下来，六条竟然分属四种不同的成因，
没有一条是"就是缺个门禁"这么简单：

**① 门禁自己不跑 make（3 条）。** `test_c_parity` / `test_c_ua_parity` 比的是
上一次编出来的二进制 —— 改坏 JA4 的 cipher 排序，82/82 照样全绿。这是本项目
第 5 次撞"用了 stale 产物所以断言失灵"。**编译产物的新鲜度，门禁必须自己负责**，
不能依赖跑的人记得 `make`。

**② 我新写的断言是循环的（1 条）。** 给 SNI 补位置检查时，期望位置写成
"看 `raw_extensions[0]` 是不是 GREASE"。可 SNI 一旦被插到第 0 位，`raw[0]` 就
不再是 GREASE，期望值跟着变成 0 —— **被测者自己出题**，改坏了照样通过。
改成从"去掉 SNI 之后的原序"算，才成立。

**③ 环境把整条路径关掉了（1 条，误报）。** "h2 的 PRIORITY 写死空表无人看管"
是假的：变异那行只在**源码推导**路径上执行，而快照为了省 40MB 排除了
`spec/cache`，推导直接跳过，变异压根没跑到。**环境关掉一条路径，看起来和
"没有门禁"一模一样。** 把缓存软链进去才看见真相。

**④ 落盘产物 + 只比一个字段（1 条，真缺口）。** 缓存接上之后，变异确实吃掉了
94 条记录的 PRIORITY 帧，却仍然没有门禁红：其余门禁读的都是落盘的
`spec/h2table.json`，只有 `test_h2_table` 会拿判据重算一遍 —— 而它**只比
`akamai_fingerprint` 一个字段**，PRIORITY 恰恰不体现在那个串的差异里。
又是"比了一个相邻但不等价的东西"，与上面表格里那两次同族。改成整条记录比。

⑤ 还查出一处真空白：`test_lua_parity` 只比 JA4，伪装另外三层的 Lua 绑定
（`header_order` / `sort_headers` / `header_value` / `ua_platform` /
`sec_ch_ua`）**离线一条都没比过**，正确性只有需要起容器的 `test_openresty`
覆盖。补了第二段，逐品牌比这五个函数，65 项。

**最后一条是偶发的。** 修完之后 SNI 那条一次红一次不红 —— make 按 mtime 判断，
上一条变异留下的 `browserfp.o` 常与本次写入落在同一秒，于是跳过重编。
**偶发的绿比稳定的红危险得多**，它会被当成噪声解释掉。所以不去调 mtime，
直接删产物强制重编（第 6 次撞同一族问题）。

清单随后从 10 条扩到 **18 条**，补的全是此前从没被变异过的轴：coherence 的矛盾
判定、h2 开场的 WINDOW_UPDATE 帧、QUIC 重组、JA4Q 的首字符、UA-CH 平台表的
判定顺序、注册表去重键、JA4T 的 window scale。这一批 **17 条当场就有人红**
—— 说明前面那六条不是"门禁普遍稀疏"，而是**我盯过的地方反而更容易留下失灵的
断言**：那些地方我改得最多，也最容易边改边把断言改成"看起来在验"。

唯一没人红的第 18 条格外刺眼：**QUIC 重组的"收齐"校验**，正是本轮手工抓到并
修掉的那个缺陷（Firefox 把 ClientHello 拆进多个 Initial，只查空洞会"成功"重组
出截断的握手消息）。修是修了，却没有任何门禁盯着它 —— 因为语料里只存了指纹、
没存原始数据报，重组器从来没被喂过不完整的输入。**"刚修好的缺陷"是回归风险
最高的地方，而它恰恰最容易被认为"已经处理过了"。** 现在 `test_quic` 里补了
一条阴性对照（三种不完整片段必须拒 + 完整片段必须过），18/18。

它还查**登记完整性**：`spec/` 下的数据文件要么被扫、要么写明"为什么不是数据源"。
少了这一条，新增一个源就会静悄悄地无人看管 —— 那正是 Edge/Opera 那次的教训
（扫描器漏掉一个轴，那个轴上的缺陷就不存在）。

扩充登记时抓出一个真缺口：**`spec/profiles.json` 是落盘产物，却没有任何门禁验证
它与 golden 同步**。实测清空 `golden/real_browsers.json` 后，不联网的门禁**没有
一个变红** —— 所有门禁读的都是那份已提交的 `profiles.json`，golden 坏了要等到
下次重建才暴露。h2 表早就有同样的检查（`test_h2_table` 的"与判据同步"），TLS 侧
一直缺。现在 `test_registry_fresh` 拿 `registry.build()` 现算一遍逐条比，
清空 golden 与改坏一条 golden 的 ciphers 都能抓到。

两条设计决定：

· **在临时副本里改，不碰工作区**。这不是洁癖 —— 手工做那轮扫描时，bash 循环
  在 10 分钟超时被杀，最后一个源的还原没执行，`headers_real.json` 就那样留在
  工作区里空着。**而这条门禁第一次跑就把它抓出来了**（它先确认"原样副本能跑绿"，
  发现不绿就报"扫描环境本身有问题"）。
· **只断言"有门禁会红"，不断言"哪个会红"**。哪个门禁负责哪个源会随重构变化，
  钉死名字就是给自己造僵尸断言。要守的是"没有哪个数据源无人看管"。

· **改共享数据时不要同时跑后台验证** —— 那次 `--live` 的其余结论全部作废，
  因为它读到的是被我改坏的中间状态。所幸它撞出了一个真缺陷。
· **改完要跑一遍确认"真的会红"，不能看 diff 就算数**。用 `re.sub` 插断言时
  `$` 没配 `re.MULTILINE`，只匹配到字符串末尾，于是常量和计数插进去了、断言
  没插 —— 而门禁照常绿。是"空表仍绿"这个实测把它抓出来的。

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

**同一个坑后来又踩了两次**，因为当时只改了数字、没加锚定：

```
三方差分 77/77   库涨到 82 之后还写着 77
现状表          "可用性门禁 132/132（66 profile × 2）" —— 早就是 104/104（52 × 2）
```

第二次尤其说明问题：**正文一直在更新，唯独开头那张概览没人动，而它是第一个被
读到的**。所以现在的规矩是：**改数字的同时必须加锚定**，只改数字等于把同一个雷
重新埋一遍。当前锚定 13 个事实；机械扫过 README 里 71 处 `N/M` 断言，把能由代码
算出来的那些逐个接上。

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
  域名方式（network.dns.localDomains + browserfp.test）              ❌
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
