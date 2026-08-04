# Disclaimer

*[中文见下](#免责声明)*

## No warranty

This software is provided **"AS IS", without warranty of any kind**, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose and noninfringement. See [LICENSE](LICENSE) (Apache
License 2.0), Sections 7 and 8, for the governing terms.

Fingerprints go stale. Browsers change their wire form with every release, and a
profile that matched last month may not match today. The test suite tells you
whether the bytes match **what was recorded**, not whether they match **what the
current browser sends**. Do not treat a green test run as a guarantee of
undetectability.

## No affiliation

This project is **not affiliated with, endorsed by, or sponsored by** Google,
Mozilla, Apple, Microsoft, Opera, Cloudflare, Akamai, or any other organisation
whose products or services are referenced here.

Browser names ("Chrome", "Firefox", "Safari", "Edge", "Opera") and protocol
fingerprint names ("JA3", "JA4", "Akamai fingerprint") appear solely to identify
the wire behaviour being reproduced or measured. All trademarks are the property
of their respective owners; their use here is nominative and implies no
association.

## Intended use

This library exists to:

- build clients that interoperate correctly with servers which behave
  differently based on TLS/HTTP-2 characteristics;
- **test anti-bot and fingerprinting systems you own or are authorised to test**;
- reproduce protocol behaviour under test, so that bugs are diagnosable;
- support research into network-layer fingerprinting.

## Your responsibility

Using this library to impersonate a browser you are not — that is the entire
point of it — is a **dual-use capability**. You are responsible for ensuring
your use is lawful and authorised. In particular:

- **Do not use it to circumvent access controls you have not been authorised to
  bypass.** That includes authentication, rate limits, paywalls, and bot
  protection on systems that are not yours.
- Comply with the terms of service, acceptable-use policies and `robots.txt` of
  any service you connect to, and with all applicable laws in your jurisdiction
  — including computer-misuse, anti-circumvention and data-protection law.
- Obtain **explicit, documented authorisation** before testing systems you do
  not own. "It was only a test" is not a defence.

The authors and contributors accept **no liability** for how you use this
software, and provide no support for uses outside the scope described above.

## Not legal advice

Nothing in this document is legal advice. Whether a particular use is lawful
depends on your jurisdiction, the target system, and the agreements you are
bound by. If you are unsure, consult a qualified lawyer before proceeding.

---

# 免责声明

## 不提供任何担保

本软件**按「原样」提供，不附带任何明示或默示的担保**，包括但不限于适销性、
特定用途适用性与不侵权的担保。以 [LICENSE](LICENSE)（Apache License 2.0）
第 7、8 条为准。

**指纹会过期。** 浏览器每次发版都可能改变其线上形态，上个月还能对上的 profile
今天未必对得上。测试套件验的是「字节是否与**记录下来的**一致」，不是「是否与
**当前浏览器实际发送的**一致」。**不要把测试全绿当成不可被检测的保证。**

## 无隶属关系

本项目**不隶属于、未获认可、也未受赞助于** Google、Mozilla、Apple、Microsoft、
Opera、Cloudflare、Akamai 或此处提及其产品与服务的任何其他组织。

文中出现的浏览器名称（Chrome、Firefox、Safari、Edge、Opera）与协议指纹名称
（JA3、JA4、Akamai 指纹）**仅用于标识所复现或所度量的线上行为**。所有商标归各自
所有者所有；此处属指称性使用，不暗示任何关联。

## 预期用途

本库的用途是：

- 构建能与「按 TLS/HTTP-2 特征区别对待客户端」的服务端正确互操作的客户端；
- **测试你自己拥有、或已获授权测试的反爬与指纹识别系统**；
- 在测试中复现协议行为，使问题可被诊断；
- 支持网络层指纹识别的相关研究。

## 使用者的责任

用本库把自己伪装成另一个客户端 —— 这正是它的全部意义 —— 是一项**双用途能力**。
**确保你的使用合法且已获授权，是你自己的责任。** 尤其是：

- **不要用它绕过你未被授权绕过的访问控制**，包括不属于你的系统上的身份认证、
  速率限制、付费墙与机器人防护。
- 遵守你所连接的任何服务的服务条款、可接受使用政策与 `robots.txt`，
  并遵守你所在司法辖区的全部适用法律 —— 包括计算机滥用、反规避与数据保护相关法律。
- 在测试并非你所拥有的系统之前，取得**明确的、有据可查的授权**。
  「我只是测试一下」不构成抗辩理由。

作者与贡献者**不对你如何使用本软件承担任何责任**，也不对上述范围之外的用途
提供任何支持。

## 本文不构成法律意见

本文任何内容均不构成法律意见。某一具体用途是否合法，取决于你所在的司法辖区、
目标系统，以及你所受约束的各项协议。如有疑问，请在行动前咨询有资质的律师。
