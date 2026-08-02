"""从 profile 定义重建 ClientHello 字节 —— C 模块的 Python 参考实现。

**这个模块存在的意义是先证伪**：在动手写 BoringSSL C 模块之前，先确认采到的
golden 是否**足够重建**一个 ClientHello。如果 Python 拿这份数据重建出的
ClientHello 解析回来与 golden 逐字段相同，说明 profile 数据是完备的，C 模块
照着做就行；如果不够，现在发现比写完 C 再发现便宜得多。

**不追求逐字节相同**：random / session_id / key_share 公钥每次连接都不同，
逐字节比对必然失败且没有意义。判据是 clienthello.fingerprint() 的那些确定性
字段——它们才是"指纹"，也正是上游用来判别的东西。
"""

import os
import secrets
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.clienthello import is_grease                      # noqa: E402

# 内容随连接变化的扩展：重建时必须重新生成，不能照搬 golden 里那份。
VOLATILE_EXTENSIONS = {
    0x0033,   # key_share —— 含真实 ECDH 公钥
    0x0029,   # pre_shared_key —— 含会话票据
    0xFE0D,   # encrypted_client_hello —— 含新鲜的 GREASE ECH payload
}


def _u16(v):
    return struct.pack(">H", v)


def _vec(body, len_bytes):
    """长度前缀向量。TLS 里到处都是，长度字段宽度各不相同。"""
    if len_bytes == 1:
        return bytes([len(body)]) + body
    if len_bytes == 2:
        return _u16(len(body)) + body
    if len_bytes == 3:
        n = len(body)
        return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]) + body
    raise ValueError(len_bytes)


# GREASE ECH 的 payload 长度**每次连接随机**，取自一个固定集合。
#
# 26 次本地抓包（curl_cffi chrome119 与 chrome131，各自 golden 是 218 与 250）
# 实测到的取值都是这四个，两两相差 32：
#
#     186 × 8    218 × 8    250 × 8    282 × 2
#
# 集合与 profile 自身大小**无关** —— 两条 golden 不同的 profile 抽到的是同一组
# 数。safari180 连采 10 次一条 ECH 都没有（Safari 不发），所以这只是 BoringSSL
# 的行为。
#
# 后果有两层，都要紧：
#   · 我们照抄 golden 的长度 ⇒ **每次连接都一模一样**，而真实客户端在变 ——
#     一个 JA4 永不变化的"Chrome"，在聚合统计里是显眼的
#   · ECH 长度进总长、总长决定 padding 补不补 ⇒ **同一个客户端打同一个目标会
#     产生两个不同的 JA4**（实测 16 次得到 10:6 两个值）。这类 profile 的
#     "那个 JA4" 本来就不存在
# 注意这是**整个扩展体**的长度，不是 payload 字段的长度：体 = 10 + enc + payload
# （type1 + kdf2 + aead2 + config_id1 + enc长2 + enc + payload长2 + payload）。
# 第一版把它当成 payload 长度直接用，于是每条都多出 10+32=42 字节 —— 构造出来
# 的 CH 全都超过 512、padding 一次都不补，与实测的 512/538/570 对不上。
ECH_BODY_LENS = (186, 218, 250, 282)

# **只对实测过的族随机 —— 而且 NSS 本来就不随机。**
#
# 真机 Firefox（本地 sniffer，连开 6 次）ECH 体长**恒为 281**、CH 体长恒为 1887：
#
#     第1..6次  ECH体=281  CH体=1887
#
# 所以这不是"我们没测所以保守"，而是**两个栈的行为本来就不同**：BoringSSL 每次
# 从 {186,218,250,282} 里抽，NSS 固定。给 NSS 套上 BoringSSL 的集合，等于让
# Firefox 发出一个真 Firefox 从不发的长度 —— 那比照抄还糟。
#
# 语料本身也印证这条界线：curl_cffi / tls_client / wreq 的 firefox 形态落在
# {186,218,250,282}（它们用 BoringSSL/utls 去**模拟** Firefox，GREASE ECH 走的是
# 自己那套），而 real:firefox153 / real_quic:firefox 这些**真机**采集是
# 249/281/569（模 32 余 25），与 BoringSSL 那组（余 26）不是一个族。
def ech_family(golden_len):
    return ECH_BODY_LENS if golden_len in ECH_BODY_LENS else None


def grease_ech(golden_body, rnd=None, payload_len=None, verbatim=False):
    """按 draft-ietf-tls-esni 的 outer 形态**新鲜生成** GREASE ECH。

        type(1)=0 | kdf(2) | aead(2) | config_id(1) | enc<2> | payload<2>

    **不能照抄 golden 的 body**：config_id 只有 1 字节，固定值一旦撞上服务端
    真实的 ECH 配置，服务端会拿自己的私钥去解 payload、失败，回
    handshake_failure(40)。这条是参考实现 `oracle/tls13.py` 实测出来的，而发货
    的构造器（本模块与 C）一直在照抄 golden —— 34/81 条默认 profile 带 0xFE0D，
    也就是绝大多数 Chrome 形态都埋着这个雷。`test_build_live` 只打三个站点，
    撞不上就一直是绿的。

    **形状必须照抄**：payload 长度决定 ClientHello 总长度，属于该 profile 指纹
    的一部分；kdf/aead 也照 golden（实测三个 Chrome profile 都是 0x0001/0x0001）。
    **payload 长度也是新鲜的**：实测它每次连接从一个固定集合里随机取
    （见 ECH_PAYLOAD_LENS 的说明），照抄 golden 会让我们的 JA4 永不变化。

    rnd: 取随机字节的函数，默认 secrets.token_bytes。C 侧没有内部 RNG（库是
    内存进内存出的），那边从调用方给的 random32 派生。
    """
    if not golden_body or len(golden_body) < 8:
        return b""
    rnd = rnd or secrets.token_bytes
    kdf, aead = struct.unpack_from(">HH", golden_body, 1)
    enc_len = struct.unpack_from(">H", golden_body, 6)[0]
    if verbatim:
        payload_len = struct.unpack_from(">H", golden_body, 8 + enc_len)[0]
    elif payload_len is None:
        fam = ech_family(len(golden_body))
        if fam:
            payload_len = fam[secrets.randbelow(len(fam))] - 10 - enc_len
        else:
            payload_len = struct.unpack_from(">H", golden_body, 8 + enc_len)[0]
    return (bytes([0]) + struct.pack(">HH", kdf, aead)
            + rnd(1)
            + _vec(rnd(enc_len), 2)
            + _vec(rnd(payload_len), 2))


# RFC 8701 的 16 个 GREASE 值。
GREASE_VALUES = tuple(0x0A0A + 0x1010 * i for i in range(16))


def pick_grease(verbatim=False):
    """按实测规格给一次连接抽一组 GREASE 值。

    **GREASE 的全部意义就是每连接随机**（RFC 8701）。照抄 golden 的固定值，
    等于让"Chrome"每次连接都发同一个 0x4a4a —— 这比长度类的破绽更容易被发现：
    不用比长度，**看两次连接就够**。

    规格是实测出来的（真机 curl_cffi chrome119，6~10 次采样，结论一致）：

        两个扩展 id            每次随机，且**恒不相同**（0/10 相同）
        密码套件               独立随机
        supported_groups 首项  随机，**且 key_share 里那条与它相同**（6/6）
        supported_versions     独立随机

    verbatim=True 时返回 None，调用方保持 golden 的值 —— 重建验证要的是采集
    那条报文，重新抽会让 test_rebuild / test_build_parity 比不了。
    """
    if verbatim:
        return None
    # **构造上就不可能相同**，不用循环重试。做代码变异时把重试条件改坏一次，
    # 那个 while 直接变成死循环、门禁挂死 10 分钟 —— "靠重试保证不变式"在取值域
    # 退化时就是这个下场。取一个偏移量绕过去，天然满足"两者不同"。
    i = secrets.randbelow(16)
    ext_a = GREASE_VALUES[i]
    ext_b = GREASE_VALUES[(i + 1 + secrets.randbelow(15)) % 16]
    group = GREASE_VALUES[secrets.randbelow(16)]
    return {
        "ext": [ext_a, ext_b],
        "cipher": GREASE_VALUES[secrets.randbelow(16)],
        "group": group,                          # key_share 里那条也用它
        "version": GREASE_VALUES[secrets.randbelow(16)],
    }


def _regrease_list(vals, new, start=0):
    """把一串值里的 GREASE 逐个换成 new 里的下一个；new 用尽后循环使用。"""
    out, i = [], start
    for v in vals:
        if is_grease(v):
            out.append(new[i % len(new)])
            i += 1
        else:
            out.append(v)
    return out


def _regrease_u16_body(body, prefix_len, new):
    """把 `<长度><u16 列表>` 形状的扩展体里的 GREASE 换成 new。"""
    if len(body) < prefix_len:
        return body
    head, rest = body[:prefix_len], body[prefix_len:]
    vals = [int.from_bytes(rest[i:i + 2], "big") for i in range(0, len(rest) - 1, 2)]
    return head + b"".join(_u16(v) for v in _regrease_list(vals, [new]))


def _parse_key_share(body):
    """golden 的 key_share 体 → [(group, pub_len)]，顺序照原样。"""
    out, i = [], 2                       # 跳过 client_shares 的 2 字节长度
    while i + 4 <= len(body):
        g = int.from_bytes(body[i:i + 2], "big")
        n = int.from_bytes(body[i + 2:i + 4], "big")
        out.append((g, n))
        i += 4 + n
    return out


def _build_key_share(golden_body, key_shares=None, grease_group=None):
    """**按 golden 的形状**重建 key_share：分组、顺序、每条的长度全部照抄，
    只换公钥内容。

    这里原来写的是"给 curves[0] 发一个占位公钥"，实测后果是重建出来的
    key_share 与真机**形状完全不同**：

        chrome131   真机 GREASE(1) + X25519MLKEM768(1216) + X25519(32)
                    重建 只有 X25519MLKEM768
        safari-ios  真机 GREASE(1) + X25519(32)
                    重建 只有 X25519

    JA4 不哈希 key_share 的内容，所以三方差分、重建闭环、真机握手全部照样绿 ——
    而 **Chrome 恒发一个 GREASE key_share，丢掉它本身就是破绽**，少发一组
    也与它自己的 supported_groups 对不上。C 侧一直是照抄 golden 的，于是
    C 与 Python 产出的字节形状长期不同，同样没人发现。

    key_shares: {group: pubkey_bytes}，真出网**必须**由调用方给 —— golden 里
    那把公钥是采集当时的，我们没有对应私钥，拿它握手算不出共享密钥。
    没给的组用随机字节占位：那只能用于指纹验证，绝不能拿去真握手。
    长度与 golden 不符时**报错而不是接受** —— 长度一变形状就变了。
    """
    shape = _parse_key_share(golden_body)
    if not shape:
        return golden_body
    # **给进来的分组必须在 profile 里存在**。调用方以为注入了、实际被忽略，
    # 是最难查的一类错：握手会拿 golden 里那把旧公钥去算共享密钥，而那把私钥
    # 不在我们手里 —— 症状是"握手莫名其妙失败"，与 key_share 毫无表面关联。
    for g in (key_shares or {}):
        if not any(g == gg for gg, _ in shape):
            raise ValueError(
                f"key_share 组 0x{g:04x} 不在该 profile 的 key_share 里 "
                f"（有的是 {[hex(gg) for gg, _ in shape]}）—— "
                "静默忽略会让调用方以为注入成功了")
    out = b""
    for group, plen in shape:
        if key_shares and group in key_shares:
            pub = key_shares[group]
            if len(pub) != plen:
                raise ValueError(
                    f"key_share 组 0x{group:04x} 的公钥长度 {len(pub)} 与 golden "
                    f"的 {plen} 不符 —— 长度一变 ClientHello 的形状就变了")
        elif is_grease(group):
            # GREASE 条目：内容按 RFC 8701 照抄 golden（1 字节 0x00），但**组 id
            # 要与 supported_groups 那条一致** —— 实测 6/6 相同，两处各抽一个
            # 会造出真客户端不会发的组合。
            pub = golden_body[
                golden_body.index(_u16(group) + _u16(plen)) + 4:][:plen]
            if grease_group is not None:
                group = grease_group
        else:
            pub = secrets.token_bytes(plen)
        out += _u16(group) + _vec(pub, 2)
    return _vec(out, 2)


# 会话恢复态 profile 的 pre_shared_key。
#
# 里面是**采集当时的票据**：发出去验不过，服务端会退回完整握手 —— 那比干净的
# 首连更可疑（一个"声称自己来过"却拿不出有效票据的客户端）。真做恢复也不可能
# 靠照抄：binder 是对整段 transcript 的 HMAC，换一个字节就得重算。
#
# 所以按用途分开：**重建验证**必须原样发（不然验不了重建闭环），**真出网**必须
# 拒绝。区分信号就是调用方有没有注入 key_share —— 注入了就说明它真要握手。
PSK_EXT = 0x0029

# padding：补齐到 512 字节（含 4 字节握手头）。见 build_client_hello 里的推导。
PADDING_EXT = 0x0015
PAD_LO, PAD_TO = 256, 512


def ext_bytes_wo_padding(ext_bytes):
    """从已拼好的扩展块里摘掉 padding 那一条。"""
    out, i = b"", 0
    while i + 4 <= len(ext_bytes):
        eid = int.from_bytes(ext_bytes[i:i + 2], "big")
        n = int.from_bytes(ext_bytes[i + 2:i + 4], "big")
        if eid != PADDING_EXT:
            out += ext_bytes[i:i + 4 + n]
        i += 4 + n
    return out


def _hello_len(profile, ext_bytes):
    """握手消息长度（含 4 字节头），用来算 padding 要补多少。"""
    return (4 + 2 + 32 + 1 + (profile.get("session_id_len", 32) or 0)
            + 2 + len(profile["raw_ciphers"]) * 2
            + 1 + len(profile.get("compression", [0]))
            + 2 + len(ext_bytes))


def build_client_hello(profile, sni=None, key_shares=None, verbatim=False):
    """verbatim=True 时**照采集那条重建**：ECH 用 golden 的长度、padding 不重算。

    判据按用途分开，与 pre_shared_key 那处同一个道理：

        重建验证   要"照采集那条" —— 不然 test_rebuild / test_build_parity
                   比的是两条本来就不同的报文
        真出网     要"每次新鲜" —— ECH 长度与 padding 都随连接变，固定不变
                   本身就是破绽

    默认是**出网口径**：默认值决定了忘记传参时会发生什么，而"忘了传参就退化成
    固定字节"比"忘了传参就重建不上"危险得多。
    """
    """按 profile 组装一条完整的 TLS record（含 5 字节 record 头）。

    profile 用的是 oracle.clienthello.fingerprint() 的输出结构，也就是 golden
    里存的那份——采集与重建共用同一个数据形态，中间没有翻译层可以出错。
    """
    raw_ciphers = profile["raw_ciphers"]
    raw_extensions = profile["raw_extensions"]
    if key_shares and PSK_EXT in raw_extensions:
        raise ValueError(
            "这条 profile 是会话恢复态（带 pre_shared_key），而你注入了 "
            "key_share —— 也就是真要握手。里面的票据是采集当时的，发出去验不过，"
            "服务端会退回完整握手，比干净的首连更可疑。请改用 initial 态的 "
            "profile（by_ua 本来就只返回 initial 态）")
    bodies = {int(k): bytes.fromhex(v) for k, v in profile["extension_bodies"].items()}

    # **profile 不含 SNI 扩展时要补进去**。80/82 条 profile 采自 nosni 场景
    # （真机浏览器只能这么采），遍历 raw_extensions 永远发不出 SNI —— 于是
    # `sni=` 这个参数对 97.5% 的 profile **被静默忽略**，打有默认证书的站点不
    # 报错，打多租户站点直接 handshake_failure(40)。
    #
    # C 侧与参考实现 oracle/tls13.py 都早就在补，只有本函数没有：三方差分都用
    # sni=None，真机端到端走的是 tls13 那份，C 的 SNI 由 snitest 单独验 ——
    # 三条路各自绕开了这里。位置规则与另两处一致：紧跟开头的 GREASE，无 GREASE
    # 时排第一。
    grease = pick_grease(verbatim)
    if grease:
        raw_ciphers = _regrease_list(raw_ciphers, [grease["cipher"]])

    ext_order = list(raw_extensions)
    if sni is not None and 0x0000 not in ext_order:
        pos = 1 if ext_order and is_grease(ext_order[0]) else 0
        ext_order.insert(pos, 0x0000)

    if grease:
        ext_order = _regrease_list(ext_order, grease["ext"])

    ext_bytes = b""
    for ext_id in ext_order:
        if is_grease(ext_id):
            # GREASE 扩展体：位置照抄 golden，内容按 RFC 8701 留空
            # （唯一例外是 Chrome 末尾那个 GREASE 会带 1 字节 0x00）。
            ext_bytes += _u16(ext_id) + _vec(bodies.get(ext_id, b""), 2)
            continue
        if ext_id == 0x0000 and sni is not None:
            name = sni.encode()
            entry = bytes([0]) + _vec(name, 2)
            body = _vec(entry, 2)
        elif ext_id == 0x0033:
            body = _build_key_share(bodies.get(ext_id, b""), key_shares,
                                    grease["group"] if grease else None)
        elif grease and ext_id == 0x000A:      # supported_groups
            body = _regrease_u16_body(bodies.get(ext_id, b""), 2, grease["group"])
        elif grease and ext_id == 0x002B:      # supported_versions
            body = _regrease_u16_body(bodies.get(ext_id, b""), 1, grease["version"])
        elif ext_id == 0xFE0D:
            body = grease_ech(bodies.get(ext_id, b""), verbatim=verbatim)
        elif ext_id in VOLATILE_EXTENSIONS:
            body = bodies.get(ext_id, b"")
        else:
            body = bodies.get(ext_id, b"")
        ext_bytes += _u16(ext_id) + _vec(body, 2)

    # **padding（0x0015）必须按实际长度重算，不能照抄 golden。**
    #
    # 它不是固定成分：BoringSSL 把 ClientHello 补齐到 **512 字节**（含 4 字节
    # 握手头），超过就整个不发。本项目自己的语料就是证据 —— 同一 target 的带
    # SNI 与 nosni 两份采集，padding 长度恰好差 18 字节（正是那个 SNI 扩展的
    # 大小），而 chrome119 带 SNI 时**根本没有 padding**：
    #
    #     去pad体长 + 4 + padding = 512   （chrome100 284/224、chrome119 506/2、
    #                                      safari153 298/210、safari180 291/217）
    #
    # 照抄的后果是真的：实测我们发的 chrome119 在对端眼里是 17 个扩展，而
    # curl_cffi 本尊是 16 个 —— 多出来的正是这条不该发的 padding。前面几档门禁
    # 全绿，因为它们比的都是"我们与我们自己算的一致"；只有与被模仿者 A/B 才看
    # 得见。
    #
    # 这也意味着 **JA4 会随 SNI 长度变化**，那正是真浏览器的行为。
    # **按长度判，不看 profile 里有没有记录 padding。**
    #
    # 只在"profile 里有 0x0015"时才补，会漏掉反方向的一半：wreq 的 OkHttp 系
    # 语料是在 nosni（体长 251）下采的，低于下界所以没有 padding —— 但换成
    # 真实 SNI（体长 268）落进区间，**本尊会补而我们不补**。实测对端看到本尊 13
    # 个扩展、我们 12 个。这正是同一个客户端在两个长度下的直接对照，也就是
    # **下界 256 的证据**。
    #
    # 全语料 82 条零反例：22 条在区间且补了、17 条 <256 未补、43 条 ≥512 未补。
    # 六条 Firefox 正好 512 且带 padding —— NSS 同样补，所以这条规则不是
    # BoringSSL 专有的。
    # recompute_padding=False 只给一种调用方：**判据里给定的那条 ClientHello**
    # （如 JA4 规范的官方向量）。那是一条固定的报文，不是让我们按长度重算的
    # profile —— 对它套长度规则会把向量本身改掉，然后"验不过官方向量"。
    base = ext_bytes if verbatim else ext_bytes_wo_padding(ext_bytes)
    fixed = _hello_len(profile, base)
    if not verbatim and PAD_LO <= fixed < PAD_TO:
        ext_bytes = base + _u16(PADDING_EXT) + _vec(b"\x00" * (PAD_TO - fixed - 4), 2)
    elif not verbatim:
        ext_bytes = base

    hello = b""
    hello += _u16(profile.get("client_version", 0x0303))
    hello += secrets.token_bytes(32)                       # random
    hello += _vec(secrets.token_bytes(profile.get("session_id_len", 32)), 1)
    hello += _vec(b"".join(_u16(c) for c in raw_ciphers), 2)
    hello += _vec(bytes(profile.get("compression", [0])), 1)
    hello += _vec(ext_bytes, 2)

    handshake = bytes([0x01]) + _vec(hello, 3)
    return bytes([0x16]) + _u16(0x0301) + _vec(handshake, 2)
