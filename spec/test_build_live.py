"""C 构造的伪装 ClientHello 能否真被服务器接受 —— 伪装链的最终验收。

`test_build_parity` 验的是"构造出的字节与 golden 逐字段一致"，那是自洽性；
自洽不等于可用：字段都对但 record 长度回填错一位、扩展块长度少两字节，解析器
能忍、服务器不会忍。这条门禁把字节真发出去，看服务端回 ServerHello 还是 Alert。

**必须打多个站点**。库里的 golden 采自无 SNI 场景，而 SNI 插入的缺陷曾经差点
被掩盖：cloudflare.com 有默认证书、缺 SNI 照样回 ServerHello，只有严格校验
SNI 的站点才会回 handshake_failure(40)。只测一个站点得出的绿是假绿。

**超时不等于被拒绝**。服务端回 Alert 才说明它读懂了我们的字节并拒绝；超时/
连接重置只说明这一跳没走通，与字节对不对无关。曾经把 github.com 的 4 次超时
报成"构造出的字节被服务端拒绝" —— 那个结论会把人指向根本不存在的长度回填
bug。所以本门禁把结果分三档，且只对网络类错误重试一次（协议拒绝一次即判死，
重发无意义还更像扫描）。

**并且必须节流**。实测 github.com 按速率丢连接，且与客户端无关：

    连发 8 次无间隔   我们的字节 2/8 成功    openssl 首次即超时
    每次间隔 3s ×5    我们的字节 5/5 成功    openssl 5/5 成功

openssl 是真实客户端、真实 TLS，它在同样节奏下一起挂 —— 这就把"字节问题"
排除掉了。所以 PACE 不是遮丑的 sleep，是让测量落在服务端不丢包的区间里；
去掉它这条门禁会周期性地假红并给出错误的排查方向。

对外发真实请求（profile 数 × 站点数），默认不在常规门禁里跑 —— 归 verify_all
的第 3 层。

跑：python -m spec.test_build_live [host,host,...]
"""

import os
import socket
import ssl
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SNITEST = os.path.join(ROOT, "csrc", "snitest")

# 选站原则与 test_live_handshake 一致：至少一个严格校验 SNI 的，
# 至少一个宽松的作对照，好把"站点策略"与"我们的实现缺陷"分开。
# 选站有两条硬要求，都可验证（见 check_hosts）：
#   至少一个**严格校验 SNI** —— 无 SNI 时回 handshake_failure。缺了它，
#     "SNI 根本没发"这个缺陷会被有默认证书的站点掩盖（曾经就是这么被掩盖的）
#   至少一个**宽松的**作对照，好把"站点策略"与"我们的实现缺陷"分开
#
# github.com 被换掉了：本机对它的连接已是持续性阻断，不是瞬时抖动 ——
# openssl 直连三次里两次也失败（真实客户端对照）。留着它这条门禁会周期性
# 假红，而假红久了就会被无视。换成同样严格且可达的 www.iana.org。
DEFAULT_HOSTS = ("cloudflare.com", "example.com", "www.iana.org")

# 每次连接之间的间隔，见模块头的测量：低于这个值 github 会按速率丢连接。
PACE = 3.0

# 覆盖三大引擎与桌面/移动两种形态
TARGETS = (("chrome", 151), ("firefox", 153), ("safari-mobile", 27),
           ("chrome-mobile", 134))


def _ensure_fresh():
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    return None if r.returncode == 0 else (r.stderr or r.stdout)[-200:]


# 结果分档：REJECT 是服务端读懂并拒绝（字节有问题），NET 是这一跳没走通
# （与字节无关）。两者混为一谈会让门禁给出错误的排查方向。
OK, REJECT, NET = "ok", "reject", "net"


def _once(brand, version, host):
    """构造 → 直发 → 读服务端首个 record。返回 (档位, 说明)。"""
    r = subprocess.run([SNITEST, brand, str(version), host],
                       capture_output=True, text=True, timeout=60)
    if not r.stdout.strip():
        return REJECT, f"构造失败（{r.stderr.strip()[:40]}）"
    rec = bytes.fromhex(r.stdout.strip())
    try:
        s = socket.create_connection((host, 443), timeout=20)
        s.settimeout(20)
        try:
            s.sendall(rec)
            resp = s.recv(4096)
        finally:
            s.close()
    except Exception as e:
        return NET, f"{type(e).__name__}: {str(e)[:40]}"
    if not resp:
        # 未回任何数据也归网络档：服务端读懂后拒绝一定会回 Alert
        return NET, "服务端未回任何数据"
    if resp[0] == 0x16:
        return OK, f"ServerHello {len(resp)}B（发出 {len(rec)}B）"
    if resp[0] == 0x15 and len(resp) >= 7:
        # desc=40 handshake_failure 多半是 SNI 或密码套件不被接受
        return REJECT, f"Alert level={resp[5]} desc={resp[6]}"
    return REJECT, f"未知响应首字节 0x{resp[0]:02x}"


def attempt(brand, version, host):
    """跑一次；网络类失败重试一次。协议拒绝不重试。"""
    kind, detail = _once(brand, version, host)
    if kind is NET:
        time.sleep(2)
        kind2, detail2 = _once(brand, version, host)
        if kind2 is not NET:
            return kind2, f"{detail2}（首次 {detail}，重试后恢复）"
        return NET, f"{detail}（重试仍失败：{detail2}）"
    return kind, detail


def check_hosts(hosts, timeout=12):
    """选站的两条要求当场验，不靠注释里的记忆。

    站点策略会变（换 CDN、加默认证书），"这批站点里有严格校验 SNI 的"这句话
    如果只写在注释里，哪天全变宽松了也没人知道 —— 那时这条门禁看着还在跑，
    实际上已经测不出"SNI 没发"这个缺陷了。
    """
    strict, loose, unreachable = [], [], []
    for h in hosts:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            socket.create_connection((h, 443), timeout=timeout).close()
        except Exception:
            unreachable.append(h)
            continue
        try:
            s = ctx.wrap_socket(socket.create_connection((h, 443), timeout=timeout))
            s.close()
            loose.append(h)
        except Exception:
            strict.append(h)
    return strict, loose, unreachable


def main(argv):
    stale = _ensure_fresh()
    if stale:
        print(f"make 失败：{stale}", file=sys.stderr)
        return 2
    if not os.path.exists(SNITEST):
        print(f"缺 {SNITEST}；先在 csrc 下 make", file=sys.stderr)
        return 2

    hosts = argv[1].split(",") if len(argv) > 1 else DEFAULT_HOSTS
    strict, loose, unreachable = check_hosts(hosts)
    print(f"C 构造的伪装 ClientHello × {len(hosts)} 个真实站点")
    print(f"  严格校验 SNI: {strict or '（无）'}   宽松: {loose or '（无）'}"
          + (f"   连不上: {unreachable}" if unreachable else ""))
    if not strict:
        print("\n✗ 这批站点没有一个严格校验 SNI —— \"SNI 根本没发\" 这个缺陷"
              "会被有默认证书的站点掩盖，等于没测。换站点。", file=sys.stderr)
        return 1
    if not loose:
        print("\n✗ 没有宽松站点作对照 —— 分不清失败是站点策略还是我们的缺陷。",
              file=sys.stderr)
        return 1
    print()

    ok_n, rejected, netbad = 0, [], []
    for brand, version in TARGETS:
        cells = []
        for host in hosts:
            time.sleep(PACE)
            kind, detail = attempt(brand, version, host)
            cells.append({OK: "✅", REJECT: "❌", NET: "⚠️"}[kind])
            if kind is OK:
                ok_n += 1
            elif kind is REJECT:
                rejected.append((brand, version, host, detail))
            else:
                netbad.append((brand, version, host, detail))
        print(f"  {''.join(cells)} {brand:14s} {version:>3}")

    total = len(TARGETS) * len(hosts)
    print(f"\n{ok_n}/{total} 组合收到 ServerHello")
    for brand, version, host, detail in rejected:
        print(f"  ✗ {brand} {version} @ {host}: {detail}")
    for brand, version, host, detail in netbad:
        print(f"  ⚠️ {brand} {version} @ {host}: {detail}")

    if rejected:
        print("\n构造出的字节被服务端拒绝 —— 字段自洽不等于可用，"
              "先查 record/扩展块的长度回填与 SNI 是否真写进去了。")
        return 1
    if netbad:
        # 不判绿：确实没验到。但也别说成"字节被拒绝" —— 那是另一回事。
        print(f"\n{len(netbad)} 个组合因网络原因没验到（重试后仍失败）。"
              "这不是字节的证据，重跑或换站点再看。")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
