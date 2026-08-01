"""C 构造的伪装 ClientHello 能否真被服务器接受 —— 伪装链的最终验收。

`test_build_parity` 验的是"构造出的字节与 golden 逐字段一致"，那是自洽性；
自洽不等于可用：字段都对但 record 长度回填错一位、扩展块长度少两字节，解析器
能忍、服务器不会忍。这条门禁把字节真发出去，看服务端回 ServerHello 还是 Alert。

**必须打多个站点**。库里的 golden 采自无 SNI 场景，而 SNI 插入的缺陷曾经差点
被掩盖：cloudflare.com 有默认证书、缺 SNI 照样回 ServerHello，只有严格校验
SNI 的站点才会回 handshake_failure(40)。只测一个站点得出的绿是假绿。

对外发真实请求（profile 数 × 站点数），默认不在常规门禁里跑 —— 归 verify_all
的第 3 层。

跑：python -m spec.test_build_live [host,host,...]
"""

import os
import socket
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SNITEST = os.path.join(ROOT, "csrc", "snitest")

# 选站原则与 test_live_handshake 一致：至少一个严格校验 SNI 的，
# 至少一个宽松的作对照，好把"站点策略"与"我们的实现缺陷"分开。
DEFAULT_HOSTS = ("cloudflare.com", "example.com", "github.com")

# 覆盖三大引擎与桌面/移动两种形态
TARGETS = (("chrome", 151), ("firefox", 153), ("safari-mobile", 27),
           ("chrome-mobile", 134))


def _ensure_fresh():
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    return None if r.returncode == 0 else (r.stderr or r.stdout)[-200:]


def attempt(brand, version, host):
    """构造 → 直发 → 读服务端首个 record。返回 (成功?, 说明)。"""
    r = subprocess.run([SNITEST, brand, str(version), host],
                       capture_output=True, text=True, timeout=60)
    if not r.stdout.strip():
        return False, f"构造失败（{r.stderr.strip()[:40]}）"
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
        return False, f"{type(e).__name__}: {str(e)[:40]}"
    if not resp:
        return False, "服务端未回任何数据"
    if resp[0] == 0x16:
        return True, f"ServerHello {len(resp)}B（发出 {len(rec)}B）"
    if resp[0] == 0x15 and len(resp) >= 7:
        # desc=40 handshake_failure 多半是 SNI 或密码套件不被接受
        return False, f"Alert level={resp[5]} desc={resp[6]}"
    return False, f"未知响应首字节 0x{resp[0]:02x}"


def main(argv):
    stale = _ensure_fresh()
    if stale:
        print(f"make 失败：{stale}", file=sys.stderr)
        return 2
    if not os.path.exists(SNITEST):
        print(f"缺 {SNITEST}；先在 csrc 下 make", file=sys.stderr)
        return 2

    hosts = argv[1].split(",") if len(argv) > 1 else DEFAULT_HOSTS
    print(f"C 构造的伪装 ClientHello × {len(hosts)} 个真实站点\n")

    ok_n, bad = 0, []
    for brand, version in TARGETS:
        cells = []
        for host in hosts:
            good, detail = attempt(brand, version, host)
            cells.append("✅" if good else "❌")
            if good:
                ok_n += 1
            else:
                bad.append((brand, version, host, detail))
        print(f"  {''.join(cells)} {brand:14s} {version:>3}")

    total = len(TARGETS) * len(hosts)
    print(f"\n{ok_n}/{total} 组合收到 ServerHello")
    for brand, version, host, detail in bad:
        print(f"  ✗ {brand} {version} @ {host}: {detail}")
    if bad:
        print("\n构造出的字节被服务端拒绝 —— 字段自洽不等于可用，"
              "先查 record/扩展块的长度回填与 SNI 是否真写进去了。")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
