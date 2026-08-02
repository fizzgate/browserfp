"""JA4 与**外部权威**的官方向量核对 —— 此前整个项目缺的一环。

本项目验 JA4 的方式一直是"自己跟自己比"：Python 与 C 逐字符差分（`test_c_parity`），
Lua 再与它们比（`test_lua_parity`）。三方一致只能证明**三份实现抄的是同一份理解**，
证明不了那份理解是对的。更隐蔽的是 golden 里的 `ja4` / `ja3` 字段 —— 它们看着像
外部数据，实际是采集时由 `oracle/clienthello.py` 算的（见 `oracle/collect.py`
第 20 行的 import），拿它们当参照是**自我确认**。

于是一整类缺陷可以在全绿的情况下存活：排序规则搞反、截断取 12 位取成 16 位、
ja4_c 少排除一个 SNI —— 只要三份实现错得一致，没有任何门禁会响，而真实检测方
算出来的指纹与我们发的对不上。

判据来自 FoxIO 的 JA4 规范（`technical_details/JA4.md`），它给出了一条完整向量：
输入的密码套件/扩展/签名算法列表，以及标准输出与 `-o`（原序）输出。**四个哈希
本门禁都当场重算**，不是照抄结论 —— 抄错一位与实现错一位的表现完全一样。

两段：
  1. 算法级：按规范给的字符串直接算 SHA256 前 12 位，必须等于规范给的哈希。
     这一段只验哈希与截断，与我们怎么解析 ClientHello 无关。
  2. 端到端：按向量的字段拼一条真的 ClientHello，喂给 Python 与 C，
     两边都必须输出 `t13d1516h2_8daaf6152771_e5627efa2ab1`。

跑：python -m spec.test_ja4_vectors
"""

import hashlib
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chbuild import build_client_hello                 # noqa: E402
from oracle.clienthello import fingerprint                    # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
JA4CLI = os.path.join(ROOT, "csrc", "ja4cli")

SPEC = "FoxIO-LLC/ja4 · technical_details/JA4.md"

# —— 规范给出的向量。列表按**规范里的原序**抄，排序由本门禁自己做 ——
CIPHERS = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
           0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
EXTENSIONS = [0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
              0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015]
SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]

WANT_JA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"
WANT_B = "8daaf6152771"          # 排序后的密码套件
WANT_C = "e5627efa2ab1"          # 排序后的扩展（去 SNI/ALPN）+ 原序签名算法
WANT_O_B = "acb858a92679"        # -o：原序密码套件
WANT_O_C = "18f69afefd3d"        # -o：原序扩展（**含** SNI/ALPN）


def h12(s):
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def csv(vals):
    return ",".join(f"{v:04x}" for v in vals)


def check_algorithm():
    """算法级：规范给的输入 → 规范给的哈希。与我们的解析器无关。"""
    bad = []
    cases = [
        ("ja4_b（密码套件排序后）", csv(sorted(CIPHERS)), WANT_B),
        ("ja4_c（扩展排序去 SNI/ALPN + 原序签名算法）",
         csv(sorted(e for e in EXTENSIONS if e not in (0x0000, 0x0010)))
         + "_" + csv(SIG_ALGS), WANT_C),
        ("ja4_o_b（密码套件原序）", csv(CIPHERS), WANT_O_B),
        ("ja4_o_c（扩展原序，含 SNI/ALPN）",
         csv(EXTENSIONS) + "_" + csv(SIG_ALGS), WANT_O_C),
    ]
    for name, text, want in cases:
        got = h12(text)
        mark = "✅" if got == want else "✗"
        print(f"  {mark} {name:38s} {got}")
        if got != want:
            bad.append(f"{name}: 算出 {got}，规范是 {want}\n      输入 {text}")
    return bad


def synthetic_profile():
    """按向量的字段拼一个 profile，交给正式的构造器出字节。

    **不手写 ClientHello 字节**：手写的话验的就是"我手写得对不对"，而不是
    构造器。扩展体只填 JA4 真正会读的那几个（SNI/ALPN/签名算法/支持版本），
    其余给空体 —— JA4 只看扩展 id，不看内容。
    """
    def ext_body(eid):
        if eid == 0x0000:                       # server_name
            host = b"example.com"
            inner = b"\x00" + len(host).to_bytes(2, "big") + host
            return len(inner).to_bytes(2, "big") + inner
        if eid == 0x0010:                       # ALPN
            item = b"\x02h2"
            return len(item).to_bytes(2, "big") + item
        if eid == 0x000d:                       # signature_algorithms
            body = b"".join(v.to_bytes(2, "big") for v in SIG_ALGS)
            return len(body).to_bytes(2, "big") + body
        if eid == 0x002b:                       # supported_versions
            return b"\x02\x03\x04"
        return b""

    return {
        "raw_ciphers": list(CIPHERS),
        "raw_extensions": list(EXTENSIONS),
        "extension_bodies": {str(e): ext_body(e).hex() for e in EXTENSIONS},
        "client_version": 0x0303,
        "compression": [0],
        "session_id_len": 32,
    }


def check_end_to_end():
    """端到端：向量字段 → ClientHello 字节 → Python / C 各算一遍。"""
    bad = []
    # **不重算 padding**：向量描述的是一条给定的 ClientHello，扩展列表就是它
    # 列的那 16 个。按长度重算会把 0x0015 丢掉（合成报文很短），于是"验不过
    # 官方向量"——而问题出在我们改写了判据本身。
    raw = build_client_hello(synthetic_profile(), sni="example.com",
                             verbatim=True)
    py = fingerprint(raw)["ja4"]
    mark = "✅" if py == WANT_JA4 else "✗"
    print(f"  {mark} Python  {py}")
    if py != WANT_JA4:
        bad.append(f"Python 算出 {py}，规范是 {WANT_JA4}")

    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        bad.append(f"make 失败：{(r.stderr or r.stdout)[-200:]}")
        return bad
    c = subprocess.run([JA4CLI], input=raw.hex(), capture_output=True,
                       text=True, timeout=60).stdout.strip()
    mark = "✅" if c == WANT_JA4 else "✗"
    print(f"  {mark} C       {c}")
    if c != WANT_JA4:
        bad.append(f"C 算出 {c}，规范是 {WANT_JA4}")
    return bad


def main():
    print(f"判据：{SPEC}\n")
    print("算法级（规范输入 → 规范哈希）：")
    bad = check_algorithm()
    print("\n端到端（向量字段 → ClientHello → 两份实现）：")
    bad += check_end_to_end()

    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'与规范官方向量一致' if not bad else f'{len(bad)} 处不符'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
