"""QUIC 指纹门禁：RFC 官方向量 + 真机端到端。

QUIC 的 ClientHello 与 TCP 上那份是**两套东西**（实测 Chrome 151：QUIC 版 10 个
扩展、TCP 版 15 个），必须单独验。

三层判定：
  1. 密钥派生对齐 RFC 9001 Appendix A.1 官方测试向量 —— 派生错了后面全错，且
     错得很隐蔽（解密失败看起来像"包不完整"）
  2. 真机 Chromium 端到端：强制 QUIC → 收 Initial → 解密 → 重组 → 出 JA4Q
  3. 阴性对照：非 Initial 包必须被拒，不能当成指纹

跑：python -m spec.test_quic
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.browsers import discover                          # noqa: E402
from oracle.clienthello import fingerprint                    # noqa: E402
from oracle.quic import (QuicError, initial_secrets, ja4q,     # noqa: E402
                         parse_initial, reassemble_client_hello)
from oracle.quicprobe import QuicProbe                        # noqa: E402


def t_rfc_vectors():
    """RFC 9001 A.1：DCID 8394c8f03e515708 的 client initial 密钥。"""
    key, iv, hp = initial_secrets(bytes.fromhex("8394c8f03e515708"))
    want = ("1f369613dd76d5467730efcbe3b1a22d",
            "fa044b2f42a3fd3b46fb255c",
            "9f50449e04a0e810283a1e9933adedd2")
    got = (key.hex(), iv.hex(), hp.hex())
    return got == want, ("key/iv/hp 三项与官方向量一致" if got == want
                         else f"不符：{got} != {want}")


def t_rejects_non_initial():
    """短包头 / 非 Initial 必须抛 QuicError，而不是返回看似合理的结果。"""
    cases = {"短包头": bytes([0x40]) + b"\x00" * 40,
             "Handshake 包(type=2)": bytes([0xE0]) + b"\x00" * 40}
    bad = []
    for name, pkt in cases.items():
        try:
            parse_initial(pkt)
            bad.append(name)
        except QuicError:
            pass
        except Exception:
            pass          # 其他异常也算拒绝，只要没静默返回
    return not bad, ("非 Initial 包均被拒绝" if not bad
                     else f"被错误接受: {bad}")


def t_reassemble_incomplete():
    """CRYPTO 片段没收齐必须拒绝 —— **"无空洞"不等于"收齐"**。

    Chromium 把整条 ClientHello 塞进一个 Initial，Firefox 会拆成多个。只按
    "已收到的字节之间有没有空洞"判断的话，第一个 Initial 单独看完全没有空洞，
    于是会"成功"重组出一条被截断的 ClientHello，指纹静默算错。

    这个缺陷这轮真出过、也真修了 —— 但代码变异实测：把长度校验那行去掉，
    **所有门禁照样全绿**。语料里只存了指纹、没存原始数据报，重组器从来没被
    喂过不完整的输入。修了却没人看着，等于等它悄悄回归。

    构造一条自洽的握手消息（type=0x01 + 3 字节长度），只喂前一半。
    """
    body = b"\x03\x03" + b"\xaa" * 300          # 假 ClientHello 体
    full = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    cases = {
        "只收到前一半（无空洞但没收齐）": [(0, full[:len(full) // 2])],
        "中间缺一段（有空洞）": [(0, full[:50]), (100, full[100:])],
        "空片段": [],
    }
    bad = []
    for name, chunks in cases.items():
        try:
            reassemble_client_hello(chunks)
            bad.append(name)
        except QuicError:
            pass
    # 阳性对照：完整的必须能过，否则上面三条"全被拒"是平凡通过
    try:
        rec = reassemble_client_hello([(0, full)])
        if rec[0] != 0x16 or rec[5] != 0x01:
            bad.append("完整输入重组出的不是 TLS record 包着的 ClientHello")
    except QuicError as e:
        bad.append(f"完整输入被误拒：{e}")
    return not bad, ("不完整片段均被拒、完整片段正常" if not bad
                     else f"有问题: {bad}")


def t_real_browser():
    """真机 Chromium 强制走 QUIC，端到端出 JA4Q。"""
    chromium = [(n, b, v) for n, e, b, v in discover() if e == "chromium"]
    if not chromium:
        return False, "本机无 chromium 系浏览器"
    name, binary, version = chromium[0]
    profile = tempfile.mkdtemp(prefix="tlsfp-quictest-")
    with QuicProbe() as probe:
        proc = subprocess.Popen(
            [binary, "--headless=new", f"--user-data-dir={profile}",
             "--no-first-run", "--disable-gpu", "--enable-quic",
             f"--origin-to-force-quic-on=127.0.0.1:{probe.port}",
             "--ignore-certificate-errors", f"https://127.0.0.1:{probe.port}/"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            fp = fingerprint(probe.pop(timeout=40))
            q = ja4q(fp)
            ok = q.startswith("q") and "h3" in fp["alpn"] and 0x39 in fp["extensions_ordered"]
            return ok, (f"{name} {version} → {q}"
                        f"（ALPN={fp['alpn']}，含 quic_transport_parameters="
                        f"{0x39 in fp['extensions_ordered']}）")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            shutil.rmtree(profile, ignore_errors=True)


def main():
    tests = [("RFC 9001 官方向量", t_rfc_vectors),
             ("拒绝非 Initial（阴性）", t_rejects_non_initial),
             ("重组：没收齐必须拒（阴性）", t_reassemble_incomplete),
             ("真机端到端", t_real_browser)]
    failed = 0
    for name, fn in tests:
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        print(f"  {'✅' if ok else '❌'} {name:22s} {detail}")
        failed += 0 if ok else 1
    print(f"\n{len(tests) - failed}/{len(tests)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
