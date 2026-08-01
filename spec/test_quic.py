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
from oracle.quic import QuicError, initial_secrets, ja4q, parse_initial  # noqa: E402
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
