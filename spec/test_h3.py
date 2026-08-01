"""HTTP/3 指纹门禁 —— 重点是**稳定性**，而不只是能采到。

H3 的 SETTINGS 里含 GREASE 项，其 id 与 value 每次连接都随机。参考实现
0x676e67/pingly 只把 GREASE 排到末尾、不剔除，那样产出的 h3_text 每次都不同，
根本不能当指纹。本门禁因此断言：连续多次采集必须得到同一个 h3_text。

跑：.venv-wreq/bin/python -m spec.test_h3 [次数]
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.browsers import discover                          # noqa: E402
from oracle.h3collect import capture_browser, spki_pin        # noqa: E402
from oracle.h3probe import h3_fingerprint, is_grease_setting  # noqa: E402


def t_grease_detection():
    """GREASE setting 判定：0x1f*N+0x21（RFC 9114 §7.2.4.1）。"""
    cases = {0x21: True, 0x21 + 0x1F: True, 123978566416: True,
             1: False, 6: False, 7: False, 51: False}
    bad = [f"{k}→{is_grease_setting(k)}" for k, v in cases.items()
           if is_grease_setting(k) != v]
    return not bad, (f"{len(cases)}/{len(cases)} 判定正确" if not bad
                     else f"错判 {bad}")


def t_grease_excluded():
    """含 GREASE 的 settings 拼出的 h3_text 不得包含该项。"""
    s = {1: 65536, 6: 262144, 123978566416: 1651753507}
    text = h3_fingerprint(s, [(":method", "m")])
    ok = "123978566416" not in text and "1:65536" in text
    return ok, f"h3_text={text}"


def t_stability(rounds=3):
    """同一浏览器连续采集，h3_text 必须恒定 —— 这是本门禁的核心。"""
    chromium = [(n, b, v) for n, e, b, v in discover() if e == "chromium"]
    if not chromium:
        return False, "本机无 chromium 系浏览器"
    name, binary, version = chromium[0]
    pin = spki_pin()
    texts, greases = set(), set()
    for _ in range(rounds):
        r = capture_browser(binary, pin)
        texts.add(r["h3_text"])
        greases.add(tuple(sorted(k for k in r["settings"]
                                 if is_grease_setting(k))))
    ok = len(texts) == 1
    # 充分性：若 GREASE 每次相同，则这次"稳定"是平凡的，没验到该验的
    varied = len(greases) > 1
    return ok and varied, (
        f"{name} {version} × {rounds}：h3_text 取值 {len(texts)}"
        f"，GREASE 取值 {len(greases)}"
        + ("" if varied else "（GREASE 未变化，稳定性验证不充分）"))


def main(argv):
    rounds = int(argv[1]) if len(argv) > 1 else 3
    tests = [("GREASE 判定", t_grease_detection),
             ("GREASE 被剔除", t_grease_excluded),
             ("跨连接稳定（含充分性）", lambda: t_stability(rounds))]
    failed = 0
    for name, fn in tests:
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        print(f"  {'✅' if ok else '❌'} {name:24s} {detail}")
        failed += 0 if ok else 1
    print(f"\n{len(tests) - failed}/{len(tests)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
