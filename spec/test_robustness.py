"""恶劣输入下 C 侧不得崩溃、不得越界 —— 它跑在 nginx worker 里。

**一次越界不是"这个请求失败"，是整个 worker 挂掉**，同 worker 上所有并发请求
一起没。所以这条门禁的判据不是"结果对不对"，而是"活着回来且没踩内存"。

必须带 **ASan + UBSan**：不带的话"没崩"只说明这次没踩到 —— 越界读发生在只读
的静态表上时常常无声无息，而正是那种最难查。

实测第一次跑就抓到 `tlsfp_ja4(NULL, …)` 直接 SEGV（少一个空指针检查）。

喂进去的东西：NULL、空串、单空格、超长串（70KB）、非 UTF-8 字节、全逗号、
越界与 (size_t)-1 下标、零长缓冲、差一字节的缓冲、截断到每一个长度的 TLS
record、长度字段撒谎的 record。

跑：python -m spec.test_robustness
"""

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FUZZCLI = os.path.join(ROOT, "csrc", "fuzzcli")

# 调用次数下限：防平凡通过 —— 程序若因为编译宏或早退只跑了几次，
# "没崩"毫无意义。当前 1543 次。
MIN_CALLS = 1000


def main():
    r = subprocess.run(["make", "-s", "fuzzcli"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=600)
    if not os.path.exists(FUZZCLI):
        print(f"构建失败：{(r.stderr or r.stdout)[-300:]}", file=sys.stderr)
        return 2

    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    try:
        p = subprocess.run([FUZZCLI], capture_output=True, text=True,
                           timeout=300, env=env)
    except subprocess.TimeoutExpired:
        print("  ✗ 超时 —— 恶劣输入让它转不出来了", file=sys.stderr)
        return 1

    combined = p.stdout + p.stderr
    bad = []
    if p.returncode != 0:
        bad.append(f"退出码 {p.returncode}")
    for kw, why in (("AddressSanitizer", "内存越界/非法访问"),
                    ("runtime error", "未定义行为（UBSan）"),
                    ("SEGV", "段错误")):
        if kw in combined:
            hit = next((l for l in combined.splitlines() if kw in l), kw)
            bad.append(f"{why}：{hit[:110]}")

    m = re.search(r"^(\d+)$", p.stdout.strip(), re.M)
    calls = int(m.group(1)) if m else 0
    print(f"恶劣输入 {calls} 次调用，ASan+UBSan 下"
          f"{'全部安全返回' if not bad else '有问题'}")
    if calls < MIN_CALLS:
        bad.append(f"只跑了 {calls} 次（下限 {MIN_CALLS}）—— "
                   "\"没崩\"在这个次数下证明不了什么")

    for b in bad[:6]:
        print(f"  ✗ {b}")
    print(f"\n{'C 侧对恶劣输入健壮' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
