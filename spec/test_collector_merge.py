"""门禁：所有写 golden 的采集器都必须合并写。

这个 bug 出现过三次（browsers.py / h2collect.py / goh2collect.py），最后一次把
h2_tls_client.json 的 71 条冲成 0 条。它不报错、只让样本静默消失，覆盖率数字随之
变小却无人察觉——纯假绿。事后审计发现 10 个采集器里 6 个都有这个风险，说明"哪里
出问题修哪里"不可靠，必须有门禁兜住。

判据：凡支持"只采子集"（argv[1:] 之类）的采集器，写盘必须经 goldenio.write_golden。

跑：python -m spec.test_collector_merge
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.path.join(os.path.dirname(HERE), "oracle")

# 不写 golden 的模块：观测点、解析器、识别器等
EXEMPT = {"__init__.py", "goldenio.py", "clienthello.py", "sniffer.py", "h2probe.py",
          "tapproxy.py", "tls13.py", "h2client.py", "chbuild.py", "match.py",
          "coverage.py", "registry.py", "targets.py", "srcaudit.py", "browsers.py",
          "pskserver.py", "capture_browser.py"}


def main():
    bad, checked = [], []
    for fn in sorted(os.listdir(ORACLE)):
        if not fn.endswith(".py") or fn in EXEMPT:
            continue
        src = open(os.path.join(ORACLE, fn)).read()
        if "spec\", \"golden\"" not in src and "golden" not in src:
            continue
        writes = bool(re.search(r'open\(\s*\w*(OUT|PATH|out_path)\w*\s*,\s*"w"', src))
        merged = "write_golden" in src or "existing" in src or ".update(" in src
        checked.append(fn)
        if writes and not merged:
            bad.append(fn)

    print(f"检查 {len(checked)} 个写 golden 的采集器")
    for fn in bad:
        print(f"  ✗ {fn}: 直接覆盖写，未经 write_golden —— 只采子集会冲掉其余样本")
    print(f"\n{len(checked) - len(bad)}/{len(checked)} 合规")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
