"""门禁：凡按名字查注册表，必须同时查 aliases，不能只看 id。

注册表按**指纹**去重，同指纹的多个名字合并成一条，保留下来的 id 只是众多别名
里的任意一个。只按 id 查会静默失配，且失配后果各不相同，很难联想到同一个根因：

  · test_cf_discrimination  KeyError，被误读成"该指纹打不通"
  · test_match              StopIteration
  · registry COVERS         第一大 UA Chrome150 命不中（id 恰为 real:edge）
  · uamap 跨品牌检查        把 firefox→tor145 这种**正确**映射判成跨品牌而拒绝

同一个坑已出现四次，故用门禁固定：源码里不得出现"只比较 rec['id'] 而不看
aliases"的查找写法。

跑：python -m spec.test_alias_lookup
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCAN_DIRS = [os.path.join(ROOT, "oracle"), HERE]

# 只比 id、且同一行/相邻行没提到 aliases 的可疑写法
SUSPECT = re.compile(r'\[["\']id["\']\]\s*(?:==|!=)|'
                     r'rec\[["\']id["\']\]\s*(?:==|!=)|'
                     r'r\[["\']id["\']\]\s*(?:==|!=)')


def main():
    findings = []
    for d in SCAN_DIRS:
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(d, fn)
            lines = open(path).read().splitlines()
            for i, line in enumerate(lines):
                if not SUSPECT.search(line):
                    continue
                # 同一行或前后两行提到 aliases 即视为已正确处理
                ctx = "\n".join(lines[max(0, i - 2):i + 3])
                if "aliases" in ctx:
                    continue
                findings.append((os.path.relpath(path, ROOT), i + 1, line.strip()))

    print(f"扫描 {sum(len([f for f in os.listdir(d) if f.endswith('.py')]) for d in SCAN_DIRS)} 个文件")
    for path, ln, code in findings:
        print(f"  ✗ {path}:{ln}  只比 id 未查 aliases\n      {code[:88]}")
    if not findings:
        print("  未发现「只比 id 不查 aliases」的查找")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
