"""文档一致性门禁：README 里的路径、命令、数字必须与实际相符。

**为什么需要它**：本项目已经两次出现僵尸文档——tls13.py 顶部那段"key_share
只发 X25519"在支持 MLKEM 后仍留着；README 的"Safari 的 L2 未采"在采到之后
仍留着。靠"改完记得同步文档"不可靠，把它变成能跑的检查才可靠。

检查三类：
  1. README 里出现的仓内路径确实存在
  2. README 里声称可跑的 `python -m xxx` 模块确实可导入
  3. 关键数字（唯一指纹数、target 名数、含 h2 数）与 profiles.json 实算一致

跑：python -m spec.test_docs
"""

import importlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
README = os.path.join(ROOT, "README.md")
REGISTRY = os.path.join(HERE, "profiles.json")


def check_paths(text):
    """README 中形如 oracle/xxx.py、spec/xxx.json 的路径必须存在。"""
    bad = []
    for m in re.finditer(r"`?((?:oracle|spec)/[\w./-]+\.(?:py|json|go|pem))`?", text):
        rel = m.group(1)
        if not os.path.exists(os.path.join(ROOT, rel)):
            bad.append(rel)
    return sorted(set(bad))


def check_modules(text):
    """README 中 `python -m xxx` 的模块必须可导入。"""
    bad = []
    for m in re.finditer(r"python -m ([\w.]+)", text):
        mod = m.group(1)
        try:
            importlib.import_module(mod)
        except Exception as e:
            bad.append(f"{mod} ({type(e).__name__})")
    return sorted(set(bad))


def check_numbers(text):
    """关键数字必须与 profiles.json 实算一致。

    **必须带上下文匹配**。首版只查"该数字是否在 README 中出现过"，变异测试
    立刻证明它是假绿：39 在文中出现多次（39/39、35/39），把"唯一指纹 39"改成
    40 照样全绿。现在锚定到具体那一处表述。

    只查能从数据唯一确定的量，不查"66/68"这类依赖外网的结果——那个每次跑都
    可能因网络变动，写死会制造假红。
    """
    with open(REGISTRY) as f:
        registry = json.load(f)
    facts = {
        "唯一指纹数": len(registry),
        "target 名数": sum(len(r["aliases"]) for r in registry),
        "含 h2 数": sum(1 for r in registry if r["h2"]),
        "真机采集数": sum(1 for r in registry if r["provenance"] == "real-capture"),
    }
    # 每个事实锚定到 README 里唯一的一处表述，改动那处才会被抓到。
    patterns = {
        "唯一指纹数": r"\|\s*唯一指纹\s*\|\s*\*\*{v}\*\*",
        "target 名数": r"来自\s*{v}\s*个\s*target\s*名",
        "含 h2 数": r"\|\s*含 h2 层\s*\|\s*{v}/",
        "真机采集数": r"开源表\s*\d+\s*\+\s*真机采集\s*{v}",
    }
    bad = []
    for label, value in facts.items():
        pat = patterns[label].format(v=value)
        if not re.search(pat, text):
            bad.append(f"{label} 实算 {value}，README 对应处不符（正则 {pat}）")
    return bad, facts


def main():
    with open(README) as f:
        text = f.read()

    paths = check_paths(text)
    modules = check_modules(text)
    numbers, facts = check_numbers(text)

    print("实算：" + "  ".join(f"{k}={v}" for k, v in facts.items()))
    print(f"\n路径检查   {'OK' if not paths else '失败'}")
    for p in paths:
        print(f"  ✗ 不存在：{p}")
    print(f"模块检查   {'OK' if not modules else '失败'}")
    for m in modules:
        print(f"  ✗ 不可导入：{m}")
    print(f"数字检查   {'OK' if not numbers else '失败'}")
    for n in numbers:
        print(f"  ✗ {n}")

    failed = len(paths) + len(modules) + len(numbers)
    print(f"\n{'文档与实现一致' if not failed else f'{failed} 处不一致'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
