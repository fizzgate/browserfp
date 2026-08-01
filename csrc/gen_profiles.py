"""把 profiles.json 编译成 C 静态数组 —— 避免运行时解析 JSON。

为什么不在 C 里读 JSON：
  · 这个库要跑在 nginx worker 里，启动期与请求期都不该做文件 I/O 与动态分配；
  · profile 数据是构建期就确定的常量，编译进只读段既快又省心；
  · 少一个 JSON 解析器就少一类解析漏洞。

生成的 profiles.inc 由 tlsfp.c 直接 #include。

跑：python csrc/gen_profiles.py > csrc/profiles.inc
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "..", "spec", "profiles.json")


def c_u16_array(name, values):
    if not values:
        return f"static const uint16_t {name}[1] = {{0}};"
    body = ", ".join(f"0x{v:04x}" for v in values)
    return f"static const uint16_t {name}[{len(values)}] = {{{body}}};"


def main():
    with open(REGISTRY) as f:
        registry = json.load(f)

    # 只导出默认配置形态：需显式 feature flag 才出现的变体不是正常用户行为，
    # 编进库里只会增大体积并稀释匹配结果。
    profiles = [r for r in registry if r.get("default_config", True)]

    out = ["/* 由 csrc/gen_profiles.py 从 spec/profiles.json 生成，请勿手改。 */",
           "/* 仅含默认配置形态；需 feature flag 才出现的变体不编入。 */", ""]

    for i, rec in enumerate(profiles):
        tls = rec["tls"]
        out.append(c_u16_array(f"p{i}_ciphers", tls.get("ciphers") or []))
        out.append(c_u16_array(f"p{i}_exts", tls.get("extensions_ordered") or []))
        out.append(c_u16_array(f"p{i}_curves", tls.get("curves") or []))
        out.append(c_u16_array(f"p{i}_sigalgs", tls.get("sig_algs") or []))

    out.append("")
    out.append("static const tlsfp_profile tlsfp_profiles[] = {")
    for i, rec in enumerate(profiles):
        tls = rec["tls"]
        h2 = (rec.get("h2") or {}).get("akamai_fingerprint") or ""
        out.append(
            f'    {{"{rec["id"]}", "{tls.get("ja4","")}", "{h2}", '
            f'"{rec.get("mode","initial")}", '
            f'p{i}_ciphers, {len(tls.get("ciphers") or [])}, '
            f'p{i}_exts, {len(tls.get("extensions_ordered") or [])}, '
            f'p{i}_curves, {len(tls.get("curves") or [])}, '
            f'p{i}_sigalgs, {len(tls.get("sig_algs") or [])}}},')
    out.append("};")
    out.append(f"#define TLSFP_PROFILE_COUNT {len(profiles)}")

    print("\n".join(out))
    print(f"/* 共 {len(profiles)} 条（注册表 {len(registry)} 条，"
          f"排除 {len(registry) - len(profiles)} 条非默认配置） */")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
