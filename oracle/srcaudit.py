"""从浏览器源码确定"指纹空间"——不下载浏览器，只读决定指纹的那几处代码。

**要解决的问题**：采集只能覆盖手上有的版本。进来一个没采过的版本，我们不知道
它会不会带一个从没见过的扩展/曲线/签名算法——也就"不认识"了。穷举下载所有
版本不可持续（Chrome 一年发十几个大版本，且索引源在本网络不可达）。

**做法**：直接读上游源码里决定 ClientHello 形态的表，得到**可能出现的全集**，
再与我们已采集到的做差。差集就是"理论上会出现、但我们从没见过"的东西——那才
是真正的识别盲区。

已验证可靠：boringssl 的 kExtensions 是超集，真机 Chrome 151 实发的 15 个扩展
全部落在表内，无一例外（"真机有而源码无"为空）。表里同时存在 0x4469 与 0x44cd
两个 ALPS codepoint，正对应我们实测到的 Chrome 133a 前后的迁移。

数据源（chromium.googlesource.com 在本网络不可达，用 GitHub 镜像）：
  Chrome/BoringSSL  google/boringssl        ssl/extensions.cc + include/openssl/tls1.h
  Firefox/NSS       nss-dev/nss             lib/ssl/ssl3ext.c
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "..", "spec", "profiles.json")

RAW = "https://raw.githubusercontent.com"
SOURCES = {
    "boringssl": {
        "ext": f"{RAW}/google/boringssl/main/ssl/extensions.cc",
        "hdr": f"{RAW}/google/boringssl/main/include/openssl/tls1.h",
    },
    "nss": {
        "ext": f"{RAW}/nss-dev/nss/master/lib/ssl/ssl3ext.c",
        "hdr": f"{RAW}/nss-dev/nss/master/lib/ssl/sslt.h",
    },
}


def fetch(url, timeout=45):
    """用 curl_cffi 取源码：本网络对 raw.githubusercontent 直连不稳，带浏览器
    指纹的请求实测可通。"""
    from curl_cffi import requests

    r = requests.get(url, impersonate="chrome136", timeout=timeout)
    if r.status_code != 200:
        raise OSError(f"{r.status_code} {url}")
    return r.text


def boringssl_extension_space():
    """BoringSSL 的 kExtensions 数组 → 扩展号集合（Chrome 可能发的全集）。"""
    body = fetch(SOURCES["boringssl"]["ext"])
    m = re.search(r"static const struct tls_extension kExtensions\[\] = \{(.*?)\n\};",
                  body, re.S)
    if not m:
        raise ValueError("未找到 kExtensions —— 上游结构可能变了，需重新定位")
    names = re.findall(r"^\s*\{\s*(TLSEXT_TYPE_\w+)", m.group(1), re.M)

    hdr = fetch(SOURCES["boringssl"]["hdr"])
    out = {}
    for name in names:
        mm = re.search(rf"#define {name}\s+(0x[0-9a-fA-F]+|\d+)", hdr)
        if mm:
            out[int(mm.group(1), 0)] = name.replace("TLSEXT_TYPE_", "")
    if len(out) < len(names) * 0.8:
        raise ValueError(f"仅解析出 {len(out)}/{len(names)} 个扩展号，头文件结构可能变了")
    return out


def observed_space():
    """我们已采集到的扩展号（全部 profile 的并集）。"""
    with open(REGISTRY) as f:
        registry = json.load(f)
    seen = set()
    for rec in registry:
        seen.update(rec["tls"].get("raw_extensions") or [])
    # GREASE 不是真实扩展，按 RFC 8701 剔除
    from oracle.clienthello import is_grease
    return {e for e in seen if not is_grease(e)}


def main():
    print("拉取上游源码…")
    space = boringssl_extension_space()
    seen = observed_space()

    # SNI(0x0000) 特殊：我们的 no-SNI 采集刻意不发它，不算盲区
    blind = {k: v for k, v in space.items() if k not in seen and k != 0x0000}
    covered = {k: v for k, v in space.items() if k in seen}

    print(f"\nBoringSSL 声明的扩展空间: {len(space)}")
    print(f"我们已观测到:             {len(covered)}")
    print(f"从未观测到:               {len(blind)}\n")

    print("已观测:")
    for k in sorted(covered):
        print(f"  0x{k:04x}  {covered[k]}")
    print("\n从未观测（理论上可能出现 → 识别盲区）:")
    for k in sorted(blind):
        print(f"  0x{k:04x}  {blind[k]}")

    unknown = [e for e in seen if e not in space]
    if unknown:
        print("\n⚠ 我们观测到但不在 BoringSSL 表内（非 Chrome 系，或表已过时）:")
        print("  " + " ".join(f"0x{e:04x}" for e in sorted(unknown)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
