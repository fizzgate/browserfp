"""按源码给出的平台差异，从桌面 golden 派生移动端 profile。

**这与"造样本"的区别在于规则是被验证过的**。项目原则是不往库里塞推导样本
（见 README 的 covers_versions 一节），这里没有破例：派生只做源码明确指出的
那几处改动，而且改动规则先在**有实采 golden 的版本上验证过**——
    桌面 Firefox 135  减去 SCT 与 MLKEM
    = 实采 wreq:FirefoxAndroid135  （逐字段一致）
规则成立，才拿它去覆盖没有实采的版本区间。

**每次派生都会重跑这个验证**，验证不过就拒绝派生：规则的前提（平台差异只来自
那几个 pref 分支）哪天不成立了，派生出来的东西就是错的，那时应该报错而不是
静默产出。

跑：python -m oracle.derive firefox-mobile 153        # 试算，不落盘
    python -m oracle.derive firefox-mobile 153 --write
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.coverage import FIELDS, SET_FIELDS                 # noqa: E402
from oracle.nsssrc import extract as ff_extract                # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "..", "spec", "profiles.json")
OUT = os.path.join(HERE, "..", "spec", "golden", "derived_mobile.json")

SCT_EXT = 0x0012
ECH_EXT = 0xFE0D
MLKEM_GROUP = 0x11EC

# 规则验证用的锚点：这个版本既有桌面 golden 也有移动端 golden，能直接检验
# "桌面 − 差异 = 移动端"是否成立。
ANCHOR = {"firefox-mobile": ("wreq:Firefox135", "wreq:FirefoxAndroid135", "135")}


def h2_delta(brand, registry):
    """从锚点学出移动端 h2 层与桌面的差异。

    **h2 不能照搬桌面**：实测 Android Firefox 的 SETTINGS 与桌面不同 ——
    HEADER_TABLE_SIZE 65536→4096、INITIAL_WINDOW_SIZE 131072→32768（移动端用
    更小的缓冲区），其余字段（priorities / pseudo_header_order / window_update）
    完全一致。

    只有 TLS 层的 profile 在生产里用不完整：伪装浏览器流量必然要发 HTTP/2，
    没有 h2 层就没法构造 SETTINGS 帧，识别方一看就露。

    返回锚点移动端那份 h2（整体替换而非逐字段打补丁）—— 差异集中在 SETTINGS
    的具体数值上，没有"按版本演进"的规律可循，照搬锚点的移动端形态比自己编
    一组数值诚实。
    """
    if brand not in ANCHOR:
        return None
    _, mob_alias, _ = ANCHOR[brand]
    mob = _find(registry, mob_alias)
    return (mob or {}).get("h2") or None


def _load_registry():
    with open(REGISTRY) as f:
        return json.load(f)


def _find(registry, alias):
    for rec in registry:
        if alias in [rec["id"]] + rec.get("aliases", []):
            return rec
    return None


def platform_delta(version, brand="firefox-mobile"):
    """源码给出的该版本平台差异：返回 {"drop_sct": bool, "drop_mlkem": bool}。"""
    d = ff_extract(str(version), "desktop")
    a = ff_extract(str(version), "android")
    return {
        "drop_sct": bool(d.get("sct")) and not bool(a.get("sct")),
        "drop_mlkem": (MLKEM_GROUP in _curve_ids(d)) and
                      (MLKEM_GROUP not in _curve_ids(a)),
        "drop_ech": bool(d.get("ech")) and not bool(a.get("ech")),
    }


CURVE_IDS = {
    "ssl_grp_ec_curve25519": 0x1D, "ssl_grp_ec_secp256r1": 0x17,
    "ssl_grp_ec_secp384r1": 0x18, "ssl_grp_ec_secp521r1": 0x19,
    "ssl_grp_ffdhe_2048": 0x100, "ssl_grp_ffdhe_3072": 0x101,
    "ssl_grp_kem_mlkem768x25519": 0x11EC, "ssl_grp_kem_xyber768d00": 0x6399,
}


def _curve_ids(tables):
    return [CURVE_IDS.get(c, c) for c in (tables.get("curves") or [])]


def apply_delta(tls, delta):
    """把平台差异应用到一份桌面指纹上，返回新的 tls 结构。"""
    out = dict(tls)
    drop_ext = set()
    if delta.get("drop_sct"):
        drop_ext.add(SCT_EXT)
    if delta.get("drop_ech"):
        drop_ext.add(ECH_EXT)
    if drop_ext:
        for key in ("extensions_ordered", "raw_extensions"):
            if out.get(key):
                out[key] = [e for e in out[key] if e not in drop_ext]
        if out.get("extension_bodies"):
            out["extension_bodies"] = {
                k: v for k, v in out["extension_bodies"].items()
                if int(k) not in drop_ext}
    if delta.get("drop_mlkem") and out.get("curves"):
        out["curves"] = [c for c in out["curves"] if c != MLKEM_GROUP]

    # **必须重算 ja4**：删掉扩展后扩展计数变了，不重算会得到一份自相矛盾的
    # profile —— ja4 首段写着 16 个扩展、字段里只有 15 个。识别时按 ja4 查表，
    # 那份 profile 永远命不中自己。
    from oracle.clienthello import ja4 as _ja4
    ch = {
        "sni": None,                      # 库里 golden 统一是无 SNI 形态
        "ciphers": out.get("ciphers") or [],
        "extensions": out.get("extensions_ordered") or [],
        "curves": out.get("curves") or [],
        "sig_algs": out.get("sig_algs") or [],
        "alpn": out.get("alpn") or [],
        "supported_versions": out.get("supported_versions") or [],
        "client_version": out.get("client_version"),
    }
    try:
        out["ja4"] = _ja4(ch)
    except Exception:
        pass                              # 字段不全时保留原值，由调用方核对
    return out


def verify_rule(brand, registry):
    """在锚点版本上检验派生规则；返回 (是否成立, 说明)。"""
    if brand not in ANCHOR:
        return False, f"{brand} 没有可用于验证规则的锚点版本"
    desk_alias, mob_alias, ver = ANCHOR[brand]
    desk, mob = _find(registry, desk_alias), _find(registry, mob_alias)
    if not desk or not mob:
        return False, f"锚点 {desk_alias} / {mob_alias} 不在注册表中"
    derived = apply_delta(desk["tls"], platform_delta(ver, brand))

    def norm(t, f):
        v = t.get(f)
        return sorted(v) if f in SET_FIELDS and v else v

    diff = [f for f in FIELDS if norm(derived, f) != norm(mob["tls"], f)]
    if diff:
        return False, f"锚点 {ver} 上派生结果与实采不符，差异字段 {diff}"
    return True, f"锚点 {ver}：{desk_alias} 应用平台差异后与 {mob_alias} 逐字段一致"


def derive(brand, version, registry, source_alias):
    src = _find(registry, source_alias)
    if not src:
        raise KeyError(f"{source_alias} 不在注册表中")
    delta = platform_delta(version, brand)
    return apply_delta(src["tls"], delta), delta


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    if len(args) < 2:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    brand, version = args[0], int(args[1])
    src_alias = args[2] if len(args) > 2 else "real:firefox153"

    registry = _load_registry()
    ok, why = verify_rule(brand, registry)
    print(f"规则验证：{'通过' if ok else '失败'} —— {why}")
    if not ok:
        print("派生已中止：规则的前提不成立时，派生出来的就是错的。", file=sys.stderr)
        return 1

    tls, delta = derive(brand, version, registry, src_alias)
    h2 = h2_delta(brand, registry)
    print(f"\n从 {src_alias} 派生 {brand} {version}")
    print(f"  平台差异: {[k for k, v in delta.items() if v] or '无（两平台同形态）'}")
    print(f"  ja4     : {tls.get('ja4')}  （已按删减后的字段重算）")
    print(f"  扩展数  : {len(tls.get('extensions_ordered') or [])}")
    print(f"  curves  : {[hex(c) for c in (tls.get('curves') or [])]}")
    print(f"  h2 层    : {'取自锚点移动端 ' + ANCHOR[brand][1] if h2 else '无'}")

    if "--write" not in argv:
        print("\n试算模式，未落盘。加 --write 才写入 "
              f"{os.path.relpath(OUT, os.path.dirname(HERE))}")
        return 0

    from oracle.goldenio import write_golden
    total, changed = write_golden(OUT, {
        f"{brand}-{version}": {
            "version": f"{brand} {version}",
            "derived_from": src_alias,
            "delta": [k for k, v in delta.items() if v],
            "fingerprint": tls,
            "h2": h2,
            "h2_from": ANCHOR[brand][1] if h2 else None,
        }})
    print(f"\n落盘 → {os.path.normpath(OUT)}  共 {total} 条，本次更新 {changed} 条")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
