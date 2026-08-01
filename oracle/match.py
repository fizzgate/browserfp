"""指纹识别器：ClientHello → 已知 profile 或明确的 unknown。

这是整个项目的落点。前面所有采集/合成都是为了这一步：进来一个握手，能说出它
是谁；**说不出的时候必须明说是 unknown，而不是硬套最近的那个**——把陌生流量
安静地归到某个已知 profile，比认不出更糟，因为它让盲区不可见。

识别结果同时给出该指纹对应的 h2（Akamai）与 h3（h3_text）应用层特征——
若观测到的应用层与之不符，就是 TLS 层与协议栈对不上的 split-brain。

匹配分三档：
  exact          13 个确定性字段逐项相同
  exact-no-pad   忽略 padding(0x15) 后相同
  unknown        以上都不满足；同时给出最接近者与差异字段，供补录

**为什么要容忍 padding**：它按 ClientHello 总长度动态添加（RFC 7685），同一个
客户端在 HelloRetryRequest 前后 padding 会有无不同（实测 safari184/155/260_ios
在 HRR 后 padding 直接消失）。性质与 GREASE 相同，是噪声不是身份。实测忽略它
只让唯一指纹 54→53（仅合并 1 对），代价远小于把同一客户端判成两个指纹。

GREASE 在 clienthello 解析阶段已按 RFC 8701 剔除，这里不再处理。
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.coverage import FIELDS, SET_FIELDS                # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "..", "spec", "profiles.json")

PADDING_EXT = 0x0015


def _norm(fp, ignore_padding=False):
    """把指纹归一成可比较的字典。"""
    out = {}
    for f in FIELDS:
        v = fp.get(f)
        if f in SET_FIELDS:
            v = sorted(x for x in (v or [])
                       if not (ignore_padding and x == PADDING_EXT))
        out[f] = v
    return out


def _diff(a, b):
    return [f for f in FIELDS if a[f] != b[f]]


class Matcher:
    """按注册表识别指纹。构造一次可重复使用。"""

    def __init__(self, registry_path=REGISTRY):
        with open(registry_path) as f:
            self.registry = json.load(f)
        # 两张索引：严格 / 忽略 padding。命中前者置信度更高。
        self._strict = {}
        self._nopad = {}
        for rec in self.registry:
            self._strict.setdefault(
                json.dumps(_norm(rec["tls"]), sort_keys=True), rec)
            self._nopad.setdefault(
                json.dumps(_norm(rec["tls"], True), sort_keys=True), rec)

    def find(self, alias):
        """按 id 或 aliases 查记录，找不到抛 KeyError。

        注册表按指纹去重，保留的 id 可能是任意一个别名——只按 id 找会对
        chrome136、real:chrome 这类被合并掉的名字扑空。**同一个坑已在
        test_cf_discrimination、test_match、以及 QUIC 并库时各踩过一次**，
        故抽成公共方法，调用方不要再自己写循环。
        """
        for rec in self.registry:
            if rec["id"] == alias or alias in rec.get("aliases", []):
                return rec
        raise KeyError(f"{alias} 不在注册表（含 aliases）")

    def identify(self, fp):
        """fp 为 clienthello.fingerprint() 的输出。返回识别结果 dict。"""
        rec = self._strict.get(json.dumps(_norm(fp), sort_keys=True))
        if rec:
            return self._hit(rec, "exact")

        rec = self._nopad.get(json.dumps(_norm(fp, True), sort_keys=True))
        if rec:
            return self._hit(rec, "exact-no-pad")

        # 未知：给出最接近者与差异字段，但**不当作匹配**
        target = _norm(fp, True)
        ranked = sorted(
            ((len(_diff(target, _norm(r["tls"], True))), r) for r in self.registry),
            key=lambda x: x[0])
        n, nearest = ranked[0]
        return {
            "match": None,
            "confidence": "unknown",
            "nearest": nearest["id"],
            "nearest_distance": n,
            "diff_fields": _diff(target, _norm(nearest["tls"], True)),
        }

    @staticmethod
    def _hit(rec, confidence):
        return {
            "match": rec["id"],
            "confidence": confidence,
            "mode": rec.get("mode"),
            "provenance": rec.get("provenance"),
            "aliases": rec.get("aliases", []),
            "h2": rec.get("h2", {}).get("akamai_fingerprint") if rec.get("h2") else None,
            "h3": rec.get("h3", {}).get("h3_text") if rec.get("h3") else None,
        }


def identify_record(record_bytes, matcher=None):
    """便捷入口：原始 TLS record → 识别结果。"""
    from oracle.clienthello import fingerprint

    return (matcher or Matcher()).identify(fingerprint(record_bytes))


def main(argv):
    m = Matcher()
    print(f"注册表 {len(m.registry)} 条；严格索引 {len(m._strict)}，"
          f"忽略 padding 索引 {len(m._nopad)}")
    # 自识别：注册表每条都应被自己精确命中
    bad = []
    for rec in m.registry:
        r = m.identify(rec["tls"])
        if r["confidence"] != "exact":
            bad.append((rec["id"], r["confidence"]))
    print(f"自识别 {len(m.registry) - len(bad)}/{len(m.registry)} 命中 exact")
    for pid, c in bad:
        print(f"  ✗ {pid} → {c}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
