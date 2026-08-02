"""请求头顺序：实采自洽、三侧一致、且**库数据仍然不可用**。

伪装是三层的：TLS、h2 开场、请求头顺序。前两层各有自己的门禁，这一层此前
完全没有 —— 而库文件里那 240 条 `header_order` 看着像现成数据，正是最容易被
想当然接回来的东西。

四件事：

  1. **实采按引擎自洽**。Chrome / Chromium / Edge 三份必须给出同一个顺序
     （同一个 Chromium 引擎），Firefox 与 Safari 各自一份。
  2. **库数据仍然自相矛盾**。这是本模块最重要的一条：把库里的 header_order
     当成偏序约束一检验，chrome 一项就有几百处矛盾 —— 同一个浏览器同一个
     版本，两家库说的先后相反，那不可能都是浏览器的行为。这条断言防的是
     "哪天有人看见 240 条数据觉得浪费，把它接回来"。矛盾数若降到 0，说明
     数据源变了，那时才该重新评估 —— 而不是现在假设它可用。
  3. **C 与 Python 一致**。C 表由 gen_profiles 独立生成。
  4. **实采背书与推断分得清**。移动端没有真机采集，必须标成推断；哪天补了
     采集再改 —— 但不能默认它等于桌面。

跑：python -m spec.test_header_order
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.h2table import observed                              # noqa: E402
from oracle.headerorder import (ATTESTED, BRAND_ENGINE,          # noqa: E402
                                BROWSER_VALUED, check_consistency,
                                engine_orders, engine_values, order_for,
                                sort_headers, values_for)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 库数据的矛盾数下限。这不是"越少越好"的指标 —— 它是"这批数据不能用"的证据，
# 掉到 0 才是需要重新评估的信号。
MIN_LIB_CONFLICTS = 100


def lib_conflicts(brand):
    orders = [x["header_order"] for (b, _v), hits in observed().items()
              if b == brand for x in hits.values() if x.get("header_order")]
    return len(check_consistency(orders)), len(orders)


def main():
    bad = []

    # 1) 实采按引擎自洽（engine_orders 内部会抛错，这里跑一遍并检查覆盖）
    try:
        orders = engine_orders()
    except Exception as e:
        print(f"实采自洽   失败：{e}", file=sys.stderr)
        return 1
    print(f"实采按引擎自洽   OK（{len(orders)} 个引擎）")
    for eng, (order, who) in sorted(orders.items()):
        print(f"  {eng:9s} {len(order):>2} 个头  ← {', '.join(who)}")
    if set(orders) != {"chromium", "gecko", "webkit"}:
        bad.append(f"引擎覆盖不全：{sorted(orders)} —— 少一个引擎意味着那一族"
                   "浏览器的头顺序没有实采支撑")

    # 2) 库数据仍然不可用
    print("\n库数据的自相矛盾（这是它不能用的证据，不是待修的缺陷）：")
    for brand in ("chrome", "firefox", "safari"):
        n, obs_n = lib_conflicts(brand)
        print(f"  {brand:9s} {obs_n:>3} 条观测 → 矛盾 {n} 处")
        if n < MIN_LIB_CONFLICTS:
            bad.append(f"{brand} 的库数据矛盾降到 {n}（<{MIN_LIB_CONFLICTS}）——"
                       "数据源变了？重新评估它能不能用，别默认还不能用")

    # 3) C 与 Python 一致
    src = "\n".join(f"{b}" for b in sorted(BRAND_ENGINE))
    exe = os.path.join(ROOT, "csrc", "hdrcli")
    r = subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "csrc"),
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0 or not os.path.exists(exe):
        bad.append(f"C 侧没构建出来：{(r.stderr or r.stdout)[-120:]}")
        n_ok = 0
    else:
        out = subprocess.run([exe], input=src, capture_output=True,
                             text=True, timeout=60).stdout.splitlines()
        n_ok = 0
        for brand, line in zip(sorted(BRAND_ENGINE), out):
            got_order, _, got_att = line.partition("\t")
            want_order, want_att = order_for(brand)
            if got_order.split(",") != want_order:
                bad.append(f"{brand}: C 的顺序与 Python 不一致")
            elif (got_att == "1") != want_att:
                bad.append(f"{brand}: C 的实采背书标记与 Python 不一致")
            else:
                n_ok += 1
        print(f"\nC/Python 一致   {n_ok}/{len(BRAND_ENGINE)}")

    # 4) 实采背书与推断分得清
    inferred = [b for b in BRAND_ENGINE if b not in ATTESTED]
    print(f"\n实采背书 {len(ATTESTED)} 个品牌，按引擎推断 {len(inferred)} 个")
    if not all(b.endswith("-mobile") or b.startswith("opera") for b in inferred):
        bad.append(f"推断集合里出现了意料外的品牌：{sorted(inferred)}")
    if any(b in ATTESTED for b in BRAND_ENGINE if b.endswith("-mobile")):
        bad.append("有移动端品牌被标成实采背书 —— 本项目的真机采集都是桌面，"
                   "标错会让调用方以为那份顺序是采到的")

    # 头取值：只收由浏览器决定的那几项，且同引擎的多份采集必须一致
    try:
        vals = engine_values()
        print(f"\n引擎级头取值   {len(vals)} 个引擎 × {len(BROWSER_VALUED)} 项")
        for eng, kv in sorted(vals.items()):
            print(f"  {eng:9s} accept-encoding = {kv.get('accept-encoding')}")
    except Exception as e:
        bad.append(f"引擎级头取值不自洽：{e}")
        vals = {}
    # WebKit 与另外两家在 accept-encoding 上必须不同 —— 这是实测到的判别位，
    # 哪天它们一样了，说明数据或采集变了，得重新看。
    if vals:
        enc = {e: kv.get("accept-encoding") for e, kv in vals.items()}
        if len({v for v in enc.values() if v}) < 2:
            bad.append(f"三个引擎的 accept-encoding 全一样了：{enc} —— "
                       "实测里 WebKit 是 gzip, deflate 而另两家带 br/zstd，"
                       "变成一样说明采集或归类出了问题")
    # accept-language 绝不能进表：它是系统 locale，不是浏览器属性
    if "accept-language" in BROWSER_VALUED:
        bad.append("accept-language 被列进了浏览器决定的头 —— 它取决于系统"
                   "locale，抄进去会把采集环境泄漏出去")
    if any("accept-language" in values_for(b) for b in BRAND_ENGINE):
        bad.append("表里出现了 accept-language")

    # 采集污染必须写在 golden 里、且必须与实际使用的字段不相交。
    # 无头 Chrome 的 user-agent 是 HeadlessChrome/…，accept-language 是新
    # profile 的 locale —— 拿它们当真值会把采集环境泄漏出去。实测（同机
    # 有头 vs 无头逐字段比）污染只有这三项，而它们都不在我们用的表里。
    with open(os.path.join(HERE, "golden", "headers_real.json")) as f:
        note = json.load(f).get("_capture_note")
    if not note:
        bad.append("headers_real.json 里没有 _capture_note —— "
                   "采集是无头的，不写清污染范围，后来人会当成真实 UA 用")
    else:
        polluted = set(note.get("headless_contaminates") or [])
        if not polluted:
            bad.append("_capture_note 说无头没有污染任何字段 —— 与实测不符")
        # **污染的是取值，不是位置**。头顺序表存的是头名，user-agent 的位置
        # 本身没被污染（实测：有头与无头的交集顺序完全一致）。所以只查
        # "我们取值的那几项"有没有被污染，不查头名是否出现在顺序里 ——
        # 第一版查了后者，把三条正常的顺序全判成有问题。
        overlap = polluted & set(BROWSER_VALUED)
        if overlap:
            bad.append(f"我们取值的字段里有被无头污染的：{sorted(overlap)}")
        if "user-agent" not in polluted:
            bad.append("污染清单里没有 user-agent —— 无头 Chrome 发的是 "
                       "HeadlessChrome/…，这条必须记着，否则会被当真实 UA 用")
        same = set(note.get("headless_identical") or [])
        if not any("顺序" in x for x in same):
            bad.append("_capture_note 没记录\"顺序不受无头影响\"这条实测 —— "
                       "头顺序正是从这类采集来的，它受不受影响必须有据")
        print(f"\n采集污染范围   {sorted(polluted)}（都不在取值表里）")

    # 排序行为：认识的排到位、不认识的留在最后
    got = sort_headers("firefox", ["Accept-Encoding", "User-Agent", "X-Custom",
                                   "Accept"])
    if got != ["User-Agent", "Accept", "Accept-Encoding", "X-Custom"]:
        bad.append(f"sort_headers 结果不对：{got}")

    for b in bad:
        print(f"  ✗ {b}")
    print(f"\n{'头顺序层可信' if not bad else f'{len(bad)} 处问题'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
