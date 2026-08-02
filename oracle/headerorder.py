"""请求头的相对顺序 —— 伪装的第三层，**只认真机实采**。

TLS 与 h2 都伪装对了，请求头却按自己的顺序发，照样能被判：头顺序是各引擎稳定
且互不相同的特征。

**库里的 header_order 不能用**。四家库文件里有 240 条带 `header_order`，看着
是现成的数据，实际上是**各库自己的发头顺序**，不是浏览器的 —— 把所有观测当成
偏序约束一检验就露馅：

```
chrome         79 条观测 → 顺序矛盾 398 处
               curl_cffi:chrome100 说 sec-fetch-dest 在 sec-fetch-mode 前，
               wreq:Chrome100 说反过来
firefox        33 条观测 → 矛盾 183 处
safari         28 条观测 → 矛盾 203 处
```

同一个浏览器同一个版本，两家库给出互相矛盾的顺序 —— 那不可能都是浏览器的行为。
用它等于抄某家库的建模，正是本项目一直在防的事。

**实采则是干净的**：Chrome 151 / Chromium 142 / Edge 151 三份的顺序**完全相同**
（同一个 Chromium 引擎，相隔 9 个大版本也没变），Firefox 149 与 Safari 27 各自
不同。所以这一层按**引擎**建模，不按版本。

**为什么按相对顺序而不是固定列表**：实际发哪些头由请求类型决定（导航请求有
`upgrade-insecure-requests` 与 `sec-fetch-user`，子资源请求没有），库数据里那些
"品牌差异"多半就是请求类型不同造成的。调用方自己决定发哪些头，本模块只回答
"这些头之间谁在前" —— 这个关系在实采里跨版本稳定。

跑：python -m oracle.headerorder
"""

import itertools
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.path.join(HERE, "..", "spec", "golden", "h2_real_browsers.json")

# 实采条目名 → 引擎。Edge 与 Chromium 归一到同一个引擎是**实采支持的**：
# 三份采集的头顺序逐项相同。Opera 没有实采，只能跟着 Chromium 走 —— 这是
# 推断而非实证，`engine_of()` 会把它标出来。
CAPTURE_ENGINE = {
    "chrome": "chromium", "chromium": "chromium", "edge": "chromium",
    "firefox": "gecko", "safari": "webkit",
}

BRAND_ENGINE = {
    "chrome": "chromium", "chrome-mobile": "chromium",
    "edge": "chromium", "edge-mobile": "chromium",
    "opera": "chromium", "opera-mobile": "chromium",
    "firefox": "gecko", "firefox-mobile": "gecko",
    "safari": "webkit", "safari-mobile": "webkit",
}

# 有实采背书的品牌；其余是按引擎推断的。
# **移动端一个都没有**：本项目的真机采集全是桌面浏览器。移动端的头名与顺序
# 大概率与桌面相同（sec-ch-ua-mobile 变的是值不是名），但"大概率"不是实证 ——
# 标成推断，调用方有权知道这个区别。
ATTESTED = {"chrome", "edge", "firefox", "safari"}


def _load():
    with open(REAL) as f:
        return json.load(f)


def engine_orders(real=None):
    """{引擎: (顺序, [来源...])}；同引擎内若有矛盾则抛错。"""
    real = real or _load()
    real = {k: v for k, v in real.items() if not k.startswith("_")}
    by_engine = {}
    for name, rec in real.items():
        eng = CAPTURE_ENGINE.get(name)
        order = rec.get("header_order")
        if not eng or not order:
            continue
        by_engine.setdefault(eng, []).append((name, rec.get("version"), order))

    out = {}
    for eng, rows in by_engine.items():
        bad = check_consistency([o for _, _, o in rows])
        if bad:
            raise ValueError(f"{eng} 的实采内部顺序矛盾：{bad[:3]} —— "
                             "同一个引擎不该给出互相矛盾的顺序，"
                             "先查是不是把不同引擎的采集归到一起了")
        # 取覆盖头名最多的那份作代表；其余是它的子序列（上面已验过不矛盾）
        rows.sort(key=lambda r: -len(r[2]))
        out[eng] = (list(rows[0][2]), [f"{n} {v}" for n, v, _ in rows])
    return out


def check_consistency(orders):
    """把每条顺序当成偏序约束，返回互相矛盾的头名对。"""
    seen, bad = {}, []
    for order in orders:
        for a, b in itertools.combinations(order, 2):
            if (b, a) in seen:
                bad.append((a, b))
            seen.setdefault((a, b), True)
    return bad


# 由**浏览器**决定、调用方不该自己编的头。其余的一律不进表：
#   accept-language  取决于系统 locale 与用户设置，不是浏览器属性 ——
#                    本次采集里 Firefox 显示 zh-CN 而其它是 en-US，那是新建
#                    profile 取 locale 的差异，把它当指纹抄会把采集环境泄漏出去
#   sec-fetch-*      取决于请求类型（导航/子资源/XHR），调用方比我们清楚
#   cookie / referer 请求上下文
BROWSER_VALUED = ("accept", "accept-encoding", "upgrade-insecure-requests")

# upgrade-insecure-requests **不是纯浏览器属性，它看目标协议**。实测两份采集：
#
#   明文 HTTP（本轮 localhost 采集）   五个浏览器全发
#   HTTPS/h2（h2_real_browsers.json）  Chromium 与 Gecko 发，**WebKit 不发**
#
# 本项目的伪装出网是 HTTPS，所以 WebKit 那侧必须不发。把它当成固定值会让
# Safari 伪装多出一个真 Safari 在 https 上不会发的头 —— 与 UA-CH 那条
# "多发也是异常"同一类问题。
SCHEME_DEPENDENT = {("webkit", "https"): {"upgrade-insecure-requests"}}

REALHDR = os.path.join(HERE, "..", "spec", "golden", "headers_real.json")


def engine_values(path=None):
    """{引擎: {头名: 取值}}，只收 BROWSER_VALUED 里那几项。

    同引擎的多份采集必须一致（chrome/chromium/edge 同属 Chromium）——
    不一致说明这一项其实不由浏览器决定，不该留在表里。
    """
    with open(path or REALHDR) as f:
        real = json.load(f)
    real = {k: v for k, v in real.items() if not k.startswith("_")}
    out, bad = {}, []
    for name, rec in real.items():
        eng = CAPTURE_ENGINE.get(name)
        if not eng:
            continue
        hdrs = dict(rec["headers"])
        for k in BROWSER_VALUED:
            if k not in hdrs:
                continue
            cur = out.setdefault(eng, {})
            if k in cur and cur[k] != hdrs[k]:
                bad.append(f"{eng} 的 {k} 在两份采集里不同：{cur[k]!r} vs {hdrs[k]!r}")
            cur[k] = hdrs[k]
    if bad:
        raise ValueError("；".join(bad) + " —— 这一项其实不由浏览器决定，"
                         "不该留在 BROWSER_VALUED 里")
    return out


def values_for(brand, scheme="https"):
    """该品牌在指定协议下由浏览器决定的头取值。

    默认 https —— 这条链的出网就是 https，拿明文 HTTP 的采集去填 https 请求
    是上下文错配（正是 upgrade-insecure-requests 那个坑）。
    """
    eng = BRAND_ENGINE.get(brand)
    if not eng:
        return {}
    vals = dict(engine_values().get(eng, {}))
    for name in SCHEME_DEPENDENT.get((eng, scheme), ()):
        vals.pop(name, None)
    return vals


def order_for(brand, real=None):
    """(顺序, 是否有该品牌的实采背书)。品牌不认识返回 (None, False)。"""
    eng = BRAND_ENGINE.get(brand)
    if not eng:
        return None, False
    orders = engine_orders(real)
    if eng not in orders:
        return None, False
    return orders[eng][0], brand in ATTESTED


def sort_headers(brand, names):
    """按该品牌的引擎顺序排调用方给的头名；顺序里没有的排在最后（保持原序）。

    **不认识的头名不能丢掉**，也不能塞到中间：调用方比我们更清楚它要发什么，
    本模块只负责把认识的那些摆到对的位置。
    """
    order, _ = order_for(brand)
    if not order:
        return list(names)
    pos = {h: i for i, h in enumerate(order)}
    known = [h for h in names if h.lower() in pos]
    unknown = [h for h in names if h.lower() not in pos]
    known.sort(key=lambda h: pos[h.lower()])
    return known + unknown


def main(argv):
    orders = engine_orders()
    for eng, (order, who) in sorted(orders.items()):
        print(f"  {eng:10s} ({', '.join(who)})")
        print(f"     {order}")
    print("\n  品牌 → 引擎：")
    for brand in sorted(BRAND_ENGINE):
        order, attested = order_for(brand)
        print(f"    {brand:16s} {BRAND_ENGINE[brand]:9s} "
              f"{'实采背书' if attested else '按引擎推断'}  {len(order or [])} 个头")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
