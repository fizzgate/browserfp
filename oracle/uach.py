"""从 Chromium 源码推 `sec-ch-ua` —— 它是纯粹的版本函数，猜不出来。

伪装的三层（TLS / h2 开场 / 头顺序）都对了之后，头的**取值**就是下一道。
`sec-ch-ua` 尤其要命：它里面有一个按主版本号确定性生成的 GREASE 品牌，
既不是固定串也不是随机串 —— 手写一个必然对不上，而它就摆在请求头里。

算法全在 `components/embedder_support/user_agent_utils.cc`，且**只依赖主版本号**：

```
greasey_chars = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"]   11 个
greasey_brand = "Not" + chars[seed % 11] + "A" + chars[(seed+1) % 11] + "Brand"
greasey_ver   = ["8", "99", "24"][seed % 3]
列表          = [greasey, {"Chromium", v}, {品牌, v}]
顺序          = GetRandomOrder(seed, 3) = orders[seed % 6]，其中
                orders = [[0,1,2],[0,2,1],[1,0,2],[1,2,0],[2,0,1],[2,1,0]]
洗牌          = shuffled[order[i]] = list[i]      ← **散射不是收集**
```

最后一行容易写反：源码是 `shuffled_brand_version_list[order[i]] = list[i]`，
即把第 i 项放到 order[i] 的位置，而不是取 order[i] 处的项。写成收集会得到逆置换，
而 orders 里**有一半是自逆的**，于是"一半版本对、一半错"——比全错更难发现。

**这条性质实采验不到**：本机能拿到的三个浏览器主版本是 151（151%6=1 →
`(0,2,1)`，对换两项，自逆）与 142（走两项分支 → `(0,1)`，恒等，也自逆）。
散射与收集在它们身上完全等价 —— 变异测试实证过：把散射改成收集，三条实采
依然 3/3 全绿。要区分得有 `major%6 ∈ {3,4}` 的版本（那两个是三轮换），而
本机既没有、Chrome for Testing 的下载源又连不上。

所以改成**从源码断言赋值方向**：`assert_scatter()` 检查 `ShuffleBrandList`
里下标在赋值号哪一侧。这把一条"实采验不到"的性质变成了"源码变了就会红"。

**先验证再使用**：`spec/test_uach.py` 拿本机三个真实 Chrome（131 / 146 / 151）
实采出来的 sec-ch-ua 比对。没验过之前不接进 C。

跑：python -m oracle.uach [主版本号...]
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.chromiumsrc import (CACHE, JSD, SKIPPED_MILESTONES,  # noqa: E402
                                _get, version_index)

SRC = "components/embedder_support/user_agent_utils.cc"

# 品牌名：Chromium 构建叫 Chromium，正式发行版另有一个品牌名。
# Edge/Opera 虽然也是 Chromium，但它们的 sec-ch-ua 用自己的品牌串，
# 且额外品牌怎么排由各自的嵌入层决定 —— 本模块只推 Chrome。
BRAND = "Google Chrome"


def _src(major):
    if major in SKIPPED_MILESTONES:
        raise LookupError(f"Chrome M{major} 从未发布")
    index = version_index()
    if major not in index:
        raise KeyError(f"M{major} 不在版本索引里")
    last = None
    for tag in reversed(index[major][-4:]):
        try:
            return _get(f"{JSD}/chromium/chromium@{tag}/{SRC}",
                        os.path.join(CACHE, tag, SRC.replace("/", "_")))
        except Exception as e:
            last = e
    raise last


def _greasey_chars(text):
    """从源码里抠出 GREASE 字符表，不写死。

    这张表改过一次（早期版本没有 `_`），写死会在老版本上算错，而错法是
    "只有部分版本对"，最难发现。
    """
    m = re.search(r"greasey_chars\s*=\s*\{(.*?)\}", text, re.S)
    if not m:
        raise LookupError("源码里找不到 greasey_chars —— 表改名或搬家了")
    return re.findall(r'"([^"]*)"', m.group(1))


def _greased_versions(text):
    m = re.search(r"greased_versions\s*=\s*\{(.*?)\}", text, re.S)
    if not m:
        raise LookupError("源码里找不到 greased_versions")
    return re.findall(r'"([^"]*)"', m.group(1))


def _orders3(text):
    """GetRandomOrder 里 size==3 那张置换表。

    **老版本是另一套算法**：M131 里 GetRandomOrder 根本不存在，GREASE 品牌由
    `permuted_order` 外部传入，还带 Finch 参数与企业策略开关。那时的形态没在
    这里实现 —— 按项目规矩弃权，不猜。
    """
    # 两种代码形态，**算法实质相同**：
    #   132 起   GetRandomOrder() 里 std::array<std::array<size_t,3>,6> orders
    #   ~131 及前 GenerateBrandVersionList() 里内联的
    #            std::vector<std::vector<int>> orders
    # 表内容、seed%6 的取法、散射赋值都一字不差 —— 只是代码搬了家。
    # 第一版只认前者，于是把 120-131 整段判成"不支持"，而它们其实推得出来。
    for pat in (r"std::array<std::array<size_t,\s*3>,\s*\d+>\s*orders\s*\{(.*?)\}\};",
                r"std::vector<std::vector<int>>\s*orders\{(.*?)\};"):
        m = re.search(pat, text, re.S)
        if m:
            nums = [int(x) for x in re.findall(r"\d+", m.group(1))]
            if len(nums) % 3 == 0 and nums:
                return [tuple(nums[i:i + 3]) for i in range(0, len(nums), 3)]
    raise LookupError("认不出置换表的形态 —— 两种已知写法都没匹配上，"
                      "不能默认还是那 6 个置换")


def assert_scatter(text):
    """确认源码里的洗牌是散射（下标在左）而不是收集（下标在右）。

    实采区分不了这两者（见模块头），所以只能盯着源码本身。哪天 Chromium 把
    这句改成 `shuffled[i] = list[order[i]]`，本函数会报错，提醒去翻转实现 ——
    而不是等着某些版本静默算错。
    """
    i = text.find("ShuffleBrandList")
    if i >= 0:
        body = text[i:i + 1200]
        if re.search(r"(\w+)\[(\w+)\[i\]\]\s*=\s*(\w+)\[i\]", body):
            return True                  # shuffled[order[i]] = list[i]，散射
        if re.search(r"(\w+)\[i\]\s*=\s*(\w+)\[(\w+)\[i\]\]", body):
            raise LookupError("ShuffleBrandList 改成了收集 —— 散射实现要翻转")
        raise LookupError("认不出 ShuffleBrandList 的赋值形态")
    # 老形态：GenerateBrandVersionList 里直接写
    #   greased_brand_version_list[order[0]] = greasey_bv;  ...
    # 同样是散射（下标在左），只是没有独立的洗牌函数。
    # **全局搜而不是从 GenerateBrandVersionList 起搜**：那个名字第一次出现
    # 往往是前向声明，离定义很远，按它开窗会整段错过。
    if re.search(r"\w+\[order\[\d\]\]\s*=\s*\w+", text):
        return True
    raise LookupError("既没有 ShuffleBrandList，也认不出内联的散射赋值")


def sec_ch_ua(major, brand=BRAND, full_version=None):
    """返回 sec-ch-ua 的值（主版本形式，除非给了 full_version）。

    `brand=None` 表示 CHROMIUM_BRANDING 构建（就是 Chromium.app 本身）：
    源码里 `brand` 是 optional，为空时列表只有 greasey + Chromium 两项，
    走 `GetRandomOrder` 的 size==2 分支。本机 Chromium 142 的实采正好验到
    这条 —— 只按三项实现的话，Chromium 构建会多出一个不存在的品牌。
    """
    text = _src(major)
    chars = _greasey_chars(text)
    gvers = _greased_versions(text)
    orders = _orders3(text)
    assert_scatter(text)

    ver = full_version or str(major)
    greasey_brand = (f"Not{chars[major % len(chars)]}A"
                     f"{chars[(major + 1) % len(chars)]}Brand")
    items = [(greasey_brand, gvers[major % len(gvers)]), ("Chromium", ver)]
    if brand:
        items.append((brand, ver))

    if len(items) == 2:
        # size==2 时源码直接返回 {seed % 2, (seed + 1) % 2}，没有置换表
        order = (major % 2, (major + 1) % 2)
    else:
        order = orders[major % len(orders)]
    shuffled = [None] * len(items)
    for i, item in enumerate(items):
        shuffled[order[i]] = item        # 散射：第 i 项放到 order[i]
    return ", ".join(f'"{b}";v="{v}"' for b, v in shuffled)


# 品牌 → sec-ch-ua 里的品牌串。
#   chrome / edge  有本机实采背书
#   opera          **不推**：Opera 的嵌入层会往列表里再加自己的品牌项，
#                  而本项目没有 Opera 实采，加几项、叫什么名字都只能猜
# 移动端与桌面**同值**：GetUserAgentBrandList 生成品牌列表时不分平台，
# 平台差异体现在另一个头（sec-ch-ua-mobile）上。这是源码结构，不是推测。
UACH_BRANDS = {
    "chrome": "Google Chrome", "chrome-mobile": "Google Chrome",
    "edge": "Microsoft Edge", "edge-mobile": "Microsoft Edge",
}


def build(dest=None):
    """算出 {品牌: {版本: sec-ch-ua}}，落成 JSON 供 C 生成器与门禁共用。

    与 h2table 同样的理由：推导要联网取 Chromium 源码，C 的构建流程不该依赖
    网络；落成文件也便于 diff。
    """
    from oracle.covscan import NEVER_RELEASED, TARGETS
    out = {}
    for brand, brand_str in UACH_BRANDS.items():
        _tpl, lo, hi = TARGETS[brand]
        skip = NEVER_RELEASED.get(brand, set())
        rows = {}
        for v in range(lo, hi + 1):
            if v in skip:
                continue
            try:
                rows[str(v)] = sec_ch_ua(v, brand_str)
            except Exception:
                continue                 # 算不出就不写，不猜
        out[brand] = rows
    if dest:
        with open(dest, "w") as f:
            json.dump(out, f, indent=1, ensure_ascii=False, sort_keys=True)
            f.write("\n")
    return out


def main(argv):
    if "--build" in argv:
        dest = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "spec", "uach.json")
        t = build(dest)
        print("  已写出：" + "  ".join(f"{b}={len(v)}" for b, v in sorted(t.items())))
        return 0
    majors = [int(x) for x in argv[1:] if not x.startswith("-")] or [131, 146, 151]
    for m in majors:
        try:
            print(f"  M{m:<4} {sec_ch_ua(m)}")
        except Exception as e:
            print(f"  M{m:<4} ✗ {type(e).__name__}: {str(e)[:70]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
