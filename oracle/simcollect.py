"""iOS 模拟器里的 Safari 真机采集：TLS / h2 / 请求头三层。

移动端此前一份实采都没有，`headers_real.json` 里"移动端与桌面大概率相同"那句
猜测**方向整个是反的**：iOS Safari 与 macOS Safari 的 h2 与头序在四个轴上同时
不同（SETTINGS 顺序、WINDOW_UPDATE、伪头序、普通头序），而 TLS 层反倒完全相同。
没有实采就看不出这种"一层同、另一层不同"的分裂。

**模拟器算不算真机，本模块不做假设，靠交叉验证回答**：采到的 h2 指纹与
curl_cffi / tls_client / wreq 三家独立库记录的 Safari iOS 17 逐字节一致，TLS 的
JA4 与 `curl_cffi:safari172_ios` 完全相同。三家各自采自真机的数据同时对上，
模拟器假象解释不了。`--verify` 就是把这件事重跑一遍。

三个操作上的要点，都是踩出来的：

  1. **CA 只装进模拟器**。`simctl keychain add-root-cert` 影响的是那台模拟器，
     不碰用户钥匙串 —— 桌面 Safari 采集当年要改用户信任设置，那是侵入性操作，
     所以一直没做。
  2. **nosni 版靠改用 IP 访问拿到**，不是事后把 SNI 扩展删掉。注册表统一用
     nosni 版；删字节是合成，不是采集。
  3. **h3 采不到，且原因不是证书**。装好 CA 之后实测：Alt-Svc 送达、页面被加载
     47 次、UDP 数据报 **0 个** —— iOS Safari 根本不发起 QUIC。把"缺证书信任"
     当成剩余障碍会让人朝已经解决的方向再走一遍。

跑：
    python -m oracle.simcollect --list              # 可用的模拟器
    python -m oracle.simcollect --tls               # 采 ClientHello（nosni）
    python -m oracle.simcollect --h2                # 采 h2 开场
    python -m oracle.simcollect --headers           # 采请求头顺序（h1 口径）
    python -m oracle.simcollect --verify            # 与已入库的 golden 逐字段比
"""

import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "..", "spec", "golden")
CA = os.path.join(HERE, "..", "spec", "certs", "ca.pem")

# golden 里这两条的标签
TLS_LABEL = H2_LABEL = "safari-ios"


def devices():
    """已启动的 iOS 模拟器 [(udid, 名字)]。"""
    out = subprocess.run(["xcrun", "simctl", "list", "devices"],
                         capture_output=True, text=True, timeout=60).stdout
    found = []
    for line in out.splitlines():
        m = re.match(r"\s+(.+?)\s+\(([0-9A-F-]{36})\)\s+\(Booted\)", line)
        if m:
            found.append((m.group(2), m.group(1)))
    return found


def pick(udid=None):
    devs = devices()
    if udid:
        return udid
    if not devs:
        raise SystemExit("没有已启动的模拟器；先 xcrun simctl boot <udid>")
    return devs[0][0]


def trust_ca(udid):
    """把测试 CA 装进**这台模拟器**的信任库。用户钥匙串不受影响。"""
    subprocess.run(["xcrun", "simctl", "keychain", udid, "add-root-cert", CA],
                   check=True, timeout=60)


def open_url(udid, url):
    subprocess.run(["xcrun", "simctl", "openurl", udid, url],
                   check=True, timeout=60)


def collect_tls(udid, port=8771):
    """ClientHello。**用 IP 访问**，Safari 因此不发 SNI —— 注册表要的就是这个口径。"""
    from oracle.clienthello import fingerprint
    from oracle.sniffer import ClientHelloSniffer
    with ClientHelloSniffer(host="0.0.0.0", port=port) as s:
        open_url(udid, f"https://127.0.0.1:{port}/")
        fp = fingerprint(s.pop(timeout=180))
    fp.pop("extension_bodies", None)
    return fp


def collect_h2(udid, port=8772):
    """h2 开场。走 localhost（证书 SAN 里有），CA 已装进模拟器。"""
    from oracle.h2probe import H2Probe
    with H2Probe(host="0.0.0.0", port=port) as p:
        open_url(udid, f"https://localhost:{port}/")
        return p.pop(timeout=180)


def collect_headers(udid, port=8773):
    """请求头顺序（明文 h1 口径）。h2 那份的顺序在 collect_h2 里已经有了 ——
    这条用来交叉核对：两者只该差 `connection` 与 `upgrade-insecure-requests`
    这类协议/scheme 相关项，桌面 Safari 上实测正是如此。"""
    import threading

    from oracle.hdrcollect import collect
    # collect() 会阻塞等请求，所以先排一个定时器去开 URL。iOS 模拟器直连宿主
    # 回环即可（安卓模拟器才要走 10.0.2.2）。
    threading.Timer(2.0, lambda: open_url(udid, f"http://127.0.0.1:{port}/")).start()
    return collect(port=port, timeout=180)


def verify():
    """把已入库的 iOS golden 与库数据交叉核对一遍 —— 模拟器有效性的复验。

    不重新采集：重采要人盯着模拟器，而这条要能在门禁里跑。它验的是
    "入库的那份仍然与三家独立库一致"，也就是当初判定模拟器有效的那条依据
    还成立。哪天库更新了、或者 golden 被改了，这里会红。
    """
    from oracle.h2table import observed
    bad = []
    with open(os.path.join(GOLDEN, "h2_real_browsers.json")) as f:
        h2g = json.load(f).get(H2_LABEL)
    if not h2g:
        return [f"h2_real_browsers.json 里没有 {H2_LABEL}"]

    obs = observed()
    major = int(float(h2g["version"]))
    hits = obs.get(("safari-mobile", major), {})
    agree = [k for k, v in hits.items()
             if v["akamai_fingerprint"] == h2g["akamai_fingerprint"]
             and not k.startswith("real:")]
    libs = {k.split(":", 1)[0] for k in agree}
    if len(libs) < 3:
        bad.append(f"h2：只有 {sorted(libs)} 与实采一致（要 ≥3 家独立库）—— "
                   "当初判定模拟器有效靠的就是三家同时对上，这条依据没了")

    with open(os.path.join(GOLDEN, "real_browsers.json")) as f:
        tlsg = json.load(f).get(TLS_LABEL)
    if not tlsg:
        return bad + [f"real_browsers.json 里没有 {TLS_LABEL}"]
    with open(os.path.join(HERE, "..", "spec", "profiles.json")) as f:
        registry = json.load(f)
    ja4 = tlsg["fingerprint"]["ja4"]
    # **按采到的版本精确选比对对象**。第一版写的是"任何带 ios 的 curl_cffi
    # Safari 别名"，结果抓到的是 iOS 18 那条，报"JA4 不再相同" —— 而那本来就
    # 该不同。比对对象挑错，看起来和真的回归一模一样。
    want = re.compile(rf"^curl_cffi:safari{major}\d*_ios$")
    same = [r for r in registry
            if any(want.match(a) for a in [r["id"]] + list(r.get("aliases") or []))]
    if not same:
        bad.append(f"TLS：注册表里找不到 curl_cffi 的 Safari iOS {major} 条目，"
                   "无法交叉核对")
    else:
        from oracle.chbuild import build_client_hello
        from oracle.clienthello import fingerprint
        got = fingerprint(build_client_hello(same[0]["tls"], sni=None))["ja4"]
        if got != ja4:
            bad.append(f"TLS：实采 JA4 {ja4} 与 {same[0]['id']} 的 {got} 不再相同")
    print(f"  h2  与 {len(agree)} 条库记录一致（{len(libs)} 家独立库）")
    print(f"  TLS JA4 {ja4}"
          + ("" if bad else f"，与 {same[0]['id']} 相同"))
    return bad


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--udid")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--h2", action="store_true")
    ap.add_argument("--headers", action="store_true")
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args(argv[1:])

    if args.list:
        for udid, name in devices():
            print(f"  {udid}  {name}")
        if not devices():
            print("  （没有已启动的模拟器）")
        return 0

    if args.verify:
        bad = verify()
        for b in bad:
            print(f"  ✗ {b}")
        print("\n" + ("模拟器采集的交叉验证仍成立" if not bad
                      else f"{len(bad)} 处问题"))
        return 1 if bad else 0

    if not (args.tls or args.h2 or args.headers):
        ap.print_help()
        return 2

    udid = pick(args.udid)
    trust_ca(udid)
    print(f"设备 {udid}\n")
    if args.tls:
        print(json.dumps(collect_tls(udid), ensure_ascii=False, default=str))
    if args.h2:
        print(json.dumps(collect_h2(udid), ensure_ascii=False))
    if args.headers:
        rec = collect_headers(udid)
        print(json.dumps(rec, ensure_ascii=False) if rec else "超时")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
