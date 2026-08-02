"""在**真实 OpenResty worker** 里验证 C 模块，而不是裸 luajit。

这是生产实际运行的形态。此前 test_lua_parity / test_lua_ua_parity 用的是本机
luajit，它们能验 FFI 绑定的语义，但验不到两件只有真 OpenResty 才暴露的事：

  1. **平台/ABI 匹配** —— 本机编译的 libtlsfp.so 是 macOS 的 Mach-O，挂进 Linux
     容器直接 `invalid ELF header`。生产跑在 Linux 上，而这条链此前从未在 Linux
     编译并加载过。
  2. **在 nginx worker 内加载** —— lua_package_path、FFI 加载时机、worker 生命
     周期都与命令行跑脚本不同。

做法：用 gcc 容器编译出 Linux 版 .so，挂进 openresty 容器，起一个把
`tlsfp.by_ua()` 与 `tlsfp.client_hello()` 暴露成 HTTP 接口的 worker，逐版本与
Python 比对。

**两个入口都要验**：by_ua 只走查表，client_hello 还要走 resty.random 与 FFI 的
输出缓冲 —— 后者才是 cosocket 实际要调的那个，而它在裸 luajit 上会退回
math.random，那条强随机路径只有真 worker 里才走得到。

**需要 docker**，没有就跳过（非失败）—— 这条门禁的前提是能起容器，而不是所有
环境都有。

跑：python -m spec.test_openresty
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.covscan import NEVER_RELEASED, TARGETS            # noqa: E402
from oracle.uamap import UAMapper                             # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PORT = 18081                      # 与手工调试用的 18080 错开
CONTAINER = "tlsfp-openresty-gate"
GCC_IMAGE = "gcc:12-bookworm"
ORTY_IMAGE = "openresty/openresty:bookworm"

NGINX_CONF = """worker_processes 1;
error_log /dev/stderr warn;
events { worker_connections 128; }
http {
    lua_package_path "/app/lua/?.lua;;";
    server {
        listen 8080;

        location /by_ua {
            content_by_lua_block {
                local tlsfp = require "tlsfp"
                tlsfp.load("/app/csrc/libtlsfp.so")
                local a = ngx.req.get_uri_args()
                local r, err, conf = tlsfp.by_ua(a.brand, tonumber(a.version))
                if r then
                    ngx.say(r.id .. "\\t" .. r.confidence)
                else
                    ngx.say("-\\t" .. tostring(conf))
                end
            }
        }

        location /h2 {
            content_by_lua_block {
                local tlsfp = require "tlsfp"
                tlsfp.load("/app/csrc/libtlsfp.so")
                local a = ngx.req.get_uri_args()
                local rec, pseudo = tlsfp.h2_preface(a.brand, tonumber(a.version))
                if not rec then
                    ngx.say("ERR\\t" .. tostring(pseudo))
                else
                    local hex = rec:gsub(".", function(c)
                        return string.format("%02x", string.byte(c))
                    end)
                    ngx.say(tostring(pseudo) .. "\\t" .. hex)
                end
            }
        }

        location /coh {
            content_by_lua_block {
                local tlsfp = require "tlsfp"
                tlsfp.load("/app/csrc/libtlsfp.so")
                local a = ngx.req.get_uri_args()
                -- 全部三层都由库自己产出，再交给库自审
                local prof = tlsfp.by_ua(a.brand, tonumber(a.version))
                local _, ak = nil, nil
                local rec, pseudo = tlsfp.h2_preface(a.brand, tonumber(a.version))
                local h2 = tlsfp.identify_h2(a.akamai or "")
                local order = tlsfp.header_order(a.mix_brand or a.brand)
                local v, e = tlsfp.coherence(prof and prof.ja4 or nil,
                                             a.akamai, order)
                ngx.say(v .. "\\t" .. tostring(e.tls) .. "\\t"
                        .. tostring(e.h2) .. "\\t" .. tostring(e.headers)
                        .. "\\t" .. tostring(h2 and h2.engine))
            }
        }

        location /hdr {
            content_by_lua_block {
                local tlsfp = require "tlsfp"
                tlsfp.load("/app/csrc/libtlsfp.so")
                local a = ngx.req.get_uri_args()
                local order, att = tlsfp.header_order(a.brand)
                local enc = tlsfp.header_value(a.brand, "accept-encoding")
                local uach = tlsfp.sec_ch_ua(a.brand, tonumber(a.version))
                local plat, mob = tlsfp.ua_platform(a.ua or "")
                ngx.say(table.concat(order or {}, ",") .. "\\t"
                        .. tostring(att) .. "\\t" .. tostring(enc) .. "\\t"
                        .. tostring(uach) .. "\\t" .. tostring(plat)
                        .. "\\t" .. tostring(mob))
            }
        }

        location /client_hello {
            content_by_lua_block {
                local tlsfp = require "tlsfp"
                tlsfp.load("/app/csrc/libtlsfp.so")
                local a = ngx.req.get_uri_args()
                local rec, prof = tlsfp.client_hello(a.brand, tonumber(a.version), a.sni)
                if not rec then
                    ngx.say("ERR\\t" .. tostring(prof))
                else
                    local hex = rec:gsub(".", function(c)
                        return string.format("%02x", string.byte(c))
                    end)
                    ngx.say(prof.id .. "\\t" .. #rec .. "\\t" .. hex)
                end
            }
        }
    }
}
"""


def _docker_ok():
    return shutil.which("docker") and subprocess.run(
        ["docker", "info"], capture_output=True, timeout=30).returncode == 0


def _build_linux_so(workdir):
    """在 gcc 容器里编译 Linux 版 .so —— 本机的 Mach-O 在 Linux 上加载不了。"""
    # gen_profiles.py 需要的全部东西都要带进去，**包括它 import 的 Python 模块**。
    # 漏一个的表现只有一句"Linux 版 .so 编译失败"，没有更多信息 —— 加
    # h2table.json 那次是这么撞上的，加头顺序/头取值/sec-ch-ua 那几张表时
    # 又撞了一次（这回还多了 oracle/ 与 spec/golden/，因为生成器要 import
    # oracle.headerorder，而它自己又去读 golden）。
    for sub in ("csrc", "lua", "oracle"):
        shutil.copytree(os.path.join(ROOT, sub), os.path.join(workdir, sub),
                        ignore=shutil.ignore_patterns("__pycache__", "go*"))
    os.makedirs(os.path.join(workdir, "spec"), exist_ok=True)
    for name in ("profiles.json", "h2table.json", "uach.json"):
        shutil.copy(os.path.join(HERE, name),
                    os.path.join(workdir, "spec", name))
    for sub in ("segments", "golden"):
        shutil.copytree(os.path.join(HERE, sub),
                        os.path.join(workdir, "spec", sub))
    out = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{workdir}:/w", GCC_IMAGE, "bash", "-c",
         "cd /w/csrc && rm -f *.o *.so *.inc ja4cli uacli lookup_test && "
         "(make libtlsfp.so 2>&1 | tail -3) && file libtlsfp.so"],
        capture_output=True, text=True, timeout=600)
    return "ELF" in out.stdout, out.stdout.strip()[:80]


def _check_client_hello(opener, mapper):
    """在真 worker 里调 client_hello，解析回来与 golden 逐字段比。"""
    import json as _json
    from oracle.clienthello import fingerprint
    from oracle.coverage import FIELDS, SET_FIELDS

    with open(os.path.join(HERE, "profiles.json")) as f:
        by_id = {r["id"]: r for r in _json.load(f)}

    def norm(t, fl):
        v = t.get(fl)
        return sorted(v) if fl in SET_FIELDS and v else v

    bad = []
    for brand, ver in (("chrome", 151), ("firefox", 153),
                       ("safari-mobile", 27), ("chrome-mobile", 134)):
        url = (f"http://127.0.0.1:{PORT}/client_hello?brand={brand}"
               f"&version={ver}&sni=example.com")
        try:
            line = opener.open(url, timeout=20).read().decode().strip()
        except Exception as e:
            bad.append(f"{brand} {ver}: 请求失败 {type(e).__name__}")
            continue
        parts = line.split("\t")
        if len(parts) != 3 or parts[0] == "ERR":
            bad.append(f"{brand} {ver}: worker 返回 {line[:60]}")
            continue
        pid, _n, hexs = parts
        rec = by_id.get(pid)
        if not rec:
            bad.append(f"{brand} {ver}: profile {pid} 不在注册表")
            continue
        try:
            fp = fingerprint(bytes.fromhex(hexs), drop_sni=True)
        except Exception as e:
            bad.append(f"{brand} {ver}: 构造的字节解析失败 {type(e).__name__}")
            continue
        diff = [fl for fl in FIELDS if norm(fp, fl) != norm(rec["tls"], fl)]
        if diff:
            bad.append(f"{brand} {ver}: 与 {pid} 差 {diff[:3]}")
    return bad


def _check_h2(opener):
    """h2 开场也要在真 worker 里验一遍。

    它和 client_hello 一样走 FFI 输出缓冲，而且**必须与 TLS 层同源**：
    两层取自不同 profile 就给出一个现实中不存在的组合。这里顺带断言
    "没有 h2 数据的 profile 确实被拒绝"，那条分支只有真跑才走得到。
    """
    import json as _json
    from spec.test_h2_build import parse_preface

    with open(os.path.join(HERE, "h2table.json")) as f:
        table = _json.load(f)

    bad = []
    # 用例从 h2table 现取，不写死版本号：写死的会随数据变动而失效 ——
    # 上一版挑了 firefox 153，而那个版本恰好没有 h2 数据。
    cases = []
    for brand in ("chrome", "chrome-mobile", "edge", "opera-mobile"):
        rows = sorted(table.get(brand, {}), key=int)
        if rows:
            cases.append((brand, int(rows[-1]), True))
    # 再加一组表里没有的，必须被拒绝
    cases.append(("safari", 12, False))
    for brand, ver, want_ok in cases:
        url = f"http://127.0.0.1:{PORT}/h2?brand={brand}&version={ver}"
        try:
            line = opener.open(url, timeout=20).read().decode().strip()
        except Exception as e:
            bad.append(f"{brand} {ver}: 请求失败 {type(e).__name__}")
            continue
        if not want_ok:
            if not line.startswith("ERR"):
                bad.append(f"{brand} {ver}: 无 h2 数据却构造出了开场")
            continue
        parts = line.split("\t")
        if len(parts) != 2 or parts[0] == "ERR":
            bad.append(f"{brand} {ver}: worker 返回 {line[:60]}")
            continue
        pseudo, hexs = parts
        rec = table.get(brand, {}).get(str(ver))
        if not rec:
            bad.append(f"{brand} {ver}: h2 表里没有这条")
            continue
        try:
            settings, window, prios = parse_preface(bytes.fromhex(hexs))
        except Exception as e:
            bad.append(f"{brand} {ver}: 开场解析失败 {e}")
            continue
        h2 = rec
        if settings != [tuple(x) for x in (h2.get("settings") or [])]:
            bad.append(f"{brand} {ver}: SETTINGS 与 golden 不符")
        if (window or 0) != (h2.get("window_update") or 0):
            bad.append(f"{brand} {ver}: WINDOW_UPDATE 与 golden 不符")
        if prios != [tuple(x) for x in (h2.get("priorities") or [])]:
            bad.append(f"{brand} {ver}: PRIORITY 与 golden 不符")
        want_pseudo = ",".join(k[1] for k in (h2.get("pseudo_header_order") or []))
        if pseudo != want_pseudo:
            bad.append(f"{brand} {ver}: 伪头序 {pseudo} != {want_pseudo}")
    return bad, len(cases)


def _check_headers(opener):
    """四个头层入口也要在真 worker 里验一遍。

    此前它们只在裸 luajit 上跑过，而本项目早有教训：裸 luajit 验得了 FFI
    语义，验不到平台/ABI 匹配与 nginx worker 内的加载 —— 第一次跑
    test_openresty 就是撞在 macOS 的 .so 挂进 Linux 容器上。

    这里另外验一件裸 luajit 上也能错、但只有拼起来才看得出的事：
    `sec_ch_ua` 按 (品牌,版本) 查、`header_order` 按品牌查、`ua_platform`
    按 UA 推 —— 三个口径必须能拼成一个自洽的请求。
    """
    import json as _json
    from oracle.covscan import TARGETS
    from oracle.headerorder import order_for, values_for
    from oracle.uach import platform_hint

    bad, n = [], 0
    for brand in ("chrome", "chrome-mobile", "firefox", "safari"):
        ver = 26 if brand.startswith("safari") else 151
        ua = TARGETS[brand][0].format(v=ver)
        url = (f"http://127.0.0.1:{PORT}/hdr?brand={brand}&version={ver}"
               f"&ua={urllib.parse.quote(ua)}")
        try:
            line = opener.open(url, timeout=20).read().decode().strip()
        except Exception as e:
            bad.append(f"{brand}: 请求失败 {type(e).__name__}")
            continue
        parts = line.split("\t")
        if len(parts) != 6:
            bad.append(f"{brand}: worker 返回 {line[:70]}")
            continue
        got_order, got_att, got_enc, got_uach, got_plat, got_mob = parts
        n += 1

        want_order, want_att = order_for(brand)
        if got_order.split(",") != want_order:
            bad.append(f"{brand}: 头顺序与 Python 不一致")
        if (got_att == "true") != want_att:
            bad.append(f"{brand}: 实采背书标记不一致")
        want_enc = values_for(brand).get("accept-encoding")
        if got_enc != (want_enc or "nil"):
            bad.append(f"{brand}: accept-encoding {got_enc!r} != {want_enc!r}")
        want_plat, want_mob = platform_hint(ua)
        if got_plat != (want_plat or "nil") or got_mob != (want_mob or "nil"):
            bad.append(f"{brand}: 平台提示 ({got_plat},{got_mob}) != "
                       f"({want_plat},{want_mob})")

        # 拼起来必须自洽：Chromium 系有 sec-ch-ua 就必须有平台提示，
        # 非 Chromium 两者都得没有
        is_chromium = brand.split("-")[0] in ("chrome", "edge")
        has_uach = got_uach != "nil"
        if is_chromium != has_uach:
            bad.append(f"{brand}: sec-ch-ua {'不该有却有' if has_uach else '该有却没有'}")
        if has_uach and got_plat == "nil":
            bad.append(f"{brand}: 有 sec-ch-ua 却推不出平台 —— 拼出来的请求会缺头")
    return bad, n


def _check_concurrency(port, rounds=60):
    """并发打不同品牌，每个响应必须属于它自己的请求。

    **模块级缓冲是这里唯一要查的东西**：lua/tlsfp.lua 里有 9 个
    `ffi.new` 出来的模块级缓冲（ch_buf / h2_buf / e1..e3 …），一个 worker
    跑多个协程共用它们。只要写缓冲和读回之间存在让出点，两个请求就会互相串 ——
    而这在单线程测试里**永远看不出来**，本项目此前所有 Lua 验证都是单线程的。

    判据不是"没报错"，是"每个响应的**字节**与它自己的请求对得上"。

    **第一版比错了字段**：比的是响应里的 profile id，而那个 id 来自 Lua 表、
    不在共享缓冲里 —— 串了也不会变。阴性对照（在 build 与 ffi.string 之间插
    一个真让出点）因此照样全绿。改成把返回的字节解析回来、与该品牌应有的指纹
    逐字段比，缓冲被串就一定露馅。
    """
    import concurrent.futures as _cf
    import json as _json
    import urllib.request as _u
    from oracle.clienthello import fingerprint
    from oracle.coverage import FIELDS, SET_FIELDS

    with open(os.path.join(HERE, "profiles.json")) as f:
        by_id = {r["id"]: r for r in _json.load(f)}

    def norm(t, fl):
        v = t.get(fl)
        return sorted(v) if fl in SET_FIELDS and v else v

    cases = [("chrome", 151), ("firefox", 135), ("safari", 26),
             ("chrome-mobile", 132), ("edge", 140)]
    op = _u.build_opener(_u.ProxyHandler({}))

    def one(i):
        brand, ver = cases[i % len(cases)]
        u = (f"http://127.0.0.1:{port}/client_hello?brand={brand}"
             f"&version={ver}&sni=example.com")
        got = op.open(u, timeout=25).read().decode().strip().split("\t")
        return (brand, ver, got)

    bad = []
    with _cf.ThreadPoolExecutor(max_workers=16) as ex:
        for brand, ver, got in ex.map(one, range(rounds)):
            if len(got) != 3:
                bad.append(f"{brand} {ver}: 响应列数 {len(got)}")
                continue
            pid, _n, hexs = got
            rec = by_id.get(pid)
            if not rec:
                bad.append(f"{brand} {ver}: 未知 profile {pid}")
                continue
            try:
                fp = fingerprint(bytes.fromhex(hexs), drop_sni=True)
            except Exception as e:
                bad.append(f"{brand} {ver}: 字节解析失败 {type(e).__name__}")
                continue
            diff = [fl for fl in FIELDS if norm(fp, fl) != norm(rec["tls"], fl)]
            if diff:
                bad.append(f"{brand} {ver}: 并发下拿到的字节与 {pid} 差 "
                           f"{diff[:3]} —— 共享缓冲被别的请求串了")
    return bad, rounds


def _check_coherence(opener):
    """在真 worker 里跑库的自审：库自己产出的三层必须自洽，跨引擎必须被抓。

    **两侧都要在生产形态下验**。只验"自己产出的判 ok"，一个恒返回 ok 的实现
    也能全绿 —— 而那正是最坏的情况：使用者以为自审过了。所以这里额外拼一组
    跨引擎的（TLS/h2 取 chrome、头顺序取 firefox），worker 必须报 mismatch。
    """
    import json as _json
    with open(os.path.join(HERE, "h2table.json")) as f:
        h2t = _json.load(f)

    bad, n = [], 0
    for brand, ver, mix, want in (
            ("chrome", 151, None, "ok"),
            ("firefox", 135, None, "ok"),
            ("safari", 26, None, "ok"),
            ("chrome", 151, "firefox", "mismatch")):   # 跨引擎，必须被抓
        ak = (h2t.get(brand, {}).get(str(ver)) or {}).get("akamai_fingerprint")
        if not ak:
            bad.append(f"{brand} {ver}: h2 表里没有，用例失效")
            continue
        url = (f"http://127.0.0.1:{PORT}/coh?brand={brand}&version={ver}"
               f"&akamai={urllib.parse.quote(ak)}"
               + (f"&mix_brand={mix}" if mix else ""))
        try:
            line = opener.open(url, timeout=20).read().decode().strip()
        except Exception as e:
            bad.append(f"{brand} {ver}: 请求失败 {type(e).__name__}")
            continue
        parts = line.split("\t")
        if len(parts) != 5:
            bad.append(f"{brand} {ver}: worker 返回 {line[:70]}")
            continue
        n += 1
        verdict, tls_e, h2_e, hdr_e, id_e = parts
        tag = f"{brand} {ver}" + (f" + 头序={mix}" if mix else "")
        if verdict != want:
            bad.append(f"{tag}: 自审判 {verdict}，应为 {want}"
                       f"（tls={tls_e} h2={h2_e} hdr={hdr_e}）")
        # identify_h2 也顺带验：它认出的引擎必须与 coherence 里那一层一致
        if id_e != h2_e:
            bad.append(f"{tag}: identify_h2 说 {id_e}，coherence 里是 {h2_e}")
    return bad, n


def main():
    if not _docker_ok():
        print("无 docker，跳过（非失败）", file=sys.stderr)
        return 0

    work = tempfile.mkdtemp(prefix="tlsfp-orty-")
    conf = os.path.join(work, "nginx.conf")
    try:
        ok, info = _build_linux_so(work)
        if not ok:
            print(f"Linux 版 .so 编译失败：{info}", file=sys.stderr)
            return 1
        print(f"  Linux .so: {info}")
        with open(conf, "w") as f:
            f.write(NGINX_CONF)

        subprocess.run(["docker", "rm", "-f", CONTAINER],
                       capture_output=True, timeout=60)
        subprocess.run(
            ["docker", "run", "-d", "--name", CONTAINER, "-p", f"{PORT}:8080",
             "-v", f"{work}:/app:ro",
             "-v", f"{conf}:/usr/local/openresty/nginx/conf/nginx.conf:ro",
             ORTY_IMAGE], capture_output=True, timeout=120)
        time.sleep(4)

        mapper = UAMapper()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        cases, bad = [], []
        for brand, (tpl, lo, hi) in TARGETS.items():
            skip = NEVER_RELEASED.get(brand, set())
            for v in range(lo, hi + 1):
                if v in skip:
                    continue
                r = mapper.lookup(tpl.format(v=v))
                cases.append((brand, v, r.get("profile") or "-", r["confidence"]))

        for brand, v, pid, conf_want in cases:
            url = f"http://127.0.0.1:{PORT}/by_ua?brand={brand}&version={v}"
            try:
                got = opener.open(url, timeout=15).read().decode().strip().split("\t")
            except Exception as e:
                bad.append((brand, v, (pid, conf_want), ("ERR", type(e).__name__)))
                continue
            if tuple(got) != (pid, conf_want):
                bad.append((brand, v, (pid, conf_want), tuple(got)))

        print(f"  by_ua 差分 {len(cases)} 条："
              f"{len(cases) - len(bad)} 一致，{len(bad)} 不符")
        for b, v, e, g in bad[:8]:
            print(f"    ✗ {b} {v}  Python={e}  OpenResty={g}")

        # client_hello：在真 worker 里构造字节，解析回来与 golden 逐字段比。
        # 这条路径 by_ua 覆盖不到 —— 它还要走 resty.random 与 FFI 的输出缓冲。
        ch_bad = _check_client_hello(opener, mapper)
        print(f"  client_hello 构造 {4 - len(ch_bad)}/4 组合与 golden 一致")
        for b in ch_bad:
            print(f"    ✗ {b}")

        h2_bad, h2_n = _check_h2(opener)
        print(f"  h2 开场 {h2_n - len(h2_bad)}/{h2_n} 组合与 h2 表一致"
              f"（含 1 组「无 h2 数据必须拒绝」）")
        for b in h2_bad:
            print(f"    ✗ {b}")

        hdr_bad, hdr_n = _check_headers(opener)
        print(f"  头层四入口 {hdr_n - len(hdr_bad)}/{hdr_n} 品牌与 Python 一致"
              f"（顺序/取值/sec-ch-ua/平台提示）")
        for b in hdr_bad:
            print(f"    ✗ {b}")

        coh_bad, coh_n = _check_coherence(opener)
        print(f"  三层自审 {coh_n - len(coh_bad)}/{coh_n} 组（含 1 组跨引擎"
              f"必须判 mismatch）")
        for b in coh_bad:
            print(f"    ✗ {b}")

        conc_bad, conc_n = _check_concurrency(PORT)
        print(f"  并发 {conc_n - len(conc_bad)}/{conc_n} 个请求各自对得上"
              f"（16 路并发打 5 个品牌，查模块级缓冲有没有串）")
        for b in conc_bad[:4]:
            print(f"    ✗ {b}")

        failed = bad or ch_bad or h2_bad or hdr_bad or coh_bad or conc_bad
        print(f"\n{'C 模块在生产形态下与 Python 一致' if not failed else '存在分歧'}")
        return 1 if failed else 0
    finally:
        subprocess.run(["docker", "rm", "-f", CONTAINER],
                       capture_output=True, timeout=60)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
