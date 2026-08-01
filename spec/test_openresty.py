"""在**真实 OpenResty worker** 里验证 C 模块，而不是裸 luajit。

这是生产实际运行的形态。此前 test_lua_parity / test_lua_ua_parity 用的是本机
luajit，它们能验 FFI 绑定的语义，但验不到两件只有真 OpenResty 才暴露的事：

  1. **平台/ABI 匹配** —— 本机编译的 libtlsfp.so 是 macOS 的 Mach-O，挂进 Linux
     容器直接 `invalid ELF header`。生产跑在 Linux 上，而这条链此前从未在 Linux
     编译并加载过。
  2. **在 nginx worker 内加载** —— lua_package_path、FFI 加载时机、worker 生命
     周期都与命令行跑脚本不同。

做法：用 gcc 容器编译出 Linux 版 .so，挂进 openresty 容器，起一个把
`tlsfp.by_ua()` 暴露成 HTTP 接口的 worker，然后逐版本与 Python 比对。

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
                if r then ngx.say(r.id .. "\\t" .. r.confidence)
                else ngx.say("-\\t" .. tostring(conf)) end
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
    for sub in ("csrc", "lua"):
        shutil.copytree(os.path.join(ROOT, sub), os.path.join(workdir, sub))
    os.makedirs(os.path.join(workdir, "spec"), exist_ok=True)
    shutil.copy(os.path.join(HERE, "profiles.json"),
                os.path.join(workdir, "spec", "profiles.json"))
    shutil.copytree(os.path.join(HERE, "segments"),
                    os.path.join(workdir, "spec", "segments"))
    out = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{workdir}:/w", GCC_IMAGE, "bash", "-c",
         "cd /w/csrc && rm -f *.o *.so *.inc ja4cli uacli lookup_test && "
         "make libtlsfp.so >/dev/null 2>&1 && file libtlsfp.so"],
        capture_output=True, text=True, timeout=600)
    return "ELF" in out.stdout, out.stdout.strip()[:80]


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

        print(f"  真实 OpenResty worker 差分 {len(cases)} 条："
              f"{len(cases) - len(bad)} 一致，{len(bad)} 不符")
        for b, v, e, g in bad[:8]:
            print(f"    ✗ {b} {v}  Python={e}  OpenResty={g}")
        print(f"\n{'C 模块在生产形态下与 Python 一致' if not bad else '存在分歧'}")
        return 1 if bad else 0
    finally:
        subprocess.run(["docker", "rm", "-f", CONTAINER],
                       capture_output=True, timeout=60)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
