"""请求头顺序/取值的真机采集：起一个本地 HTTP 观测点，记下浏览器发来的原样头。

`spec/golden/headers_real.json` 是头顺序层的唯一真值源，但它此前**只有一份
`_capture_note` 描述怎么采的，没有可重跑的脚本** —— 换句话说那份数据不可复现：
想补一个浏览器、想核对某条是不是采错了，都只能从头再搭一次。移动端至今是
"按引擎推断"而非实采，也卡在这里。

三件事必须在采集层就做对，事后补不回来：

  1. **原样记录，不能过 dict**。`http.server` 的 `self.headers` 是
     `email.message.Message`，保序、允许重名 —— 用 `items()` 取，别转 dict，
     否则顺序（本模块唯一要采的东西）就没了。
  2. **同一次请求里同时记下 UA**。头顺序与 UA 必须来自同一个请求，事后拿另一次
     启动的 UA 去配是错的（无头/有头、不同 profile 的 UA 都可能不同）。
  3. **只采导航请求**。浏览器对 favicon、子资源发的头集合与顺序都不一样
     （`sec-fetch-dest` 不同、少 `upgrade-insecure-requests`），混进来会把
     "这个引擎的头顺序"污染成"某类子资源的头顺序"。

不做的事：不自动启动浏览器。启动方式各平台差异太大（模拟器、真机、有头无头），
写死在这里只会僵尸化 —— 脚本负责"接住并记准"，怎么打开由调用方决定，
命令行会把要访问的 URL 打出来。

跑：
    python -m oracle.hdrcollect --label chrome-mobile          # 等一次导航请求
    python -m oracle.hdrcollect --label safari-mobile --merge  # 采完并入 golden
"""

import argparse
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
REALHDR = os.path.join(HERE, "..", "spec", "golden", "headers_real.json")

PAGE = b"""<!doctype html><meta charset=utf-8><title>hdrcollect</title>
<h1>captured</h1><p>This page exists only to record request headers.</p>"""

# 只有这些路径算导航请求；其余（favicon、各种探测）一律忽略但计数
NAV_PATHS = ("/", "/index.html")


class _Recorder(BaseHTTPRequestHandler):
    captured = None
    ignored = []

    def do_GET(self):                     # noqa: N802
        if self.path not in NAV_PATHS:
            _Recorder.ignored.append(self.path)
            self.send_response(404)
            self.end_headers()
            return
        if _Recorder.captured is None:
            # items() 保序且保留重名 —— 转成 dict 就把顺序丢了，而顺序正是
            # 本模块唯一要采的东西。
            # **丢掉 host**：HTTP/1.1 的 host 在 h2 里是伪头 `:authority`，
            # 不属于普通头顺序。golden 里的既有采集就是这个口径，不统一的话
            # 新采的每一条都会比旧的多一个头，比对时看起来像"顺序变了"。
            _Recorder.captured = {
                "headers": [[k.lower(), v] for k, v in self.headers.items()
                            if k.lower() != "host"],
                "path": self.path,
            }
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *a):            # 静音默认访问日志
        pass


def collect(port=0, timeout=180, bind="0.0.0.0"):
    """起服务等一次导航请求。返回记录，超时返回 None。

    默认 bind 到 0.0.0.0 而不是 127.0.0.1 —— 模拟器/真机要从别的地址连进来，
    只听回环的话它们根本连不上（安卓模拟器走 10.0.2.2，iOS 模拟器走本机 LAN IP）。
    """
    _Recorder.captured = None
    _Recorder.ignored = []
    srv = HTTPServer((bind, port), _Recorder)
    real_port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    lan = socket.gethostbyname(socket.gethostname())
    print(f"观测点已起：")
    print(f"  本机        http://127.0.0.1:{real_port}/")
    print(f"  局域网/iOS  http://{lan}:{real_port}/")
    print(f"  安卓模拟器  http://10.0.2.2:{real_port}/")
    print(f"用浏览器打开其中一个（最多等 {timeout}s）…")

    waited = 0.0
    while _Recorder.captured is None and waited < timeout:
        threading.Event().wait(0.5)
        waited += 0.5
    srv.shutdown()
    if _Recorder.ignored:
        print(f"  （忽略了 {len(_Recorder.ignored)} 个非导航请求："
              f"{sorted(set(_Recorder.ignored))[:4]}）")
    return _Recorder.captured


def merge(label, rec, dest=REALHDR):
    """并入 golden。**同名已存在时不静默覆盖** —— 真值源被悄悄改掉最难查。"""
    with open(dest) as f:
        data = json.load(f)
    if label in data:
        raise SystemExit(f"{label} 已存在于 {os.path.basename(dest)}；"
                         "要替换请先手工删掉那条，别让覆盖静默发生")
    data[label] = rec
    with open(dest, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(f"  已并入 {label}")


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True, help="浏览器标签，如 chrome-mobile")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--merge", action="store_true", help="采到后并入 golden")
    args = ap.parse_args(argv[1:])

    rec = collect(port=args.port, timeout=args.timeout)
    if rec is None:
        print("超时，没等到导航请求", file=sys.stderr)
        return 1

    hdrs = rec["headers"]
    ua = next((v for k, v in hdrs if k == "user-agent"), None)
    print(f"\n采到 {len(hdrs)} 个头")
    print(f"  user-agent: {ua}")
    print(f"  顺序: {[k for k, _ in hdrs]}")
    if args.merge:
        merge(args.label, {"headers": hdrs, "user_agent": ua})
    else:
        print("\n（未并入；加 --merge 才写 golden）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
