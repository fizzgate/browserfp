"""HTTP CONNECT 代理形态的 ClientHello 观测点 —— 采到的握手**带真实 SNI**。

**为什么不能直接让浏览器连 127.0.0.1**：那样 ClientHello 里没有 server_name
扩展（TLS 不允许对 IP 发 SNI），JA4 首段会从 t13d 变成 t13i，与库里的 golden
不可比。实测 Firefox 149 直连 IP 采到的是 t13i1716h2_…，白采。

**为什么不用 network.dns.localDomains**：Firefox 149 上这条 pref 不再把域名
指到本地（实测设了也超时），Chromium 那套 --host-resolver-rules 对 Firefox 也
不适用。

**为什么不改 /etc/hosts**：要 sudo，而且会影响本机所有进程，采完还得记得改回
去——一个忘了就污染后续所有测量。

代理路径没有这些问题：浏览器发 `CONNECT example.com:443`，我们回 200，随后
隧道里第一段字节就是带 SNI 的完整 ClientHello。浏览器只需一个 pref/命令行参数，
关掉即恢复，不留痕迹。

**Firefox 的 headless 与有头指纹相同**（实测 153.0.1，两种模式采到的
t13i1616h2_86a278354501_3cbfd9057e0d 逐字段一致），所以容器里用 MOZ_HEADLESS=1
采 Firefox 是可靠的。**这个结论不能外推到 Chromium**——项目此前就是因为
"headless Chrome 的 TLS 栈配置可能与有头不同"才坚持有头采集（见
oracle/capture_browser.py），Chrome 侧没做过同样的对照。

容器内的浏览器要连宿主的观测点时，ProxySniffer 必须绑 0.0.0.0（默认 127.0.0.1
容器连不进来），容器内则用 host.docker.internal 访问宿主。

注意采到的是"经代理时"的形态。理论上浏览器可能因走代理而调整握手（例如放弃
ECH），比对 golden 时若见到 ECH 相关差异，先怀疑这一点。

**与库里 golden 比对时必须先归一化 SNI**。库里的 profile 全部采自无 SNI 场景
（ja4 首段是 t13i），而本采集器拿到的是带 SNI 的真实形态（t13d），扩展数也因此
多 1。实测 Firefox 149：
    真机       t13d1717h2_5b57614c22b0_3cbfd9057e0d
    real:firefox t13i1716h2_5b57614c22b0_3cbfd9057e0d
后两段（cipher 哈希、扩展哈希）完全相同 —— 是同一指纹，只差 server_name 一项。
直接比 ja4 字符串会得出"库里没有这个指纹"的错误结论。
"""

import os
import re
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ProxySniffer:
    """监听本地端口，扮演 HTTP CONNECT 代理，留下隧道内第一个 TLS record。"""

    def __init__(self, host="127.0.0.1", port=0):
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._records = []
        self._hosts = []
        self._event = threading.Event()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(20)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                head += chunk
            line = head.split(b"\r\n", 1)[0].decode("latin1")
            if not line.upper().startswith("CONNECT"):
                # 明文请求：浏览器可能先探测代理是否可用，礼貌回一句就好
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                return
            target = line.split()[1] if len(line.split()) > 1 else "?"
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

            # 隧道建立后的第一段字节就是 ClientHello。按 record 头取足长度，
            # 不能只 recv 一次——ClientHello 常被拆成多个 TCP 段（实测 1876
            # 字节的那份就分了两段），截断的 record 解析出来字段会缺。
            buf = b""
            while len(buf) < 5:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            total = 5 + int.from_bytes(buf[3:5], "big")
            while len(buf) < total:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if buf[:1] == b"\x16":
                self._records.append(buf[:total])
                self._hosts.append(target)
                self._event.set()
        except (OSError, ValueError, IndexError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def pop(self, timeout=60, want_host=None):
        """返回 (record, target)；超时抛 TimeoutError。

        **want_host 几乎总是该传**。代理会收到浏览器的**全部**出站连接，不只是
        我们让它打开的那个页面：遥测、OCSP、位置服务、更新检查都会先到。实测
        Firefox 149 第一个到达的是 location.services.mozilla.com，而且它协商的
        是 TLS1.2（采到 t12i1310h2，13 个 cipher），与该浏览器访问网页时的
        t13d1717h2 完全不是一回事。不过滤就会把这种后台连接的形态当成浏览器
        指纹落库 —— 这个错误发生过一次，落盘后才从 ja4 的 t12 前缀看出来。
        """
        import time as _time
        deadline = _time.monotonic() + timeout
        while True:
            for i, host in enumerate(self._hosts):
                if want_host is None or host.split(":")[0] == want_host:
                    self._hosts.pop(i)
                    return self._records.pop(i), host
            left = deadline - _time.monotonic()
            if left <= 0:
                seen = sorted({h.split(":")[0] for h in self._hosts})
                raise TimeoutError(
                    f"no ClientHello for {want_host or 'any host'} within "
                    f"{timeout}s（期间收到：{seen or '无'}）")
            self._event.clear()
            self._event.wait(min(left, 1.0))


FIREFOX_PREFS = """user_pref("network.proxy.type", 1);
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", {port});
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", {port});
user_pref("network.proxy.allow_hijacking_localhost", true);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("datareporting.policy.dataSubmissionPolicyBypassNotification", true);
user_pref("network.trr.mode", 5);
user_pref("network.dns.disablePrefetch", true);
"""


def firefox_profile(port):
    """建一个只在本次采集使用的 profile，把代理指到观测点。"""
    import tempfile
    d = tempfile.mkdtemp(prefix="browserfp-ff-")
    with open(os.path.join(d, "user.js"), "w") as f:
        f.write(FIREFOX_PREFS.format(port=port))
    return d


def is_firefox(path):
    return "firefox" in os.path.basename(path).lower()


def launch_argv(path, port, url):
    """两家浏览器的代理配置方式不同，profile 也不同。

    Chromium 系用命令行 --proxy-server，Firefox 只能靠 profile 里的 pref
    （命令行没有等价开关）。两边都用一次性 profile，不碰用户正在用的那个。
    """
    import tempfile
    if is_firefox(path):
        prof = firefox_profile(port)
        return [path, "-profile", prof, "-no-remote", "-new-instance", url], prof
    prof = tempfile.mkdtemp(prefix="browserfp-cr-")
    return ([path,
             f"--proxy-server=http://127.0.0.1:{port}",
             f"--user-data-dir={prof}",
             "--no-first-run", "--no-default-browser-check",
             "--disable-background-networking",
             url], prof)


def save_golden(name, version, engine, fp):
    """把采到的指纹并入 spec/golden/real_browsers.json。

    **存归一化后的无 SNI 形态**：库里其余 profile 全部采自无 SNI 场景，混入带
    SNI 的记录会让同一浏览器在注册表里裂成两条互不相认的指纹。

    键名带主版本号（firefox78 而非 firefox），这样多个历史版本能共存——现有的
    'firefox' 那条是本机最新版，不带版本号，两者互不覆盖。写入走 goldenio 的
    合并模式：此前采集器覆盖式落盘毁过一次 golden（71 条 h2 记录），那之后所有
    落盘都必须先读回再更新。
    """
    from oracle.goldenio import write_golden
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "spec", "golden", "real_browsers.json")
    total, changed = write_golden(path, {
        name: {"version": version, "engine": engine, "fingerprint": fp},
    })
    return os.path.normpath(path), total, changed


def main(argv):
    """采一次浏览器：python -m oracle.proxysniffer [浏览器路径] [--save 名字]"""
    import shutil
    import subprocess

    from oracle.clienthello import fingerprint

    args = [a for a in argv[1:] if not a.startswith("--")]
    save_as = None
    if "--save" in argv:
        i = argv.index("--save")
        save_as = argv[i + 1] if i + 1 < len(argv) else None
        if save_as in args:
            args.remove(save_as)
    path = args[0] if args else \
        "/Applications/Firefox.app/Contents/MacOS/firefox"
    if not os.path.exists(path):
        print(f"找不到 {path}", file=sys.stderr)
        return 2

    ver = subprocess.run([path, "--version"], capture_output=True, text=True,
                         timeout=20).stdout.strip()
    with ProxySniffer() as sniffer:
        argv, prof = launch_argv(path, sniffer.port, "https://example.com/")
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            record, target = sniffer.pop(timeout=90, want_host="example.com")
            fp = fingerprint(record)
            print(f"浏览器 : {ver}")
            print(f"CONNECT: {target}")
            print(f"ja4    : {fp['ja4']}")
            print(f"ciphers: {len(fp['ciphers'])}  extensions: "
                  f"{len(fp['extensions_ordered'])}  has_sni: {fp.get('has_sni')}")
            print(f"curves : {[hex(x) for x in fp['curves']]}")
            print(f"sigalgs: {[hex(x) for x in fp['sig_algs']]}")

            if save_as:
                norm = fingerprint(record, drop_sni=True)
                engine = "gecko" if is_firefox(path) else "chromium"
                vnum = re.search(r"(\d[\d.]*)", ver)
                where, total, changed = save_golden(
                    save_as, vnum.group(1) if vnum else ver, engine, norm)
                print(f"\n归一化 : {norm['ja4']}  （去 SNI，与库中 golden 同口径）")
                print(f"落盘   : {where}  共 {total} 条，本次更新 {changed} 条")
            return 0
        except TimeoutError as e:
            print(f"未采到：{e}", file=sys.stderr)
            return 1
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            shutil.rmtree(prof, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
