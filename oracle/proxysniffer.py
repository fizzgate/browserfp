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

    def pop(self, timeout=60):
        """返回 (record, target)；超时抛 TimeoutError。"""
        if not self._event.wait(timeout):
            raise TimeoutError(f"no ClientHello within {timeout}s")
        self._event.clear()
        return self._records.pop(0), self._hosts.pop(0)


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
    d = tempfile.mkdtemp(prefix="tlsfp-ff-")
    with open(os.path.join(d, "user.js"), "w") as f:
        f.write(FIREFOX_PREFS.format(port=port))
    return d


def main(argv):
    """采一次本机 Firefox：python -m oracle.proxysniffer [浏览器路径]"""
    import shutil
    import subprocess

    from oracle.clienthello import fingerprint

    path = argv[1] if len(argv) > 1 else \
        "/Applications/Firefox.app/Contents/MacOS/firefox"
    if not os.path.exists(path):
        print(f"找不到 {path}", file=sys.stderr)
        return 2

    ver = subprocess.run([path, "--version"], capture_output=True, text=True,
                         timeout=20).stdout.strip()
    with ProxySniffer() as sniffer:
        prof = firefox_profile(sniffer.port)
        proc = subprocess.Popen(
            [path, "-profile", prof, "-no-remote", "-new-instance",
             "https://example.com/"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            record, target = sniffer.pop(timeout=90)
            fp = fingerprint(record)
            print(f"浏览器 : {ver}")
            print(f"CONNECT: {target}")
            print(f"ja4    : {fp['ja4']}")
            print(f"ciphers: {len(fp['ciphers'])}  extensions: "
                  f"{len(fp['extensions_ordered'])}  has_sni: {fp.get('has_sni')}")
            print(f"curves : {[hex(x) for x in fp['curves']]}")
            print(f"sigalgs: {[hex(x) for x in fp['sig_algs']]}")
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
