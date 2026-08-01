"""HTTP/3 观测点：完成 QUIC 握手，取客户端的 SETTINGS 与伪头顺序。

与 quicprobe.py 的分工：
  quicprobe  旁路解 Initial 包 → ClientHello（TLS 层，不需要握手，也不回包）
  h3probe    真正完成 QUIC 握手 → H3 控制流的 SETTINGS + 请求的伪头顺序

H3 层必须完成握手才拿得到：SETTINGS 在客户端的控制流上、请求头经 QPACK 编码，
两者都在加密的 1-RTT 包里。自己实现 QUIC 握手工作量过大，故用 aioquic 起服务端
（须 .venv-wreq/bin/python，Python ≥3.11）。

**H3 指纹的 SETTINGS 是排序的**，与 h2 的 Akamai 指纹不同——后者保留发送顺序。
参考 0x676e67/pingly 的 src/h3/fingerprint.rs：
    normalized_settings.sort_by_key(|s| (s.is_grease(), s.id))

**但我们与该参考实现有一处有意分歧：GREASE 设置项必须剔除，不能只排到末尾。**
实测 Chrome 151 连续 3 次，GREASE 项每次 id 与 value 都随机：
    (4286499706, 2513092772) / (128806768986, 1076861976) / (96762675253, 2315703211)
保留它 → h3_text 三次三个值，根本不能当指纹；剔除后 → 三次同一个值。
这与 TLS 层按 RFC 8701 剔 GREASE 是同一个道理。

剔除的同时保留 `has_grease` 布尔：**发不发 GREASE 本身是区分点**，不能连这个
信息一起丢掉。
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "..", "spec", "certs", "fullchain.pem")
KEY = os.path.join(HERE, "..", "spec", "certs", "key.pem")

# GREASE 设置项：0x1f * N + 0x21（RFC 9114 §7.2.4.1）
def is_grease_setting(sid):
    return sid >= 0x21 and (sid - 0x21) % 0x1F == 0


def h3_fingerprint(settings, pseudo_order):
    """拼 h3_text：<剔除 GREASE 后按 id 排序的 settings>|<伪头顺序缩写>。

    见模块 docstring：GREASE 项每次随机，保留它指纹就不稳定。
    """
    items = sorted((k, v) for k, v in settings.items() if not is_grease_setting(k))
    text = ",".join(f"{k}:{v}" for k, v in items) or "0"
    order = ",".join(p[1] for p in pseudo_order) or "0"
    return f"{text}|{order}"


async def _serve(port, result, done):
    from aioquic.asyncio import QuicConnectionProtocol, serve
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import ProtocolNegotiated

    class Proto(QuicConnectionProtocol):
        """必须继承 QuicConnectionProtocol —— 它提供 datagram_received / close
        等 asyncio 传输回调，自己裸写一个类会在收到第一个包时 AttributeError。"""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._h3 = None

        def quic_event_received(self, event):
            if isinstance(event, ProtocolNegotiated):
                self._h3 = H3Connection(self._quic)
            if self._h3 is None:
                return
            for h3ev in self._h3.handle_event(event):
                if isinstance(h3ev, HeadersReceived) and not done.is_set():
                    pseudo = [(k.decode(), k.decode()[1])
                              for k, _ in h3ev.headers if k.startswith(b":")]
                    regular = [k.decode() for k, _ in h3ev.headers
                               if not k.startswith(b":")]
                    settings = self._h3.received_settings or {}
                    result.update({
                        "settings": dict(settings),
                        "has_grease_setting": any(is_grease_setting(k)
                                                  for k in settings),
                        "pseudo_header_order": [p[0] for p in pseudo],
                        "header_order": regular,
                        "h3_text": h3_fingerprint(settings, pseudo),
                    })
                    done.set()

    cfg = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    cfg.load_cert_chain(CERT, KEY)
    server = await serve("127.0.0.1", port, configuration=cfg,
                         create_protocol=Proto)
    try:
        await asyncio.wait_for(done.wait(), timeout=45)
    except asyncio.TimeoutError:
        pass
    finally:
        server.close()


def capture(port, launch):
    """起 H3 服务端并调用 launch(port) 拉起客户端，返回指纹 dict。

    launch 应是同步函数，返回一个可 terminate 的进程对象。
    """
    result, proc_box = {}, []

    async def run():
        done = asyncio.Event()
        task = asyncio.create_task(_serve(port, result, done))
        await asyncio.sleep(1.0)          # 等服务端 bind 完成再拉客户端
        proc_box.append(launch(port))
        await task

    try:
        asyncio.run(run())
    finally:
        for p in proc_box:
            try:
                p.terminate()
                p.wait(timeout=10)
            except Exception:
                pass
    if not result:
        raise TimeoutError("未收到 H3 请求头")
    return result
