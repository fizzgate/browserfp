// h2early —— 会发 1xx 中间响应（103 Early Hints）的 HTTP/2 服务端。
//
// 为什么需要它：HTTP/2 里 1xx 是**独立的 HEADERS 帧**，客户端必须跳过它继续读，
// 直到拿到非 1xx 的最终响应（RFC 9113 §8.1，RFC 8297）。HTTP/1.1 那条链由
// resty.http 自己吃掉 1xx，所以只有自己写的 h2 客户端需要处理这件事。
//
// 不处理的后果是**静默的**：103 被当成最终响应返回，它的头里只有 Link，
// 没有 content-type、没有 content-encoding —— 浏览器拿到一个 103 加一段
// 未声明编码的 gzip 字节，既不解压也不渲染，**整个页面变成文件下载**。
//
// 2026-08-04 生产实测：网页代理打开账号后拿到 `"GET /new HTTP/1.1" 103 10910`，
// 用户下载到的 .gz 解压出来正是那张 33521 字节的页面。
// 本地一直没暴露，因为 h2echo(Go net/http) 与 tls.peet.ws 都不发 Early Hints，
// claude.ai 也只对**带会话**的请求发（未登录直接 403）。这个服务端就为补这个洞。
//
// 用法：
//
//	go build -o h2early . && ./h2early -addr 127.0.0.1:8443 -hints 1
//
// 参数 -hints N：先发 N 个 103，再发最终 200。N=0 即退化成普通服务端（阴性对照：
// 客户端在 N=0 时也必须正常，否则说明跳过逻辑把正常响应也吃掉了）。
package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/net/http2/hpack"
)

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	fData     = 0x0
	fHeaders  = 0x1
	fSettings = 0x4
	fGoAway   = 0x7
	fWindow   = 0x8
)

const (
	flagEndStream  = 0x1
	flagEndHeaders = 0x4
)

type frame struct {
	length uint32
	ftype  byte
	flags  byte
	sid    uint32
	body   []byte
}

func readFrame(c net.Conn) (*frame, error) {
	var h [9]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	n := uint32(h[0])<<16 | uint32(h[1])<<8 | uint32(h[2])
	f := &frame{length: n, ftype: h[3], flags: h[4],
		sid: binary.BigEndian.Uint32(h[5:9]) & 0x7fffffff}
	f.body = make([]byte, n)
	if _, err := io.ReadFull(c, f.body); err != nil {
		return nil, err
	}
	return f, nil
}

func writeFrame(c net.Conn, ftype, flags byte, sid uint32, body []byte) error {
	h := []byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body)),
		ftype, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(h[5:9], sid)
	if _, err := c.Write(h); err != nil {
		return err
	}
	_, err := c.Write(body)
	return err
}

// encodeHeaders 用**同一个** HPACK encoder 编码，动态表状态因此跨帧累积 ——
// 这正是要考验客户端的地方：1xx 的头也进动态表，客户端若为了"跳过"而不解码，
// 后续所有响应头都会错位。
func encodeHeaders(enc *hpack.Encoder, buf *writeBuf, kv ...[2]string) []byte {
	buf.reset()
	for _, p := range kv {
		_ = enc.WriteField(hpack.HeaderField{Name: p[0], Value: p[1]})
	}
	return buf.bytes()
}

type writeBuf struct{ b []byte }

func (w *writeBuf) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }
func (w *writeBuf) reset()                      { w.b = w.b[:0] }
func (w *writeBuf) bytes() []byte               { out := make([]byte, len(w.b)); copy(out, w.b); return out }

func serve(c net.Conn, hints int, body string) {
	defer c.Close()
	buf := make([]byte, len(preface))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != preface {
		return
	}
	if err := writeFrame(c, fSettings, 0, 0, nil); err != nil {
		return
	}

	wb := &writeBuf{}
	enc := hpack.NewEncoder(wb)

	for {
		f, err := readFrame(c)
		if err != nil {
			return
		}
		switch f.ftype {
		case fSettings:
			if f.flags&0x1 == 0 { // 不是 ACK → 回 ACK
				if err := writeFrame(c, fSettings, 0x1, 0, nil); err != nil {
					return
				}
			}
		case fWindow, fData:
			// 请求体收下即可，不做流控刁难（那是 h2strict 的活）
		case fHeaders:
			if f.flags&flagEndHeaders == 0 {
				continue // 等 CONTINUATION，简化：本服务端只应对一次发完的情形
			}
			sid := f.sid
			// ① 先发 N 个 103 Early Hints —— 只有 :status 与 link，**没有**
			//    content-type / content-encoding，这正是漏跳时症状那么怪的原因。
			for i := 0; i < hints; i++ {
				hb := encodeHeaders(enc, wb,
					[2]string{":status", "103"},
					[2]string{"link", fmt.Sprintf("</style%d.css>; rel=preload; as=style", i)},
				)
				// 注意：**不带 END_STREAM**。1xx 后面必然还有最终响应。
				if err := writeFrame(c, fHeaders, flagEndHeaders, sid, hb); err != nil {
					return
				}
			}
			// ② 再发最终响应
			hb := encodeHeaders(enc, wb,
				[2]string{":status", "200"},
				[2]string{"content-type", "text/html; charset=utf-8"},
				[2]string{"x-early-hints-sent", fmt.Sprintf("%d", hints)},
			)
			if err := writeFrame(c, fHeaders, flagEndHeaders, sid, hb); err != nil {
				return
			}
			if err := writeFrame(c, fData, flagEndStream, sid, []byte(body)); err != nil {
				return
			}
		case fGoAway:
			return
		}
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "监听地址")
	cert := flag.String("cert", "../../../spec/certs/fullchain.pem", "证书")
	key := flag.String("key", "../../../spec/certs/key.pem", "私钥")
	hints := flag.Int("hints", 1, "先发几个 103（0=不发，阴性对照）")
	body := flag.String("body", "<!doctype html><html><body>ok</body></html>", "响应体")
	flag.Parse()

	crt, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读证书失败: %v\n", err)
		os.Exit(1)
	}
	ln, err := tls.Listen("tcp", *addr, &tls.Config{
		Certificates: []tls.Certificate{crt},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "监听失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("h2early 监听 %s，每个请求先发 %d 个 103\n", *addr, *hints)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go serve(c, *hints, *body)
	}
}
