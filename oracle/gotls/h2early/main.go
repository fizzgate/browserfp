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
	"strings"

	"golang.org/x/net/http2/hpack"
)

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	fData     = 0x0
	fHeaders  = 0x1
	fRst      = 0x3
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

func serve(c net.Conn, hints int, body string, strictCase, strictHost bool, tableSize int) {
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

	// 请求头解码器。用来实施 RFC 9113 §8.2.1：字段名含大写字母的请求
	// **MUST be treated as malformed** —— 严格的对端会 RST_STREAM(PROTOCOL_ERROR)。
	// 实测 claude.ai 容忍大写，s-cdn.anthropic.com 不容忍（回错误码 1）。
	// 宽容的服务端撞不出这条，所以这里必须自己较真。
	// 记下每个请求解出来的头，用于实施 RFC 9113 的"malformed request"判定。
	var badCase, badConn, sawHost, sawAuthority string
	sizeUpdateSent := false
	// 连接特定头在 HTTP/2 里是禁止的（RFC 9113 §8.2.2）
	connHdrs := map[string]bool{"connection": true, "keep-alive": true,
		"proxy-connection": true, "transfer-encoding": true, "upgrade": true}
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		for i := 0; i < len(f.Name); i++ {
			if f.Name[i] >= 'A' && f.Name[i] <= 'Z' {
				badCase = f.Name
			}
		}
		ln := strings.ToLower(f.Name)
		if connHdrs[ln] {
			badConn = f.Name
		}
		if ln == "host" {
			sawHost = f.Value
		}
		if ln == ":authority" {
			sawAuthority = f.Value
		}
	})

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
			badCase, badConn, sawHost, sawAuthority = "", "", "", ""
			// HEADERS 帧可能带 PADDED(0x8)/PRIORITY(0x20)，头块前后有额外字节，
			// 直接喂给 HPACK 解码器会解错 —— 先剥掉。
			reqHB := f.body
			if f.flags&0x8 != 0 && len(reqHB) > 0 { // PADDED
				padLen := int(reqHB[0])
				reqHB = reqHB[1:]
				if padLen <= len(reqHB) {
					reqHB = reqHB[:len(reqHB)-padLen]
				}
			}
			if f.flags&0x20 != 0 && len(reqHB) >= 5 { // PRIORITY
				reqHB = reqHB[5:]
			}
			if _, err := dec.Write(reqHB); err != nil {
				fmt.Printf("HPACK 解码请求头失败: %v (flags=0x%x len=%d)\n", err, f.flags, len(f.body))
			}
			// 逐条报告这次请求踩了哪些 RFC 判定（诊断用，逐个排除）
			fmt.Printf("请求诊断: 大写头名=%q 连接特定头=%q host=%q :authority=%q host一致=%v\n",
				badCase, badConn, sawHost, sawAuthority,
				sawHost == "" || sawHost == sawAuthority)
			if strictHost && sawHost != "" {
				// RFC 9113 §8.3.1：HTTP/2 用 :authority，客户端不该再发 host 普通头。
				// s-cdn.anthropic.com 实测就是这么拒的（错误码 1）。
				b := make([]byte, 4)
				binary.BigEndian.PutUint32(b, 1)
				_ = writeFrame(c, fRst, 0, sid, b)
				fmt.Printf("拒绝：客户端发了 host 普通头 %q → RST_STREAM(1)\n", sawHost)
				continue
			}
			if strictCase && badCase != "" {
				// RST_STREAM(PROTOCOL_ERROR=1)，与 s-cdn.anthropic.com 的行为一致
				b := make([]byte, 4)
				binary.BigEndian.PutUint32(b, 1)
				_ = writeFrame(c, fRst, 0, sid, b)
				fmt.Printf("拒绝：请求头名含大写 %q → RST_STREAM(1)\n", badCase)
				continue
			}
			// ⓪ 可选：先发一条 HPACK「动态表大小更新」。客户端在 SETTINGS 里通告了
			//    HEADER_TABLE_SIZE，就必须能接住 <= 该值的 size update；只按 4096 解
			//    会整块解不动（2026-08-04 生产事故：通告 65536、解码器 4096）。
			if tableSize > 0 && !sizeUpdateSent {
				// ⚠ 必须先放开 limit：Go 的 Encoder 默认 maxSizeLimit=4096，
				// 直接 SetMaxDynamicTableSize(12288) 会被截回 4096，于是**根本不发**
				// size update —— 判据看着绿其实什么都没考。（变异测试抓到的。）
				enc.SetMaxDynamicTableSizeLimit(uint32(tableSize))
				enc.SetMaxDynamicTableSize(uint32(tableSize))
				sizeUpdateSent = true
				fmt.Printf("已发 HPACK 动态表大小更新 = %d\n", tableSize)
			}
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
	strict := flag.Bool("strictcase", true, "请求头名含大写就 RST_STREAM(1)（RFC 9113 §8.2.1）")
	strictHost := flag.Bool("stricthost", false, "客户端发 host 普通头就 RST_STREAM(1)（RFC 9113 §8.3.1）")
	tableSize := flag.Int("tablesize", 0, "响应前发一条 HPACK 动态表大小更新（0=不发）")
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
		go serve(c, *hints, *body, *strict, *strictHost, *tableSize)
	}
}
