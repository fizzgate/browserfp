// h2strict —— 对 HTTP/2 较真的服务端，用来当那两条「没有判据」的判据。
//
// browserfp_h2.lua 里记着两条行为**没有任何判据看得住**：
//
//	不 ACK 对端的 SETTINGS      RFC 9113 §6.5.3 要求必须 ACK
//	发请求体时无视流控窗口       RFC 9113 §6.9
//
// 本地 h2echo（Go net/http）与 tls.peet.ws 都撞不出来：Go 的服务端不等 ACK 也
// 照常回响应，而且边读边补窗口，客户端就算完全无视窗口也撞不上。
// 这个服务端就为这两条而写：
//
//	SETTINGS 没在 ackTimeout 内被 ACK  →  GOAWAY(SETTINGS_TIMEOUT=4)
//	收到的 DATA 超过通告的窗口          →  GOAWAY(FLOW_CONTROL_ERROR=3)
//
// **窗口会补，只是慢**：每收满一批就等 refillDelay 再发 WINDOW_UPDATE。这样
// 守规矩的客户端仍然能跑完（只是慢），不守的当场被判 —— 若干脆不补，守规矩的
// 会永远阻塞，那就分不出"守规矩"和"卡住"了。
//
// 只做够用的那一点：一条连接、一个流、响应恒 200 空体（HPACK 静态表第 8 项就是
// :status 200，一个字节 0x88）。不做 HPACK 解码 —— 请求头解不解与这两条无关。
package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	fData     = 0x0
	fHeaders  = 0x1
	fSettings = 0x4
	fPing     = 0x6
	fGoAway   = 0x7
	fWindow   = 0x8
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

func goAway(c net.Conn, code uint32, why string) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[4:8], code)
	_ = writeFrame(c, fGoAway, 0, 0, append(b, []byte(why)...))
}

func serve(c net.Conn, window int, ackTimeout, refill time.Duration) {
	defer c.Close()
	buf := make([]byte, len(preface))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != preface {
		return
	}
	// 通告一个**很小**的窗口：客户端只要不看它就会立刻超发
	set := make([]byte, 6)
	binary.BigEndian.PutUint16(set[0:2], 4) // INITIAL_WINDOW_SIZE
	binary.BigEndian.PutUint32(set[2:6], uint32(window))
	if err := writeFrame(c, fSettings, 0, 0, set); err != nil {
		return
	}
	sentAt := time.Now()

	acked := false
	// avail = 还允许对端发多少字节。**同步补**：单线程处理这条连接，收到 DATA
	// 就扣，扣到一半以下就先睡一会儿再发 WINDOW_UPDATE 把额度加回去。守规矩的
	// 客户端会在那里等（只是慢），不守的在扣成负数时当场被判。
	// **ACK 之前按 65535 算**。RFC 9113 §6.9.2：初始窗口恒为 65535，服务端通告的
	// 小窗口要等对端处理过 SETTINGS 才生效 —— 在那之前发满 65535 是合法的。
	// 第一版从一开始就按小窗口算，把守规矩的客户端也判成越界（实测：正确实现
	// 与"无视窗口"的实现都被 GOAWAY(3)，那样的判据分不出对错）。
	avail := 65535
	// 请求收齐了但还没回 —— 要等 SETTINGS ACK 到了才回。
	// **不能在这里 sleep 等 ACK**：sleep 期间不读，ACK 永远到不了，于是守规矩的
	// 客户端也被判成"没 ACK"。第一版就是这么错的，表现是无请求体的请求恒
	// GOAWAY(4)，而带请求体的反而正常（后者读了更多帧）。
	pending := uint32(0)
	for {
		if pending != 0 && acked {
			_ = writeFrame(c, fHeaders, 0x4|0x1, pending, []byte{0x88})
			return
		}
		if !acked && time.Since(sentAt) > ackTimeout {
			goAway(c, 4, "settings not acked")
			return
		}
		// 短读超时：让循环能周期性回来查 ACK 有没有超时
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		f, err := readFrame(c)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(sentAt) > 10*time.Second {
					return
				}
				continue
			}
			return
		}
		switch f.ftype {
		case fSettings:
			if f.flags&0x1 != 0 {
				acked = true
				if avail > window {
					avail = window // ACK 之后才收紧
				}
			} else {
				_ = writeFrame(c, fSettings, 0x1, 0, nil)
			}
		case fPing:
			if f.flags&0x1 == 0 {
				_ = writeFrame(c, fPing, 0x1, 0, f.body)
			}
		case fData:
			avail -= int(f.length)
			if avail < 0 {
				goAway(c, 3, "flow control")
				return
			}
			if f.flags&0x1 != 0 {
				pending = f.sid
			} else if avail < window/2 {
				time.Sleep(refill)
				inc := make([]byte, 4)
				binary.BigEndian.PutUint32(inc, uint32(window-avail))
				_ = writeFrame(c, fWindow, 0, 0, inc)
				_ = writeFrame(c, fWindow, 0, f.sid, inc)
				avail = window
			}
		case fHeaders:
			if f.flags&0x1 != 0 {
				pending = f.sid
			}
		}
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "")
	cert := flag.String("cert", "", "")
	key := flag.String("key", "", "")
	// **必须比对端的最大帧长小**：等于 16384 时，无视窗口的客户端一帧正好塞得下，
	// 那条缺陷就撞不出来（实测过：改坏客户端后照样 200）。
	window := flag.Int("window", 8192, "通告的初始窗口，故意小于一帧")
	ackMs := flag.Int("ackms", 1500, "等 SETTINGS ACK 的上限（毫秒）")
	refillMs := flag.Int("refillms", 150, "补窗口前的延迟（毫秒）")
	flag.Parse()

	c, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ln, err := tls.Listen("tcp", *addr, &tls.Config{
		Certificates: []tls.Certificate{c},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "h2strict ready on %s\n", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go serve(conn, *window, time.Duration(*ackMs)*time.Millisecond,
			time.Duration(*refillMs)*time.Millisecond)
	}
}
