// kyberserver —— 只接受 X25519Kyber768Draft00(0x6399) 的 TLS 1.3 服务端。
//
// 为什么单独一个模块、单独一份 go.mod：**这个组只有 Go 1.23 的 crypto/tls 有**，
// 1.24 起被删掉了（换成 ML-KEM）。本机 /usr/local/go 恰好是 1.23.1，而 PATH 上
// 的 go 会转发给模块工具链 1.25.7 —— 后者编出来的服务端会安静地退回 X25519，
// 于是「0x6399 走通了」这个结论根本没被验到。
//
// 用法：GOTOOLCHAIN=local /usr/local/go/bin/go build -o kyberserver ./
//
// 它只做一件事：握手，然后回一行「协商到的组」。指纹判据不在这里。
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "")
	cert := flag.String("cert", "", "")
	key := flag.String("key", "", "")
	flag.Parse()

	c, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// 0x6399 **不能单独出现**：Go 的 defaults.go 写着 must always be followed
	// by X25519，只给它一个会直接 handshake_failure(40)。
	cfg := &tls.Config{
		Certificates:     []tls.Certificate{c},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{0x6399, tls.X25519},
		NextProtos:       []string{"http/1.1"},
	}
	ln, err := tls.Listen("tcp", *addr, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "kyberserver ready on %s\n", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(cn net.Conn) {
			defer cn.Close()
			tc := cn.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				return
			}
			buf := make([]byte, 4096)
			_, _ = tc.Read(buf)
			// Go 1.23 的 ConnectionState 还没有 CurveID 字段。这里不回显组号，
			// 而是靠「服务端只接受 0x6399」这一点：握手能成就说明走的是它。
			body := "ok\n"
			fmt.Fprintf(tc, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"+
				"Content-Type: text/plain\r\n\r\n%s", len(body), body)
		}(conn)
	}
}
