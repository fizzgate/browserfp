// HelloRetryRequest 观测服务端：只接受客户端不会首发的密钥交换组，逼它重发
// ClientHello。
//
// 为什么必须用 Go：Python ssl 的 set_ecdh_curve 是 TLS 1.2 的 ECDHE 设置，
// TLS 1.3 下不限制 supported_groups，服务端会照单全收客户端首发的 X25519，
// 永远触发不了 HRR；而 ssl 模块没有暴露 SSL_CTX_set1_groups_list。
// Go 的 tls.Config.CurvePreferences 是真正生效的组白名单。
//
// 客户端首发的 key_share 通常是 X25519MLKEM768 + X25519，所以这里只留 P-384
// （它在客户端的 supported_groups 里，但不在 key_share 里）——服务端据此发
// HelloRetryRequest，客户端补发带 P-384 key_share 的第二个 ClientHello。
//
// 原始字节仍由前置的 tapproxy 记录，本进程只负责促成 HRR。
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	var (
		addr  = flag.String("addr", "127.0.0.1:0", "监听地址")
		cert  = flag.String("cert", "", "证书链 PEM")
		key   = flag.String("key", "", "私钥 PEM")
		curve = flag.String("curve", "P384", "唯一允许的组：P384 / P256 / P521 / X25519")
	)
	flag.Parse()

	if *cert == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "need -cert and -key")
		os.Exit(2)
	}

	curves := map[string]tls.CurveID{
		"P256": tls.CurveP256, "P384": tls.CurveP384,
		"P521": tls.CurveP521, "X25519": tls.X25519,
	}
	cid, ok := curves[*curve]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown curve %q\n", *curve)
		os.Exit(2)
	}

	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load cert: %v\n", err)
		os.Exit(1)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		// 只留一个组 —— 客户端首发的 key_share 里没有它，服务端就必须发 HRR。
		CurvePreferences: []tls.CurveID{cid},
		NextProtos:       []string{"http/1.1"},
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "hrrserver ready on %s (curve=%s)\n",
		ln.Addr().String(), *curve)

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Connection", "close")
			fmt.Fprint(w, "ok")
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	_ = srv.Serve(tls.NewListener(ln, cfg))
}
