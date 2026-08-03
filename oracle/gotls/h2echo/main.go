// h2echo —— 本地 HTTP/2 服务端，用来验网关这条链能不能真的说 h2。
//
// 只回一个固定 JSON。**指纹判据不在这里** —— 对端实际看到的 Akamai 指纹由
// spec 里的第三方回显门禁负责；这个服务端只回答"我们的 h2 客户端能不能把
// 请求发出去、把响应读回来"。
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"golang.org/x/net/http2"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "")
	cert := flag.String("cert", "", "")
	key := flag.String("key", "", "")
	flag.Parse()

	c, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "h2echo ready on %s\n", ln.Addr())

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		fmt.Fprintf(w, `{"proto":%q,"method":%q,"path":%q,"authority":%q}`,
			r.Proto, r.Method, r.URL.Path, r.Host)
	})
	srv := &http.Server{Handler: mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{c},
			NextProtos: []string{"h2", "http/1.1"}}}
	http2.ConfigureServer(srv, &http2.Server{})
	log.Fatal(srv.ServeTLS(ln, "", ""))
}
