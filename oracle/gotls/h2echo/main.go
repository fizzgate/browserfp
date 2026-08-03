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
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "")
	cert := flag.String("cert", "", "")
	key := flag.String("key", "", "")
	// **默认按真实服务端的保守值**：Go 自己的默认是 1MB 帧 + 1MB 窗口，
	// 大到让 CONTINUATION 与发送侧流控这两条路径根本走不到 —— 门禁会因此
	// 「全绿但没验」。16384/65535 是 RFC 默认，也是 nginx 一类的常见值。
	maxFrame := flag.Int("maxframe", 16384, "advertise SETTINGS_MAX_FRAME_SIZE")
	// **故意低于 RFC 默认的 65535**：等于默认时，"客户端根本没读对端 SETTINGS"
	// 这个缺陷观察不到 —— 它会沿用默认值，而默认值恰好也对。
	initWin := flag.Int("initwin", 32768, "advertise SETTINGS_INITIAL_WINDOW_SIZE")
	// Go 在 MaxUploadBufferPerConnection < 65535 时会退回 1MB，所以连接窗口
	// 最小只能压到 65535。压不下去就意味着"无视发送窗口"这个缺陷在本地观察
	// 不到 —— 这一点写在 tlsfp_h2.lua 里。
	connWin := flag.Int("connwin", 65535, "advertise connection-level window")
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
		// ?slow=1：先睡再读。Go 的服务端是边读边补流控窗口的，handler 立刻
		// 读完时，客户端就算完全无视窗口也撞不上 FLOW_CONTROL_ERROR ——
		// 那条路径于是永远走不到。睡一下让窗口不被及时补回。
		if r.URL.Query().Get("slow") == "1" {
			time.Sleep(700 * time.Millisecond)
		}
		b, _ := io.ReadAll(r.Body)
		// 回显请求体长度与我们关心的那个头 —— 门禁要能断言「发出去的确实收到了」
		w.Header().Set("content-type", "application/json")
		w.Header().Set("x-echo-h", r.Header.Get("x-probe"))
		// ?big=N 时回 N 字节的填充，用来验收侧的流控窗口
		if n, err := strconv.Atoi(r.URL.Query().Get("big")); err == nil && n > 0 {
			w.Header().Set("x-pad-len", strconv.Itoa(n))
			fmt.Fprintf(w, `{"proto":%q,"pad":%q}`, r.Proto, strings.Repeat("x", n))
			return
		}
		fmt.Fprintf(w, `{"proto":%q,"method":%q,"path":%q,"authority":%q,"bodylen":%d,"probe":%q}`,
			r.Proto, r.Method, r.URL.Path, r.Host, len(b), r.Header.Get("x-probe"))
	})
	srv := &http.Server{Handler: mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{c},
			NextProtos: []string{"h2", "http/1.1"}}}
	http2.ConfigureServer(srv, &http2.Server{
		MaxReadFrameSize:              uint32(*maxFrame),
		MaxUploadBufferPerStream:      int32(*initWin),
		MaxUploadBufferPerConnection:  int32(*connWin),
	})
	log.Fatal(srv.ServeTLS(ln, "", ""))
}
