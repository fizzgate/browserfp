// 用 enetx/surf 的 profile 打本地观测点，采 Chrome 150 / Firefox 148 的指纹。
//
// 为什么单独接这个库：curl_cffi 停在 Chrome 136 / Firefox 135，tls-client 停在
// Chrome 146 / Firefox 147，而真机是 Chrome 151 / Firefox 149 —— 中间是空洞。
// surf 恰好提供 Chrome 150 与 Firefox 148，落在空洞里。
//
// 对 Chrome 尤其关键：我们已知 chrome_146 的 sig_algs 不含 ML-DSA，而真机 151
// 含。150 这个点能把变更区间从 (146,151] 缩到 (146,150] 或 (150,151]。
//
// 依赖拉取需走镜像：proxy.golang.org 在本网络超时，用 GOPROXY=https://goproxy.cn,direct
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/enetx/surf"
)

func main() {
	var (
		url     = flag.String("url", "", "观测点 URL")
		browser = flag.String("browser", "chrome", "chrome | firefox")
	)
	flag.Parse()

	if *url == "" {
		fmt.Fprintln(os.Stderr, "need -url")
		os.Exit(2)
	}

	b := surf.NewClient().Builder()
	switch *browser {
	case "chrome":
		b = b.Impersonate().Chrome()
	case "firefox":
		b = b.Impersonate().FireFox()
	default:
		fmt.Fprintf(os.Stderr, "unknown browser %q\n", *browser)
		os.Exit(2)
	}

	// 观测点收到 ClientHello（或首个 HEADERS）就断，这里的错误是预期的。
	resp := b.Build().Get(*url).Do()
	if resp.IsErr() {
		fmt.Printf("%s\tSENT\t%v\n", *browser, resp.Err())
		return
	}
	fmt.Printf("%s\tSENT\tok\n", *browser)
}
