// 用 bogdanfinn/tls-client 的 profile 表逐个打本地观测点，采指纹 golden。
//
// 为什么不手工解析 profiles/*.go：那 5851 行是 Go 结构体字面量，手抄成 JSON
// 既费事又会引入翻译错误。让库自己按 profile 发一次真实 ClientHello，采到的是
// 线上字节，格式与 curl_cffi 那套 golden 完全一致，还能顺便验证这张表本身。
//
// 串行连接，一个 profile 一次，顺序与 -profiles 给的顺序一致——观测点按顺序
// 收，靠顺序对应而不是靠连接里的标识（ClientHello 里没有地方能塞标识）。
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	tls "github.com/bogdanfinn/utls"

	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

func main() {
	var (
		addr     = flag.String("addr", "", "观测点地址 host:port")
		list     = flag.Bool("list", false, "只列出全部 profile 名，不连接")
		selected = flag.String("profiles", "", "逗号分隔的 profile 名；空=全部")
		sni      = flag.String("sni", "", "SNI；空=不发 SNI（与真机浏览器采集条件一致）")
		timeout  = flag.Duration("timeout", 8*time.Second, "单次连接超时")
		h2       = flag.Bool("h2", false, "走完整 HTTP 栈以采 h2 层指纹")
	)
	flag.Parse()

	names := make([]string, 0, len(profiles.MappedTLSClients))
	for name := range profiles.MappedTLSClients {
		names = append(names, name)
	}
	sort.Strings(names)

	if *list {
		for _, n := range names {
			fmt.Println(n)
		}
		return
	}
	if *addr == "" {
		fmt.Fprintln(os.Stderr, "need -addr")
		os.Exit(2)
	}
	if *selected != "" {
		names = strings.Split(*selected, ",")
	}

	for _, name := range names {
		profile, ok := profiles.MappedTLSClients[name]
		if !ok {
			fmt.Printf("%s\tERR\tunknown profile\n", name)
			continue
		}
		if *h2 {
			// L2：走 tls-client 的 HTTP 栈，它会按 profile 发 h2 SETTINGS /
			// WINDOW_UPDATE / 伪头顺序 —— 那些字段只有走完整 HTTP 栈才发得出来，
			// 裸 UClient 握手拿不到。
			if err := probeHTTP(*addr, *sni, name, *timeout); err != nil {
				fmt.Printf("%s\tSENT\t%v\n", name, err)
				continue
			}
			fmt.Printf("%s\tSENT\tok\n", name)
			continue
		}
		if err := probe(*addr, *sni, profile, *timeout); err != nil {
			// 观测点收完 ClientHello 就断，握手必然失败——这里的 error 是预期的。
			// 真正的失败是连不上，两者都打出来由上层按是否收到 ClientHello 判定。
			fmt.Printf("%s\tSENT\t%v\n", name, err)
			continue
		}
		fmt.Printf("%s\tSENT\tok\n", name)
	}
}

func probe(addr, sni string, profile profiles.ClientProfile, timeout time.Duration) error {
	raw, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))

	cfg := &tls.Config{InsecureSkipVerify: true}
	if sni != "" {
		cfg.ServerName = sni
	} else {
		// 不发 SNI：与真机浏览器采集条件一致（Chrome 的 host-resolver-rules
		// 已失效，只能直连 IP），两侧同条件才可逐字段比对。
		cfg.ServerName = ""
		cfg.InsecureSkipVerify = true
	}

	// 三个 bool 是 bogdanfinn fork 的扩展：随机化扩展顺序 / 强制 HTTP1 /
	// 禁用 HTTP3。全给 false —— 采 golden 要的是 profile 的原样形态，
	// 随机化扩展顺序会让同一 profile 每次采到不同的扩展序列。
	conn := tls.UClient(raw, cfg, profile.GetClientHelloId(), false, false, false)
	defer conn.Close()
	return conn.Handshake()
}


// probeHTTP 用 tls-client 的 HTTP 栈发一次请求，好让它按 profile 发出
// h2 SETTINGS / WINDOW_UPDATE / PRIORITY / 伪头顺序。观测点收到第一个
// HEADERS 帧就断，所以这里的 error 是预期的。
func probeHTTP(addr, sni, profileName string, timeout time.Duration) error {
	host := sni
	if host == "" {
		host = strings.Split(addr, ":")[0]
	}
	port := addr[strings.LastIndex(addr, ":")+1:]

	opts := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(int(timeout.Seconds())),
		tlsclient.WithClientProfile(profiles.MappedTLSClients[profileName]),
		tlsclient.WithInsecureSkipVerify(),
		tlsclient.WithNotFollowRedirects(),
	}
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), opts...)
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get(fmt.Sprintf("https://%s:%s/", host, port))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
