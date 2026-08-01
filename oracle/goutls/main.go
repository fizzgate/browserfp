// 用 refraction-networking/utls 的内置 ClientHelloID 打本地观测点。
//
// 为什么单独接：我们此前的 Go 采集器走 bogdanfinn/utls（tls-client 的 fork）。
// refraction 上游 v1.8.3-dev 比 v1.8.2 多两个 HelloID —— HelloFirefox_148 与
// HelloSafari_26_3 —— 且都正好落在我们的版本空洞里（Firefox 有 147 与真机 149，
// Safari 有 26.0 与真机 27）。
//
// 与其他采集器同条件：直连 IP、不发 SNI，两侧才可逐字段比对。
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
)

// 内置 ID 没有反射式的名字表，只能显式列。加新版本时这里要同步。
var ids = map[string]tls.ClientHelloID{
	"Chrome_58": tls.HelloChrome_58, "Chrome_62": tls.HelloChrome_62,
	"Chrome_70": tls.HelloChrome_70, "Chrome_72": tls.HelloChrome_72,
	"Chrome_83": tls.HelloChrome_83, "Chrome_87": tls.HelloChrome_87,
	"Chrome_96": tls.HelloChrome_96, "Chrome_100": tls.HelloChrome_100,
	"Chrome_102": tls.HelloChrome_102, "Chrome_106_Shuffle": tls.HelloChrome_106_Shuffle,
	"Chrome_115_PQ": tls.HelloChrome_115_PQ, "Chrome_120": tls.HelloChrome_120,
	"Chrome_120_PQ": tls.HelloChrome_120_PQ, "Chrome_131": tls.HelloChrome_131,
	"Chrome_133": tls.HelloChrome_133,
	"Firefox_55": tls.HelloFirefox_55, "Firefox_56": tls.HelloFirefox_56,
	"Firefox_63": tls.HelloFirefox_63, "Firefox_65": tls.HelloFirefox_65,
	"Firefox_99": tls.HelloFirefox_99, "Firefox_102": tls.HelloFirefox_102,
	"Firefox_105": tls.HelloFirefox_105, "Firefox_120": tls.HelloFirefox_120,
	"Firefox_148": tls.HelloFirefox_148,
	"Safari_16_0": tls.HelloSafari_16_0, "Safari_26_3": tls.HelloSafari_26_3,
	"Edge_85": tls.HelloEdge_85, "Edge_106": tls.HelloEdge_106,
	"IOS_11_1": tls.HelloIOS_11_1, "IOS_12_1": tls.HelloIOS_12_1,
	"IOS_13": tls.HelloIOS_13, "IOS_14": tls.HelloIOS_14,
	"Android_11_OkHttp": tls.HelloAndroid_11_OkHttp,
	"QQ_11_1": tls.HelloQQ_11_1, "360_7_5": tls.Hello360_7_5, "360_11_0": tls.Hello360_11_0,
}

func main() {
	var (
		addr     = flag.String("addr", "", "观测点 host:port")
		list     = flag.Bool("list", false, "只列名字")
		selected = flag.String("profiles", "", "逗号分隔；空=全部")
		timeout  = flag.Duration("timeout", 8*time.Second, "单次超时")
	)
	flag.Parse()

	names := make([]string, 0, len(ids))
	for n := range ids {
		names = append(names, n)
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
		id, ok := ids[name]
		if !ok {
			fmt.Printf("%s\tERR\tunknown\n", name)
			continue
		}
		raw, err := net.DialTimeout("tcp", *addr, *timeout)
		if err != nil {
			fmt.Printf("%s\tERR\tdial: %v\n", name, err)
			continue
		}
		_ = raw.SetDeadline(time.Now().Add(*timeout))
		// ServerName 留空 = 不发 SNI，与真机浏览器采集条件一致
		conn := tls.UClient(raw, &tls.Config{InsecureSkipVerify: true}, id)
		err = conn.Handshake() // 观测点收完 ClientHello 就断，报错是预期的
		fmt.Printf("%s\tSENT\t%v\n", name, err)
		conn.Close()
		raw.Close()
	}
}
