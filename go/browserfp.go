// Package browserfp 构造浏览器的网络指纹：TLS 1.3 ClientHello 与 HTTP/2 开场帧。
//
// 给一条 User-Agent，输出那个浏览器会发的字节。与 Lua 绑定共用同一份 C 实现
// （../csrc），profile 表也是同一份，两边不会漂移。
//
// # 认不出就报错，绝不顶替
//
// Select 认不出 UA、或该版本没有 profile 时返回错误，**不会退回另一个浏览器**。
// 拿 Chrome 的 TLS 指纹配 Safari 的 UA 比不伪装更显眼 —— 那正是指纹检测在找的东西。
//
// # 线程安全
//
// Profile 是只读的，可并发使用。Keys 持有私钥，**不可并发**，且用完必须 Close。
package browserfp

/*
#cgo CFLAGS: -I${SRCDIR}/../csrc -O2
#cgo LDFLAGS: -ldl
#include <stdlib.h>
#include <string.h>
#include "browserfp.h"
#include "browserfp_kx.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

// 密钥交换要先把 libcrypto 的符号解析出来。**懒初始化、只做一次**，与 Lua 绑定
// 一致（那边在 keygen/gen_key_shares 里各调一次 browserfp_kx_init(nil)）。
// 传 NULL = 用进程里已经加载的那份 libcrypto；解析不到时 keygen 会失败，
// 错误会指向"某某组生成密钥失败"，与真因（没初始化）毫无关系 —— 所以这里
// 把初始化的错误单独留住，第一时间报出来。
var (
	kxOnce sync.Once
	kxErr  error
)

// InitCrypto 显式指定 libcrypto 路径，**必须在任何 Keygen 之前调用**。
//
// 不调用时走自动探测：先看进程里有没有已加载的 libcrypto（OpenResty 那种宿主
// 直接命中），没有才按内置列表 dlopen。
//
// ⚠ macOS 已知问题：Go 宿主本身不链 libcrypto，只能走 dlopen，而 dlopen 来的
// 那份在 EVP keygen 上会失败（符号全部解析成功、OpenSSL_version 也能调，
// 但 EVP_PKEY_generate 返回错误）。同一份 .so 在 OpenResty 里是好的。
// 这条在 Linux 上未复现 —— 生产（Linux + OpenResty）走的是 RTLD_DEFAULT 那条路。
// 若你在 macOS 上要用 Keygen，先用本函数指定一份 Homebrew 的 libcrypto 试试；
// 仍失败请开 issue，不要绕过 —— 生成不出密钥就握不了手，静默降级只会更难查。
func InitCrypto(path string) error {
	kxOnce.Do(func() {
		var c *C.char
		if path != "" {
			c = C.CString(path)
			defer C.free(unsafe.Pointer(c))
		}
		if C.browserfp_kx_init(c) != 0 {
			kxErr = fmt.Errorf("初始化 libcrypto 失败(path=%q)", path)
		}
	})
	return kxErr
}

func kxInit() error {
	kxOnce.Do(func() {
		if C.browserfp_kx_init(nil) != 0 {
			kxErr = errors.New("解析 libcrypto 符号失败：进程里没有已加载的 libcrypto，" +
				"或版本太老不支持所需的 EVP 接口")
		}
	})
	return kxErr
}

// OpenSSLVersion 返回解析到的 OpenSSL 版本串（未初始化时为空）。
// **建议记进日志**：版本不同意味着能不能做 ML-KEM 不同。
func OpenSSLVersion() string {
	if err := kxInit(); err != nil {
		return ""
	}
	return C.GoString(C.browserfp_kx_openssl_version())
}

// Reason 是 Select 失败的**有限枚举**，供调用方做日志聚合与降级决策。
// 错误字符串是给人看的，不要拿它做判断。
type Reason string

const (
	ReasonNoUA      Reason = "no_ua"      // 没有 UA 可解析
	ReasonUnknownUA Reason = "unknown_ua" // UA 认不出品牌/版本
	ReasonNoProfile Reason = "no_profile" // 认出了品牌版本，但没有对应 profile
	ReasonNoH2      Reason = "no_h2"      // 有 TLS profile 但没有 h2 指纹（safari-mobile 12/13/14 就是）
)

// SelectError 带分类的选择失败。
type SelectError struct {
	Reason Reason
	Detail string
}

func (e *SelectError) Error() string { return string(e.Reason) + ": " + e.Detail }

// Spec 描述要伪装谁。目前只有 browser 一种 kind；bun / rust 等运行时后续加进来时
// 走同一个入口，按 Kind 分派（见 docs/browserfp-api-redesign.md 第 2 节）。
type Spec struct {
	Kind    string // 留空即 "browser"
	UA      string // 有 UA 就按 UA 解析，优先级高于 Brand/Version
	Brand   string // chrome / firefox / safari / edge / opera / *-mobile
	Version uint16
}

// Profile 是一个可用的浏览器指纹句柄。只读，可并发使用。
type Profile struct {
	p *C.browserfp_profile

	ID     string // 注册表 id，如 "real:edge"、"curl_cffi:chrome131"
	Brand  string
	Version uint16

	// JA4 是**注册表记录值**，其中绝大多数采自 nosni 场景。带 SNI 出网时第一段
	// 必然不同（d/i 标志 + 扩展数 ±1）。**不要拿它跟线上观测值直接比** ——
	// 要比就用 JA4For(sni) 现算。
	JA4 string

	// Akamai h2 指纹，形如 "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p"
	Akamai string
}

// ParseUA 从 User-Agent 解析品牌与主版本号。
//
// Chromium 系衍生浏览器（Edge/Opera）取的是**内核 Chrome 的版本**，不是自己那个 ——
// 实证：Opera 110 的 UA 里写着 Chrome/125，差了 15 个大版本。
func ParseUA(ua string) (brand string, version uint16, err error) {
	if strings.TrimSpace(ua) == "" {
		return "", 0, &SelectError{ReasonNoUA, "空 User-Agent"}
	}
	cua := C.CString(ua)
	defer C.free(unsafe.Pointer(cua))

	buf := make([]C.char, 32)
	var ver C.uint16_t
	// ⚠ 返回值是 **1=成功 / 0=失败**（不是 C 里常见的 0=成功）。
	// Lua 绑定判的也是 ~= 1；按 !=0 写会让每个 UA 都被判成认不出。
	if C.browserfp_parse_ua(cua, &buf[0], C.size_t(len(buf)), &ver) != 1 {
		d := ua
		if len(d) > 60 {
			d = d[:60] + "…"
		}
		return "", 0, &SelectError{ReasonUnknownUA, d}
	}
	return C.GoString(&buf[0]), uint16(ver), nil
}

// Select 按 spec 挑一个可用的 profile。
//
// **两层都要有**才算可用：TLS profile 与 h2 指纹。只查前者会让每个缺 h2 的请求
// 白白握完一次手才失败。
func Select(spec Spec) (*Profile, error) {
	if spec.Kind != "" && spec.Kind != "browser" {
		return nil, &SelectError{ReasonUnknownUA,
			fmt.Sprintf("kind=%q 暂不支持（目前只有 browser）", spec.Kind)}
	}

	brand, version := spec.Brand, spec.Version
	if spec.UA != "" {
		b, v, err := ParseUA(spec.UA)
		if err != nil {
			return nil, err
		}
		brand, version = b, v
	}
	if brand == "" {
		return nil, &SelectError{ReasonNoUA, "既没有 UA 也没有 brand"}
	}

	cb := C.CString(brand)
	defer C.free(unsafe.Pointer(cb))

	var confidence C.int
	p := C.browserfp_lookup_ua(cb, C.uint16_t(version), &confidence)
	if p == nil {
		return nil, &SelectError{ReasonNoProfile,
			fmt.Sprintf("%s %d 没有可用 profile", brand, version)}
	}
	h2 := C.browserfp_lookup_h2(cb, C.uint16_t(version))
	if h2 == nil {
		// 有 TLS 却没有 h2：握得上手但说不了话，出网即失败。宁可在这里拒绝。
		return nil, &SelectError{ReasonNoH2,
			fmt.Sprintf("%s %d 有 TLS profile 但没有 h2 指纹", brand, version)}
	}

	return &Profile{
		p:       p,
		ID:      C.GoString(p.id),
		Brand:   brand,
		Version: version,
		JA4:     C.GoString(p.ja4),
		Akamai:  C.GoString(h2.akamai),
	}, nil
}

// SelectUA 是 Select({UA: ua}) 的便捷包装。
func SelectUA(ua string) (*Profile, error) { return Select(Spec{UA: ua}) }

// Engine 返回该 profile 所属的引擎（chromium / gecko / webkit）。
// 实测 81 条 profile 无一跨引擎，所以这个值是良定义的。
func (p *Profile) Engine() string { return C.GoString(p.p.engine) }

// Count 返回内置 profile 总数（差分测试遍历用；生产请走 Select）。
func Count() int { return int(C.browserfp_profile_count()) }

// ---- 密钥交换 ----

// Keys 是一次连接用的密钥材料。**私钥不出这个对象**，用完必须 Close。
// 不可并发使用。
type Keys struct {
	groups []uint16
	ctxs   []unsafe.Pointer
	pubs   [][]byte
	closed bool
}

// Keygen 为这个 profile 生成全部需要的 key_share。
//
// **不止一组**：生产 UA 里六成以上落在需要 X25519MLKEM768 的 profile 上，
// Firefox 还会同时发 P-256。算共享密钥时要按服务端选中的组去取。
func (p *Profile) Keygen() (*Keys, error) {
	if err := kxInit(); err != nil {
		return nil, err
	}
	const maxGroups = 8
	groups := make([]C.uint16_t, maxGroups)
	lens := make([]C.size_t, maxGroups)
	n := int(C.browserfp_key_share_groups(p.p, &groups[0], &lens[0], C.size_t(maxGroups)))
	if n <= 0 {
		return nil, errors.New("该 profile 没有 key_share 组")
	}

	k := &Keys{}
	runtime.SetFinalizer(k, (*Keys).Close) // 忘了 Close 也不至于泄漏私钥
	for i := 0; i < n; i++ {
		g := groups[i]
		publen := C.browserfp_kx_pub_len(g)
		if publen == 0 {
			k.Close()
			return nil, fmt.Errorf("不支持的 key_share 组 0x%04x", uint16(g))
		}
		pub := make([]byte, int(publen))
		var ctx unsafe.Pointer
		if C.browserfp_kx_keygen(g, (*C.uint8_t)(unsafe.Pointer(&pub[0])),
			publen, &ctx) != 0 {
			k.Close()
			return nil, fmt.Errorf("组 0x%04x 生成密钥失败", uint16(g))
		}
		k.groups = append(k.groups, uint16(g))
		k.ctxs = append(k.ctxs, ctx)
		k.pubs = append(k.pubs, pub)
	}
	return k, nil
}

// Groups 返回这批密钥覆盖的组（顺序与 ClientHello 里一致）。
func (k *Keys) Groups() []uint16 { return append([]uint16(nil), k.groups...) }

// Derive 用服务端选中组的公钥算共享密钥。
func (k *Keys) Derive(group uint16, peer []byte) ([]byte, error) {
	if k.closed {
		return nil, errors.New("Keys 已 Close")
	}
	for i, g := range k.groups {
		if g != group {
			continue
		}
		slen := C.browserfp_kx_secret_len(C.uint16_t(group))
		if slen == 0 {
			return nil, fmt.Errorf("组 0x%04x 没有共享密钥长度", group)
		}
		out := make([]byte, int(slen))
		if len(peer) == 0 {
			return nil, errors.New("peer 公钥为空")
		}
		if C.browserfp_kx_derive(k.ctxs[i],
			(*C.uint8_t)(unsafe.Pointer(&peer[0])), C.size_t(len(peer)),
			(*C.uint8_t)(unsafe.Pointer(&out[0])), slen) != 0 {
			return nil, fmt.Errorf("组 0x%04x 算共享密钥失败", group)
		}
		return out, nil
	}
	return nil, fmt.Errorf("这批密钥里没有组 0x%04x（有 %v）", group, k.groups)
}

// Close 释放全部私钥。可重复调用。
func (k *Keys) Close() error {
	if k == nil || k.closed {
		return nil
	}
	k.closed = true
	for _, c := range k.ctxs {
		if c != nil {
			C.browserfp_kx_free(c)
		}
	}
	k.ctxs = nil
	runtime.SetFinalizer(k, nil)
	return nil
}

// ---- 字节构造 ----

// ClientHello 组装一条完整的 TLS record（**含 5 字节头**），可直接写进 socket。
//
// GREASE 值每次调用重新随机（RFC 8701 要求），Chrome 106 起的扩展顺序置换也在
// 这里做 —— 所以同一个 profile 连续调用产出的字节**本来就应该不同**。
func (p *Profile) ClientHello(sni string, keys *Keys) ([]byte, error) {
	if keys == nil || keys.closed {
		return nil, errors.New("需要一组有效的 Keys（先 Keygen）")
	}
	csni := C.CString(sni)
	defer C.free(unsafe.Pointer(csni))

	ks := make([]C.browserfp_keyshare, len(keys.groups))
	for i := range keys.groups {
		ks[i].group = C.uint16_t(keys.groups[i])
		ks[i].pub = (*C.uint8_t)(unsafe.Pointer(&keys.pubs[i][0]))
		ks[i].pub_len = C.size_t(len(keys.pubs[i]))
	}

	out := make([]byte, 8192)
	n := C.browserfp_build_client_hello_ex(p.p, csni, nil, nil,
		&ks[0], C.size_t(len(ks)), 0,
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)))
	if n <= 0 {
		return nil, fmt.Errorf("构造 ClientHello 失败（错误码 %d）", int(n))
	}
	return out[:int(n)], nil
}

// H2Preface 返回 HTTP/2 的开场字节（MAGIC + SETTINGS + WINDOW_UPDATE + PRIORITY）
// 与伪头顺序（如 "m,a,s,p"）。
//
// **一个字节都不要改**：Akamai 指纹取的正是这几帧。任何通用 h2 库都会发它自己的
// SETTINGS，那样 TLS 像 Chrome、h2 像那个库 —— 现实中不存在的组合，比不伪装还显眼。
func (p *Profile) H2Preface() (preface []byte, pseudoOrder string, err error) {
	cb := C.CString(p.Brand)
	defer C.free(unsafe.Pointer(cb))
	h2 := C.browserfp_lookup_h2(cb, C.uint16_t(p.Version))
	if h2 == nil {
		return nil, "", &SelectError{ReasonNoH2, p.Brand}
	}
	out := make([]byte, 512)
	n := C.browserfp_build_h2_preface(h2,
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)))
	if n <= 0 {
		return nil, "", fmt.Errorf("构造 h2 开场失败（错误码 %d）", int(n))
	}
	return out[:int(n)], C.GoString(C.browserfp_h2_pseudo(h2)), nil
}

// ---- 识别方向 ----

// JA4For 按给定 SNI 现算 JA4。**要与线上观测值比较就用它**，不要用 Profile.JA4
// （那是 nosni 场景采的记录值，第一段必然不同）。
func (p *Profile) JA4For(sni string) (string, error) {
	keys, err := p.Keygen()
	if err != nil {
		return "", err
	}
	defer keys.Close()
	rec, err := p.ClientHello(sni, keys)
	if err != nil {
		return "", err
	}
	return JA4(rec, 't')
}

// JA4 解析一条 ClientHello record 并算出 JA4。transport 传 't'(TCP) 或 'q'(QUIC)。
func JA4(record []byte, transport byte) (string, error) {
	if len(record) == 0 {
		return "", errors.New("空 record")
	}
	var h C.browserfp_hello
	if C.browserfp_parse_client_hello((*C.uint8_t)(unsafe.Pointer(&record[0])),
		C.size_t(len(record)), &h) != 0 {
		return "", errors.New("解析 ClientHello 失败")
	}
	buf := make([]C.char, C.TLSFP_JA4_LEN)
	if C.browserfp_ja4(&h, C.char(transport), &buf[0], C.size_t(len(buf))) != 0 {
		return "", errors.New("计算 JA4 失败")
	}
	return C.GoString(&buf[0]), nil
}

// LookupJA4 按 JA4 反查内置 profile。**不做近似匹配** —— 把陌生指纹归到最近的
// 已知 profile 会让盲区永远不可见。未命中返回 nil。
func LookupJA4(ja4 string) *Profile {
	c := C.CString(ja4)
	defer C.free(unsafe.Pointer(c))
	p := C.browserfp_lookup_ja4(c)
	if p == nil {
		return nil
	}
	return &Profile{p: p, ID: C.GoString(p.id), JA4: C.GoString(p.ja4)}
}

// Coherence 检查 JA4 与 Akamai h2 指纹是否出自同一引擎。
// 两层对不上就是「TLS 像 Chrome、h2 像 Firefox」这种现实中不存在的组合。
func Coherence(ja4, akamai string) bool {
	cj, ca := C.CString(ja4), C.CString(akamai)
	defer C.free(unsafe.Pointer(cj))
	defer C.free(unsafe.Pointer(ca))
	// 后两个出参用来取两侧引擎名；这里只要一致性结论，传 nil 即可
	return C.browserfp_coherence(cj, ca, nil, nil) == 0
}


// keygenOne 只生成一个组的密钥，供诊断/测试逐组定位用。
func keygenOne(group uint16) (*Keys, error) {
	if err := kxInit(); err != nil {
		return nil, err
	}
	publen := C.browserfp_kx_pub_len(C.uint16_t(group))
	if publen == 0 {
		return nil, fmt.Errorf("组 0x%04x 不支持", group)
	}
	pub := make([]byte, int(publen))
	var ctx unsafe.Pointer
	if C.browserfp_kx_keygen(C.uint16_t(group),
		(*C.uint8_t)(unsafe.Pointer(&pub[0])), publen, &ctx) != 0 {
		return nil, fmt.Errorf("组 0x%04x keygen 返回非 0", group)
	}
	k := &Keys{groups: []uint16{group}, ctxs: []unsafe.Pointer{ctx}, pubs: [][]byte{pub}}
	runtime.SetFinalizer(k, (*Keys).Close)
	return k, nil
}
