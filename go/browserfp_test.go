package browserfp

import (
	"bytes"
	"strings"
	"testing"
)

// UA → (品牌, 版本)。Chromium 系衍生浏览器取的是**内核 Chrome 版本**。
func TestParseUA(t *testing.T) {
	cases := []struct {
		ua    string
		brand string
		ver   uint16
	}{
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36", "chrome", 150},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0", "firefox", 135},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1", "safari-mobile", 18},
	}
	for _, c := range cases {
		b, v, err := ParseUA(c.ua)
		if err != nil {
			t.Errorf("ParseUA(%.40s…) 报错: %v", c.ua, err)
			continue
		}
		if b != c.brand || v != c.ver {
			t.Errorf("ParseUA 得 (%s,%d)，期望 (%s,%d)", b, v, c.brand, c.ver)
		}
	}
}

// **认不出就报错，绝不顶替**：这是整个库最重要的一条约束。
// 拿 Chrome 的指纹配 Safari 的 UA 比不伪装更显眼。
func TestSelectNeverFallsBack(t *testing.T) {
	for _, ua := range []string{
		"",
		"curl/8.4.0",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"python-requests/2.31.0",
	} {
		p, err := SelectUA(ua)
		if err == nil {
			t.Errorf("UA %q 竟然选出了 profile %s —— 绝不该顶替", ua, p.ID)
			continue
		}
		var se *SelectError
		if !asSelectError(err, &se) {
			t.Errorf("UA %q 的错误不是 *SelectError（拿不到分类）: %v", ua, err)
			continue
		}
		switch se.Reason {
		case ReasonNoUA, ReasonUnknownUA, ReasonNoProfile, ReasonNoH2:
		default:
			t.Errorf("UA %q 的 Reason=%q 不在有限枚举内", ua, se.Reason)
		}
	}
}


// requireKeygen 在密钥交换不可用时跳过，并把原因说清楚。
// **不要改成静默 return** —— 那会让"Keygen 全挂"看起来像测试通过。
func requireKeygen(t *testing.T, p *Profile) *Keys {
	t.Helper()
	k, err := p.Keygen()
	if err != nil {
		t.Skipf("跳过：本机密钥交换不可用（%v）。"+
			"macOS + Go 宿主已知问题：只能 dlopen libcrypto，EVP keygen 会失败；"+
			"OpenResty(Linux) 走 RTLD_DEFAULT 不受影响。OpenSSL=%q", err, OpenSSLVersion())
	}
	return k
}

func asSelectError(err error, out **SelectError) bool {
	se, ok := err.(*SelectError)
	if ok {
		*out = se
	}
	return ok
}

// Select 必须同时保证 TLS profile 与 h2 指纹都在 —— 只有前者的话，
// 每个这样的请求都要白白握完一次手才失败。
func TestSelectRequiresBothLayers(t *testing.T) {
	p, err := SelectUA("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
	if err != nil {
		t.Fatalf("chrome 150 应该可用: %v", err)
	}
	if p.ID == "" {
		t.Error("profile id 为空")
	}
	if !strings.HasPrefix(p.JA4, "t13") {
		t.Errorf("JA4 形状不对: %q", p.JA4)
	}
	if !strings.Contains(p.Akamai, "|") {
		t.Errorf("akamai 形状不对: %q", p.Akamai)
	}
	if e := p.Engine(); e != "chromium" {
		t.Errorf("engine 得 %q，期望 chromium", e)
	}
}

// ClientHello 是完整 record（含 5 字节头），且 GREASE 每次重随机 ——
// **同一 profile 连续两次产出的字节本来就应该不同**（RFC 8701）。
func TestClientHelloIsRecordAndGreaseVaries(t *testing.T) {
	p, err := SelectUA("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
	if err != nil {
		t.Fatal(err)
	}
	var recs [][]byte
	for i := 0; i < 2; i++ {
		k := requireKeygen(t, p)
		rec, err := p.ClientHello("example.com", k)
		k.Close()
		if err != nil {
			t.Fatalf("ClientHello: %v", err)
		}
		if len(rec) < 5 || rec[0] != 0x16 || rec[1] != 0x03 {
			t.Fatalf("不是 TLS handshake record: % x", rec[:min(8, len(rec))])
		}
		body := int(rec[3])<<8 | int(rec[4])
		if body+5 != len(rec) {
			t.Errorf("record 长度字段 %d 与实际 %d 对不上", body+5, len(rec))
		}
		recs = append(recs, rec)
	}
	if bytes.Equal(recs[0], recs[1]) {
		t.Error("两次 ClientHello 完全相同 —— GREASE 没有每连接随机（RFC 8701）")
	}
}

// key_share 可能不止一组：六成以上生产 UA 落在需要 X25519MLKEM768 的 profile 上，
// Firefox 还会同时发 P-256。
func TestKeygenGroupsAndDerive(t *testing.T) {
	p, err := SelectUA("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0")
	if err != nil {
		t.Fatal(err)
	}
	k := requireKeygen(t, p)
	defer k.Close()
	if len(k.Groups()) == 0 {
		t.Fatal("一组 key_share 都没有")
	}
	// 拿一个不存在的组要报错，不能静默返回垃圾
	if _, err := k.Derive(0xFFFF, []byte{1, 2, 3}); err == nil {
		t.Error("对不存在的组 Derive 竟然成功了")
	}
	// Close 后再用要报错
	k.Close()
	if _, err := k.Derive(k.Groups()[0], []byte{1}); err == nil {
		t.Error("Close 之后 Derive 竟然成功了")
	}
}

// Close 必须可重复调用（defer + 显式调用是常见写法）
func TestKeysCloseIdempotent(t *testing.T) {
	p, err := SelectUA("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
	if err != nil {
		t.Fatal(err)
	}
	k := requireKeygen(t, p)
	for i := 0; i < 3; i++ {
		if err := k.Close(); err != nil {
			t.Fatalf("第 %d 次 Close 报错: %v", i+1, err)
		}
	}
}

// h2 开场字节一个都不能少：Akamai 指纹取的正是这几帧。
func TestH2Preface(t *testing.T) {
	p, err := SelectUA("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
	if err != nil {
		t.Fatal(err)
	}
	pre, pseudo, err := p.H2Preface()
	if err != nil {
		t.Fatal(err)
	}
	const magic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if !bytes.HasPrefix(pre, []byte(magic)) {
		t.Errorf("开场不是 h2 MAGIC: % x", pre[:min(24, len(pre))])
	}
	// 伪头顺序是 Akamai 指纹第四段，Chrome 是 m,a,s,p
	if pseudo != "m,a,s,p" {
		t.Errorf("chrome 伪头序得 %q，期望 m,a,s,p", pseudo)
	}
	if !strings.HasSuffix(p.Akamai, pseudo) {
		t.Errorf("akamai 末段 %q 与 H2Preface 给的 %q 对不上", p.Akamai, pseudo)
	}
}

// JA4For(sni) 与注册表里记录的 JA4 **本来就应该不同**：
// 注册表绝大多数采自 nosni 场景，带 SNI 时第一段必然变（d/i 标志 + 扩展数）。
// 这条断言是为了防止有人"修正"成相等 —— 那会让线上比对得出错误结论。
func TestJA4ForDiffersFromRegistryValue(t *testing.T) {
	p, err := SelectUA("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
	if err != nil {
		t.Fatal(err)
	}
	// JA4For 内部要 Keygen，密钥交换不可用时同样跳过（理由见 requireKeygen）
	requireKeygen(t, p).Close()
	live, err := p.JA4For("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(live, "t13") {
		t.Errorf("现算 JA4 形状不对: %q", live)
	}
	// 第一段（含 SNI 标志与扩展数）应当不同；后两段哈希可能相同也可能不同，不断言
	regSeg := strings.SplitN(p.JA4, "_", 2)[0]
	liveSeg := strings.SplitN(live, "_", 2)[0]
	if regSeg == liveSeg && strings.Contains(regSeg, "i") {
		t.Errorf("注册表值 %q 与带 SNI 现算值 %q 第一段相同 —— 注册表多为 nosni 采集，"+
			"相同说明取值口径变了，线上比对会被误导", p.JA4, live)
	}
}

// 两层一致性：TLS 与 h2 必须出自同一引擎，否则是现实中不存在的组合。
func TestCoherence(t *testing.T) {
	chrome, err := SelectUA("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
	if err != nil {
		t.Fatal(err)
	}
	firefox, err := SelectUA("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0")
	if err != nil {
		t.Fatal(err)
	}
	if !Coherence(chrome.JA4, chrome.Akamai) {
		t.Error("chrome 自己的两层竟然判为不一致")
	}
	// 阴性对照：跨引擎必须判不一致，否则这个函数等于没用
	if Coherence(chrome.JA4, firefox.Akamai) {
		t.Error("chrome 的 JA4 配 firefox 的 h2 竟然判为一致 —— 这是现实中不存在的组合")
	}
}

func TestCountAndLookupJA4(t *testing.T) {
	if n := Count(); n < 50 {
		t.Errorf("profile 总数 %d，太少了（应有 80+）", n)
	}
	if p := LookupJA4("t13d0000h0_000000000000_000000000000"); p != nil {
		t.Errorf("陌生 JA4 竟然命中了 %s —— 不该做近似匹配", p.ID)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
