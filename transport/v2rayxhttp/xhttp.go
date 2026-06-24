// Package v2rayxhttp 实现 XTLS/Xray XHTTP (aka splithttp) 传输协议的客户端。
//
// 协议对齐来源:
//   - XTLS/Xray-core/transport/internet/splithttp (MPL-2.0, 参考用)
//   - MetaCubeX/mihomo/transport/xhttp            (GPL-3.0, 实现参考)
//
// 本实现不 vendor mihomo / Xray 源码（避免拉入庞大 fork 依赖链），而是依据
// 两者协议规范用 sing-box 自有 deps (stdlib net/http + golang.org/x/net/http2)
// 重写。协议关键点:
//
//   1. Path 结构（与 mihomo / XTLS-Xray 完全对齐）:
//      stream-one:                     POST  <base>/                （无 session — h2 stream 天然隔离）
//      stream-up upload / download:    POST  <base>/<session>  /  GET <base>/<session>
//      packet-up download:              GET   <base>/<session>
//      packet-up upload (每条):         POST  <base>/<session>/<seq>
//      session 是 16-byte 随机 hex；seq 是自 0 递增的十进制。
//      *** 历史 bug: 早期把 session 也拼进了 stream-one 的 URL，被 Xray 服务端
//      当成 stream-up 半截上行而拒绝 (404 / 立即关连接)，表现为 urltest 永远
//      不通、xhttp outbound 完全不可用。fix: stream-one 路径必须保持 <base>/。
//
//   2. 上行 Content-Type = application/grpc（stream 模式 req.Body 非 nil 时）
//      packet-up 上行 Content-Type 缺省（服务端按 payload 解析）
//
//   3. Padding: 默认放在 Referer header 里，形式 Referer: <URL>?x_padding=<random>。
//      部分 CDN / WAF 会对 URL query 里的未知字段报错，放 Referer 更稳。
//
//   4. 默认浏览器伪装 header (Chrome fetch variant): Accept: */*,
//      Cache-Control: no-cache, Pragma: no-cache, Sec-Fetch-Mode: cors,
//      Sec-Fetch-Dest: empty, Sec-Fetch-Site: same-origin, Priority: u=1,i,
//      Sec-CH-UA-*, User-Agent = 动态生成 Chrome 版本号 UA。
//
//   5. Deadlock-avoidance: RoundTrip 会阻塞等对端返回 200 后才交出 response.Body，
//      而 CDN 又可能等上行 body 才发 response —— 必然死锁。解法是用 httptrace
//      GotConn 回调，检测到 TCP 建立后立即返回 conn；response body 经 WaitReadCloser
//      异步交付给 Read 路径。
package v2rayxhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

// ──────────────────────────────────────────────────────────────────────
// Config — 将 option.V2RayXHTTPOptions 规范化为协议层需要的形态
// ──────────────────────────────────────────────────────────────────────

type xhttpRange struct {
	Min int
	Max int
}

func (r xhttpRange) rand() int {
	if r.Max <= r.Min {
		return r.Min
	}
	return r.Min + mrand.Intn(r.Max-r.Min+1)
}

func parseRange(s, fallback string) (xhttpRange, error) {
	if strings.TrimSpace(s) == "" {
		s = fallback
	}
	if s == "" {
		return xhttpRange{}, nil
	}
	parts := strings.Split(strings.TrimSpace(s), "-")
	switch len(parts) {
	case 1:
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return xhttpRange{}, err
		}
		return xhttpRange{v, v}, nil
	case 2:
		lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return xhttpRange{}, err
		}
		hi, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return xhttpRange{}, err
		}
		if lo < 0 || hi < lo {
			return xhttpRange{}, fmt.Errorf("invalid range: %s", s)
		}
		return xhttpRange{lo, hi}, nil
	default:
		return xhttpRange{}, fmt.Errorf("invalid range: %s", s)
	}
}

type config struct {
	hosts []string
	// 基础路径，恒以 / 开头且以 / 结尾
	path string
	// 额外请求头（来自用户配置）
	headers http.Header
	// Mode: stream-one / stream-up / packet-up
	mode string

	// Padding 范围
	padding xhttpRange

	// packet-up 参数
	scMaxEachPostBytes   int
	scMinPostsIntervalMs xhttpRange

	// ─── XTLS/Xray PR#5414 反 CDN 探测扩展 ───
	xPaddingObfsMode  bool
	xPaddingKey       string
	xPaddingHeader    string
	xPaddingPlacement string
	xPaddingMethod    PaddingMethod

	uplinkHTTPMethod string

	sessionPlacement string
	sessionKey       string
	seqPlacement     string
	seqKey           string

	uplinkDataPlacement string
	uplinkDataKey       string
	uplinkChunkSize     xhttpRange

	// PR#5802 浏览器伪装类型: "" / "chrome" / "firefox" / "edge" / "golang"
	userAgent string

	// ─── 服务端 (inbound) 字段 ───
	scMaxBufferedPosts  int
	serverMaxHeaderBytes int
	noGRPCHeader         bool

	// PR#5711 XHTTP/3 拥塞控制
	quicCongestion string // "bbr" / "reno" / "force-brutal"
	quicUp         uint64 // force-brutal 带宽 bytes/sec
	// 服务端地址（用于缺 Host 时的 fallback）
	serverHost string
	serverAddr M.Socksaddr

	// 是否走 HTTPS（决定 URL scheme 和 transport 类型）
	useTLS bool
	// 是否启用了 Reality（影响 auto mode 选择）
	hasReality bool
}

// validatePlacement 包装 switch 风格的合法值校验。
func validatePlacement(field, value string, allowed ...string) (string, error) {
	for _, a := range allowed {
		if value == a {
			return value, nil
		}
	}
	return "", E.New("xhttp: unsupported ", field, ": ", value)
}

func newConfig(opts *option.V2RayXHTTPOptions, serverAddr M.Socksaddr, hasReality bool, useTLS bool) (*config, error) {
	if opts == nil {
		return nil, E.New("xhttp: missing options")
	}
	c := &config{
		hosts:              append([]string(nil), opts.Host...),
		path:               normalizePath(opts.Path),
		headers:            cloneHeader(opts.Headers.Build()),
		mode:               normalizeMode(opts.Mode, hasReality, useTLS),
		scMaxEachPostBytes: opts.ScMaxEachPostBytes,
		serverAddr:         serverAddr,
		useTLS:             useTLS,
		hasReality:         hasReality,
	}
	if c.headers == nil {
		c.headers = http.Header{}
	}
	p, err := parseRange(opts.XPaddingBytes, defaultPaddingRange)
	if err != nil {
		return nil, E.Cause(err, "xhttp: invalid x_padding_bytes")
	}
	c.padding = p
	if c.scMaxEachPostBytes <= 0 {
		c.scMaxEachPostBytes = defaultScMaxEachPostBytes
	}
	iv, _ := parseRange("", strconv.Itoa(cmpDefault(opts.ScMinPostsIntervalMs, defaultScMinPostsIntervalMs)))
	c.scMinPostsIntervalMs = iv

	c.serverHost = serverAddr.AddrString()
	if serverAddr.Port != 0 {
		c.serverHost = net.JoinHostPort(serverAddr.AddrString(), strconv.Itoa(int(serverAddr.Port)))
	}
	if len(c.hosts) == 0 {
		c.hosts = []string{serverAddr.AddrString()}
	}

	// ── PR#5414 字段规范化：与 Xray Build() 一致 ──
	c.xPaddingObfsMode = opts.XPaddingObfsMode
	c.xPaddingKey = opts.XPaddingKey
	if c.xPaddingKey == "" {
		c.xPaddingKey = paddingQueryKey
	}
	c.xPaddingHeader = opts.XPaddingHeader
	if c.xPaddingHeader == "" {
		c.xPaddingHeader = "X-Padding"
	}
	if opts.XPaddingPlacement == "" {
		c.xPaddingPlacement = PlacementQueryInHeader
	} else {
		c.xPaddingPlacement, err = validatePlacement("x_padding_placement", opts.XPaddingPlacement,
			PlacementQueryInHeader, PlacementCookie, PlacementHeader, PlacementQuery)
		if err != nil {
			return nil, err
		}
	}
	switch opts.XPaddingMethod {
	case "":
		c.xPaddingMethod = PaddingMethodRepeatX
	case string(PaddingMethodRepeatX), string(PaddingMethodTokenish):
		c.xPaddingMethod = PaddingMethod(opts.XPaddingMethod)
	default:
		return nil, E.New("xhttp: unsupported x_padding_method: ", opts.XPaddingMethod)
	}

	if opts.UplinkHTTPMethod == "" {
		c.uplinkHTTPMethod = methodPost
	} else {
		c.uplinkHTTPMethod = strings.ToUpper(opts.UplinkHTTPMethod)
	}

	// PR#5720: 默认改为 PlacementAuto (与 PlacementBody 在客户端等价)。
	// auto 让服务端能从 header+cookie+body 三处拼接 payload，client 这边仍走 body。
	if opts.UplinkDataPlacement == "" {
		c.uplinkDataPlacement = PlacementAuto
	} else {
		c.uplinkDataPlacement, err = validatePlacement("uplink_data_placement", opts.UplinkDataPlacement,
			PlacementAuto, PlacementBody, PlacementCookie, PlacementHeader)
		if err != nil {
			return nil, err
		}
		// auto/body 任何 mode 都允许；cookie/header 必须 packet-up。
		if (c.uplinkDataPlacement == PlacementCookie || c.uplinkDataPlacement == PlacementHeader) && c.mode != ModePacketUp {
			return nil, E.New("xhttp: uplink_data_placement=", c.uplinkDataPlacement,
				" requires mode=packet-up (got ", c.mode, ")")
		}
	}

	if c.uplinkHTTPMethod == methodGet && c.mode != ModePacketUp {
		return nil, E.New("xhttp: uplink_http_method=GET requires mode=packet-up (got ", c.mode, ")")
	}

	if opts.SessionPlacement == "" {
		c.sessionPlacement = PlacementPath
	} else {
		c.sessionPlacement, err = validatePlacement("session_placement", opts.SessionPlacement,
			PlacementPath, PlacementCookie, PlacementHeader, PlacementQuery)
		if err != nil {
			return nil, err
		}
	}

	if opts.SeqPlacement == "" {
		c.seqPlacement = PlacementPath
	} else {
		c.seqPlacement, err = validatePlacement("seq_placement", opts.SeqPlacement,
			PlacementPath, PlacementCookie, PlacementHeader, PlacementQuery)
		if err != nil {
			return nil, err
		}
		// PR#5720 移除了 "session=path 强制 seq=path" 约束。允许 session 在 path、seq 在
		// header/cookie/query，xray 服务端的 ExtractMetaFromRequest 也按 placement 独立解析。
	}

	c.sessionKey = opts.SessionKey
	if c.sessionKey == "" && c.sessionPlacement != PlacementPath {
		switch c.sessionPlacement {
		case PlacementCookie, PlacementQuery:
			c.sessionKey = "x_session"
		case PlacementHeader:
			c.sessionKey = "X-Session"
		}
	}
	c.seqKey = opts.SeqKey
	if c.seqKey == "" && c.seqPlacement != PlacementPath {
		switch c.seqPlacement {
		case PlacementCookie, PlacementQuery:
			c.seqKey = "x_seq"
		case PlacementHeader:
			c.seqKey = "X-Seq"
		}
	}
	c.uplinkDataKey = opts.UplinkDataKey
	if c.uplinkDataKey == "" && c.uplinkDataPlacement != PlacementBody && c.uplinkDataPlacement != PlacementAuto {
		switch c.uplinkDataPlacement {
		case PlacementCookie:
			c.uplinkDataKey = "x_data"
		case PlacementHeader:
			c.uplinkDataKey = "X-Data"
		}
	}
	// UplinkChunkSize 从 v26.3.27 起改为 range。默认值与 Xray 一致：
	//   cookie  → 2048-3072 (~2-3 KiB)
	//   header  → 3000-4000 (~3-4 KB)
	//   其他    → 留空 (走 scMaxEachPostBytes，仅 body 模式相关)
	// From < 64 时强制提到 64（chunk 太小会产生过多 header / cookie）。
	chunkRange, err := parseRange(opts.UplinkChunkSize, "")
	if err != nil {
		return nil, E.Cause(err, "xhttp: invalid uplink_chunk_size")
	}
	if chunkRange.Max == 0 {
		switch c.uplinkDataPlacement {
		case PlacementCookie:
			chunkRange = xhttpRange{Min: 2048, Max: 3072}
		case PlacementHeader:
			chunkRange = xhttpRange{Min: 3000, Max: 4000}
		}
	} else if chunkRange.Min < 64 {
		chunkRange.Min = 64
		if chunkRange.Max < 64 {
			chunkRange.Max = 64
		}
	}
	c.uplinkChunkSize = chunkRange

	// PR#5802 浏览器伪装。默认 "chrome"；"" / "chrome" / "firefox" / "edge" / "golang"
	// 之外的值当作用户自定义 UA 字符串，由 caller 直接写到 headers 里，
	// tryDefaultHeadersWith 不再附加 Sec-CH-UA / Sec-Fetch-*。
	switch opts.UserAgent {
	case "", "chrome", "firefox", "edge", "golang":
		c.userAgent = opts.UserAgent
	default:
		return nil, E.New("xhttp: unsupported user_agent: ", opts.UserAgent)
	}

	// ── 服务端字段 ──
	c.scMaxBufferedPosts = opts.ScMaxBufferedPosts
	if c.scMaxBufferedPosts <= 0 {
		c.scMaxBufferedPosts = defaultScMaxBufferedPosts
	}
	c.serverMaxHeaderBytes = int(opts.ServerMaxHeaderBytes)
	if c.serverMaxHeaderBytes <= 0 {
		c.serverMaxHeaderBytes = 8192
	}
	c.noGRPCHeader = opts.NoGRPCHeader

	// PR#5711 QUIC 拥塞控制
	c.quicCongestion = opts.QuicCongestion
	c.quicUp = opts.QuicUp
	switch c.quicCongestion {
	case "", "bbr", "reno":
	case "force-brutal":
		if c.quicUp > 0 && c.quicUp < 65536 {
			return nil, E.New("xhttp: quic_up must be at least 65536 bytes/s")
		}
		if c.quicUp == 0 {
			return nil, E.New("xhttp: quic_congestion=force-brutal requires quic_up")
		}
	default:
		return nil, E.New("xhttp: unknown quic_congestion: ", c.quicCongestion,
			" (valid: bbr, reno, force-brutal)")
	}

	return c, nil
}

func cmpDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := make(http.Header, len(h))
	for k, vs := range h {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

func normalizePath(p string) string {
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

// normalizeMode 与 mihomo / Xray 服务端 auto 默认一致：
//   - Reality 场景：stream-one（H2 双向单流，最低开销）
//   - 其他（包括普通 TLS、纯 HTTP）：packet-up（每包独立 POST，CDN/WAF 兼容性最好）
//
// 之前 useTLS → stream-one 的判定和 Xray 服务端 auto 不一致，会导致客户端
// 用 H2 单流握上 stream-one 路径而服务端期待 packet-up 路径，握手必失败。
func normalizeMode(m string, hasReality, useTLS bool) string {
	_ = useTLS
	if m == "" || m == ModeAuto {
		if hasReality {
			return ModeStreamOne
		}
		return ModePacketUp
	}
	return m
}

func (c *config) pickHost() string {
	switch len(c.hosts) {
	case 0:
		return c.serverAddr.AddrString()
	case 1:
		return c.hosts[0]
	default:
		// math/rand is fine here — this is only a traffic-pattern choice,
		// not a security-sensitive decision.
		return c.hosts[mrand.Intn(len(c.hosts))]
	}
}

func (c *config) baseURL(host string) *url.URL {
	scheme := "http"
	if c.useTLS {
		scheme = "https"
	}
	return &url.URL{Scheme: scheme, Host: host, Path: c.path}
}

// appendPath 把一个或多个段接到 path，保证段间正好一个斜杠。
func appendPath(p string, segs ...string) string {
	for _, s := range segs {
		if s == "" {
			continue
		}
		if !strings.HasSuffix(p, "/") {
			p += "/"
		}
		p += s
	}
	return p
}

// ──────────────────────────────────────────────────────────────────────
// Browser masquerade (Chrome fetch variant) — headers 默认值
// ──────────────────────────────────────────────────────────────────────


// applyXPadding 把 padding 写进 request。两条路径：
//
//  1. 默认 (xPaddingObfsMode=false)：保留与 mihomo / 老 Xray 兼容的行为 —
//     padding 塞进 Referer header 里的 query (Referer: <URL>?x_padding=XXX...)
//     字符是重复 X（HPACK 静态 huffman 给 'X' 8-bit 编码，wire 长度恒等）。
//
//  2. obfsMode=true：按配置的 xPaddingPlacement / Key / Header / Method 走
//     —— 对齐 XTLS/Xray-core PR#5414 (https://github.com/XTLS/Xray-core/pull/5414)
//     绕开 CDN 对 "x_padding=XXXX..." 的精确字符串匹配。
func (c *config) applyXPadding(req *http.Request) {
	length := c.padding.rand()
	if length <= 0 {
		return
	}
	pc := XPaddingConfig{Length: length}
	if c.xPaddingObfsMode {
		pc.Placement = XPaddingPlacement{
			Placement: c.xPaddingPlacement,
			Key:       c.xPaddingKey,
			Header:    c.xPaddingHeader,
			RawURL:    req.URL.String(),
		}
		pc.Method = c.xPaddingMethod
	} else {
		pc.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       paddingQueryKey,
			Header:    paddingRefererHD,
			RawURL:    req.URL.String(),
		}
		pc.Method = PaddingMethodRepeatX
	}
	applyPaddingToRequest(req, pc)
}

// appendURLPath 把一个段追加到 req.URL.Path，保证段间正好一个斜杠。
func appendURLPath(u *url.URL, value string) {
	if value == "" {
		return
	}
	if strings.HasSuffix(u.Path, "/") {
		u.Path += value
	} else {
		u.Path += "/" + value
	}
}

// applyMetaToRequest 按 sessionPlacement / seqPlacement 把 sessionId / seqStr
// 装进 path / query / header / cookie。
//
// stream-one 模式不需要 session（H2 stream 自带隔离），sessionId 传 ""。
// packet-up 模式两个都有；stream-up 只有 sessionId（无 seq）。
func (c *config) applyMetaToRequest(req *http.Request, sessionId, seqStr string) {
	if sessionId != "" {
		switch c.sessionPlacement {
		case PlacementPath:
			appendURLPath(req.URL, sessionId)
		case PlacementQuery:
			q := req.URL.Query()
			q.Set(c.sessionKey, sessionId)
			req.URL.RawQuery = q.Encode()
		case PlacementHeader:
			req.Header.Set(c.sessionKey, sessionId)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: c.sessionKey, Value: sessionId, Path: "/"})
		}
	}
	if seqStr != "" {
		switch c.seqPlacement {
		case PlacementPath:
			appendURLPath(req.URL, seqStr)
		case PlacementQuery:
			q := req.URL.Query()
			q.Set(c.seqKey, seqStr)
			req.URL.RawQuery = q.Encode()
		case PlacementHeader:
			req.Header.Set(c.seqKey, seqStr)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: c.seqKey, Value: seqStr, Path: "/"})
		}
	}
}

// applyUplinkData 当 uplinkDataPlacement != body 时，把 base64(data) 切片塞进
// header 或 cookie。对齐 PR#5414 服务端拼装规则：
//   - header: <key>-0, <key>-1, ... + <key>-Length: <total> + <key>-Upstream: 1
//   - cookie: <key>_0, <key>_1, ... + <key>_upstream=1
//
// 返回 true 表示数据已塞进 header/cookie（caller 应把 req.Body 置 nil）。
func (c *config) applyUplinkData(req *http.Request, data []byte) bool {
	// PlacementBody / PlacementAuto: 客户端走 body，由 caller 写 req.Body。
	if c.uplinkDataPlacement == PlacementBody || c.uplinkDataPlacement == PlacementAuto || len(data) == 0 {
		return false
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	// Xray v26.3.27 PR#5720 把 UplinkChunkSize 改成 Range，每片大小在区间里随机抽。
	// 这模仿真实 CDN 用户上传分块时大小自然抖动，避免每片都是死板的 4KB 留指纹。
	switch c.uplinkDataPlacement {
	case PlacementHeader:
		i := 0
		idx := 0
		for i < len(encoded) {
			step := c.uplinkChunkSize.rand()
			if step <= 0 {
				step = len(encoded) - i
			}
			end := i + step
			if end > len(encoded) {
				end = len(encoded)
			}
			req.Header.Set(fmt.Sprintf("%s-%d", c.uplinkDataKey, idx), encoded[i:end])
			i = end
			idx++
		}
		req.Header.Set(c.uplinkDataKey+"-Length", strconv.Itoa(len(encoded)))
		req.Header.Set(c.uplinkDataKey+"-Upstream", "1")
	case PlacementCookie:
		i := 0
		idx := 0
		for i < len(encoded) {
			step := c.uplinkChunkSize.rand()
			if step <= 0 {
				step = len(encoded) - i
			}
			end := i + step
			if end > len(encoded) {
				end = len(encoded)
			}
			req.AddCookie(&http.Cookie{
				Name:  fmt.Sprintf("%s_%d", c.uplinkDataKey, idx),
				Value: encoded[i:end],
				Path:  "/",
			})
			i = end
			idx++
		}
		req.AddCookie(&http.Cookie{Name: c.uplinkDataKey + "_upstream", Value: "1", Path: "/"})
	}
	return true
}

// ──────────────────────────────────────────────────────────────────────
// Client — 外暴露给 transport/v2ray 的 V2RayClientTransport 实现
// ──────────────────────────────────────────────────────────────────────

type Client struct {
	ctx    context.Context
	cfg    *config
	dialer N.Dialer

	transport http.RoundTripper
	// packetUp seq 在多条连接间不复用；每条 Dial 新开一个 PacketUpWriter，
	// 但底层 transport 共享 —— h2 下这样能 H2-multiplex 到同一 TCP 上。
	closeOnce sync.Once
}

// NewClient 创建 XHTTP 客户端。dialer 是到 xhttp 服务器的底层 dialer；
// serverAddr 是目标 host:port；tlsConfig 为 nil 时走 HTTP (stream-up/packet-up
// only — 没有 H2，stream-one 不可用)。
func NewClient(
	ctx context.Context,
	dialer N.Dialer,
	serverAddr M.Socksaddr,
	options *option.V2RayXHTTPOptions,
	tlsConfig boxtls.Config,
) (adapter.V2RayClientTransport, error) {
	hasReality := false
	if tlsConfig != nil {
		// Reality 用 bit-identical client-hello 绕检测，在此只用来决定 auto mode
		// 的 fallback 偏好；具体 TLS 握手由 sing-box tls 层做。
		if names := tlsConfig.NextProtos(); len(names) > 0 {
			for _, n := range names {
				if n == "reality" {
					hasReality = true
				}
			}
		}
	}

	cfg, err := newConfig(options, serverAddr, hasReality, tlsConfig != nil)
	if err != nil {
		return nil, err
	}

	transport, err := buildTransport(dialer, serverAddr, tlsConfig, cfg)
	if err != nil {
		return nil, err
	}

	return &Client{
		ctx:       ctx,
		cfg:       cfg,
		dialer:    dialer,
		transport: transport,
	}, nil
}

// buildTransport 按 ALPN 派发底层 RoundTripper（与 mihomo / Xray 对齐）：
//
//	显式 alpn = ["http/1.1"]   → http.Transport（裸 H1 长 POST + GET，CDN 兼容性最好）
//	显式 alpn = ["h3"]         → 暂未实现（需 quic-go），返回错误而不是错配 transport
//	其他（默认 / ["h2", ...]） → http2.Transport
//
// 之前不分 ALPN 一律走 http2.Transport，遇到 alpn=["http/1.1"] 的服务端配置时
// TLS 实际协商出 h1，http2.Transport.RoundTrip 立即失败 (`http2: unsupported`)，
// DialContext 整个失败 → URLTest 永远不通、xhttp outbound 完全不可用。
//
// 无 TLS 时只能走 H1（h2 需要 ALPN）。
func buildTransport(
	dialer N.Dialer,
	serverAddr M.Socksaddr,
	tlsConfig boxtls.Config,
	cfg *config,
) (http.RoundTripper, error) {
	if tlsConfig == nil {
		return &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, N.NetworkTCP, serverAddr)
			},
			ForceAttemptHTTP2: false,
			IdleConnTimeout:   ConnIdleTimeout,
			MaxIdleConns:      16,
		}, nil
	}

	alpn := tlsConfig.NextProtos()
	tlsDialer := boxtls.NewDialer(dialer, tlsConfig)

	// alpn = ["http/1.1"] → 强制 H1 transport，复用同一 TLS dial。
	if len(alpn) == 1 && alpn[0] == "http/1.1" {
		return &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tlsDialer.DialTLSContext(ctx, serverAddr)
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tlsDialer.DialTLSContext(ctx, serverAddr)
			},
			ForceAttemptHTTP2: false,
			IdleConnTimeout:   ConnIdleTimeout,
			MaxIdleConns:      16,
		}, nil
	}
	// alpn = ["h3"] → HTTP/3，由 buildH3Transport 实现（with_quic 构建标签）。
	// 未启用 with_quic 时返回明确错误信息（见 h3_stub.go）。
	if len(alpn) == 1 && alpn[0] == "h3" {
		return buildH3Transport(dialer, serverAddr, tlsConfig, cfg)
	}

	// 默认 / 多值 → H2。若 ALPN 完全为空（未配置），补 ["h2", "http/1.1"]
	// 让 TLS 优先尝试 h2，失败时仍能 fallback 到 h1（但仍走 http2.Transport，
	// 这是 mihomo / Xray 的同构行为 — 默认假定服务端支持 h2）。
	if len(alpn) == 0 {
		tlsConfig.SetNextProtos([]string{"h2", "http/1.1"})
	}
	return &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			c, err := tlsDialer.DialTLSContext(ctx, serverAddr)
			if err != nil {
				return nil, err
			}
			return c, nil
		},
		ReadIdleTimeout:  ChromeH2KeepAlivePeriod,
		PingTimeout:      15 * time.Second,
		MaxReadFrameSize: 1 << 20,
		AllowHTTP:        false,
	}, nil
}

// DialContext 建立一条新逻辑连接。每次调用都产生独立的 session。
func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	switch c.cfg.mode {
	case ModeStreamOne:
		return c.dialStreamOne(ctx)
	case ModeStreamUp:
		return c.dialStreamUp(ctx)
	case ModePacketUp:
		return c.dialPacketUp(ctx)
	default:
		return nil, E.New("xhttp: unknown mode: ", c.cfg.mode)
	}
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		closeTransport(c.transport)
	})
	return nil
}

func closeTransport(rt http.RoundTripper) {
	switch t := rt.(type) {
	case *http.Transport:
		t.CloseIdleConnections()
	case *http2.Transport:
		t.CloseIdleConnections()
	}
}

func randSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// gotConnSignal 封装 httptrace.GotConn 的一次性通知通道。
// 语义：
//   - signal() 由 GotConn 回调调用（可能多次：http2 内部重试 / 连接池事件），
//     向 wait() 发送一个建连成功信号，已满或已关闭都静默丢弃。
//   - close() 由错误/取消路径调用，用来解阻塞还在 wait() 上挂着的协程。
//
// 关键点：signal 与 close 之间必须互斥，否则 "在已关闭通道上发送" 会 panic
// （历史 bug：x/net/http2 在 RoundTrip 返回后仍可能回调 GotConn，与错误路径
// 的 close(gotConn) 赛跑）。这里用 Mutex 保证两者严格互斥，并用 closed 标记
// 让 close 幂等。
type gotConnSignal struct {
	mu     sync.Mutex
	ch     chan struct{}
	closed bool
}

func newGotConnSignal() *gotConnSignal {
	return &gotConnSignal{ch: make(chan struct{}, 1)}
}

func (g *gotConnSignal) signal() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	select {
	case g.ch <- struct{}{}:
	default:
	}
}

func (g *gotConnSignal) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	g.closed = true
	close(g.ch)
}

func (g *gotConnSignal) wait() <-chan struct{} { return g.ch }

// ──────────────────────────────────────────────────────────────────────
// stream-one: 单 POST H2 双向 (req.Body ↑ / resp.Body ↓)
// ──────────────────────────────────────────────────────────────────────

func (c *Client) dialStreamOne(ctx context.Context) (net.Conn, error) {
	// stream-one 不需要 session：单条 H2 双向流，无须服务端做 upload/download
	// 关联。带 session 反而会被 Xray 服务端当成 stream-up 半截上行直接拒绝。
	host := c.cfg.pickHost()
	u := c.cfg.baseURL(host)

	pr, pw := io.Pipe()
	conn := newLateXHTTPConn(pw, c.cfg.serverAddr.TCPAddr())

	// reqCtx 跟 conn 生命周期绑定；ctx (dial 的上下文) 只用来 cancel
	// 握手阶段。拿到 tunnel 后 ctx 取消 / 过期都不应影响后续读写。
	reqCtx, reqCancel := context.WithCancel(c.ctx)
	stopLink := linkContexts(ctx, reqCancel)
	defer stopLink()

	gotConn := newGotConnSignal()
	traceCtx := httptrace.WithClientTrace(reqCtx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { gotConn.signal() },
	})

	req, err := http.NewRequestWithContext(traceCtx, c.cfg.uplinkHTTPMethod, u.String(), pr)
	if err != nil {
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	c.cfg.fillRequest(req, host, "", "")

	wrc := newWaitReadCloser()
	setupErr := make(chan error, 1)

	go func() {
		resp, err := c.transport.RoundTrip(req)
		if err != nil {
			setupErr <- err
			gotConn.close() // 解阻塞 wait()；与 signal() 互斥，避免 send on closed。
			wrc.closeWithError(err)
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			wrc.closeWithError(fmt.Errorf("xhttp stream-one: bad status %s", resp.Status))
			return
		}
		wrc.set(resp.Body)
	}()

	// 等 TCP 连上再返回（打破 CDN 缓冲头的死锁），但给 dial ctx 一个
	// 逃生口：ctx 过期 / RoundTrip 拨号失败都要可以 bail。
	select {
	case <-gotConn.wait():
		// OK，tunnel 已建立
	case err := <-setupErr:
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	case <-ctx.Done():
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, ctx.Err()
	}

	// 把 setupErr 信号路由回 wrc 供 Read 一侧消费
	go func() {
		select {
		case err := <-setupErr:
			if err != nil {
				wrc.closeWithError(err)
			}
		case <-reqCtx.Done():
		}
	}()

	conn.setupReader(wrc, nil)
	conn.onClose = func() {
		_ = pr.Close()
		reqCancel()
	}
	return conn, nil
}

// ──────────────────────────────────────────────────────────────────────
// stream-up: POST 上行 + GET 下行，session path 相同（method 区分）
// ──────────────────────────────────────────────────────────────────────

func (c *Client) dialStreamUp(ctx context.Context) (net.Conn, error) {
	session := randSessionID()
	host := c.cfg.pickHost()

	uStream := c.cfg.baseURL(host)

	pr, pw := io.Pipe()
	conn := newLateXHTTPConn(pw, c.cfg.serverAddr.TCPAddr())

	reqCtx, reqCancel := context.WithCancel(c.ctx)
	stopLink := linkContexts(ctx, reqCancel)
	defer stopLink()

	gotConn := newGotConnSignal()
	downCtx := httptrace.WithClientTrace(reqCtx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { gotConn.signal() },
	})

	// 先发 GET 下行，等 TCP 建立；然后再发 POST 上行。顺序要先 down 再 up，
	// 服务端语义：GET 创建 session 上下文，POST 投递上行 body。
	downReq, err := http.NewRequestWithContext(downCtx, methodGet, uStream.String(), nil)
	if err != nil {
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	c.cfg.fillRequest(downReq, host, session, "")

	wrc := newWaitReadCloser()
	downErr := make(chan error, 1)

	go func() {
		resp, err := c.transport.RoundTrip(downReq)
		if err != nil {
			downErr <- err
			gotConn.close() // 解阻塞 wait()；与 signal() 互斥。
			wrc.closeWithError(err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			wrc.closeWithError(fmt.Errorf("xhttp stream-up down: bad status %s", resp.Status))
			return
		}
		wrc.set(resp.Body)
	}()

	select {
	case <-gotConn.wait():
	case err := <-downErr:
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	case <-ctx.Done():
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, ctx.Err()
	}

	// 上行：body = pipeR。Write 到 pw 即流向 upload 请求。
	upReq, err := http.NewRequestWithContext(reqCtx, c.cfg.uplinkHTTPMethod, uStream.String(), pr)
	if err != nil {
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	c.cfg.fillRequest(upReq, host, session, "")

	go func() {
		resp, err := c.transport.RoundTrip(upReq)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = pw.CloseWithError(fmt.Errorf("xhttp stream-up up: bad status %s", resp.Status))
		}
	}()

	conn.setupReader(wrc, nil)
	conn.onClose = func() {
		_ = pr.Close()
		reqCancel()
	}
	return conn, nil
}

// ──────────────────────────────────────────────────────────────────────
// packet-up: 每 Write 一次 POST (带 seq)，GET 负责 SSE 下行
// ──────────────────────────────────────────────────────────────────────

func (c *Client) dialPacketUp(ctx context.Context) (net.Conn, error) {
	session := randSessionID()
	host := c.cfg.pickHost()

	uDown := c.cfg.baseURL(host)

	writerCtx, writerCancel := context.WithCancel(c.ctx)
	writer := &packetUpWriter{
		ctx:       writerCtx,
		cancel:    writerCancel,
		cfg:       c.cfg,
		transport: c.transport,
		session:   session,
		host:      host,
	}
	writer.writeCond.L = &writer.writeMu
	writer.maxEachPost = c.cfg.scMaxEachPostBytes
	writer.minInterval = time.Duration(c.cfg.scMinPostsIntervalMs.rand()) * time.Millisecond

	conn := newLateXHTTPConn(writer, c.cfg.serverAddr.TCPAddr())

	reqCtx, reqCancel := context.WithCancel(c.ctx)
	stopLink := linkContexts(ctx, reqCancel)
	defer stopLink()

	gotConn := newGotConnSignal()
	downCtx := httptrace.WithClientTrace(reqCtx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { gotConn.signal() },
	})
	downReq, err := http.NewRequestWithContext(downCtx, methodGet, uDown.String(), nil)
	if err != nil {
		reqCancel()
		writerCancel()
		return nil, err
	}
	c.cfg.fillRequest(downReq, host, session, "")
	downReq.Header.Set("Accept", contentTypeSSE)

	wrc := newWaitReadCloser()
	downErr := make(chan error, 1)
	go func() {
		resp, err := c.transport.RoundTrip(downReq)
		if err != nil {
			downErr <- err
			gotConn.close() // 解阻塞 wait()；与 signal() 互斥。
			wrc.closeWithError(err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			wrc.closeWithError(fmt.Errorf("xhttp packet-up down: bad status %s", resp.Status))
			return
		}
		wrc.set(resp.Body)
	}()

	select {
	case <-gotConn.wait():
	case err := <-downErr:
		reqCancel()
		writerCancel()
		return nil, err
	case <-ctx.Done():
		reqCancel()
		writerCancel()
		return nil, ctx.Err()
	}

	conn.setupReader(wrc, nil)
	conn.onClose = func() {
		writerCancel()
		reqCancel()
	}
	return conn, nil
}

// ──────────────────────────────────────────────────────────────────────
// fillRequest — 公共 header + session/seq + padding 填充
// ──────────────────────────────────────────────────────────────────────

// fillRequest 在 net/http.Request 上铺好头、塞 session/seq、再加 padding。
// 顺序敏感：padding 的 queryInHeader 模式会读 req.URL.String()，所以必须在
// applyMetaToRequest 之后再做，否则 Referer 里少 session id。
//
// 调用约定:
//   stream-one:        fillRequest(req, host, "",        "")
//   stream-up down/up: fillRequest(req, host, sessionId, "")
//   packet-up down:    fillRequest(req, host, sessionId, "")
//   packet-up post:    fillRequest(req, host, sessionId, seqStr)
func (c *config) fillRequest(req *http.Request, host, sessionId, seqStr string) {
	h := cloneHeader(c.headers)
	if h == nil {
		h = http.Header{}
	}
	// 把 config 里的 user_agent 选项推到 header 里给 tryDefaultHeadersWith 派发：
	//   "" / "chrome" / "firefox" / "edge" / "golang" → masquerade 集合
	//   用户在 headers 里直接写了一个 UA 字符串 → 不动 (走 default chrome 集合)
	if c.userAgent != "" && h.Get("User-Agent") == "" {
		h.Set("User-Agent", c.userAgent)
	}
	tryDefaultHeadersWith(h, "fetch")
	if req.Body != nil && !c.noGRPCHeader {
		h.Set("Content-Type", contentTypeGRPC)
	}
	req.Header = h
	req.Host = host

	c.applyMetaToRequest(req, sessionId, seqStr)
	c.applyXPadding(req)
}

// ──────────────────────────────────────────────────────────────────────
// packetUpWriter — packet-up 模式下 conn.Write 的实际承载
// ──────────────────────────────────────────────────────────────────────

type packetUpWriter struct {
	ctx    context.Context
	cancel context.CancelFunc

	cfg       *config
	transport http.RoundTripper
	session   string
	host      string

	maxEachPost int
	minInterval time.Duration

	writeMu   sync.Mutex
	writeCond sync.Cond
	seq       uint64
	buf       []byte
	timer     *time.Timer
	flushErr  error
}

func (w *packetUpWriter) Write(p []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if w.flushErr != nil {
		return 0, w.flushErr
	}

	// 切片式积累；超过 maxEachPost 就触发同步 flush。
	data := bytes.NewBuffer(p)
	for data.Len() > 0 {
		if w.timer == nil {
			w.timer = time.AfterFunc(w.minInterval, w.flush)
		}
		room := w.maxEachPost - len(w.buf)
		if room > 0 {
			w.buf = append(w.buf, data.Next(room)...)
		}
		if len(w.buf) >= w.maxEachPost {
			w.writeCond.Wait()
			if w.flushErr != nil {
				return 0, w.flushErr
			}
		}
	}
	return len(p), nil
}

func (w *packetUpWriter) flush() {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	defer w.writeCond.Broadcast()

	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	if w.flushErr != nil || len(w.buf) == 0 {
		return
	}

	chunk := w.buf
	w.buf = nil
	if err := w.post(chunk); err != nil {
		w.flushErr = err
	}
}

func (w *packetUpWriter) post(data []byte) error {
	seqStr := strconv.FormatUint(w.seq, 10)
	w.seq++

	u := w.cfg.baseURL(w.host)

	// 当 uplinkDataPlacement != body 时数据走 header/cookie，请求体置空。
	// 这是为 GET-only CDN 准备的：method=GET 时 net/http 拒绝带 body。
	var bodyReader io.Reader = bytes.NewReader(data)
	var contentLength int64 = int64(len(data))
	willPlaceInHeaderOrCookie := w.cfg.uplinkDataPlacement != PlacementBody
	if willPlaceInHeaderOrCookie {
		bodyReader = nil
		contentLength = 0
	}

	req, err := http.NewRequestWithContext(w.ctx, w.cfg.uplinkHTTPMethod, u.String(), bodyReader)
	if err != nil {
		return err
	}
	req.ContentLength = contentLength

	h := cloneHeader(w.cfg.headers)
	if h == nil {
		h = http.Header{}
	}
	if w.cfg.userAgent != "" && h.Get("User-Agent") == "" {
		h.Set("User-Agent", w.cfg.userAgent)
	}
	tryDefaultHeadersWith(h, "fetch")
	// packet-up 上行默认不带 Content-Type（与 Xray 一致；服务端按长度读）
	req.Header = h
	req.Host = w.host

	// session + seq 进 path/cookie/header/query（默认 path 兼容旧版）
	w.cfg.applyMetaToRequest(req, w.session, seqStr)
	// uplink data 进 header/cookie（如果配置了）
	if willPlaceInHeaderOrCookie {
		w.cfg.applyUplinkData(req, data)
	}
	// padding 最后 — 让 queryInHeader 能捕到完整最终 URL
	w.cfg.applyXPadding(req)

	resp, err := w.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xhttp packet-up post seq=%d: bad status %s", w.seq-1, resp.Status)
	}
	return nil
}

func (w *packetUpWriter) Close() error {
	// 让后台 flush 完成（最多 1s）
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.flush()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
	w.cancel()
	return nil
}

// ──────────────────────────────────────────────────────────────────────
// waitReadCloser — 异步交付 HTTP response.Body
// ──────────────────────────────────────────────────────────────────────

type waitReadCloser struct {
	wait chan struct{}
	once sync.Once

	rc  io.ReadCloser
	err error

	closed atomic.Bool
}

func newWaitReadCloser() *waitReadCloser {
	return &waitReadCloser{wait: make(chan struct{})}
}

func (w *waitReadCloser) set(rc io.ReadCloser) {
	w.once.Do(func() {
		w.rc = rc
		close(w.wait)
	})
	if w.closed.Load() && rc != nil {
		_ = rc.Close()
	}
}

func (w *waitReadCloser) closeWithError(err error) {
	w.once.Do(func() {
		w.err = err
		close(w.wait)
	})
}

func (w *waitReadCloser) Read(p []byte) (int, error) {
	<-w.wait
	if w.rc == nil {
		return 0, w.err
	}
	return w.rc.Read(p)
}

func (w *waitReadCloser) Close() error {
	w.closed.Store(true)
	w.once.Do(func() {
		w.err = net.ErrClosed
		close(w.wait)
	})
	if w.rc != nil {
		return w.rc.Close()
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────
// linkContexts — 让 handshake ctx 过期时 cancel tunnel ctx（通过 AfterFunc）
// ──────────────────────────────────────────────────────────────────────

// linkContexts: 在 ctx 过期时调用 cancel；返回 stop 函数取消关联。
// 用于：dial 阶段 ctx 过期应拆 tunnel，但一旦 Dial 成功返回 conn，后续读写
// 不应再被 dial ctx 影响，此时 caller 调 stop() 取消联动。
func linkContexts(ctx context.Context, cancel context.CancelFunc) func() bool {
	return context.AfterFunc(ctx, func() {
		cancel()
	})
}

func init() {
	// math/rand global source seed. Go 1.20+ auto-seeds per-goroutine, this
	// only matters on older runtimes — harmless elsewhere.
	mrand.New(mrand.NewSource(time.Now().UnixNano()))
}
