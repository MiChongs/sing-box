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
	// Host 头（多个时每次随机挑一个）
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

	// 服务端地址（用于缺 Host 时的 fallback）
	serverHost string
	serverAddr M.Socksaddr

	// 是否走 HTTPS（决定 URL scheme 和 transport 类型）
	useTLS bool
	// 是否启用了 Reality（影响 auto mode 选择）
	hasReality bool
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

var cachedChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" +
	chromeMajorVersion() + ".0.0.0 Safari/537.36"

// chromeMajorVersion 用日期外推出一个"合理的"版本号（和 mihomo 思路一致），
// 避免 UA 永远停在编译期常量（那会留下指纹）。
func chromeMajorVersion() string {
	// 基准：Chrome 120 (2023-12-06)。每 ~4 周一个大版本。
	const baseline = 120
	const baselineTs = int64(1701820800) // 2023-12-06 UTC
	elapsed := time.Now().Unix() - baselineTs
	if elapsed <= 0 {
		return strconv.Itoa(baseline)
	}
	weeks := elapsed / (7 * 86400)
	return strconv.Itoa(baseline + int(weeks/4))
}

// applyDefaultHeaders 在 Chrome "fetch" 语义下补齐 header；不覆盖用户已有值。
func applyDefaultHeaders(h http.Header) {
	if h.Get("User-Agent") == "" {
		h.Set("User-Agent", cachedChromeUA)
	}
	if h.Get("Accept") == "" {
		h.Set("Accept", "*/*")
	}
	if h.Get("Accept-Language") == "" {
		h.Set("Accept-Language", "en-US,en;q=0.9")
	}
	if h.Get("Cache-Control") == "" {
		h.Set("Cache-Control", "no-cache")
	}
	if h.Get("Pragma") == "" {
		h.Set("Pragma", "no-cache")
	}
	if h.Get("Sec-Fetch-Mode") == "" {
		h.Set("Sec-Fetch-Mode", "cors")
	}
	if h.Get("Sec-Fetch-Dest") == "" {
		h.Set("Sec-Fetch-Dest", "empty")
	}
	if h.Get("Sec-Fetch-Site") == "" {
		h.Set("Sec-Fetch-Site", "same-origin")
	}
	if h.Get("Priority") == "" {
		h.Set("Priority", "u=1, i")
	}
	// X-Requested-With 被某些 Xray 服务端日志期望存在（标记 CORS 预检已通过）
	if h.Get("X-Requested-With") == "" {
		h.Set("X-Requested-With", "XMLHttpRequest")
	}
}

// applyRefererPadding 把 padding 塞进 Referer header 里（默认 placement）。
// 格式: Referer: <absolute-request-url>?x_padding=<random>
func (c *config) applyRefererPadding(req *http.Request) {
	length := c.padding.rand()
	if length <= 0 {
		return
	}
	refURL := *req.URL // shallow copy
	q := refURL.Query()
	q.Set(paddingQueryKey, generatePadding(length))
	refURL.RawQuery = q.Encode()
	req.Header.Set(paddingRefererHD, refURL.String())
}

// generatePadding 产生长度为 n 的可打印 ASCII 字符串（Xray Tokenish 近似）。
// 用 crypto/rand 避免被流量分析者通过 RNG 特征反推。
func generatePadding(n int) string {
	if n <= 0 {
		return ""
	}
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, n)
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	for i, b := range raw {
		buf[i] = charset[int(b)%len(charset)]
	}
	return string(buf)
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

	transport, err := buildTransport(dialer, serverAddr, tlsConfig)
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
	// alpn = ["h3"] 暂不支持 — 显式报错好于装 http2.Transport 静默失败。
	if len(alpn) == 1 && alpn[0] == "h3" {
		return nil, E.New("xhttp: HTTP/3 transport not yet implemented (alpn=[\"h3\"])")
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

	gotConn := make(chan struct{}, 1)
	traceCtx := httptrace.WithClientTrace(reqCtx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			select {
			case gotConn <- struct{}{}:
			default:
			}
		},
	})

	req, err := http.NewRequestWithContext(traceCtx, methodPost, u.String(), pr)
	if err != nil {
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	c.fillStreamRequest(req, host)

	wrc := newWaitReadCloser()
	setupErr := make(chan error, 1)

	go func() {
		resp, err := c.transport.RoundTrip(req)
		if err != nil {
			setupErr <- err
			close(gotConn) // 可能 gotConn 一直没触发（DNS/拨号失败），解阻塞
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
	case <-gotConn:
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
	uStream.Path = appendPath(uStream.Path, session)

	pr, pw := io.Pipe()
	conn := newLateXHTTPConn(pw, c.cfg.serverAddr.TCPAddr())

	reqCtx, reqCancel := context.WithCancel(c.ctx)
	stopLink := linkContexts(ctx, reqCancel)
	defer stopLink()

	gotConn := make(chan struct{}, 1)
	downCtx := httptrace.WithClientTrace(reqCtx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			select {
			case gotConn <- struct{}{}:
			default:
			}
		},
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
	c.fillStreamRequest(downReq, host)

	wrc := newWaitReadCloser()
	downErr := make(chan error, 1)

	go func() {
		resp, err := c.transport.RoundTrip(downReq)
		if err != nil {
			downErr <- err
			close(gotConn)
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
	case <-gotConn:
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
	upReq, err := http.NewRequestWithContext(reqCtx, methodPost, uStream.String(), pr)
	if err != nil {
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	c.fillStreamRequest(upReq, host)

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
	uDown.Path = appendPath(uDown.Path, session)

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

	gotConn := make(chan struct{}, 1)
	downCtx := httptrace.WithClientTrace(reqCtx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			select {
			case gotConn <- struct{}{}:
			default:
			}
		},
	})
	downReq, err := http.NewRequestWithContext(downCtx, methodGet, uDown.String(), nil)
	if err != nil {
		reqCancel()
		writerCancel()
		return nil, err
	}
	c.fillStreamRequest(downReq, host)
	downReq.Header.Set("Accept", contentTypeSSE)

	wrc := newWaitReadCloser()
	downErr := make(chan error, 1)
	go func() {
		resp, err := c.transport.RoundTrip(downReq)
		if err != nil {
			downErr <- err
			close(gotConn)
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
	case <-gotConn:
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
// fillStreamRequest — 公共 header + padding 填充
// ──────────────────────────────────────────────────────────────────────

func (c *Client) fillStreamRequest(req *http.Request, host string) {
	// 1) 用户配置的 headers 作为基底
	h := cloneHeader(c.cfg.headers)
	if h == nil {
		h = http.Header{}
	}
	// 2) Chrome fetch 默认 headers
	applyDefaultHeaders(h)
	// 3) stream mode 的 body 设 grpc（packet-up 时 body 由 packetUpWriter 单独管理）
	if req.Body != nil {
		h.Set("Content-Type", contentTypeGRPC)
	}
	req.Header = h
	req.Host = host

	// 4) padding
	c.cfg.applyRefererPadding(req)
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
	u.Path = appendPath(u.Path, w.session, seqStr)

	req, err := http.NewRequestWithContext(w.ctx, methodPost, u.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(data))

	h := cloneHeader(w.cfg.headers)
	if h == nil {
		h = http.Header{}
	}
	applyDefaultHeaders(h)
	// packet-up 上行默认不带 Content-Type（与 Xray 一致；服务端按长度读）
	req.Header = h
	req.Host = w.host
	w.cfg.applyRefererPadding(req)

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
