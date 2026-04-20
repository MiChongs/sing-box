package v2rayxhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	mathRand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"

	"golang.org/x/net/http2"
)

// Client 对应 V2RayXHTTPOptions.Mode 三种实现。
// DialContext 一次一条新"逻辑" net.Conn（不复用）：
//   stream-one: 一个 H2 duplex 请求
//   stream-up:  两个请求（POST 上，GET 下）
//   packet-up:  一个 GET 下，多个 POST 上（每次 Write）
type Client struct {
	ctx        context.Context
	dialer     N.Dialer
	serverAddr M.Socksaddr
	transport  http.RoundTripper
	httpClient *http.Client
	http2Mode  bool

	mode        string
	baseURL     url.URL
	host        []string
	headers     http.Header
	padding     paddingRange
	noSSE       bool
	maxEachPost int
	minInterval time.Duration

	// packet-up / stream-up 下用：sessionID 计数（避免不同 Dial 用同一 id）
	sessionSeq atomic.Uint64
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options *option.V2RayXHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	if options == nil {
		return nil, E.New("xhttp: missing options")
	}
	var transport http.RoundTripper
	http2Mode := false
	if tlsConfig == nil {
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
			MaxIdleConnsPerHost: 16,
		}
	} else {
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
		}
		tlsDialer := tls.NewDialer(dialer, tlsConfig)
		transport = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.STDConfig) (net.Conn, error) {
				return tlsDialer.DialTLSContext(ctx, M.ParseSocksaddr(addr))
			},
			ReadIdleTimeout:  30 * time.Second,
			PingTimeout:      15 * time.Second,
			AllowHTTP:        false,
			MaxReadFrameSize: 1 << 20,
		}
		http2Mode = true
	}

	var baseURL url.URL
	if tlsConfig == nil {
		baseURL.Scheme = "http"
	} else {
		baseURL.Scheme = "https"
	}
	baseURL.Host = serverAddr.String()
	baseURL.Path = options.Path
	if err := sHTTP.URLSetPath(&baseURL, options.Path); err != nil {
		return nil, E.Cause(err, "parse path")
	}
	if !strings.HasPrefix(baseURL.Path, "/") {
		baseURL.Path = "/" + baseURL.Path
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")

	mode := options.Mode
	if mode == "" || mode == ModeAuto {
		if http2Mode {
			mode = ModeStreamOne
		} else {
			mode = ModeStreamUp
		}
	}

	client := &Client{
		ctx:         ctx,
		dialer:      dialer,
		serverAddr:  serverAddr,
		transport:   transport,
		httpClient:  &http.Client{Transport: transport},
		http2Mode:   http2Mode,
		mode:        mode,
		baseURL:     baseURL,
		host:        options.Host,
		headers:     options.Headers.Build(),
		padding:     parsePaddingRange(options.XPaddingBytes),
		noSSE:       options.NoSSEHeader,
		maxEachPost: options.ScMaxEachPostBytes,
		minInterval: time.Duration(options.ScMinPostsIntervalMs) * time.Millisecond,
	}
	return client, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	switch c.mode {
	case ModeStreamOne:
		return c.dialStreamOne(ctx)
	case ModeStreamUp:
		return c.dialStreamUp(ctx)
	case ModePacketUp:
		return c.dialPacketUp(ctx)
	default:
		return nil, E.New("xhttp: unknown mode: ", c.mode)
	}
}

// randSessionID 生成 16 字节的 hex ID（与 Xray 一致）。
func (c *Client) randSessionID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		// fallback，永远不会走到（除非 getrandom 挂了）
		mathRand.New(mathRand.NewSource(time.Now().UnixNano() + int64(c.sessionSeq.Add(1)))).Read(raw)
	}
	return hex.EncodeToString(raw)
}

func (c *Client) pickHost() string {
	switch len(c.host) {
	case 0:
		return c.serverAddr.AddrString()
	case 1:
		return c.host[0]
	default:
		// crypto/rand 给安全，不用 math/rand 避免被攻击者预测
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(c.host))))
		if err != nil {
			return c.host[0]
		}
		return c.host[n.Int64()]
	}
}

// dialStreamOne: 发一条 POST <base>/<sid>/0，request.Body = 上行 pipe，
// response.Body = 下行。H2 下只有这一个请求两向传字节。
func (c *Client) dialStreamOne(ctx context.Context) (net.Conn, error) {
	sessionID := c.randSessionID()
	u := c.baseURL
	u.Path = appendPathSegment(appendPathSegment(u.Path, sessionID), "0")
	if pad := c.padding.randomHex(); pad != "" {
		q := u.Query()
		q.Set(paddingQueryKey, pad)
		u.RawQuery = q.Encode()
	}
	pipeR, pipeW := io.Pipe()
	req := &http.Request{
		Method: methodPost,
		URL:    &u,
		Body:   pipeR,
		Header: c.headers.Clone(),
		Host:   c.pickHost(),
	}
	if pad := c.padding.randomHex(); pad != "" {
		req.Header.Set(paddingHeaderKey, pad)
	}
	req = req.WithContext(ctx)

	conn := newLateXHTTPConn(pipeW, c.serverAddr.TCPAddr())
	go func() {
		resp, err := c.transport.RoundTrip(req)
		if err != nil {
			conn.setupReader(nil, err)
			return
		}
		if resp.StatusCode/100 != 2 {
			resp.Body.Close()
			conn.setupReader(nil, E.New("xhttp stream-one: status ", resp.Status))
			return
		}
		conn.setupReader(resp.Body, nil)
	}()
	return conn, nil
}

// dialStreamUp: 两个请求。UP 用 POST body = pipe(上行)；DOWN 用 GET，
// response.Body = 下行。双向独立，可以走不同 H2 stream / H1 连接。
func (c *Client) dialStreamUp(ctx context.Context) (net.Conn, error) {
	sessionID := c.randSessionID()
	// UP 请求
	upURL := c.baseURL
	upURL.Path = appendPathSegment(appendPathSegment(upURL.Path, sessionID), "up")
	if pad := c.padding.randomHex(); pad != "" {
		q := upURL.Query()
		q.Set(paddingQueryKey, pad)
		upURL.RawQuery = q.Encode()
	}
	pipeR, pipeW := io.Pipe()
	upReq := &http.Request{
		Method: methodPost,
		URL:    &upURL,
		Body:   pipeR,
		Header: c.headers.Clone(),
		Host:   c.pickHost(),
	}
	upReq = upReq.WithContext(ctx)

	// DOWN 请求
	downURL := c.baseURL
	downURL.Path = appendPathSegment(appendPathSegment(downURL.Path, sessionID), "down")
	if pad := c.padding.randomHex(); pad != "" {
		q := downURL.Query()
		q.Set(paddingQueryKey, pad)
		downURL.RawQuery = q.Encode()
	}
	downReq := &http.Request{
		Method: methodGet,
		URL:    &downURL,
		Header: c.headers.Clone(),
		Host:   c.pickHost(),
	}
	downReq = downReq.WithContext(ctx)

	// 先发 DOWN 拿 body（服务端拿到 down 才 attach writer，up 才有意义）
	// 但不能阻塞太久，go 起来并发送。
	conn := newLateXHTTPConn(pipeW, c.serverAddr.TCPAddr())
	go func() {
		resp, err := c.httpClient.Do(downReq)
		if err != nil {
			conn.setupReader(nil, err)
			return
		}
		if resp.StatusCode/100 != 2 {
			resp.Body.Close()
			conn.setupReader(nil, E.New("xhttp stream-up down: status ", resp.Status))
			return
		}
		conn.setupReader(resp.Body, nil)
	}()
	// UP 请求也 go 起来（request body 是 pipe，客户端调 Write(pipeW) 即送数据）
	go func() {
		resp, err := c.httpClient.Do(upReq)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	return conn, nil
}

// dialPacketUp: 每 Write 发独立 POST；单条 GET SSE 收下行。
func (c *Client) dialPacketUp(ctx context.Context) (net.Conn, error) {
	sessionID := c.randSessionID()
	// DOWN SSE 请求
	downURL := c.baseURL
	downURL.Path = appendPathSegment(downURL.Path, sessionID)
	if pad := c.padding.randomHex(); pad != "" {
		q := downURL.Query()
		q.Set(paddingQueryKey, pad)
		downURL.RawQuery = q.Encode()
	}
	downReq := &http.Request{
		Method: methodGet,
		URL:    &downURL,
		Header: c.headers.Clone(),
		Host:   c.pickHost(),
	}
	downReq.Header.Set("Accept", contentTypeSSE)
	downReq = downReq.WithContext(ctx)

	// 上行 URL base（writer 会在后面追 /seq）
	upBaseURL := c.baseURL
	upBaseURL.Path = appendPathSegment(upBaseURL.Path, sessionID)

	writer := &packetUpWriter{
		client:      c.httpClient,
		requestURL:  upBaseURL,
		host:        c.pickHost(),
		headers:     c.headers.Clone(),
		padding:     c.padding,
		minInterval: c.minInterval,
		maxEachPost: c.maxEachPost,
	}
	conn := newLateXHTTPConn(writer, c.serverAddr.TCPAddr())
	go func() {
		resp, err := c.httpClient.Do(downReq)
		if err != nil {
			conn.setupReader(nil, err)
			return
		}
		if resp.StatusCode/100 != 2 {
			resp.Body.Close()
			conn.setupReader(nil, E.New("xhttp packet-up down: status ", resp.Status))
			return
		}
		conn.setupReader(resp.Body, nil)
	}()
	return conn, nil
}

func (c *Client) Close() error {
	if t, ok := c.transport.(*http2.Transport); ok {
		t.CloseIdleConnections()
	} else if t, ok := c.transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
	return nil
}
