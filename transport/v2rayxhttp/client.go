package v2rayxhttp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	boxtls "github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

// endpoint 是一侧 (上行或下行) 的完整拨号参数: XHTTP 配置 + 服务器地址 + TLS +
// dialer + XMUX。没有 download_settings 时上下行共用同一个 endpoint。
type endpoint struct {
	cfg         *config
	dialer      N.Dialer
	serverAddr  M.Socksaddr
	tlsConfig   boxtls.Config
	tlsDialer   boxtls.Dialer
	httpVersion string
	isReality   bool
	scheme      string
	defaultHost string

	access sync.Mutex
	xmux   *xmuxManager
}

func newEndpoint(cfg *config, dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig boxtls.Config) (*endpoint, error) {
	e := &endpoint{
		cfg:        cfg,
		dialer:     dialer,
		serverAddr: serverAddr,
		tlsConfig:  tlsConfig,
		isReality:  isRealityConfig(tlsConfig),
		scheme:     "http",
	}
	// Xray decideHTTPVersion: REALITY → 2；无 TLS → 1.1；ALPN 仅 http/1.1 → 1.1；
	// ALPN 仅 h3 → 3；其他 → 2。
	if tlsConfig == nil {
		e.httpVersion = httpVersion1
	} else {
		nextProtos := tlsConfig.NextProtos()
		switch {
		case e.isReality:
			e.httpVersion = httpVersion2
		case len(nextProtos) == 1 && nextProtos[0] == "http/1.1":
			e.httpVersion = httpVersion1
		case len(nextProtos) == 1 && nextProtos[0] == "h3":
			e.httpVersion = httpVersion3
		default:
			e.httpVersion = httpVersion2
		}
		if e.httpVersion == httpVersion2 && len(nextProtos) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
		}
	}
	if e.httpVersion == httpVersion3 {
		if err := checkH3Available(); err != nil {
			return nil, err
		}
		// QUIC 握手只能用标准库 TLS：与 Xray 一致，忽略 uTLS 指纹。
		quicTLSConfig, err := boxtls.QUICClientConfig(tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "xhttp h3")
		}
		e.tlsConfig = quicTLSConfig
	}
	if tlsConfig != nil {
		e.scheme = "https"
		e.tlsDialer = boxtls.NewDialer(dialer, tlsConfig)
	}
	// Host 优先级 (Xray): host > TLS server_name > 服务器地址
	if tlsConfig != nil {
		e.defaultHost = tlsConfig.ServerName()
	}
	if e.defaultHost == "" {
		e.defaultHost = serverAddr.AddrString()
	}
	e.xmux = newXmuxManager(cfg.xmux, func() xmuxConn {
		return e.newDialerClient()
	})
	return e, nil
}

func (e *endpoint) requestURL() string {
	host := e.cfg.pickHost()
	if host == "" {
		host = e.defaultHost
	}
	requestURL := url.URL{
		Scheme:   e.scheme,
		Host:     host,
		Path:     e.cfg.path,
		RawQuery: e.cfg.query,
	}
	return requestURL.String()
}

func (e *endpoint) getClient() (*dialerClient, *xmuxClient) {
	e.access.Lock()
	defer e.access.Unlock()
	client := e.xmux.getXmuxClient()
	return client.conn.(*dialerClient), client
}

func (e *endpoint) close() {
	e.access.Lock()
	defer e.access.Unlock()
	e.xmux.close()
}

func (e *endpoint) dialConn(ctx context.Context) (net.Conn, error) {
	if e.tlsDialer != nil {
		return e.tlsDialer.DialTLSContext(ctx, e.serverAddr)
	}
	return e.dialer.DialContext(ctx, N.NetworkTCP, e.serverAddr)
}

func (e *endpoint) keepAlivePeriod() time.Duration {
	return time.Duration(e.cfg.xmux.hKeepAlivePeriod) * time.Second
}

// newDialerClient 对应 Xray createHTTPClient: 每个 XMUX 连接一套独立的 RoundTripper。
func (e *endpoint) newDialerClient() *dialerClient {
	client := &dialerClient{
		cfg:         e.cfg,
		httpVersion: e.httpVersion,
	}
	switch e.httpVersion {
	case httpVersion3:
		transport, err := buildH3Transport(e.dialer, e.serverAddr, e.tlsConfig, e.cfg, e.keepAlivePeriod())
		if err != nil {
			// checkH3Available 已在构造时校验，这里只是兜底。
			client.transport = errorRoundTripper{err}
		} else {
			client.transport = transport
		}
	case httpVersion2:
		keepAlivePeriod := e.keepAlivePeriod()
		if keepAlivePeriod == 0 {
			keepAlivePeriod = ChromeH2KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		client.transport = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return e.dialConn(ctx)
			},
			IdleConnTimeout: ConnIdleTimeout,
			ReadIdleTimeout: keepAlivePeriod,
		}
	default:
		dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return e.dialConn(ctx)
		}
		client.transport = &http.Transport{
			Proxy:           nil,
			DialContext:     dialContext,
			DialTLSContext:  dialContext,
			IdleConnTimeout: ConnIdleTimeout,
			// chunked transfer download with KeepAlives is buggy with
			// http.Client and our custom dial context.
			DisableKeepAlives: true,
		}
		client.uploadPool = newH1UploadPool(e.dialConn)
	}
	return client
}

type errorRoundTripper struct{ err error }

func (t errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

// dialerClient 对应 Xray DefaultDialerClient: 一个 XMUX 连接 (一套 RoundTripper)。
type dialerClient struct {
	cfg         *config
	transport   http.RoundTripper
	httpVersion string
	closed      atomic.Bool
	// HTTP/1.1 时 packet-up 上行走手写序列化 + 连接池 (可安全重试)。
	uploadPool *h1UploadPool
}

func (c *dialerClient) IsClosed() bool {
	return c.closed.Load()
}

func (c *dialerClient) Close() error {
	switch transport := c.transport.(type) {
	case *http.Transport:
		transport.CloseIdleConnections()
	case *http2.Transport:
		transport.CloseIdleConnections()
	case io.Closer:
		_ = transport.Close()
	}
	if c.uploadPool != nil {
		c.uploadPool.close()
	}
	return nil
}

// openStream 发起一个长请求: body == nil 为 GET 下行 (stream-down)，否则为
// stream-one / stream-up 上行。等到底层连接建立 (httptrace.GotConn) 就返回，
// 响应体通过 waitReadCloser 异步交付 —— 避免 CDN 等上行数据才回响应头时的死锁。
//
// dialCtx 只控制等待建连；requestCtx 控制整个请求的生命周期。
func (c *dialerClient) openStream(dialCtx, requestCtx context.Context, requestURL, sessionId string, body io.ReadCloser, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	method := methodGet // stream-down
	var requestBody io.Reader
	if body != nil {
		method = c.cfg.uplinkHTTPMethod // stream-up/one
		requestBody = body
	}
	var (
		gotConnOnce sync.Once
		gotConn     = make(chan struct{})
		remoteAddr  net.Addr
		localAddr   net.Addr
	)
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			gotConnOnce.Do(func() {
				if info.Conn != nil {
					remoteAddr = info.Conn.RemoteAddr()
					localAddr = info.Conn.LocalAddr()
				}
				close(gotConn)
			})
		},
	}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(requestCtx, trace), method, requestURL, requestBody)
	if err != nil {
		return nil, nil, nil, err
	}
	c.cfg.fillStreamRequest(request, sessionId)

	reader := newWaitReadCloser()
	setupErr := make(chan error, 1)
	go func() {
		response, err := c.transport.RoundTrip(request)
		if err != nil {
			if !uploadOnly { // stream-down is enough
				c.closed.Store(true)
			}
			setupErr <- err
			closeWithError(body, err)
			reader.closeWithError(err)
			return
		}
		if response.StatusCode != http.StatusOK || uploadOnly {
			if response.StatusCode != http.StatusOK {
				err = E.New("xhttp: unexpected status ", response.Status, " for ", method, " ", requestURL)
				setupErr <- err
			} else {
				err = io.ErrClosedPipe
			}
			// 对 stream-up 而言响应体随上传结束才结束；提前关闭会打断上传。
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			closeWithError(body, err)
			reader.closeWithError(err)
			return
		}
		reader.set(response.Body)
	}()

	select {
	case <-gotConn:
		return reader, remoteAddr, localAddr, nil
	case err = <-setupErr:
		return nil, nil, nil, err
	case <-dialCtx.Done():
		_ = reader.Close()
		return nil, nil, nil, dialCtx.Err()
	}
}

func closeWithError(body io.ReadCloser, err error) {
	if body == nil {
		return
	}
	if pipeReader, loaded := body.(*io.PipeReader); loaded {
		_ = pipeReader.CloseWithError(err)
		return
	}
	_ = body.Close()
}

// postPacket 发送一个 packet-up 上行包。onWrote 在请求完整写出后调用，
// 上行协程据此继续发下一个包而不必等待响应 (Xray: httptrace.WroteRequest)。
func (c *dialerClient) postPacket(ctx context.Context, requestURL, sessionId, seqStr string, payload []byte, onWrote func()) error {
	if c.uploadPool == nil {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			WroteRequest: func(httptrace.WroteRequestInfo) { onWrote() },
		})
	}
	request, err := http.NewRequestWithContext(ctx, c.cfg.uplinkHTTPMethod, requestURL, nil)
	if err != nil {
		return err
	}
	c.cfg.fillPacketRequest(request, sessionId, seqStr, payload)
	if c.uploadPool != nil {
		return c.uploadPool.postPacket(ctx, request, onWrote)
	}
	response, err := c.transport.RoundTrip(request)
	if err != nil {
		c.closed.Store(true)
		return err
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return E.New("xhttp: bad status code: ", response.Status)
	}
	return nil
}

// waitReadCloser 异步交付 response.Body (Xray WaitReadCloser)。
type waitReadCloser struct {
	access sync.Mutex
	wait   chan struct{}
	done   bool
	closed bool
	reader io.ReadCloser
	err    error
}

func newWaitReadCloser() *waitReadCloser {
	return &waitReadCloser{wait: make(chan struct{})}
}

func (w *waitReadCloser) set(reader io.ReadCloser) {
	w.access.Lock()
	if w.done || w.closed {
		w.access.Unlock()
		_ = reader.Close()
		return
	}
	w.reader = reader
	w.done = true
	close(w.wait)
	w.access.Unlock()
}

func (w *waitReadCloser) closeWithError(err error) {
	w.access.Lock()
	defer w.access.Unlock()
	if w.done {
		return
	}
	w.err = err
	w.done = true
	close(w.wait)
}

func (w *waitReadCloser) Read(p []byte) (int, error) {
	<-w.wait
	w.access.Lock()
	reader, err := w.reader, w.err
	w.access.Unlock()
	if reader == nil {
		if err == nil {
			err = io.ErrClosedPipe
		}
		return 0, err
	}
	return reader.Read(p)
}

func (w *waitReadCloser) Close() error {
	w.access.Lock()
	w.closed = true
	if !w.done {
		w.err = net.ErrClosed
		w.done = true
		close(w.wait)
	}
	reader := w.reader
	w.access.Unlock()
	if reader != nil {
		return reader.Close()
	}
	return nil
}
