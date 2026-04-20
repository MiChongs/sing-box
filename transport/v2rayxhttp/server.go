package v2rayxhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	sHttp "github.com/sagernet/sing/protocol/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Server 处理三种 XHTTP 模式:
//
//  stream-one:
//    单个 HTTP/2 请求 (POST <path>/<uuid>/0)，body 既是上行流、response body 是下行流。
//    用 hijack 不可行 (h2 不支持)，必须用 request.Body + response writer。
//
//  stream-up:
//    client 开两个独立请求：
//      POST <path>/<uuid>/up   → 上行数据流（长连 request body）
//      GET  <path>/<uuid>/down → 下行数据流（长连 response body，SSE 或 chunked）
//
//  packet-up:
//    client 开一个 SSE GET <path>/<uuid>，同时对每个上行包发一个独立 POST
//    <path>/<uuid>/<seq>，body 是数据分片。服务端按 seq 重组后投递给 handler。
//
// 所有模式的 URL 共用前缀 <path>。uuid / seq 从 URL path 解析；不对 uuid
// 做强校验（任意非空字符串视为合法 session id），让 client 可以自己决定
// session id 格式。
type Server struct {
	ctx       context.Context
	logger    logger.ContextLogger
	tlsConfig tls.ServerConfig
	handler   adapter.V2RayServerTransportHandler

	httpServer *http.Server
	h2Server   *http2.Server
	h2cHandler http.Handler

	host         []string
	path         string
	headers      http.Header
	noSSE        bool
	maxBuffered  int

	// packet-up sessions
	sessionsAccess sync.Mutex
	sessions       map[string]*packetUpSession
	sessionJanitor *time.Ticker
}

// NewServer 被 v2ray plugin registry 通过 init() 注册后从 v2ray 包调起。
func NewServer(ctx context.Context, logger logger.ContextLogger, options *option.V2RayXHTTPOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, error) {
	if options == nil {
		return nil, E.New("xhttp: missing options")
	}
	server := &Server{
		ctx:         ctx,
		logger:      logger,
		tlsConfig:   tlsConfig,
		handler:     handler,
		host:        options.Host,
		path:        options.Path,
		headers:     options.Headers.Build(),
		noSSE:       options.NoSSEHeader,
		maxBuffered: options.ScMaxBufferedPosts,
		sessions:    map[string]*packetUpSession{},
		h2Server:    &http2.Server{},
	}
	if server.maxBuffered <= 0 {
		server.maxBuffered = defaultScMaxBufferedPosts
	}
	if !strings.HasPrefix(server.path, "/") {
		server.path = "/" + server.path
	}
	// 去掉 trailing slash，统一处理
	server.path = strings.TrimRight(server.path, "/")
	server.httpServer = &http.Server{
		Handler:           server,
		ReadHeaderTimeout: C.TCPTimeout,
		MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return log.ContextWithNewID(ctx)
		},
	}
	server.h2cHandler = h2c.NewHandler(server, server.h2Server)
	// 定期清理空闲 session（客户端掉线不一定正常关闭 SSE）
	server.sessionJanitor = time.NewTicker(time.Duration(sessionIdleTimeoutSeconds) * time.Second)
	go server.janitorLoop()
	return server, nil
}

func (s *Server) janitorLoop() {
	for {
		select {
		case <-s.ctx.Done():
			s.sessionJanitor.Stop()
			return
		case <-s.sessionJanitor.C:
			s.gcSessions()
		}
	}
}

func (s *Server) gcSessions() {
	s.sessionsAccess.Lock()
	defer s.sessionsAccess.Unlock()
	cutoff := time.Now().Add(-time.Duration(sessionIdleTimeoutSeconds) * time.Second).UnixNano()
	for id, sess := range s.sessions {
		if sess.lastActiveNanos.Load() < cutoff {
			sess.close()
			delete(s.sessions, id)
		}
	}
}

// routing: 把 request URL 拆成 (mode, session_id, seq/subpath)。
// URL 形态:
//   /<server.path>/<session-id>[/ up | / down | / <seq> ]
// 规则:
//   method=POST 带 "/up"  → stream-up 的 UP 通道
//   method=GET  带 "/down" → stream-up 的 DOWN 通道
//   method=GET  没 subpath → packet-up 的 SSE
//   method=POST 带数字 seq → packet-up 的 UP 分片；seq=0 也可能是 stream-one 首包
//   method=POST seq=0 且后续会长时间写 → stream-one（与 packet-up seq=0 + 立刻关闭 body
//     无法一眼区分，用 Content-Length 启发式：Content-Length 为 -1/0/未设 视为长连）
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// h2c 优先：curl --http2-prior-knowledge 会发 "PRI * HTTP/2.0"
	if r.Method == "PRI" && len(r.Header) == 0 && r.URL.Path == "*" && r.Proto == "HTTP/2.0" {
		s.h2cHandler.ServeHTTP(w, r)
		return
	}
	// host 校验
	if len(s.host) > 0 && !common.Contains(s.host, r.Host) {
		s.reject(w, r, http.StatusBadRequest, E.New("bad host: ", r.Host))
		return
	}
	// path 前缀校验
	if !strings.HasPrefix(r.URL.Path, s.path+"/") && r.URL.Path != s.path {
		s.reject(w, r, http.StatusNotFound, E.New("bad path: ", r.URL.Path))
		return
	}
	// 写 server 预设的返回 header（Xray 里常见 "Content-Type: text/plain"
	// 伪装，由用户自己配）
	for k, vs := range s.headers {
		for _, v := range vs {
			w.Header().Set(k, v)
		}
	}
	w.Header().Set("Cache-Control", "no-store")

	sub := strings.TrimPrefix(r.URL.Path, s.path)
	sub = strings.TrimPrefix(sub, "/")
	segments := strings.Split(sub, "/")
	if len(segments) == 0 || segments[0] == "" {
		s.reject(w, r, http.StatusNotFound, E.New("missing session id"))
		return
	}
	sessionID := segments[0]
	// 后续段（可能是 "up" / "down" / seq 字符串）
	var tail string
	if len(segments) > 1 {
		tail = segments[1]
	}

	source := sHttp.SourceAddress(r)
	switch {
	case r.Method == methodGet && (tail == "" || tail == "down"):
		s.handleDown(w, r, sessionID, source)
	case r.Method == methodPost && tail == "up":
		s.handleStreamUpUp(w, r, sessionID, source)
	case r.Method == methodPost:
		// packet-up POST 分片（seq 数字），或 stream-one 首包（seq=0 长连）
		seq, err := strconv.ParseUint(tail, 10, 64)
		if err != nil {
			s.reject(w, r, http.StatusBadRequest, E.New("invalid seq: ", tail))
			return
		}
		// 启发式判定 stream-one：seq=0 + HTTP/2.0 + 请求没带 Content-Length（长连）
		if seq == 0 && r.ProtoMajor >= 2 && r.ContentLength <= 0 {
			s.handleStreamOne(w, r, sessionID, source)
			return
		}
		s.handlePacketUp(w, r, sessionID, seq)
	default:
		s.reject(w, r, http.StatusMethodNotAllowed, E.New("bad method/path: ", r.Method, " ", r.URL.Path))
	}
}

// handleStreamOne: h2 duplex。request.Body = upstream, response = downstream。
// 与 v2rayhttp.Server 的 h2 模式几乎相同，只多一层 URL 校验。
func (s *Server) handleStreamOne(w http.ResponseWriter, r *http.Request, _ string, source M.Socksaddr) {
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.reject(w, r, 0, E.New("stream-one requires HTTP/2 flusher"))
		return
	}
	flusher.Flush()
	done := make(chan struct{})
	conn := newXHTTPConn(r.Body, &flushingWriter{w: w, flusher: flusher}, &dummyAddr{addr: r.RemoteAddr})
	s.handler.NewConnectionEx(r.Context(), conn, source, M.Socksaddr{}, N.OnceClose(func(it error) {
		close(done)
	}))
	<-done
	_ = conn.Close()
}

// handleStreamUpUp: stream-up 的 UP 请求，长连 POST，body = 全部上行字节。
// 我们需要把 UP 请求的 body 和 DOWN 请求的 response writer 对应起来（按 sessionID
// 匹配）。因为 UP / DOWN 是两个独立 HTTP 请求，可能乱序到达。
func (s *Server) handleStreamUpUp(w http.ResponseWriter, r *http.Request, sessionID string, source M.Socksaddr) {
	sess := s.getOrCreatePacketSession(sessionID)
	// 把 UP 的 body pipe 到 session 的 upReader（让 handler 读）
	// stream-up 没有 seq，直接用 seq=0 的单条长包，session 的 expected 刚好 0
	done := make(chan struct{})
	// 给 handler 构造一个 conn: reader = session.upReader, writer → session.writeDown
	conn := newXHTTPConn(sess.upReader, &sessionDownWriter{session: sess, noSSE: s.noSSE}, &dummyAddr{addr: r.RemoteAddr})
	firstSubmit := sync.Once{}
	// 用一个循环从 r.Body 读，submit 到 session 的 pipe。submit 会阻塞在
	// upReader 被读取的速度；r.Body 关闭即 UP 结束。
	go func() {
		defer func() {
			sess.closeUp()
			close(done)
		}()
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				firstSubmit.Do(func() {
					// 首帧到了就通知 handler 开工
					go s.handler.NewConnectionEx(r.Context(), conn, source, M.Socksaddr{}, N.OnceClose(func(it error) {
						sess.close()
					}))
				})
				// 直接写 pipe（stream-up 单请求，不走 seq 重组）
				if _, werr := sess.upReaderWriter.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	<-done
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// handleDown: 处理 GET /path/session/down (stream-up) 或 GET /path/session (packet-up)。
// 共用一份 SSE / chunked response 逻辑。
func (s *Server) handleDown(w http.ResponseWriter, r *http.Request, sessionID string, _ M.Socksaddr) {
	sess := s.getOrCreatePacketSession(sessionID)
	if s.noSSE {
		w.Header().Set("Content-Type", contentTypeOctet)
	} else {
		w.Header().Set("Content-Type", contentTypeSSE)
	}
	w.Header().Set("X-Accel-Buffering", "no") // nginx: 禁下行 buffering
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.reject(w, r, 0, E.New("xhttp down: requires flushable writer"))
		return
	}
	flusher.Flush()
	sess.attachDownWriter(w, flusher)
	// 阻塞到客户端断开 或 session close
	select {
	case <-r.Context().Done():
	case <-sess.closed:
	}
	sess.closeDown()
}

// handlePacketUp: POST /path/session/<seq>
//
// 注意顺序：
//   1. 读完 body
//   2. 如果 seq=0，必须 先启动 handler goroutine（开始从 upReader 读），
//      然后才能 submitPacket（它对 pipe 的 Write 会阻塞直到 Read 发起）
//   3. 后续 seq>0 的请求可直接 submitPacket
//
// session.firstSubmitDone 作为状态机保证 handler 只启动一次，即使 seq=0
// 因任何原因被客户端发送多次（理论上不会，保险起见）。
func (s *Server) handlePacketUp(w http.ResponseWriter, r *http.Request, sessionID string, seq uint64) {
	sess := s.getOrCreatePacketSession(sessionID)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		s.reject(w, r, http.StatusInternalServerError, E.Cause(err, "read packet body"))
		return
	}
	// seq=0: 先起 handler（让 pipe 有 reader），再 submit
	if seq == 0 && sess.handlerStarted.CompareAndSwap(false, true) {
		source := sHttp.SourceAddress(r)
		conn := newXHTTPConn(sess.upReader, &sessionDownWriter{session: sess, noSSE: s.noSSE}, &dummyAddr{addr: r.RemoteAddr})
		go s.handler.NewConnectionEx(r.Context(), conn, source, M.Socksaddr{}, N.OnceClose(func(it error) {
			sess.close()
		}))
	}
	if err := sess.submitPacket(seq, data); err != nil {
		s.reject(w, r, http.StatusInsufficientStorage, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) getOrCreatePacketSession(id string) *packetUpSession {
	s.sessionsAccess.Lock()
	defer s.sessionsAccess.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		sess = newPacketUpSession(id, s.maxBuffered)
		s.sessions[id] = sess
	}
	return sess
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request, statusCode int, err error) {
	if statusCode > 0 {
		w.WriteHeader(statusCode)
	}
	if s.logger != nil {
		s.logger.ErrorContext(r.Context(), E.Cause(err, "xhttp reject ", r.RemoteAddr))
	}
}

// V2RayServerTransport 接口
func (s *Server) Network() []string                  { return []string{N.NetworkTCP} }
func (s *Server) ServePacket(net.PacketConn) error   { return os.ErrInvalid }

func (s *Server) Serve(listener net.Listener) error {
	if s.tlsConfig != nil {
		if len(s.tlsConfig.NextProtos()) == 0 {
			s.tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
		} else if !common.Contains(s.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			s.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, s.tlsConfig.NextProtos()...))
		}
		listener = aTLS.NewListener(listener, s.tlsConfig)
	}
	return s.httpServer.Serve(listener)
}

func (s *Server) Close() error {
	s.sessionsAccess.Lock()
	for id, sess := range s.sessions {
		sess.close()
		delete(s.sessions, id)
	}
	s.sessionsAccess.Unlock()
	return common.Close(common.PtrOrNil(s.httpServer))
}

// ── helper types ──

type flushingWriter struct {
	w       io.Writer
	flusher http.Flusher
}

func (w *flushingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if err == nil {
		w.flusher.Flush()
	}
	return n, err
}
func (w *flushingWriter) Close() error { return nil }

type sessionDownWriter struct {
	session *packetUpSession
	noSSE   bool
}

func (w *sessionDownWriter) Write(p []byte) (int, error) {
	return w.session.writeDown(p, w.noSSE)
}
func (w *sessionDownWriter) Close() error {
	w.session.closeDown()
	return nil
}

// dummyAddr 把 HTTP RemoteAddr 字符串包成 net.Addr（避免让 handler 层误解析）。
type dummyAddr struct{ addr string }

func (a *dummyAddr) Network() string { return "tcp" }
func (a *dummyAddr) String() string  { return a.addr }
