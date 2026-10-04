package v2rayxhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
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
	"golang.org/x/net/http2/h2c" //nolint:staticcheck
)

// Server 是 XHTTP 入站，对齐 XTLS/Xray-core v26.9.30 splithttp/hub.go。
//
//   - alpn = ["h3"]: 仅监听 UDP，走 HTTP/3 (需要 with_quic)
//   - 其他: TCP 上同时支持 HTTP/1.1、HTTP/2 (TLS ALPN) 与 h2c (明文 prior knowledge)
//
// 服务端 mode=auto 时同时接受 stream-one / stream-up / packet-up；
// 上下行分离 (客户端 download_settings) 不需要服务端额外配置，只要上行与下行
// 请求最终到达同一个入站即可按 session 关联。
var _ adapter.V2RayServerTransport = (*Server)(nil)

type Server struct {
	ctx        context.Context
	logger     logger.ContextLogger
	cfg        *config
	tlsConfig  tls.ServerConfig
	handler    adapter.V2RayServerTransportHandler
	httpServer *http.Server
	h2Server   *http2.Server
	h2cHandler http.Handler
	h3Access   sync.Mutex
	h3Server   io.Closer
	isH3       bool

	hosts         []string
	path          string
	sessionAccess sync.Mutex
	sessions      sync.Map // sessionId → *httpSession
	localAddr     atomic.Pointer[net.Addr]
}

type httpSession struct {
	uploadQueue *uploadQueue
	// GET 下行到达之前 session 可能被超时回收；下行到达之后 session 与 GET 同生命周期。
	isFullyConnected chan struct{}
	connectOnce      sync.Once
}

func (s *httpSession) markFullyConnected() {
	s.connectOnce.Do(func() { close(s.isFullyConnected) })
}

func NewServer(
	ctx context.Context,
	logger logger.ContextLogger,
	options *option.V2RayXHTTPOptions,
	tlsConfig tls.ServerConfig,
	handler adapter.V2RayServerTransportHandler,
) (adapter.V2RayServerTransport, error) {
	cfg, err := newConfig(options)
	if err != nil {
		return nil, err
	}
	if options.DownloadSettings != nil {
		return nil, E.New("xhttp: download_settings is a client-only option")
	}
	server := &Server{
		ctx:       ctx,
		logger:    logger,
		cfg:       cfg,
		tlsConfig: tlsConfig,
		handler:   handler,
		hosts:     cfg.hosts,
		path:      cfg.path,
		h2Server:  &http2.Server{},
	}
	if tlsConfig != nil {
		nextProtos := tlsConfig.NextProtos()
		server.isH3 = len(nextProtos) == 1 && nextProtos[0] == "h3"
	}
	server.httpServer = &http.Server{
		Handler:           server,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		MaxHeaderBytes:    cfg.serverMaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return log.ContextWithNewID(ctx)
		},
	}
	//nolint:staticcheck
	server.h2cHandler = h2c.NewHandler(server, server.h2Server)
	return server, nil
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// h2c prior knowledge，以及非 *tls.Conn 的 TLS 实现 (REALITY 等) 上协商出的 h2，
	// 都会以 "PRI * HTTP/2.0" 的形式落到 HTTP/1 路径，交给 h2c handler 接管。
	if request.Method == "PRI" && len(request.Header) == 0 && request.URL.Path == "*" && request.Proto == "HTTP/2.0" {
		s.h2cHandler.ServeHTTP(writer, request)
		return
	}
	ctx := request.Context()
	if len(s.hosts) > 0 && !isValidHTTPHost(request.Host, s.hosts) {
		s.logger.DebugContext(ctx, "xhttp: failed to validate host, request: ", request.Host, ", config: ", strings.Join(s.hosts, ","))
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if !strings.HasPrefix(request.URL.Path, s.path) {
		s.logger.DebugContext(ctx, "xhttp: failed to validate path, request: ", request.URL.Path, ", config: ", s.path)
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	s.cfg.writeResponseHeader(writer, request.Method, request.Header)
	applyXPaddingToResponse(writer, s.cfg.responsePaddingConfig())

	if request.Method == http.MethodOptions {
		writer.WriteHeader(http.StatusOK)
		return
	}

	paddingValue, paddingPlacement := s.cfg.extractXPaddingFromRequest(request)
	if !s.cfg.isPaddingValid(paddingValue) {
		s.logger.DebugContext(ctx, "xhttp: invalid padding (", paddingPlacement, ") length: ", len(paddingValue))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	obfsPaddingAccepted := s.cfg.xPaddingObfsMode && paddingValue != ""

	sessionId, seqStr := s.cfg.extractMetaFromRequest(request, s.path)
	if sessionId == "" && s.cfg.mode != ModeAuto && s.cfg.mode != ModeStreamOne && s.cfg.mode != ModeStreamUp {
		s.logger.DebugContext(ctx, "xhttp: stream-one mode is not allowed")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	var session *httpSession
	if sessionId != "" {
		session = s.upsertSession(sessionId)
	}

	isUplinkRequest := request.Method != http.MethodGet || seqStr != ""
	switch {
	case isUplinkRequest && sessionId != "": // stream-up, packet-up
		if seqStr == "" {
			s.handleStreamUp(writer, request, session, obfsPaddingAccepted)
		} else {
			s.handlePacketUp(writer, request, session, seqStr)
		}
	case request.Method == http.MethodGet || sessionId == "": // stream-down, stream-one
		s.handleDownlink(writer, request, sessionId, session)
	default:
		s.logger.DebugContext(ctx, "xhttp: unsupported method: ", request.Method)
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleStreamUp(writer http.ResponseWriter, request *http.Request, session *httpSession, obfsPaddingAccepted bool) {
	ctx := request.Context()
	if s.cfg.mode != ModeAuto && s.cfg.mode != ModeStreamUp {
		s.logger.DebugContext(ctx, "xhttp: stream-up mode is not allowed")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	enableFullDuplex(writer, request)
	httpSC := newHTTPServerConn(request.Body, writer)
	err := session.uploadQueue.push(packet{reader: httpSC})
	if err != nil {
		s.logger.DebugContext(ctx, E.Cause(err, "xhttp: failed to upload (push reader)"))
		writer.WriteHeader(http.StatusConflict)
		httpSC.Close()
		return
	}
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	// 部分 CDN 会掐掉长时间没有下行数据的上传请求，服务端在 POST 响应里周期性写 padding 保活。
	// 只对新版客户端 (带 Referer 兼容标记或通过了 obfs padding 校验) 开启。
	hasLegacyRefererCompatMarker := request.Header.Get("Referer") != ""
	if (hasLegacyRefererCompatMarker || obfsPaddingAccepted) && s.cfg.scStreamUpServerSecs.To > 0 {
		go func() {
			for {
				_, err := httpSC.Write(bytes.Repeat([]byte{'X'}, int(s.cfg.xPaddingBytes.rand())))
				if err != nil {
					return
				}
				select {
				case <-time.After(time.Duration(s.cfg.scStreamUpServerSecs.rand()) * time.Second):
				case <-httpSC.Wait():
					return
				}
			}
		}()
	} else if flusher, loaded := writer.(http.Flusher); loaded {
		flusher.Flush()
	}
	select {
	case <-ctx.Done():
	case <-httpSC.Wait():
	}
	httpSC.Close()
}

func (s *Server) handlePacketUp(writer http.ResponseWriter, request *http.Request, session *httpSession, seqStr string) {
	ctx := request.Context()
	if s.cfg.mode != ModeAuto && s.cfg.mode != ModePacketUp {
		s.logger.DebugContext(ctx, "xhttp: packet-up mode is not allowed")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	scMaxEachPostBytes := int(s.cfg.scMaxEachPostBytes.To)
	dataPlacement := s.cfg.uplinkDataPlacement
	uplinkDataKey := s.cfg.uplinkDataKey

	var headerPayload, cookiePayload, bodyPayload []byte
	var err error
	if dataPlacement == PlacementAuto || dataPlacement == PlacementHeader {
		headerPayload, err = decodeChunkedPayload(func(i int) (string, bool) {
			chunk := request.Header.Get(fmt.Sprintf("%s-%d", uplinkDataKey, i))
			return chunk, chunk != ""
		})
		if err != nil {
			s.logger.DebugContext(ctx, "xhttp: invalid base64 in header's payload: ", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	if dataPlacement == PlacementAuto || dataPlacement == PlacementCookie {
		cookiePayload, err = decodeChunkedPayload(func(i int) (string, bool) {
			cookie, _ := request.Cookie(fmt.Sprintf("%s_%d", uplinkDataKey, i))
			if cookie == nil {
				return "", false
			}
			return cookie.Value, true
		})
		if err != nil {
			s.logger.DebugContext(ctx, "xhttp: invalid base64 in cookies' payload: ", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	if dataPlacement == PlacementAuto || dataPlacement == PlacementBody {
		if request.ContentLength > int64(scMaxEachPostBytes) {
			s.logger.DebugContext(ctx, "xhttp: too large upload. sc_max_each_post_bytes is set to ", scMaxEachPostBytes,
				" but request size exceed it. Adjust sc_max_each_post_bytes on the server to be at least as large as client.")
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		if request.ContentLength > 0 {
			bodyPayload = make([]byte, request.ContentLength)
			_, err = io.ReadFull(request.Body, bodyPayload)
		} else {
			bodyPayload, err = io.ReadAll(io.LimitReader(request.Body, int64(scMaxEachPostBytes)+1))
		}
		if err != nil {
			s.logger.DebugContext(ctx, E.Cause(err, "xhttp: failed to read body payload"))
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	var payload []byte
	switch dataPlacement {
	case PlacementHeader:
		payload = headerPayload
	case PlacementCookie:
		payload = cookiePayload
	case PlacementBody:
		payload = bodyPayload
	case PlacementAuto:
		payload = slices.Concat(headerPayload, cookiePayload, bodyPayload)
	}
	if len(payload) > scMaxEachPostBytes {
		s.logger.DebugContext(ctx, "xhttp: too large upload. sc_max_each_post_bytes is set to ", scMaxEachPostBytes,
			" but request size exceed it. Adjust sc_max_each_post_bytes on the server to be at least as large as client.")
		writer.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if err != nil {
		s.logger.DebugContext(ctx, E.Cause(err, "xhttp: failed to upload (parse seq)"))
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = session.uploadQueue.push(packet{payload: payload, seq: seq})
	if err != nil {
		s.logger.DebugContext(ctx, E.Cause(err, "xhttp: failed to upload (push payload)"))
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(bodyPayload) == 0 {
		// Methods without a body are usually cached by default.
		writer.Header().Set("Cache-Control", "no-store")
	}
	writer.WriteHeader(http.StatusOK)
}

// decodeChunkedPayload 按序号收集 base64 分片并解码。
func decodeChunkedPayload(getChunk func(int) (string, bool)) ([]byte, error) {
	var chunks []string
	for i := 0; ; i++ {
		chunk, loaded := getChunk(i)
		if !loaded {
			break
		}
		chunks = append(chunks, chunk)
	}
	return base64.RawURLEncoding.DecodeString(strings.Join(chunks, ""))
}

func (s *Server) handleDownlink(writer http.ResponseWriter, request *http.Request, sessionId string, session *httpSession) {
	if session != nil {
		// GET 到达后 session 与该请求同生命周期，关闭超时回收，结束时在 defer 里删除。
		session.markFullyConnected()
		defer s.sessions.Delete(sessionId)
	}
	if session == nil {
		// stream-one 在 HTTP/1.1 上需要边读请求体边写响应。
		enableFullDuplex(writer, request)
	}

	// magic header instructs nginx + apache to not buffer response body
	writer.Header().Set("X-Accel-Buffering", "no")
	// A web-compliant header telling all middleboxes to disable caching.
	writer.Header().Set("Cache-Control", "no-store")
	if !s.cfg.noSSEHeader {
		// magic header to make the HTTP middle box consider this as SSE to disable buffer
		writer.Header().Set("Content-Type", contentTypeSSE)
	}
	writer.WriteHeader(http.StatusOK)
	if flusher, loaded := writer.(http.Flusher); loaded {
		flusher.Flush()
	}

	httpSC := newHTTPServerConn(request.Body, writer)
	source := sHttp.SourceAddress(request)
	conn := &splitConn{
		writer:     httpSC,
		reader:     httpSC,
		remoteAddr: s.remoteAddr(request, source),
	}
	if localAddr := s.localAddr.Load(); localAddr != nil {
		conn.localAddr = *localAddr
	}
	if localAddr, loaded := request.Context().Value(http.LocalAddrContextKey).(net.Addr); loaded && localAddr != nil {
		conn.localAddr = localAddr
	}
	if session != nil { // stream-up / packet-up
		conn.reader = session.uploadQueue
	}

	done := make(chan struct{})
	s.handler.NewConnectionEx(request.Context(), conn, source, M.Socksaddr{}, N.OnceClose(func(it error) {
		close(done)
	}))
	// "A ResponseWriter may not be used after Handler.ServeHTTP has returned."
	select {
	case <-request.Context().Done():
	case <-httpSC.Wait():
	case <-done:
	}
	conn.Close()
}

func (s *Server) remoteAddr(request *http.Request, source M.Socksaddr) net.Addr {
	if request.ProtoMajor == 3 {
		return source.UDPAddr()
	}
	return source.TCPAddr()
}

// enableFullDuplex 让 HTTP/1.1 handler 能在写响应后继续读请求体
// (stream-one / stream-up)。HTTP/2、HTTP/3 本身就是全双工，返回的错误忽略即可。
func enableFullDuplex(writer http.ResponseWriter, request *http.Request) {
	if request.ProtoMajor == 1 {
		_ = http.NewResponseController(writer).EnableFullDuplex()
	}
}

func (s *Server) upsertSession(sessionId string) *httpSession {
	// fast path
	if currentSession, loaded := s.sessions.Load(sessionId); loaded {
		return currentSession.(*httpSession)
	}
	// slow path
	s.sessionAccess.Lock()
	defer s.sessionAccess.Unlock()
	if currentSession, loaded := s.sessions.Load(sessionId); loaded {
		return currentSession.(*httpSession)
	}
	session := &httpSession{
		uploadQueue:      newUploadQueue(s.cfg.scMaxBufferedPosts),
		isFullyConnected: make(chan struct{}),
	}
	s.sessions.Store(sessionId, session)
	go func() {
		timer := time.NewTimer(sessionReapTimeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			s.sessions.Delete(sessionId)
			session.uploadQueue.Close()
		case <-session.isFullyConnected:
		}
	}()
	return session
}

// isValidHTTPHost 对应 Xray internet.IsValidHTTPHost (忽略请求里的端口)，支持多个 host。
func isValidHTTPHost(requestHost string, hosts []string) bool {
	requestHost = strings.ToLower(requestHost)
	if strings.Contains(requestHost, ":") {
		host, _, err := net.SplitHostPort(requestHost)
		if err == nil {
			requestHost = host
		}
	}
	for _, host := range hosts {
		if requestHost == strings.ToLower(host) {
			return true
		}
	}
	return false
}

func (s *Server) Network() []string {
	if s.isH3 {
		return []string{N.NetworkUDP}
	}
	return []string{N.NetworkTCP}
}

func (s *Server) Serve(listener net.Listener) error {
	if s.isH3 {
		return os.ErrInvalid
	}
	if s.tlsConfig != nil {
		if len(s.tlsConfig.NextProtos()) == 0 {
			s.tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
		}
		listener = aTLS.NewListener(listener, s.tlsConfig)
	}
	localAddr := listener.Addr()
	s.localAddr.Store(&localAddr)
	err := s.httpServer.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) ServePacket(listener net.PacketConn) error {
	if !s.isH3 {
		return os.ErrInvalid
	}
	localAddr := listener.LocalAddr()
	s.localAddr.Store(&localAddr)
	return s.serveH3(listener)
}

func (s *Server) setH3Server(h3Server io.Closer) {
	s.h3Access.Lock()
	defer s.h3Access.Unlock()
	s.h3Server = h3Server
}

func (s *Server) Close() error {
	s.h3Access.Lock()
	h3Server := s.h3Server
	s.h3Access.Unlock()
	err := common.Close(common.PtrOrNil(s.httpServer), h3Server)
	s.sessions.Range(func(key, value any) bool {
		value.(*httpSession).uploadQueue.Close()
		s.sessions.Delete(key)
		return true
	})
	return err
}
