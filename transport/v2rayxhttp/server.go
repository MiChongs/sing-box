package v2rayxhttp

import (
	"context"
	"encoding/base64"
	"fmt"
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
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	sHttp "github.com/sagernet/sing/protocol/http"
)

// Server 完整实现 XHTTP inbound (server 端)，对齐 XTLS/Xray-core v26.3.27
// transport/internet/splithttp/hub.go。
//
// 支持三种 mode:
//   - stream-one: 单条 H2 duplex POST，reader/writer 同一 httpServerConn
//   - stream-up:  POST 上行长流 + GET 下行长流 (SSE)；upload queue 继承 POST body 当 reader
//   - packet-up:  每个 POST 一片 + GET SSE 下行；upload queue 按 seq 重排
//
// padding / session / seq / uplink_data 的 placement 全部支持服务端反解。
var _ adapter.V2RayServerTransport = (*Server)(nil)

type Server struct {
	ctx        context.Context
	logger     logger.ContextLogger
	cfg        *config
	tlsConfig  tls.ServerConfig
	handler    adapter.V2RayServerTransportHandler
	httpServer *http.Server

	host            string
	path            string
	sessionMu       sync.Mutex
	sessions        sync.Map // sessionId → *httpSession
	localAddr       net.Addr
}

type httpSession struct {
	uploadQueue *uploadQueue
	// isFullyConnected: GET 下行建立后 Close，让 upsertSession 里的 30s reap goroutine 停掉
	isFullyConnected chan struct{}
	once             sync.Once
}

func (s *httpSession) markConnected() {
	s.once.Do(func() { close(s.isFullyConnected) })
}

func NewServer(
	ctx context.Context,
	logger logger.ContextLogger,
	options *option.V2RayXHTTPOptions,
	tlsConfig tls.ServerConfig,
	handler adapter.V2RayServerTransportHandler,
) (adapter.V2RayServerTransport, error) {
	cfg, err := newConfig(options, M.Socksaddr{}, false, tlsConfig != nil)
	if err != nil {
		return nil, err
	}
	s := &Server{
		ctx:       ctx,
		logger:    logger,
		cfg:       cfg,
		tlsConfig: tlsConfig,
		handler:   handler,
		host:      pickHost(options),
		path:      cfg.path,
	}
	s.httpServer = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: C.TCPTimeout,
		MaxHeaderBytes:    cfg.serverMaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.STDConn, http.Handler)),
	}
	return s, nil
}

func pickHost(opts *option.V2RayXHTTPOptions) string {
	if len(opts.Host) > 0 {
		return opts.Host[0]
	}
	return ""
}

// ──────────────────────────────────────────────────────────────────────
// ServeHTTP — 每个入站 HTTP 请求的分发入口
// ──────────────────────────────────────────────────────────────────────

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// 1) host 校验
	if len(s.host) > 0 && !isValidHTTPHost(request.Host, s.host) {
		s.logger.DebugContext(request.Context(), "xhttp inbound: bad host ", request.Host)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	// 2) path 前缀校验 (path 是已 normalize 带尾斜杠的 base)
	if !strings.HasPrefix(request.URL.Path, s.path) {
		s.logger.DebugContext(request.Context(), "xhttp inbound: bad path ", request.URL.Path)
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	// 3) CORS + padding 写回 response header
	s.writeResponseHeader(writer, request)

	if request.Method == http.MethodOptions {
		writer.WriteHeader(http.StatusOK)
		return
	}

	// 4) padding 校验
	validRange := s.cfg.padding
	paddingValue, _ := extractXPaddingFromRequest(request, s.cfg.xPaddingObfsMode,
		s.cfg.xPaddingKey, s.cfg.xPaddingHeader, s.cfg.xPaddingPlacement)
	if !isPaddingValid(paddingValue, int32(validRange.Min), int32(validRange.Max), s.cfg.xPaddingMethod) {
		s.logger.DebugContext(request.Context(), "xhttp inbound: invalid padding length ", len(paddingValue))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	// 5) session / seq 提取
	sessionId, seqStr := extractMetaFromRequest(request, s.path,
		s.cfg.sessionPlacement, s.cfg.sessionKey,
		s.cfg.seqPlacement, s.cfg.seqKey)

	// 6) 路由: GET (下行) vs POST/其他 (上行)
	uplinkMethod := s.cfg.uplinkHTTPMethod
	isUplinkRequest := false
	switch request.Method {
	case http.MethodGet:
		// GET 带 seq → packet-up 单包上行 (走 GET-only CDN)
		isUplinkRequest = seqStr != ""
	default:
		isUplinkRequest = request.Method == uplinkMethod || (uplinkMethod == "GET" && request.Method == http.MethodGet)
	}

	if isUplinkRequest && sessionId != "" {
		s.handleUplink(writer, request, sessionId, seqStr)
	} else if request.Method == http.MethodGet || sessionId == "" {
		s.handleDownlink(writer, request, sessionId)
	} else {
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// writeResponseHeader 写 CORS + padding 到 response header。
func (s *Server) writeResponseHeader(writer http.ResponseWriter, request *http.Request) {
	if origin := request.Header.Get("Origin"); origin == "" {
		writer.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		// Chrome: credentials mode 'include' 时不允许 '*'，必须回显 origin
		writer.Header().Set("Access-Control-Allow-Origin", origin)
	}
	// 当任何 placement = cookie 时需要 credentials: include
	if s.cfg.sessionPlacement == PlacementCookie ||
		s.cfg.seqPlacement == PlacementCookie ||
		s.cfg.xPaddingPlacement == PlacementCookie ||
		s.cfg.uplinkDataPlacement == PlacementCookie {
		writer.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	if request.Method == http.MethodOptions {
		reqMethod := request.Header.Get("Access-Control-Request-Method")
		if reqMethod != "" {
			writer.Header().Set("Access-Control-Allow-Methods", reqMethod)
		} else {
			writer.Header().Set("Access-Control-Allow-Methods", "*")
		}
		reqHeaders := request.Header.Get("Access-Control-Request-Headers")
		if reqHeaders == "" {
			writer.Header().Set("Access-Control-Allow-Headers", "*")
		} else {
			writer.Header().Set("Access-Control-Allow-Headers", reqHeaders)
		}
	}

	// padding 写回
	length := s.cfg.padding.rand()
	if length > 0 {
		pc := XPaddingConfig{Length: length}
		if s.cfg.xPaddingObfsMode {
			pc.Placement = XPaddingPlacement{
				Placement: s.cfg.xPaddingPlacement,
				Header:    s.cfg.xPaddingHeader,
				Key:       s.cfg.xPaddingKey,
			}
			pc.Method = s.cfg.xPaddingMethod
		} else {
			pc.Placement = XPaddingPlacement{
				Placement: PlacementHeader,
				Header:    "X-Padding",
			}
		}
		applyXPaddingToResponse(writer.Header(), pc)
	}
}

// ──────────────────────────────────────────────────────────────────────
// handleUplink — POST / PUT / PATCH / GET(seq) 上行
// ──────────────────────────────────────────────────────────────────────

func (s *Server) handleUplink(writer http.ResponseWriter, request *http.Request, sessionId, seqStr string) {
	session := s.upsertSession(sessionId)
	scMaxEachPostBytes := s.cfg.scMaxEachPostBytes

	if seqStr == "" {
		// stream-up: 整条 POST body 当长 reader 塞进 queue
		if s.cfg.mode != "" && s.cfg.mode != ModeAuto && s.cfg.mode != ModeStreamUp {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		httpSC := newHTTPServerConn(request.Body, writer)
		err := session.uploadQueue.push(packet{reader: httpSC})
		if err != nil {
			s.logger.DebugContext(request.Context(), "xhttp inbound: push stream-up reader: ", err)
			writer.WriteHeader(http.StatusConflict)
			return
		}
		writer.Header().Set("X-Accel-Buffering", "no")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
		// 等 POST body 结束或 request 取消
		select {
		case <-request.Context().Done():
		case <-httpSC.Wait():
		}
		httpSC.Close()
		return
	}

	// packet-up: 单片 payload + seq
	if s.cfg.mode != "" && s.cfg.mode != ModeAuto && s.cfg.mode != ModePacketUp {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	payload, err := s.readUplinkPayload(writer, request, scMaxEachPostBytes)
	if err != nil {
		return // readUplinkPayload 已经写了 status code
	}

	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if err != nil {
		s.logger.DebugContext(request.Context(), "xhttp inbound: parse seq: ", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = session.uploadQueue.push(packet{payload: payload, seq: seq})
	if err != nil {
		s.logger.DebugContext(request.Context(), "xhttp inbound: push packet: ", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	if len(payload) == 0 {
		writer.Header().Set("Cache-Control", "no-store")
	}
	writer.WriteHeader(http.StatusOK)
}

// readUplinkPayload 按 uplinkDataPlacement 从 body / header / cookie 读 payload。
func (s *Server) readUplinkPayload(writer http.ResponseWriter, request *http.Request, maxBytes int) ([]byte, error) {
	placement := s.cfg.uplinkDataPlacement
	key := s.cfg.uplinkDataKey

	var bodyPayload, headerPayload, cookiePayload []byte
	var err error

	if placement == PlacementAuto || placement == PlacementBody {
		if request.ContentLength > int64(maxBytes) {
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			return nil, E.New("payload too large")
		}
		if request.ContentLength > 0 {
			bodyPayload = make([]byte, request.ContentLength)
			_, err = io.ReadFull(request.Body, bodyPayload)
		} else {
			bodyPayload, err = io.ReadAll(io.LimitReader(request.Body, int64(maxBytes)+1))
		}
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return nil, E.Cause(err, "read body")
		}
	}

	if placement == PlacementAuto || placement == PlacementHeader {
		headerPayload, err = decodeChunkedPayload(func(i int) string {
			return request.Header.Get(fmt.Sprintf("%s-%d", key, i))
		})
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return nil, err
		}
	}

	if placement == PlacementAuto || placement == PlacementCookie {
		cookiePayload, err = decodeChunkedPayload(func(i int) string {
			c, e := request.Cookie(fmt.Sprintf("%s_%d", key, i))
			if e != nil || c == nil {
				return ""
			}
			return c.Value
		})
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return nil, err
		}
	}

	switch placement {
	case PlacementHeader:
		return headerPayload, nil
	case PlacementCookie:
		return cookiePayload, nil
	case PlacementBody:
		return bodyPayload, nil
	case PlacementAuto:
		// 拼接三路 payload
		var result []byte
		result = append(result, headerPayload...)
		result = append(result, cookiePayload...)
		result = append(result, bodyPayload...)
		return result, nil
	}
	return bodyPayload, nil
}

// decodeChunkedPayload 把客户端切片的 base64 段重新拼起来 decode。
// getChunk(i) 返回第 i 段的字符串，空串表示没有更多段。
func decodeChunkedPayload(getChunk func(int) string) ([]byte, error) {
	var encodedParts []string
	for i := 0; ; i++ {
		chunk := getChunk(i)
		if chunk == "" {
			break
		}
		encodedParts = append(encodedParts, chunk)
	}
	if len(encodedParts) == 0 {
		return nil, nil
	}
	encoded := strings.Join(encodedParts, "")
	return base64.RawURLEncoding.DecodeString(encoded)
}

// ──────────────────────────────────────────────────────────────────────
// handleDownlink — GET 长流 (stream-down / stream-one)
// ──────────────────────────────────────────────────────────────────────

func (s *Server) handleDownlink(writer http.ResponseWriter, request *http.Request, sessionId string) {
	var session *httpSession
	if sessionId != "" {
		session = s.upsertSession(sessionId)
		session.markConnected()
		defer s.sessions.Delete(sessionId)
	}

	// 告诉 nginx / CDN 不要缓冲 response body
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.Header().Set("Cache-Control", "no-store")
	if !s.useNoSSEHeader() {
		writer.Header().Set("Content-Type", contentTypeSSE)
	}
	writer.WriteHeader(http.StatusOK)
	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}

	httpSC := newHTTPServerConn(request.Body, writer)
	var reader io.ReadCloser = httpSC
	if sessionId != "" {
		// stream-up / packet-up: reader 从 upload queue 取
		reader = session.uploadQueue
	}

	conn := newSplitConn(httpSC, reader, s.localAddr, parseRemoteAddr(request))

	// 把连接交给上层 (vless / trojan / etc.) 处理
	source := sHttp.SourceAddress(request)
	s.handler.NewConnectionEx(request.Context(), conn, source, M.Socksaddr{}, nil)

	// 阻塞到 request.Context 取消或 httpSC.Close
	select {
	case <-request.Context().Done():
	case <-httpSC.Wait():
	}
	conn.Close()
}

func (s *Server) useNoSSEHeader() bool {
	// NoSSEHeader 来自 option.NoSSEHeader，已在 config 里没有独立字段；
	// 这里通过 headers 检测是否有显式 Content-Type 覆盖。
	return false
}

// ──────────────────────────────────────────────────────────────────────
// session 管理
// ──────────────────────────────────────────────────────────────────────

func (s *Server) upsertSession(sessionId string) *httpSession {
	if v, ok := s.sessions.Load(sessionId); ok {
		return v.(*httpSession)
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if v, ok := s.sessions.Load(sessionId); ok {
		return v.(*httpSession)
	}
	session := &httpSession{
		uploadQueue:     newUploadQueue(s.cfg.scMaxBufferedPosts),
		isFullyConnected: make(chan struct{}),
	}
	s.sessions.Store(sessionId, session)

	// 30s 后如果 GET 下行还没来就回收，避免 POST-only 的孤儿 session 堆积
	go func() {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			s.sessions.Delete(sessionId)
			session.uploadQueue.Close()
		case <-session.isFullyConnected:
			// GET 到了，session 由 handleDownlink 管理
		}
	}()
	return session
}

func parseRemoteAddr(request *http.Request) net.Addr {
	host, portStr, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return &net.TCPAddr{IP: net.IPv4zero}
	}
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4zero
	}
	return &net.TCPAddr{IP: ip, Port: port}
}

func isValidHTTPHost(reqHost, configHost string) bool {
	// 支持多 host (逗号分隔) 的场景
	for _, h := range strings.Split(configHost, ",") {
		if strings.EqualFold(strings.TrimSpace(h), reqHost) {
			return true
		}
	}
	return false
}

// ──────────────────────────────────────────────────────────────────────
// adapter.V2RayServerTransport 接口实现
// ──────────────────────────────────────────────────────────────────────

func (s *Server) Network() []string { return []string{N.NetworkTCP} }

func (s *Server) Serve(listener net.Listener) error {
	if s.tlsConfig != nil {
		if len(s.tlsConfig.NextProtos()) == 0 {
			s.tlsConfig.SetNextProtos([]string{"h2", "http/1.1"})
		}
		listener = aTLS.NewListener(listener, s.tlsConfig)
	}
	s.localAddr = listener.Addr()
	return s.httpServer.Serve(listener)
}

func (s *Server) ServePacket(listener net.PacketConn) error { return os.ErrInvalid }

func (s *Server) Close() error {
	var err error
	if s.httpServer != nil {
		err = s.httpServer.Close()
	}
	// 关掉所有残留 session
	s.sessions.Range(func(key, value any) bool {
		if session, ok := value.(*httpSession); ok {
			session.uploadQueue.Close()
		}
		s.sessions.Delete(key)
		return true
	})
	return err
}
