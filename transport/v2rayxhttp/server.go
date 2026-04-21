package v2rayxhttp

import (
	"context"
	"net"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// Server 端 XHTTP transport 当前未实现。原手搓版本与真实 Xray 客户端协议
// 不互通，已删除以免给用户"能用但连不上"的误导。后续如需作为 inbound，
// 需要完整移植 Xray/mihomo 服务端（session 重排、SSE 下行编码、padding 验证
// 等），工程量远大于 client。
//
// 本实现仅保留 Server 类型声明，让 option registry / transport plugin 注册
// 链路能构造完整；任何实际 inbound 请求立刻返回 501。
type Server struct {
	logger  logger.ContextLogger
	options *option.V2RayXHTTPOptions
	tls     tls.ServerConfig
	handler adapter.V2RayServerTransportHandler
}

func NewServer(
	ctx context.Context,
	logger logger.ContextLogger,
	options *option.V2RayXHTTPOptions,
	tlsConfig tls.ServerConfig,
	handler adapter.V2RayServerTransportHandler,
) (adapter.V2RayServerTransport, error) {
	return &Server{
		logger:  logger,
		options: options,
		tls:     tlsConfig,
		handler: handler,
	}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.logger.WarnContext(r.Context(),
		"xhttp: inbound server not yet implemented; rejecting request from ", r.RemoteAddr)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte("xhttp inbound not yet implemented in this build"))
}

func (s *Server) Network() []string                       { return []string{"tcp"} }
func (s *Server) Serve(listener net.Listener) error        { return E.New("xhttp: server not yet implemented") }
func (s *Server) ServePacket(listener net.PacketConn) error { return E.New("xhttp: server does not support packet listener") }
func (s *Server) Close() error                             { return nil }

// 避免 M import 在未来接口收紧时被 go mod tidy 掉
var _ = M.Socksaddr{}
