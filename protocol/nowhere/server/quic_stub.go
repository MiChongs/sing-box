//go:build !with_quic

package server

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/internal/quicsettings"
)

// QUICServer is unavailable without with_quic.
type QUICServer struct{}

func NewQUICServer(
	ctx context.Context,
	handler *Handler,
	tlsConfig tls.ServerConfig,
	quicOptions option.QUICOptions,
	congestionControl quicsettings.CongestionControl,
	observer diagnostic.Observer,
) *QUICServer {
	return &QUICServer{}
}

func (s *QUICServer) Start(packetConn net.PacketConn) error {
	return C.ErrQUICNotIncluded
}

func (s *QUICServer) Close() error { return nil }

func (s *QUICServer) Restart(listenPacket func() (net.PacketConn, error)) error {
	return C.ErrQUICNotIncluded
}
