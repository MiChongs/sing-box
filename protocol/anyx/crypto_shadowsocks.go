package anyx

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	shadowsocks2 "github.com/sagernet/sing-shadowsocks2"
	shadowaead_2022_client "github.com/sagernet/sing-shadowsocks2/shadowaead_2022"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
)

var ssDummyDestination = M.ParseSocksaddr("127.0.0.1:0")

func NewShadowsocksClient(ctx context.Context, opt *option.AnyXEncryptionOptions) (shadowsocks2.Method, error) {
	if opt == nil || opt.Method == "" || opt.Method == "none" {
		return nil, nil
	}
	return shadowsocks2.CreateMethod(ctx, opt.Method, shadowsocks2.MethodOptions{
		Password: opt.Password,
	})
}

func DialShadowsocksConn(ctx context.Context, method shadowsocks2.Method, conn net.Conn) (net.Conn, error) {
	if method == nil {
		return conn, nil
	}
	if _, is2022 := method.(*shadowaead_2022_client.Method); is2022 {
		handshakeCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
		defer cancel()
		closed := make(chan struct{})
		stop := context.AfterFunc(handshakeCtx, func() {
			conn.Close()
			close(closed)
		})
		outConn, handshakeErr := method.DialConn(conn, ssDummyDestination)
		if !stop() {
			<-closed
		}
		if handshakeCtx.Err() != nil {
			handshakeErr = handshakeCtx.Err()
		}
		if handshakeErr != nil {
			conn.Close()
			return nil, handshakeErr
		}
		return outConn, nil
	}
	return method.DialEarlyConn(conn, ssDummyDestination), nil
}

func NewShadowsocksServer(ctx context.Context, opt *option.AnyXEncryptionOptions, upstream func(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error) (shadowsocks.Service, error) {
	if opt == nil || opt.Method == "" || opt.Method == "none" {
		return nil, nil
	}
	handler := adapter.NewLegacyUpstreamHandler(adapter.InboundContext{}, upstream, nil, nil)
	switch {
	case common.Contains(shadowaead.List, opt.Method):
		return shadowaead.NewService(opt.Method, nil, opt.Password, 300, handler)
	case common.Contains(shadowaead_2022.List, opt.Method):
		return shadowaead_2022.NewServiceWithPassword(opt.Method, opt.Password, 300, handler, ntp.TimeFuncFromContext(ctx))
	default:
		return nil, E.New("anyx: unsupported shadowsocks encryption method: ", opt.Method)
	}
}