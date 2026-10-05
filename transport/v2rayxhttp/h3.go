//go:build with_quic

package v2rayxhttp

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	boxtls "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	brutal "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func checkH3Available() error {
	return nil
}

func disablePathMTUDiscovery() bool {
	return !C.IsLinux && !C.IsWindows && !C.IsDarwin
}

// buildH3Transport 对应 Xray createHTTPClient 的 httpVersion == "3" 分支。
func buildH3Transport(dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig boxtls.Config, cfg *config, keepAlivePeriod time.Duration) (http.RoundTripper, error) {
	if tlsConfig == nil {
		return nil, E.New("xhttp h3: TLS required")
	}
	quicConfig := &quic.Config{
		MaxIdleTimeout:          ConnIdleTimeout,
		KeepAlivePeriod:         QuicgoH3KeepAlivePeriod,
		MaxIncomingStreams:      -1,
		DisablePathMTUDiscovery: disablePathMTUDiscovery(),
	}
	if keepAlivePeriod > 0 {
		quicConfig.KeepAlivePeriod = keepAlivePeriod
	} else if keepAlivePeriod < 0 {
		quicConfig.KeepAlivePeriod = 0
	}
	return &http3.Transport{
		QUICConfig: quicConfig,
		Dial: func(ctx context.Context, addr string, _ *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			dialTLSConfig, err := boxtls.QUICDialConfig(ctx, tlsConfig)
			if err != nil {
				return nil, err
			}
			udpConn, err := dialer.DialContext(ctx, N.NetworkUDP, serverAddr)
			if err != nil {
				return nil, err
			}
			quicConn, err := qtls.Dial(ctx, udpConn, dialTLSConfig, quicConfig)
			if err != nil {
				_ = udpConn.Close()
				return nil, err
			}
			// quic-go does not take ownership of the conn passed to Dial.
			context.AfterFunc(quicConn.Context(), func() {
				_ = udpConn.Close()
			})
			applyH3CongestionControl(quicConn, cfg)
			return quicConn, nil
		},
	}, nil
}

// applyH3CongestionControl: "" / "bbr" → BBR；"force-brutal" → Brutal；"reno" → quic-go 默认。
func applyH3CongestionControl(conn *quic.Conn, cfg *config) {
	switch cfg.quicCongestion {
	case "", "bbr":
		conn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), congestion_meta2.ProfileStandard))
	case "force-brutal":
		conn.SetCongestionControl(brutal.NewBrutalSender(cfg.quicUp, conn.InitialPacketSize(), false, nil))
	}
}

// serveH3 对应 Xray ListenXH 的 isH3 分支。
func (s *Server) serveH3(packetConn net.PacketConn) error {
	err := qtls.ConfigureHTTP3(s.tlsConfig)
	if err != nil {
		return err
	}
	quicListener, err := qtls.ListenEarly(packetConn, s.tlsConfig, &quic.Config{
		MaxIdleTimeout:          ConnIdleTimeout,
		MaxIncomingStreams:      1 << 60,
		DisablePathMTUDiscovery: disablePathMTUDiscovery(),
	})
	if err != nil {
		return err
	}
	h3Server := &http3.Server{
		Handler: s,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			applyH3CongestionControl(conn, s.cfg)
			return log.ContextWithNewID(ctx)
		},
	}
	s.setH3Server(&h3ServerCloser{server: h3Server, listener: quicListener})
	err = h3Server.ServeListener(quicListener)
	if E.IsClosedOrCanceled(err) || err == http.ErrServerClosed {
		return nil
	}
	return err
}

type h3ServerCloser struct {
	server   *http3.Server
	listener qtls.EarlyListener
}

func (c *h3ServerCloser) Close() error {
	return common.Close(c.server, c.listener)
}
