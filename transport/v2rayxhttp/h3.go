//go:build with_quic

package v2rayxhttp

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	boxtls "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	qtls "github.com/sagernet/sing-quic"
	bbr1 "github.com/sagernet/sing-quic/congestion_bbr1"
	brutal "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// QuicgoH3KeepAlivePeriod 与 quic-go 默认 keep-alive 一致 (10s)。
// h3 链路上 NAT 折返窗口比 TCP 短，需要更勤的 ping。
const QuicgoH3KeepAlivePeriod = 10 * time.Second

// buildH3Transport 装配 HTTP/3 RoundTripper（仅 with_quic 构建可用）。
//
// PR#5711: 支持 quicCongestion = "bbr" (默认) / "reno" / "force-brutal"。
// bbr 用 sing-quic/congestion_bbr1 的 BbrSender；force-brutal 用
// sing-quic/hysteria/congestion 的 BrutalSender (需配 quicUp 带宽)。
// Dial 回调拿到 *quic.Conn 后立即调 SetCongestionControl 切换。
func buildH3Transport(dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig boxtls.Config, cfg *config) (http.RoundTripper, error) {
	if tlsConfig == nil {
		return nil, E.New("xhttp h3: TLS required (alpn=[\"h3\"] without TLS is invalid)")
	}
	if alpn := tlsConfig.NextProtos(); len(alpn) == 0 {
		tlsConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	quicConfig := &quic.Config{
		MaxIncomingStreams:      -1,
		KeepAlivePeriod:         QuicgoH3KeepAlivePeriod,
		MaxIdleTimeout:          ConnIdleTimeout,
		EnableDatagrams:         false,
		DisablePathMTUDiscovery: !C.IsLinux && !C.IsWindows,
	}
	return &http3.Transport{
		QUICConfig: quicConfig,
		Dial: func(ctx context.Context, addr string, _ *tls.Config, cfg2 *quic.Config) (*quic.Conn, error) {
			udpConn, err := dialer.DialContext(ctx, N.NetworkUDP, serverAddr)
			if err != nil {
				return nil, err
			}
			pc := bufio.NewUnbindPacketConn(udpConn)
			qc, err := qtls.Dial(ctx, pc, udpConn.RemoteAddr(), tlsConfig, cfg2)
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
			// PR#5711: 连接建立后切换拥塞控制算法
			applyH3CongestionControl(qc, cfg)
			return qc, nil
		},
	}, nil
}

// applyH3CongestionControl 按 cfg.quicCongestion 切换 QUIC 拥塞控制。
// 空值或 "bbr" → BBR (v26.3.27 默认)；"reno" → 保留 quic-go 默认 cubic；
// "force-brutal" → BrutalSender 固定带宽。
func applyH3CongestionControl(conn *quic.Conn, cfg *config) {
	if cfg == nil {
		return
	}
	switch cfg.quicCongestion {
	case "", "bbr":
		clock := bbr1.DefaultClock{}
		sender := bbr1.NewBbrSender(clock, bbr1.InitialCongestionWindowPackets, 0, 0)
		conn.SetCongestionControl(sender)
	case "force-brutal":
		sender := brutal.NewBrutalSender(cfg.quicUp, false, nil)
		conn.SetCongestionControl(sender)
	case "reno":
		// quic-go 默认就是 cubic；reno 留给以后
	}
}
