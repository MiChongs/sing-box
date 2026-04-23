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
// dialer：sing-box outbound dialer，可承载 TUN / detour / 路由策略。
// serverAddr：xhttp 服务端 host:port（UDP）。
// tlsConfig：与 H1 / H2 路径同构的 sing-box TLS 配置；ALPN 为空时补 ["h3"]。
//
// 设计要点：
//   - quic.Config: MaxIncomingStreams=-1 禁止服务端反向开流（与 mihomo 对齐），
//     KeepAlivePeriod 默认 10s，PathMTU 在 Linux/Windows 之外禁用以兼容 macOS/BSD。
//   - Dial 回调：复用 sing-box dialer 取 UDP socket → bufio.UnbindPacketConn 解
//     绑后端 PacketConn，再用 sing-quic qtls.Dial 完成 QUIC 握手。这样跟
//     v2rayquic / hysteria2 / tuic 走同一条底层路径，所有 dial 钩子（路由、
//     bind、fwmark、ECH、Reality 等）都生效。
func buildH3Transport(dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig boxtls.Config) (http.RoundTripper, error) {
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
		Dial: func(ctx context.Context, addr string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			udpConn, err := dialer.DialContext(ctx, N.NetworkUDP, serverAddr)
			if err != nil {
				return nil, err
			}
			pc := bufio.NewUnbindPacketConn(udpConn)
			qc, err := qtls.Dial(ctx, pc, udpConn.RemoteAddr(), tlsConfig, cfg)
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
			return qc, nil
		},
	}, nil
}
