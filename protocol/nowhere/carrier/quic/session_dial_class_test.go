//go:build with_quic

package quic

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/dialgate"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type staticPacketDialer struct {
	conn net.Conn
}

func (d staticPacketDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (d staticPacketDialer) ListenPacket(ctx context.Context, address M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

var _ N.Dialer = staticPacketDialer{}

// A packet socket that dies while the QUIC handshake is in flight (server
// restart window) must surface as a retryable dial failure, not a terminal one.
func TestDialTransientSocketLossClassifiedRetryable(t *testing.T) {
	tlsConfig, err := tls.NewClient(context.Background(), nil, "127.0.0.1:1", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.org",
		ALPN:       []string{wire.DefaultALPN},
		MinVersion: "1.3",
		MaxVersion: "1.3",
	})
	require.NoError(t, err)

	deadSocket, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	require.NoError(t, err)
	require.NoError(t, deadSocket.Close())

	session := NewSession(&QUICConfig{
		Addr:      "127.0.0.1:1",
		TLSConfig: tlsConfig,
		Dialer:    staticPacketDialer{conn: deadSocket},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = session.EnsureReady(ctx)
	require.Error(t, err)
	require.Equal(t, dialgate.ClassRetryable, dialgate.Classify(err), "establish error %v must classify retryable", err)
}
