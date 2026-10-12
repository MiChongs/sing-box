package observability

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type tcpConcurrentTestConn struct {
	net.Conn
}

func (c *tcpConcurrentTestConn) Close() error {
	return nil
}

func TestTCPConcurrentMetrics(t *testing.T) {
	tcpConcurrent, err := dialer.NewTCPConcurrent(log.NewNOPFactory().NewLogger("tcp-concurrent"), &option.TCPConcurrentOptions{Enabled: true})
	require.NoError(t, err)
	refused, accepted := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	_, err = tcpConcurrent.Dial(context.Background(), M.ParseSocksaddrHostPort("example.com", 443), []netip.Addr{accepted, refused}, false, func(ctx context.Context, address netip.Addr) (net.Conn, error) {
		if address == refused {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &tcpConcurrentTestConn{}, nil
	})
	require.NoError(t, err)

	manager := &Manager{ctx: service.ContextWithPtr(context.Background(), tcpConcurrent)}
	var output bytes.Buffer
	manager.writeTCPConcurrentMetrics(&output)
	metrics := output.String()
	for _, line := range []string{
		"singbox_tcp_concurrent_enabled 1\n",
		"singbox_tcp_concurrent_races_total 1\n",
		"singbox_tcp_concurrent_attempts_total 2\n",
		"singbox_tcp_concurrent_attempt_failures_total 0\n",
		`singbox_tcp_concurrent_wins_total{position="1"} 1` + "\n",
		`singbox_tcp_concurrent_wins_total{position="4+"} 0` + "\n",
		"singbox_tcp_concurrent_remembered_destinations 1\n",
		"# TYPE singbox_tcp_concurrent_connect_seconds_total counter\n",
	} {
		require.Contains(t, metrics, line)
	}

	var empty bytes.Buffer
	(&Manager{ctx: context.Background()}).writeTCPConcurrentMetrics(&empty)
	require.Zero(t, empty.Len(), "nothing is exported without an instance")
}
