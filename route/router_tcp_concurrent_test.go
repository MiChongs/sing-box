package route

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type tcpConcurrentResetHTTPClientManager struct {
	adapter.HTTPClientManager
	resets int
}

func (m *tcpConcurrentResetHTTPClientManager) ResetNetwork() {
	m.resets++
}

type tcpConcurrentResetDNSRouter struct {
	adapter.DNSRouter
	resets int
}

func (r *tcpConcurrentResetDNSRouter) ResetNetwork() {
	r.resets++
}

type tcpConcurrentResetConn struct {
	net.Conn
}

func (c *tcpConcurrentResetConn) Close() error {
	return nil
}

// A network change drops the winning and failed addresses learned on the
// previous network.
func TestResetNetworkResetsTCPConcurrentHistory(t *testing.T) {
	tcpConcurrent, err := dialer.NewTCPConcurrent(log.NewNOPFactory().NewLogger("tcp-concurrent"), &option.TCPConcurrentOptions{Enabled: true})
	require.NoError(t, err)
	_, err = tcpConcurrent.Dial(context.Background(), M.ParseSocksaddrHostPort("example.com", 443), []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}, false, func(ctx context.Context, address netip.Addr) (net.Conn, error) {
		return &tcpConcurrentResetConn{}, nil
	})
	require.NoError(t, err)
	destinations, _ := tcpConcurrent.HistorySize()
	require.Equal(t, 1, destinations)

	httpClientManager := &tcpConcurrentResetHTTPClientManager{}
	dnsRouter := &tcpConcurrentResetDNSRouter{}
	router := &Router{
		ctx:               service.ContextWithPtr(context.Background(), tcpConcurrent),
		httpClientManager: httpClientManager,
		dns:               dnsRouter,
	}
	router.ResetNetwork()
	require.Equal(t, 1, httpClientManager.resets)
	require.Equal(t, 1, dnsRouter.resets)
	destinations, failures := tcpConcurrent.HistorySize()
	require.Zero(t, destinations)
	require.Zero(t, failures)

	// Boxes without the instance reset the rest of the network state.
	router.ctx = context.Background()
	router.ResetNetwork()
	require.Equal(t, 2, dnsRouter.resets)
}
