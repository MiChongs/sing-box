package provider

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type udpCheckOutbound struct {
	adapter.Outbound
	tag      string
	networks []string
	// target replaces the probe destination, so a node can be "broken"
	target atomic.Pointer[net.UDPAddr]
}

func (o *udpCheckOutbound) Tag() string       { return o.tag }
func (o *udpCheckOutbound) Network() []string { return o.networks }

func (o *udpCheckOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &redirectPacketConn{PacketConn: conn, target: o.target.Load()}, nil
}

type redirectPacketConn struct {
	net.PacketConn
	target *net.UDPAddr
}

func (c *redirectPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.PacketConn.WriteTo(p, c.target)
}

func startResponder(t *testing.T, answer bool) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query mDNS.Msg
			if !answer || query.Unpack(buffer[:n]) != nil {
				continue
			}
			response := new(mDNS.Msg)
			response.SetReply(&query)
			packed, _ := response.Pack()
			_, _ = conn.WriteTo(packed, addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

func TestProviderUDPHealthCheck(t *testing.T) {
	logFactory := log.NewNOPFactory()
	a := NewAdapter(context.Background(), nil, nil, nil, logFactory, logFactory.NewLogger("test"), "p", "remote",
		option.ProviderHealthCheckOptions{UDP: &option.ProviderUDPHealthCheckOptions{
			Enabled: true,
			Server:  "127.0.0.1:53",
			Timeout: badoption.Duration(1500 * time.Millisecond),
			TTL:     badoption.Duration(time.Minute),
		}})
	history := urltest.NewHistoryStorage()
	a.history = history

	working := startResponder(t, true)
	silent := startResponder(t, false)
	udpNode := &udpCheckOutbound{tag: "p/udp", networks: []string{N.NetworkTCP, N.NetworkUDP}}
	udpNode.target.Store(working)
	tcpNode := &udpCheckOutbound{tag: "p/tcp", networks: []string{N.NetworkTCP}}
	a.outbounds = []adapter.Outbound{udpNode, tcpNode}

	var updates atomic.Int32
	a.RegisterCallback(func(string) error {
		updates.Add(1)
		return nil
	})

	// working node: stored, nothing changes for groups
	_, _ = a.healthcheck(context.Background())
	result := history.LoadUDPTestHistory("p/udp")
	require.NotNil(t, result)
	require.Empty(t, result.Error)
	require.WithinDuration(t, time.Now().Add(time.Minute), result.Expire, 5*time.Second)
	require.Nil(t, history.LoadUDPTestHistory("p/tcp"), "nodes without UDP are not probed")
	require.Zero(t, updates.Load())

	// the node stops relaying UDP: groups are told once
	udpNode.target.Store(silent)
	_, _ = a.healthcheck(context.Background())
	require.True(t, urltest.UDPUnavailable(history, "p/udp"))
	require.EqualValues(t, 1, updates.Load())
	_, _ = a.healthcheck(context.Background())
	require.EqualValues(t, 1, updates.Load(), "no update while the state stays the same")

	// recovery
	udpNode.target.Store(working)
	_, _ = a.healthcheck(context.Background())
	require.False(t, urltest.UDPUnavailable(history, "p/udp"))
	require.EqualValues(t, 2, updates.Load())
}
