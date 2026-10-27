package urltest

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type udpTestDialer struct {
	N.Dialer
}

func (udpTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

// startDNSResponder answers queries; drop decides per query whether to stay
// silent, and spoof sends a reply with a wrong ID first.
func startDNSResponder(t *testing.T, drop func(n int64) bool, spoof bool) M.Socksaddr {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	var received atomic.Int64
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			if drop != nil && drop(received.Add(1)) {
				continue
			}
			var query mDNS.Msg
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			response := new(mDNS.Msg)
			response.SetReply(&query)
			if spoof {
				fake := response.Copy()
				fake.Id++
				packed, _ := fake.Pack()
				_, _ = conn.WriteTo(packed, addr)
			}
			packed, _ := response.Pack()
			_, _ = conn.WriteTo(packed, addr)
		}
	}()
	return M.SocksaddrFromNet(conn.LocalAddr())
}

func TestUDPTest(t *testing.T) {
	t.Parallel()
	probe := func(server M.Socksaddr, timeout time.Duration) (uint16, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return UDPTest(ctx, udpTestDialer{}, server, DefaultUDPTestDomain)
	}
	t.Run("answer", func(t *testing.T) {
		delay, err := probe(startDNSResponder(t, nil, false), 3*time.Second)
		require.NoError(t, err)
		require.NotZero(t, delay)
	})
	t.Run("spoofed id is ignored", func(t *testing.T) {
		_, err := probe(startDNSResponder(t, nil, true), 3*time.Second)
		require.NoError(t, err)
	})
	t.Run("retransmits after loss", func(t *testing.T) {
		start := time.Now()
		_, err := probe(startDNSResponder(t, func(n int64) bool { return n == 1 }, false), 3*time.Second)
		require.NoError(t, err)
		require.GreaterOrEqual(t, time.Since(start), udpTestRetransmit)
	})
	t.Run("no answer", func(t *testing.T) {
		start := time.Now()
		_, err := probe(startDNSResponder(t, func(int64) bool { return true }, false), 1500*time.Millisecond)
		require.ErrorContains(t, err, "no UDP response")
		require.Less(t, time.Since(start), 3*time.Second)
	})
	t.Run("requires timeout", func(t *testing.T) {
		_, err := UDPTest(context.Background(), udpTestDialer{}, M.ParseSocksaddr("127.0.0.1:53"), DefaultUDPTestDomain)
		require.Error(t, err)
	})
}

func TestUDPUnavailable(t *testing.T) {
	t.Parallel()
	history := NewHistoryStorage()
	now := time.Now()
	history.StoreUDPTestHistory("failed", &adapter.UDPTestHistory{Time: now, Expire: now.Add(time.Minute), Error: "timeout"})
	history.StoreUDPTestHistory("expired", &adapter.UDPTestHistory{Time: now, Expire: now.Add(-time.Second), Error: "timeout"})
	history.StoreUDPTestHistory("ok", &adapter.UDPTestHistory{Time: now, Expire: now.Add(time.Minute), Delay: 20})

	require.True(t, UDPUnavailable(history, "failed"))
	require.False(t, UDPUnavailable(history, "expired"), "expired results no longer count")
	require.False(t, UDPUnavailable(history, "ok"))
	require.False(t, UDPUnavailable(history, "never probed"))
	require.False(t, UDPUnavailable(nil, "failed"))
	var nilHistory *HistoryStorage
	require.False(t, UDPUnavailable(nilHistory, "failed"))
}
