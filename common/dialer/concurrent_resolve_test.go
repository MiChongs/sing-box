package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type concurrentTestDNSRouter struct {
	adapter.DNSRouter
	addresses []netip.Addr
}

func (r *concurrentTestDNSRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return r.addresses, nil
}

// concurrentTestHangDialer hangs on hang until the attempt is canceled and
// connects to any other address at once, so a serial dial of [hang, other]
// times out while a race connects.
type concurrentTestHangDialer struct {
	access sync.Mutex
	hang   netip.Addr
	dialed []netip.Addr
}

func (d *concurrentTestHangDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.dialed = append(d.dialed, destination.Addr)
	d.access.Unlock()
	if destination.Addr == d.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &concurrentTestConn{address: destination.Addr}, nil
}

func (d *concurrentTestHangDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type concurrentTestOutboundManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *concurrentTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.outbound, true
}

// concurrentTestOutbound dials through its own dialer.
type concurrentTestOutbound struct {
	adapter.Outbound
	dialer N.Dialer
}

func (o *concurrentTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.dialer.DialContext(ctx, network, destination)
}

// concurrentTestParallelOutbound also dials address lists itself and records
// the lists it receives.
type concurrentTestParallelOutbound struct {
	concurrentTestOutbound
	access sync.Mutex
	lists  [][]netip.Addr
	policy TCPConcurrentPolicy
}

func (o *concurrentTestParallelOutbound) DialParallel(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr) (net.Conn, error) {
	o.access.Lock()
	o.lists = append(o.lists, destinationAddresses)
	o.access.Unlock()
	return DialSerialConcurrent(ctx, o.policy, o.dialer, network, destination, destinationAddresses)
}

func TestResolveDialerTCPConcurrent(t *testing.T) {
	hanging, connecting := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	concurrent, err := NewTCPConcurrent(log.NewNOPFactory().NewLogger("tcp-concurrent"), &option.TCPConcurrentOptions{Enabled: true})
	require.NoError(t, err)
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), &concurrentTestDNSRouter{addresses: []netip.Addr{hanging, connecting}})
	ctx = service.ContextWithPtr(ctx, concurrent)
	destination := M.ParseSocksaddrHostPort("concurrent.test", 443)
	dial := func(dialer N.Dialer) (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer cancel()
		return dialer.DialContext(dialCtx, N.NetworkTCP, destination)
	}
	requireRaced := func(t *testing.T, dialer N.Dialer) {
		t.Helper()
		conn, dialErr := dial(dialer)
		require.NoError(t, dialErr)
		require.Equal(t, connecting, conn.(*concurrentTestConn).address)
	}
	requireSerial := func(t *testing.T, dialer N.Dialer) {
		t.Helper()
		_, dialErr := dial(dialer)
		require.ErrorIs(t, dialErr, context.DeadlineExceeded, "a serial dial waits for the first address")
	}
	newParallelOutbound := func() *concurrentTestParallelOutbound {
		return &concurrentTestParallelOutbound{
			concurrentTestOutbound: concurrentTestOutbound{dialer: &concurrentTestHangDialer{hang: hanging}},
			policy:                 TCPConcurrentPolicy{instance: concurrent},
		}
	}

	t.Run("races the resolved addresses", func(t *testing.T) {
		requireRaced(t, NewResolveDialer(ctx, &concurrentTestHangDialer{hang: hanging}, true, "", adapter.DNSQueryOptions{}, 0))
		winner, loaded := concurrent.winners.Get(concurrentDestination{host: "concurrent.test", port: 443})
		require.True(t, loaded)
		require.Equal(t, connecting, winner.address)
		concurrent.ResetHistory()
	})

	t.Run("fast open stays serial", func(t *testing.T) {
		requireSerial(t, NewResolveDialer(ctx, &concurrentTestHangDialer{hang: hanging}, false, "", adapter.DNSQueryOptions{}, 0))
	})

	t.Run("dialer override", func(t *testing.T) {
		concurrent.SetEnabled(false)
		defer concurrent.SetEnabled(true)
		forced := NewResolveDialer(ctx, &concurrentTestHangDialer{hang: hanging}, false, "", adapter.DNSQueryOptions{}, 0)
		outbound := newParallelOutbound()
		detour := NewResolveDialer(ctx, NewDetour(&concurrentTestOutboundManager{outbound: outbound}, "detour", true), false, "", adapter.DNSQueryOptions{}, 0)
		enabled := true
		setTCPConcurrentOverride(detour, &enabled)
		setTCPConcurrentOverride(forced, &enabled)
		outbound.policy = TCPConcurrentPolicy{instance: concurrent, override: &enabled}
		requireRaced(t, detour)
		requireSerial(t, forced) // fast open never races

		concurrent.SetEnabled(true)
		disabled := false
		optOut := NewResolveDialer(ctx, NewDetour(&concurrentTestOutboundManager{outbound: newParallelOutbound()}, "detour", true), false, "", adapter.DNSQueryOptions{}, 0)
		setTCPConcurrentOverride(optOut, &disabled)
		requireSerial(t, optOut)
	})

	t.Run("detours delegate to outbounds that dial address lists", func(t *testing.T) {
		outbound := newParallelOutbound()
		detour := NewDetour(&concurrentTestOutboundManager{outbound: outbound}, "detour", true)
		requireRaced(t, NewResolveDialer(ctx, detour, false, "", adapter.DNSQueryOptions{}, 0))
		require.Equal(t, [][]netip.Addr{{hanging, connecting}}, outbound.lists)
	})

	t.Run("detours without address lists stay serial", func(t *testing.T) {
		outbound := &concurrentTestOutbound{dialer: &concurrentTestHangDialer{hang: hanging}}
		detour := NewDetour(&concurrentTestOutboundManager{outbound: outbound}, "detour", true)
		requireSerial(t, NewResolveDialer(ctx, detour, false, "", adapter.DNSQueryOptions{}, 0))
	})

	t.Run("runtime switch", func(t *testing.T) {
		concurrent.SetEnabled(false)
		defer concurrent.SetEnabled(true)
		outbound := newParallelOutbound()
		detour := NewDetour(&concurrentTestOutboundManager{outbound: outbound}, "detour", true)
		requireSerial(t, NewResolveDialer(ctx, detour, false, "", adapter.DNSQueryOptions{}, 0))
		require.Empty(t, outbound.lists, "disabled dialers do not delegate")
	})
}

// Route-resolved addresses reach outbounds through DialSerialNetwork, which
// hands TCP to the ones that dial address lists themselves.
func TestDialSerialNetworkParallelDialer(t *testing.T) {
	hanging, connecting := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	concurrent, err := NewTCPConcurrent(log.NewNOPFactory().NewLogger("tcp-concurrent"), &option.TCPConcurrentOptions{Enabled: true})
	require.NoError(t, err)
	outbound := &concurrentTestParallelOutbound{
		concurrentTestOutbound: concurrentTestOutbound{dialer: &concurrentTestHangDialer{hang: hanging}},
		policy:                 TCPConcurrentPolicy{instance: concurrent},
	}
	destination := M.ParseSocksaddrHostPort("concurrent.test", 443)
	conn, err := DialSerialNetwork(context.Background(), outbound, N.NetworkTCP, destination, []netip.Addr{hanging, connecting}, nil, nil, nil, 0)
	require.NoError(t, err)
	require.Equal(t, connecting, conn.(*concurrentTestConn).address)
	require.Len(t, outbound.lists, 1)

	udpOutbound := &concurrentTestParallelOutbound{concurrentTestOutbound: concurrentTestOutbound{dialer: &concurrentTestHangDialer{}}}
	_, err = DialSerialNetwork(context.Background(), udpOutbound, N.NetworkUDP, destination, []netip.Addr{connecting}, nil, nil, nil, 0)
	require.NoError(t, err)
	require.Empty(t, udpOutbound.lists, "UDP keeps dialing address by address")
}

func TestDialEach(t *testing.T) {
	dialer := &concurrentTestNDialer{results: map[netip.Addr]error{testAddress4A: net.ErrClosed}}
	conn, err := DialEach(context.Background(), dialer, N.NetworkUDP, testDomain, []netip.Addr{testAddress4A, testAddress4B})
	require.NoError(t, err)
	require.Equal(t, testAddress4B, conn.(*concurrentTestConn).address)
	require.Equal(t, []M.Socksaddr{M.SocksaddrFrom(testAddress4A, 443), M.SocksaddrFrom(testAddress4B, 443)}, dialer.dialed)
	_, err = DialEach(context.Background(), &concurrentTestNDialer{results: map[netip.Addr]error{testAddress4A: net.ErrClosed}}, N.NetworkUDP, testDomain, []netip.Addr{testAddress4A})
	require.ErrorIs(t, err, net.ErrClosed)
}
