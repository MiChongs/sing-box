package easytier

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type egressTestRoute struct {
	conn     N.PacketConn
	metadata adapter.InboundContext
	onClose  N.CloseHandlerFunc
}

type egressTestRouter struct {
	adapter.Router
	routes chan egressTestRoute
}

func (r *egressTestRouter) RoutePacketConnectionEx(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.routes <- egressTestRoute{conn: conn, metadata: metadata, onClose: onClose}
}

func TestEgressPacketConnRoutesEachDestination(t *testing.T) {
	t.Parallel()
	router := &egressTestRouter{routes: make(chan egressTestRoute, 8)}
	endpoint := &Endpoint{ctx: context.Background(), router: router, logger: log.NewNOPFactory().NewLogger("easytier")}
	conn := endpoint.newEgressPacketConn()
	defer conn.Close()

	dns := netip.MustParseAddrPort("192.0.2.53:53")
	ntp := netip.MustParseAddrPort("198.51.100.123:123")
	_, err := conn.WriteTo([]byte("query"), net.UDPAddrFromAddrPort(dns))
	require.NoError(t, err)
	_, err = conn.WriteTo([]byte("time"), net.UDPAddrFromAddrPort(ntp))
	require.NoError(t, err)
	_, err = conn.WriteTo([]byte("again"), net.UDPAddrFromAddrPort(dns))
	require.NoError(t, err)

	routes := map[netip.AddrPort]egressTestRoute{}
	for range 2 {
		select {
		case route := <-router.routes:
			routes[route.metadata.Destination.AddrPort()] = route
		case <-time.After(time.Second):
			t.Fatal("missing routed session")
		}
	}
	require.Contains(t, routes, dns, "each destination is routed by its own metadata")
	require.Contains(t, routes, ntp)
	select {
	case route := <-router.routes:
		t.Fatalf("a destination was routed twice: %v", route.metadata.Destination)
	default:
	}

	read := func(route egressTestRoute) string {
		buffer := buf.NewPacket()
		defer buffer.Release()
		destination, readErr := route.conn.ReadPacket(buffer)
		require.NoError(t, readErr)
		require.Equal(t, route.metadata.Destination, destination)
		return string(buffer.Bytes())
	}
	require.Equal(t, "query", read(routes[dns]))
	require.Equal(t, "again", read(routes[dns]))
	require.Equal(t, "time", read(routes[ntp]))

	// Responses of every session reach the core's socket with their source.
	response := buf.NewPacket()
	_, _ = response.WriteString("answer")
	require.NoError(t, routes[ntp].conn.WritePacket(response, M.SocksaddrFromNetIP(ntp)))
	payload := make([]byte, 64)
	n, source, err := conn.ReadFrom(payload)
	require.NoError(t, err)
	require.Equal(t, "answer", string(payload[:n]))
	require.Equal(t, ntp, source.(*net.UDPAddr).AddrPort())

	// A session closed by the router is replaced on the next datagram.
	routes[dns].onClose(nil)
	_, err = conn.WriteTo([]byte("retry"), net.UDPAddrFromAddrPort(dns))
	require.NoError(t, err)
	select {
	case route := <-router.routes:
		require.Equal(t, dns, route.metadata.Destination.AddrPort())
		require.Equal(t, "retry", read(route))
	case <-time.After(time.Second):
		t.Fatal("closed session was not replaced")
	}
	conn.access.Lock()
	require.Len(t, conn.sessions, 2)
	conn.access.Unlock()
}
