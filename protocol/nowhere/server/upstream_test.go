package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	N "github.com/sagernet/sing/common/network"
)

func TestRouterUpstreamAssignsIndependentFlowLogIDs(t *testing.T) {
	router := &flowIDRouter{}
	upstream := &RouterUpstream{Tag: "nowhere-in", Type: "nowhere", Router: router}
	base := log.ContextWithID(context.Background(), log.ID{ID: 1, CreatedAt: time.Unix(1, 0)})
	source := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	tcpTarget, err := wire.NewDomainTarget("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	udpTarget, err := wire.NewDomainTarget("example.com", 53)
	if err != nil {
		t.Fatal(err)
	}

	for range 2 {
		left, right := net.Pipe()
		if err := upstream.HandleStream(base, left, source, tcpTarget, nil); err != nil {
			t.Fatal(err)
		}
		_ = right.Close()
	}
	for range 2 {
		if err := upstream.HandlePacket(base, &testPacketConn{}, source, udpTarget, nil); err != nil {
			t.Fatal(err)
		}
	}

	ids := router.IDs()
	if len(ids) != 4 {
		t.Fatalf("captured %d IDs, want 4", len(ids))
	}
	unique := make(map[uint32]struct{}, len(ids))
	for _, id := range ids {
		if id.ID == 1 {
			t.Fatal("flow retained the physical connection ID")
		}
		unique[id.ID] = struct{}{}
	}
	if len(unique) != len(ids) {
		t.Fatalf("flow IDs are not unique: %+v", ids)
	}
}

type flowIDRouter struct {
	mu  sync.Mutex
	ids []log.ID
}

func (r *flowIDRouter) capture(ctx context.Context) {
	id, loaded := log.IDFromContext(ctx)
	if !loaded {
		return
	}
	r.mu.Lock()
	r.ids = append(r.ids, id)
	r.mu.Unlock()
}

func (r *flowIDRouter) IDs() []log.ID {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]log.ID(nil), r.ids...)
}

func (r *flowIDRouter) RouteConnection(context.Context, net.Conn, adapter.InboundContext) error {
	return nil
}

func (r *flowIDRouter) RoutePacketConnection(context.Context, N.PacketConn, adapter.InboundContext) error {
	return nil
}

func (r *flowIDRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.capture(ctx)
	_ = conn.Close()
}

func (r *flowIDRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.capture(ctx)
	_ = conn.Close()
}

type testPacketConn struct{}

func (*testPacketConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, net.ErrClosed }
func (*testPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (*testPacketConn) Close() error                              { return nil }
func (*testPacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (*testPacketConn) SetDeadline(time.Time) error               { return nil }
func (*testPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (*testPacketConn) SetWriteDeadline(time.Time) error          { return nil }

var (
	_ adapter.ConnectionRouterEx = (*flowIDRouter)(nil)
	_ net.PacketConn             = (*testPacketConn)(nil)
)
