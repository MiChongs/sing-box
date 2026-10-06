package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestServeQUICAuthFailureReportsQUICCarrier(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	invalidCredentials, err := wire.NewCredentials("wrong-secret")
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewConfig(ConfigOptions{
		Credentials: credentials,
		Networks:    []Network{NetworkUDP},
		Timeouts:    Timeouts{Auth: 10 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan diagnostic.Event, 1)
	handler, err := NewHandler(HandlerOptions{
		Config:   config,
		Upstream: v15DiscardUpstream{},
		Observer: diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
			if event.Code == "auth_failed" {
				events <- event
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	var exporter wire.TLSExporter
	exporter[0] = 5
	auth, err := wire.EncodeAuthFrame(invalidCredentials, wire.AuthTransportQUIC, exporter, wire.SessionID{1})
	if err != nil {
		t.Fatal(err)
	}
	conn := newV15QUICConn(exporter, &v15QuicStream{Reader: bytes.NewReader(auth[:])})
	if err := handler.ServeQUIC(context.Background(), conn); err == nil {
		t.Fatal("ServeQUIC accepted invalid authentication")
	}

	select {
	case event := <-events:
		if event.Carrier != diagnostic.CarrierQUIC {
			t.Fatalf("auth_failed carrier = %q, want %q", event.Carrier, diagnostic.CarrierQUIC)
		}
	case <-time.After(time.Second):
		t.Fatal("auth_failed event was not emitted")
	}
}

func TestServeQUICAuthOnlyNotifiesAdapterAfterAuthentication(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewConfig(ConfigOptions{Credentials: credentials, Networks: []Network{NetworkUDP}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: v15DiscardUpstream{}})
	if err != nil {
		t.Fatal(err)
	}
	var exporter wire.TLSExporter
	exporter[0] = 7
	id := wire.SessionID{1}
	auth, err := wire.EncodeAuthFrame(credentials, wire.AuthTransportQUIC, exporter, id)
	if err != nil {
		t.Fatal(err)
	}
	conn := newV15QUICConn(exporter, &v15QuicStream{Reader: bytes.NewReader(auth[:])})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- handler.ServeQUIC(ctx, conn) }()
	select {
	case <-conn.authenticated:
	case <-time.After(time.Second):
		t.Fatal("authenticated connection did not notify adapter")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeQUIC = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeQUIC did not exit after cancellation")
	}
}

func TestServeQUICRoutesFirstFlowCoalescedWithAuthentication(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewConfig(ConfigOptions{Credentials: credentials, Networks: []Network{NetworkUDP}})
	if err != nil {
		t.Fatal(err)
	}
	upstream := &v15SignalingUpstream{
		routed: make(chan wire.Target, 1),
		infos:  make(chan FlowInfo, 1),
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: upstream})
	if err != nil {
		t.Fatal(err)
	}

	var exporter wire.TLSExporter
	exporter[0] = 9
	id := wire.SessionID{2}
	auth, err := wire.EncodeAuthFrame(credentials, wire.AuthTransportQUIC, exporter, id)
	if err != nil {
		t.Fatal(err)
	}
	target, err := wire.NewIPTarget(netip.MustParseAddr("192.0.2.1"), 443)
	if err != nil {
		t.Fatal(err)
	}
	header, err := wire.WriteFlowHeader(wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierQUIC, Downlink: wire.CarrierQUIC, Hops: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	targetBytes, err := wire.EncodeTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 0, len(auth)+len(header)+len(targetBytes))
	payload = append(payload, auth[:]...)
	payload = append(payload, header[:]...)
	payload = append(payload, targetBytes...)

	conn := newV15QUICConn(exporter, &v15QuicStream{Reader: bytes.NewReader(payload)})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handler.ServeQUIC(ctx, conn) }()

	select {
	case got := <-upstream.routed:
		if got != target {
			t.Fatalf("routed target = %+v, want %+v", got, target)
		}
	case <-time.After(time.Second):
		t.Fatal("coalesced first flow was not routed")
	}
	select {
	case info := <-upstream.infos:
		if info.Hops != 5 {
			t.Fatalf("routed HOPS=%d want=5", info.Hops)
		}
	case <-time.After(time.Second):
		t.Fatal("flow metadata was not exposed to Upstream")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeQUIC = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeQUIC did not exit after cancellation")
	}
}

type v15DiscardUpstream struct{}

func (v15DiscardUpstream) HandleStream(context.Context, net.Conn, net.Addr, wire.Target, FlowReadiness) error {
	return nil
}

func (v15DiscardUpstream) HandlePacket(context.Context, net.PacketConn, net.Addr, wire.Target, FlowReadiness) error {
	return nil
}

type v15SignalingUpstream struct {
	routed chan wire.Target
	infos  chan FlowInfo
}

func (u *v15SignalingUpstream) HandleStream(ctx context.Context, _ net.Conn, _ net.Addr, target wire.Target, readiness FlowReadiness) error {
	if err := readiness.Ready(); err != nil {
		return err
	}
	if u.infos != nil {
		info, _ := FlowInfoFromContext(ctx)
		u.infos <- info
	}
	u.routed <- target
	return nil
}

func (*v15SignalingUpstream) HandlePacket(context.Context, net.PacketConn, net.Addr, wire.Target, FlowReadiness) error {
	return errors.New("unexpected packet flow")
}

type v15QUICConn struct {
	exporter wire.TLSExporter
	stream   QuicStream
	ctx      context.Context
	cancel   context.CancelFunc

	accepted      atomic.Bool
	authenticated chan struct{}
	authOnce      sync.Once
}

func newV15QUICConn(exporter wire.TLSExporter, stream QuicStream) *v15QUICConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &v15QUICConn{exporter: exporter, stream: stream, ctx: ctx, cancel: cancel, authenticated: make(chan struct{})}
}

func (c *v15QUICConn) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	return wire.TLSHandshakeInfo{
		TLSVersion: 0x0304, NegotiatedALPN: wire.DefaultALPN, Exporter: c.exporter,
	}, nil
}
func (c *v15QUICConn) MarkAuthenticated() { c.authOnce.Do(func() { close(c.authenticated) }) }
func (c *v15QUICConn) AcceptStream(ctx context.Context) (QuicStream, error) {
	if c.accepted.CompareAndSwap(false, true) {
		return c.stream, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (c *v15QUICConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (c *v15QUICConn) SendDatagram(context.Context, []byte) error { return nil }
func (c *v15QUICConn) CloseWithError(uint64, string) error        { c.cancel(); return nil }
func (c *v15QUICConn) Close() error                               { c.cancel(); return nil }
func (c *v15QUICConn) Context() context.Context                   { return c.ctx }
func (*v15QUICConn) LocalAddr() net.Addr                          { return &net.UDPAddr{} }
func (*v15QUICConn) RemoteAddr() net.Addr                         { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)} }

type v15QuicStream struct {
	*bytes.Reader
}

func (s *v15QuicStream) Write(p []byte) (int, error)    { return len(p), nil }
func (*v15QuicStream) Close() error                     { return nil }
func (*v15QuicStream) SetDeadline(time.Time) error      { return nil }
func (*v15QuicStream) SetReadDeadline(time.Time) error  { return nil }
func (*v15QuicStream) SetWriteDeadline(time.Time) error { return nil }
func (*v15QuicStream) CancelRead(uint64)                {}
func (*v15QuicStream) CancelWrite(uint64)               {}

var (
	_ QuicConn   = (*v15QUICConn)(nil)
	_ QuicStream = (*v15QuicStream)(nil)
)
