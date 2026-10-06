package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestServeQUICRejectsLegacyDerivedUDP(t *testing.T) {
	handler, credentials, upstream := newLegacyTestHandler(t, func(event diagnostic.Event) {
		if event.Code == "udp_queue_drop_total" && event.Outcome == "unknown_flow" {
			// The assertion observes this through the supplied channel below.
		}
	})
	var exporter wire.TLSExporter
	exporter[0] = 1
	auth := legacyAuthFrame(t, credentials, wire.AuthTransportQUIC, exporter)
	stream := newLegacyQUICStream(auth[:])
	conn := newLegacyQUICConn(exporter, stream)
	drops := make(chan diagnostic.Event, 1)
	handler.observer = diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
		if event.Code == "udp_queue_drop_total" {
			drops <- event
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handler.ServeQUIC(ctx, conn) }()
	select {
	case <-conn.authenticated:
	case <-time.After(time.Second):
		t.Fatal("QUIC session did not authenticate")
	}
	frame, err := wire.EncodeUDPData(1, []byte("legacy-derived-payload"))
	if err != nil {
		t.Fatal(err)
	}
	conn.datagrams <- frame
	select {
	case <-conn.datagramRead:
	case <-time.After(time.Second):
		t.Fatal("legacy datagram was not consumed")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeQUIC: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeQUIC did not stop")
	}
	select {
	case event := <-drops:
		if event.FlowID != 1 || event.Outcome != "unknown_flow" {
			t.Fatalf("drop event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("legacy derived UDP datagram was not rejected as an unknown flow")
	}
	if got := upstream.calls.Load(); got != 0 {
		t.Fatalf("legacy derived UDP routed %d upstream flows", got)
	}
}

func TestServeQUICRejectsLegacyCompactUDP(t *testing.T) {
	handler, credentials, upstream := newLegacyTestHandler(t, nil)
	var exporter wire.TLSExporter
	exporter[0] = 2
	auth := legacyAuthFrame(t, credentials, wire.AuthTransportQUIC, exporter)
	compact, err := wire.EncodeUDPData(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	input := append(append([]byte(nil), auth[:]...), compact...)
	stream := newLegacyQUICStream(input)
	conn := newLegacyQUICConn(exporter, stream)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handler.ServeQUIC(ctx, conn) }()
	select {
	case <-stream.closed:
	case <-time.After(time.Second):
		t.Fatal("legacy compact UDP control stream was not rejected")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeQUIC: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeQUIC did not stop")
	}
	if got := upstream.calls.Load(); got != 0 {
		t.Fatalf("legacy compact UDP routed %d upstream flows", got)
	}
}

func TestServeTCPRejectsLegacyUOT(t *testing.T) {
	handler, credentials, upstream := newLegacyTestHandler(t, nil)
	var exporter wire.TLSExporter
	exporter[0] = 3
	auth := legacyAuthFrame(t, credentials, wire.AuthTransportTLSTCP, exporter)
	packet, err := wire.EncodeUDPPacket([]byte("legacy-uot-without-flow"))
	if err != nil {
		t.Fatal(err)
	}
	input := append(append([]byte(nil), auth[:]...), packet...)
	err = serveLegacyTCP(handler, exporter, input)
	if err == nil {
		t.Fatal("legacy UoT without FLOW envelope was accepted")
	}
	if got := upstream.calls.Load(); got != 0 {
		t.Fatalf("legacy UoT routed %d upstream flows", got)
	}
}

func TestServeTCPRejectsMissingFlowEnvelope(t *testing.T) {
	handler, credentials, upstream := newLegacyTestHandler(t, nil)
	var exporter wire.TLSExporter
	exporter[0] = 4
	auth := legacyAuthFrame(t, credentials, wire.AuthTransportTLSTCP, exporter)
	input := append(append([]byte(nil), auth[:]...), []byte("raw-request-without-flow")...)
	err := serveLegacyTCP(handler, exporter, input)
	if err == nil {
		t.Fatal("request without FLOW envelope was accepted")
	}
	if got := upstream.calls.Load(); got != 0 {
		t.Fatalf("missing FLOW envelope routed %d upstream flows", got)
	}
}

func serveLegacyTCP(handler *Handler, exporter wire.TLSExporter, input []byte) error {
	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- handler.HandleConn(context.Background(), wire.HandshakedConn{
			Conn: serverConn,
			TLSHandshakeInfo: wire.TLSHandshakeInfo{
				TLSVersion: tls.VersionTLS13, NegotiatedALPN: wire.DefaultALPN, Exporter: exporter,
			},
		}, &net.TCPAddr{}, nil)
	}()
	_, _ = clientConn.Write(input)
	_ = clientConn.Close()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		return errors.New("legacy TCP rejection timed out")
	}
}

func legacyAuthFrame(t *testing.T, credentials *wire.Credentials, transport wire.AuthTransport, exporter wire.TLSExporter) wire.AuthFrame {
	t.Helper()
	frame, err := wire.EncodeAuthFrame(credentials, transport, exporter, wire.SessionID{1})
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func newLegacyTestHandler(t *testing.T, observe func(diagnostic.Event)) (*Handler, *wire.Credentials, *legacyRejectUpstream) {
	t.Helper()
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewConfig(ConfigOptions{
		Credentials: credentials,
		Networks:    []Network{NetworkTCP, NetworkUDP},
		Timeouts:    Timeouts{Auth: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	upstream := &legacyRejectUpstream{}
	var observer diagnostic.Observer
	if observe != nil {
		observer = diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) { observe(event) })
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: upstream, Observer: observer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	return handler, credentials, upstream
}

type legacyRejectUpstream struct {
	calls atomic.Int32
}

func (u *legacyRejectUpstream) HandleStream(context.Context, net.Conn, net.Addr, wire.Target, FlowReadiness) error {
	u.calls.Add(1)
	return errors.New("unexpected legacy stream route")
}

func (u *legacyRejectUpstream) HandlePacket(context.Context, net.PacketConn, net.Addr, wire.Target, FlowReadiness) error {
	u.calls.Add(1)
	return errors.New("unexpected legacy packet route")
}

type legacyQUICConn struct {
	exporter      wire.TLSExporter
	first         QuicStream
	datagrams     chan []byte
	datagramRead  chan struct{}
	ctx           context.Context
	cancel        context.CancelFunc
	accepted      atomic.Bool
	authenticated chan struct{}
	authOnce      sync.Once
	datagramOnce  sync.Once
}

func newLegacyQUICConn(exporter wire.TLSExporter, first QuicStream) *legacyQUICConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &legacyQUICConn{
		exporter: exporter, first: first, datagrams: make(chan []byte, 1),
		datagramRead: make(chan struct{}), ctx: ctx, cancel: cancel, authenticated: make(chan struct{}),
	}
}

func (c *legacyQUICConn) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	return wire.TLSHandshakeInfo{
		TLSVersion: tls.VersionTLS13, NegotiatedALPN: wire.DefaultALPN, Exporter: c.exporter,
	}, nil
}

func (c *legacyQUICConn) AcceptStream(ctx context.Context) (QuicStream, error) {
	if c.accepted.CompareAndSwap(false, true) {
		return c.first, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (c *legacyQUICConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case data := <-c.datagrams:
		c.datagramOnce.Do(func() { close(c.datagramRead) })
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (*legacyQUICConn) SendDatagram(context.Context, []byte) error { return nil }
func (c *legacyQUICConn) CloseWithError(uint64, string) error      { c.cancel(); return nil }
func (c *legacyQUICConn) Close() error                             { c.cancel(); return nil }
func (c *legacyQUICConn) Context() context.Context                 { return c.ctx }
func (*legacyQUICConn) LocalAddr() net.Addr                        { return &net.UDPAddr{} }
func (*legacyQUICConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *legacyQUICConn) MarkAuthenticated() {
	c.authOnce.Do(func() { close(c.authenticated) })
}

type legacyQUICStream struct {
	*bytes.Reader
	closed    chan struct{}
	closeOnce sync.Once
}

func newLegacyQUICStream(input []byte) *legacyQUICStream {
	return &legacyQUICStream{Reader: bytes.NewReader(input), closed: make(chan struct{})}
}
func (*legacyQUICStream) Write(p []byte) (int, error)      { return len(p), nil }
func (s *legacyQUICStream) Close() error                   { s.closeOnce.Do(func() { close(s.closed) }); return nil }
func (*legacyQUICStream) SetDeadline(time.Time) error      { return nil }
func (*legacyQUICStream) SetReadDeadline(time.Time) error  { return nil }
func (*legacyQUICStream) SetWriteDeadline(time.Time) error { return nil }
func (*legacyQUICStream) CancelRead(uint64)                {}
func (*legacyQUICStream) CancelWrite(uint64)               {}

var (
	_ io.ReadWriteCloser         = (*legacyQUICStream)(nil)
	_ QuicConn                   = (*legacyQUICConn)(nil)
	_ QuicAuthenticationNotifier = (*legacyQUICConn)(nil)
)
