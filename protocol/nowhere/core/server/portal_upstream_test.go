package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/bundle"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestForwardedPortalHops(t *testing.T) {
	tests := []struct {
		incoming uint8
		want     uint8
		wantErr  error
	}{
		{incoming: 0, want: 7},
		{incoming: 7, want: 6},
		{incoming: 2, want: 1},
		{incoming: 1, wantErr: ErrPortalHopLimit},
		{incoming: 8, wantErr: wire.ErrInvalidFlowHeader},
	}
	for _, test := range tests {
		ctx := withFlowInfo(context.Background(), FlowInfo{Hops: test.incoming})
		got, err := forwardedPortalHops(ctx)
		if !errors.Is(err, test.wantErr) {
			t.Fatalf("incoming=%d error=%v want=%v", test.incoming, err, test.wantErr)
		}
		if got != test.want {
			t.Fatalf("incoming=%d hops=%d want=%d", test.incoming, got, test.want)
		}
	}
}

func TestForwardedPortalChainStopsAfterSevenTransitions(t *testing.T) {
	hops := uint8(0)
	for transition := 1; transition <= int(wire.MaxPortalHops); transition++ {
		ctx := withFlowInfo(context.Background(), FlowInfo{Hops: hops})
		var err error
		hops, err = forwardedPortalHops(ctx)
		if err != nil {
			t.Fatalf("transition %d: %v", transition, err)
		}
	}
	if hops != 1 {
		t.Fatalf("HOPS after seven transitions=%d want=1", hops)
	}
	if _, err := forwardedPortalHops(withFlowInfo(context.Background(), FlowInfo{Hops: hops})); !errors.Is(err, ErrPortalHopLimit) {
		t.Fatalf("eighth transition error=%v want ErrPortalHopLimit", err)
	}
}

func TestPortalUpstreamPropagatesSetupResult(t *testing.T) {
	for code := wire.SetupResultInvalidRequest; code <= wire.SetupResultInternalError; code++ {
		code := code
		t.Run("tcp/"+code.String(), func(t *testing.T) {
			client := &recordingPortalClient{tcpErr: &bundle.SetupResultError{Code: code}}
			upstream := &PortalUpstream{client: client, tcpReadGrace: time.Second}
			readiness := &recordingReadiness{}
			err := upstream.HandleStream(context.Background(), nil, nil, wire.Target{}, readiness)
			if err == nil {
				t.Fatal("expected forwarded setup failure")
			}
			if got := readiness.rejectedCode(); got != code {
				t.Fatalf("rejected code=%v want=%v", got, code)
			}
		})
		t.Run("udp/"+code.String(), func(t *testing.T) {
			client := &recordingPortalClient{udpErr: &bundle.SetupResultError{Code: code}}
			upstream := &PortalUpstream{client: client, tcpReadGrace: time.Second}
			readiness := &recordingReadiness{}
			err := upstream.HandlePacket(context.Background(), nil, nil, wire.Target{}, readiness)
			if err == nil {
				t.Fatal("expected forwarded setup failure")
			}
			if got := readiness.rejectedCode(); got != code {
				t.Fatalf("rejected code=%v want=%v", got, code)
			}
		})
	}
}

func TestPortalUpstreamRejectsExhaustedBudgetBeforeOpening(t *testing.T) {
	client := &recordingPortalClient{}
	upstream := &PortalUpstream{client: client, tcpReadGrace: time.Second}
	readiness := &recordingReadiness{}
	ctx := withFlowInfo(context.Background(), FlowInfo{Hops: 1})
	err := upstream.HandleStream(ctx, nil, nil, wire.Target{}, readiness)
	if !errors.Is(err, ErrPortalHopLimit) {
		t.Fatalf("HandleStream error=%v", err)
	}
	if client.tcpCalls != 0 {
		t.Fatalf("upstream opens=%d want=0", client.tcpCalls)
	}
	if got := readiness.rejectedCode(); got != wire.SetupResultFlowLimit {
		t.Fatalf("rejected code=%v want=%v", got, wire.SetupResultFlowLimit)
	}
}

func TestPortalUpstreamRelaysTCPAndUsesInitializedBudget(t *testing.T) {
	incoming, clientPeer := net.Pipe()
	remote, targetPeer := net.Pipe()
	defer clientPeer.Close()
	defer targetPeer.Close()

	client := &recordingPortalClient{tcpConn: remote}
	upstream := &PortalUpstream{client: client, tcpReadGrace: time.Second}
	readiness := &recordingReadiness{}
	done := make(chan error, 1)
	go func() {
		done <- upstream.HandleStream(context.Background(), incoming, nil, wire.Target{}, readiness)
	}()
	waitReadinessReady(t, readiness)

	written := make(chan error, 1)
	go func() {
		_, err := clientPeer.Write([]byte("upload"))
		written <- err
	}()
	assertReadPayload(t, targetPeer, "upload")
	if err := <-written; err != nil {
		t.Fatalf("upload write: %v", err)
	}
	go func() {
		_, err := targetPeer.Write([]byte("download"))
		written <- err
	}()
	assertReadPayload(t, clientPeer, "download")
	if err := <-written; err != nil {
		t.Fatalf("download write: %v", err)
	}

	_ = clientPeer.Close()
	_ = targetPeer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleStream: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HandleStream did not finish")
	}
	if client.tcpHops != wire.MaxPortalHops {
		t.Fatalf("outgoing hops=%d want=%d", client.tcpHops, wire.MaxPortalHops)
	}
}

func TestPortalUpstreamTCPStopsOnCancellation(t *testing.T) {
	incoming, clientPeer := net.Pipe()
	remote, targetPeer := net.Pipe()
	defer clientPeer.Close()
	defer targetPeer.Close()

	client := &recordingPortalClient{tcpConn: remote}
	upstream := &PortalUpstream{client: client, tcpReadGrace: time.Second}
	readiness := &recordingReadiness{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- upstream.HandleStream(ctx, incoming, nil, wire.Target{}, readiness)
	}()
	waitReadinessReady(t, readiness)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleStream: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HandleStream did not finish after cancellation")
	}
}

func TestPortalUpstreamRelaysUDPAndDecrementsBudget(t *testing.T) {
	incoming, clientPeer := newMemoryPacketPair()
	remote, targetPeer := newMemoryPacketPair()
	defer clientPeer.Close()
	defer targetPeer.Close()

	client := &recordingPortalClient{udpConn: remote}
	upstream := &PortalUpstream{client: client, tcpReadGrace: time.Second}
	readiness := &recordingReadiness{}
	ctx, cancel := context.WithCancel(withFlowInfo(context.Background(), FlowInfo{Hops: 7}))
	done := make(chan error, 1)
	go func() {
		done <- upstream.HandlePacket(ctx, incoming, nil, wire.Target{}, readiness)
	}()
	waitReadinessReady(t, readiness)

	if _, err := clientPeer.WriteTo([]byte("upload"), nil); err != nil {
		t.Fatalf("upload write: %v", err)
	}
	assertReadPacket(t, targetPeer, "upload")
	if _, err := targetPeer.WriteTo([]byte("download"), nil); err != nil {
		t.Fatalf("download write: %v", err)
	}
	assertReadPacket(t, clientPeer, "download")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandlePacket: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HandlePacket did not finish after cancellation")
	}
	if client.udpHops != 6 {
		t.Fatalf("outgoing HOPS=%d want=6", client.udpHops)
	}
}

func TestNewPortalUpstreamRejectsNilBundle(t *testing.T) {
	if _, err := NewPortalUpstream(nil); !errors.Is(err, ErrUpstreamNotConfigured) {
		t.Fatalf("NewPortalUpstream(nil)=%v", err)
	}
}

type recordingPortalClient struct {
	tcpConn  net.Conn
	tcpErr   error
	tcpHops  uint8
	tcpCalls int
	udpConn  net.PacketConn
	udpErr   error
	udpHops  uint8
	udpCalls int
}

func (c *recordingPortalClient) OpenTCPWithHops(_ context.Context, _ wire.Target, hops uint8) (net.Conn, error) {
	c.tcpCalls++
	c.tcpHops = hops
	return c.tcpConn, c.tcpErr
}

func (c *recordingPortalClient) OpenUDPWithHops(_ context.Context, _ wire.Target, hops uint8) (net.PacketConn, error) {
	c.udpCalls++
	c.udpHops = hops
	return c.udpConn, c.udpErr
}

type recordingReadiness struct {
	mu       sync.Mutex
	ready    bool
	rejected wire.SetupResult
	readyCh  chan struct{}
}

func (r *recordingReadiness) Ready() error {
	r.mu.Lock()
	r.ready = true
	if r.readyCh != nil {
		close(r.readyCh)
		r.readyCh = nil
	}
	r.mu.Unlock()
	return nil
}

func (r *recordingReadiness) Reject(cause error) error {
	r.mu.Lock()
	r.rejected = setupFailureCode(cause)
	r.mu.Unlock()
	return nil
}

func (r *recordingReadiness) rejectedCode() wire.SetupResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rejected
}

func waitReadinessReady(t *testing.T, readiness *recordingReadiness) {
	t.Helper()
	readiness.mu.Lock()
	if readiness.ready {
		readiness.mu.Unlock()
		return
	}
	if readiness.readyCh == nil {
		readiness.readyCh = make(chan struct{})
	}
	ready := readiness.readyCh
	readiness.mu.Unlock()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("flow did not become ready")
	}
}

func assertReadPayload(t *testing.T, reader io.Reader, want string) {
	t.Helper()
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if got := string(buf); got != want {
		t.Fatalf("payload=%q want=%q", got, want)
	}
}

func assertReadPacket(t *testing.T, pc net.PacketConn, want string) {
	t.Helper()
	buf := make([]byte, 64)
	if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	if got := string(buf[:n]); got != want {
		t.Fatalf("packet=%q want=%q", got, want)
	}
}

type memoryPacket struct {
	payload []byte
	addr    net.Addr
}

type memoryPacketConn struct {
	recv      chan memoryPacket
	closed    chan struct{}
	closeOnce sync.Once
	peer      *memoryPacketConn
	deadline  time.Time
	mu        sync.Mutex
}

func newMemoryPacketPair() (*memoryPacketConn, *memoryPacketConn) {
	a := &memoryPacketConn{recv: make(chan memoryPacket, 8), closed: make(chan struct{})}
	b := &memoryPacketConn{recv: make(chan memoryPacket, 8), closed: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

func (c *memoryPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	var timer <-chan time.Time
	if !deadline.IsZero() {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, nil, context.DeadlineExceeded
		}
		t := time.NewTimer(remaining)
		defer t.Stop()
		timer = t.C
	}
	select {
	case packet := <-c.recv:
		return copy(p, packet.payload), packet.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-timer:
		return 0, nil, context.DeadlineExceeded
	}
}

func (c *memoryPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	packet := memoryPacket{payload: append([]byte(nil), p...), addr: addr}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.peer.closed:
		return 0, net.ErrClosed
	case c.peer.recv <- packet:
		return len(p), nil
	}
}

func (c *memoryPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*memoryPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (c *memoryPacketConn) SetDeadline(deadline time.Time) error {
	return c.SetReadDeadline(deadline)
}

func (c *memoryPacketConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return nil
}

func (*memoryPacketConn) SetWriteDeadline(time.Time) error { return nil }
