package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

type drainTestUpstream struct {
	started      chan struct{}
	attemptReady chan struct{}
	release      chan struct{}
	readyResult  chan error
}

func (u *drainTestUpstream) HandleStream(_ context.Context, conn net.Conn, _ net.Addr, _ wire.Target, readiness FlowReadiness) error {
	close(u.started)
	if u.attemptReady != nil {
		<-u.attemptReady
	}
	err := readiness.Ready()
	u.readyResult <- err
	if err == nil && u.release != nil {
		<-u.release
	}
	_ = conn.Close()
	return err
}

func (*drainTestUpstream) HandlePacket(context.Context, net.PacketConn, net.Addr, wire.Target, FlowReadiness) error {
	panic("unexpected packet flow")
}

func TestHandlerShutdownDrainsReadyRelay(t *testing.T) {
	upstream := &drainTestUpstream{
		started:     make(chan struct{}),
		release:     make(chan struct{}),
		readyResult: make(chan error, 1),
	}
	handler := newDrainTestHandler(t, upstream)
	serverConn, peerConn := net.Pipe()
	defer peerConn.Close()

	routeDone := make(chan error, 1)
	go func() {
		routeDone <- handler.routeStream(
			context.Background(),
			serverConn,
			nil,
			wire.Target{},
			newFlowReadiness(nil, nil),
			nil,
		)
	}()
	waitDrainSignal(t, upstream.started, "upstream start")
	if err := waitDrainResult(t, upstream.readyResult, "READY"); err != nil {
		t.Fatalf("Ready error = %v", err)
	}

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		shutdownDone <- handler.Shutdown(ctx)
	}()
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned before READY relay completed: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	close(upstream.release)
	if err := waitDrainResult(t, routeDone, "route completion"); err != nil {
		t.Fatalf("route error = %v", err)
	}
	if err := waitDrainResult(t, shutdownDone, "shutdown completion"); err != nil {
		t.Fatalf("Shutdown error = %v", err)
	}
}

func TestHandlerDrainRejectsLateReadyWithFlowLimit(t *testing.T) {
	attemptReady := make(chan struct{})
	upstream := &drainTestUpstream{
		started:      make(chan struct{}),
		attemptReady: attemptReady,
		readyResult:  make(chan error, 1),
	}
	handler := newDrainTestHandler(t, upstream)
	serverConn, peerConn := net.Pipe()
	defer peerConn.Close()

	rejected := make(chan wire.SetupResult, 1)
	readiness := newFlowReadiness(
		func() error {
			t.Error("READY writer called after drain barrier")
			return nil
		},
		func(result wire.SetupResult) error {
			rejected <- result
			return nil
		},
	)
	routeDone := make(chan error, 1)
	go func() {
		routeDone <- handler.routeStream(
			context.Background(),
			serverConn,
			nil,
			wire.Target{},
			readiness,
			nil,
		)
	}()
	waitDrainSignal(t, upstream.started, "upstream start")

	handler.BeginDrain()
	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		shutdownDone <- handler.Shutdown(ctx)
	}()
	close(attemptReady)

	if result := waitDrainResult(t, rejected, "FLOW_LIMIT rejection"); result != wire.SetupResultFlowLimit {
		t.Fatalf("setup result = %v, want %v", result, wire.SetupResultFlowLimit)
	}
	if err := waitDrainResult(t, upstream.readyResult, "late READY result"); !errors.Is(err, ErrDraining) {
		t.Fatalf("Ready error = %v, want ErrDraining", err)
	}
	if err := waitDrainResult(t, routeDone, "route completion"); !errors.Is(err, ErrDraining) {
		t.Fatalf("route error = %v, want ErrDraining", err)
	}
	if err := waitDrainResult(t, shutdownDone, "shutdown completion"); err != nil {
		t.Fatalf("Shutdown error = %v", err)
	}
}

func TestServerKeepsQUICListenerUntilReadyRelayDrains(t *testing.T) {
	upstream := &drainTestUpstream{
		started:     make(chan struct{}),
		release:     make(chan struct{}),
		readyResult: make(chan error, 1),
	}
	handler := newDrainTestHandler(t, upstream)
	quicListener := &drainTestQUICListener{closed: make(chan struct{})}
	server := &Server{
		config:       handler.config,
		handler:      handler,
		quicListener: quicListener,
	}
	serverConn, peerConn := net.Pipe()
	defer peerConn.Close()

	routeDone := make(chan error, 1)
	go func() {
		routeDone <- handler.routeStream(
			context.Background(),
			serverConn,
			nil,
			wire.Target{},
			newFlowReadiness(nil, nil),
			nil,
		)
	}()
	waitDrainSignal(t, upstream.started, "upstream start")
	if err := waitDrainResult(t, upstream.readyResult, "READY"); err != nil {
		t.Fatalf("Ready error = %v", err)
	}

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		shutdownDone <- server.Shutdown(ctx)
	}()
	select {
	case <-quicListener.closed:
		t.Fatal("QUIC listener closed before READY relay drained")
	case <-time.After(30 * time.Millisecond):
	}

	close(upstream.release)
	if err := waitDrainResult(t, routeDone, "route completion"); err != nil {
		t.Fatalf("route error = %v", err)
	}
	if err := waitDrainResult(t, shutdownDone, "server shutdown"); err != nil {
		t.Fatalf("Shutdown error = %v", err)
	}
	waitDrainSignal(t, quicListener.closed, "QUIC listener close")
}

func TestClaimRegistryDrainRejectsPendingAndPreservesActive(t *testing.T) {
	registry := newClaimRegistry(time.Second, Limits{
		PendingFlowsPerSession:          4,
		UDPFlowsPerSession:              4,
		AuthenticatedTCPIdleConnections: 4,
	})
	sessionID := wire.SessionID{1}

	activeServer, activePeer := net.Pipe()
	defer activePeer.Close()
	active, err := registry.Submit(context.Background(), flowClaim{
		SessionID: sessionID,
		FlowID:    1,
		Role:      wire.FlowRoleDuplex,
		Carrier:   wire.CarrierTLSTCP,
		Metadata: claimMetadata{
			Kind: wire.FlowKindTCP, Uplink: wire.CarrierTLSTCP, Downlink: wire.CarrierTLSTCP,
		},
		Stream: activeServer,
	})
	if err != nil {
		t.Fatal(err)
	}

	pendingServer, pendingPeer := net.Pipe()
	defer pendingPeer.Close()
	pendingDone := make(chan error, 1)
	go func() {
		_, submitErr := registry.Submit(context.Background(), flowClaim{
			SessionID: sessionID,
			FlowID:    2,
			Role:      wire.FlowRoleAttach,
			Carrier:   wire.CarrierTLSTCP,
			Metadata: claimMetadata{
				Kind: wire.FlowKindTCP, Uplink: wire.CarrierQUIC, Downlink: wire.CarrierTLSTCP,
			},
			Stream: pendingServer,
		})
		pendingDone <- submitErr
	}()
	waitForPendingClaim(t, registry, sessionID)

	resultDone := make(chan wire.SetupResult, 1)
	resultErr := make(chan error, 1)
	go func() {
		result, readErr := wire.ReadSetupResult(pendingPeer)
		resultDone <- result
		resultErr <- readErr
	}()
	if err := registry.BeginDrainContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := waitDrainResult(t, resultErr, "pending setup result read"); err != nil {
		t.Fatalf("read setup result: %v", err)
	}
	if result := waitDrainResult(t, resultDone, "pending setup result"); result != wire.SetupResultFlowLimit {
		t.Fatalf("setup result = %v, want %v", result, wire.SetupResultFlowLimit)
	}
	if err := waitDrainResult(t, pendingDone, "pending claim completion"); !errors.Is(err, ErrDraining) {
		t.Fatalf("pending claim error = %v, want ErrDraining", err)
	}
	select {
	case <-active.Context.Done():
		t.Fatalf("active flow canceled during drain: %v", context.Cause(active.Context))
	default:
	}

	active.Release()
	_ = activeServer.Close()
	if err := registry.CloseContext(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type drainTestQUICListener struct {
	closed chan struct{}
	once   sync.Once
}

func (*drainTestQUICListener) Accept(ctx context.Context) (QuicConn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (l *drainTestQUICListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func newDrainTestHandler(t *testing.T, upstream Upstream) *Handler {
	t.Helper()
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewConfig(ConfigOptions{
		Credentials: credentials,
		Networks:    []Network{NetworkTCP},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: upstream})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func waitForPendingClaim(t *testing.T, registry *claimRegistry, sessionID wire.SessionID) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		registry.mu.Lock()
		pending := registry.pending[sessionID]
		registry.mu.Unlock()
		if pending == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("pending claim was not installed")
}

func waitDrainSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func waitDrainResult[T any](t *testing.T, result <-chan T, name string) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
		var zero T
		return zero
	}
}
