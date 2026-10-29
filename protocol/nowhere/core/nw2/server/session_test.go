package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

// newUDPSetupSession builds a portal session whose only stream carries a QUIC
// UDP control half, mirroring how a Vector opens a UDP flow.
func newUDPSetupSession(t *testing.T, upstream Upstream) (*portalSession, *Handler) {
	t.Helper()
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewConfig(ConfigOptions{Credentials: credentials, Networks: []Network{NetworkUDP}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: upstream})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	raw := newAuthQUICConn(wire.TLSExporter{}, &authQUICStream{})
	session := newPortalSession(wire.SessionID{1}, raw, handler, raw.RemoteAddr())
	if err := handler.sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session, handler
}

func udpControlHeader(role wire.FlowRole, flowID wire.FlowID) wire.FlowHeader {
	return wire.FlowHeader{
		Role: role, FlowID: flowID, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierQUIC, Downlink: wire.CarrierQUIC,
	}
}

func udpControlSetup(t *testing.T, header wire.FlowHeader, trailing []byte) []byte {
	t.Helper()
	headerBytes, err := wire.EncodeFlowHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	target, err := wire.NewDomainTarget("example.com", 53)
	if err != nil {
		t.Fatal(err)
	}
	targetBytes, err := wire.EncodeTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	return append(append(headerBytes[:], targetBytes...), trailing...)
}

func pendingControlCount(s *portalSession) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pendingControls)
}

func TestCancelledUDPSetupRemovesPendingControl(t *testing.T) {
	session, _ := newUDPSetupSession(t, discardUpstream{})
	gate, err := session.beginPendingUDPControl(udpControlHeader(wire.FlowRoleOpen, 7))
	if err != nil {
		t.Fatal(err)
	}
	if got := pendingControlCount(session); got != 1 {
		t.Fatalf("pending controls = %d, want 1", got)
	}

	gate.cancel()

	if got := pendingControlCount(session); got != 0 {
		t.Fatalf("cancelled setup left %d pending controls", got)
	}
	gate.cancel()
	if got := pendingControlCount(session); got != 0 {
		t.Fatalf("second cancel left %d pending controls", got)
	}
}

func TestStaleUDPSetupDoesNotRemoveReusedFlowID(t *testing.T) {
	session, _ := newUDPSetupSession(t, discardUpstream{})
	const flowID = wire.FlowID(7)
	stale, err := session.beginPendingUDPControl(udpControlHeader(wire.FlowRoleOpen, flowID))
	if err != nil {
		t.Fatal(err)
	}

	// The attempt is abandoned before the control stream reaches its setup
	// boundary, so the preactivation sweeper retires it.
	session.expirePendingControls(time.Now().Add(preactivationTTL + time.Second))
	if got := pendingControlCount(session); got != 0 {
		t.Fatalf("expired control was not retired: %d left", got)
	}

	// The flow id is free again and a new attempt registers it.
	current, err := session.beginPendingUDPControl(udpControlHeader(wire.FlowRoleOpen, flowID))
	if err != nil {
		t.Fatal(err)
	}

	// The stale attempt finishes late; it must not drop the reused flow id.
	stale.cancel()
	session.mu.Lock()
	reused := session.pendingControls[flowID]
	session.mu.Unlock()
	if reused == nil {
		t.Fatal("stale setup guard removed the reused registration")
	}
	if reused != current.control {
		t.Fatal("stale setup guard replaced the reused registration")
	}

	current.cancel()
	if got := pendingControlCount(session); got != 0 {
		t.Fatalf("current setup left %d pending controls", got)
	}
}

func TestCommittedUDPSetupOutlivesSetupGuard(t *testing.T) {
	session, _ := newUDPSetupSession(t, discardUpstream{})
	const flowID = wire.FlowID(7)
	gate, err := session.beginPendingUDPControl(udpControlHeader(wire.FlowRoleOpen, flowID))
	if err != nil {
		t.Fatal(err)
	}
	target, err := wire.NewDomainTarget("example.com", 53)
	if err != nil {
		t.Fatal(err)
	}
	flow := newNowuFlow(session, flowID, target)
	if err := session.activateNOWUFlow(flow, gate.pending()); err != nil {
		t.Fatal(err)
	}

	gate.commit()
	gate.cancel()

	if pending := gate.pending(); pending != nil {
		t.Fatal("committed guard still owns a registration")
	}
	session.mu.Lock()
	live := session.flows[flowID]
	controls := len(session.pendingControls)
	session.mu.Unlock()
	if live != flow {
		t.Fatal("committed flow was dropped from the session")
	}
	if controls != 0 {
		t.Fatalf("pending controls = %d, want 0", controls)
	}
	if _, err := session.beginPendingUDPControl(udpControlHeader(wire.FlowRoleOpen, flowID)); !errors.Is(err, ErrDuplicateHalf) {
		t.Fatalf("re-registering an active flow id = %v, want ErrDuplicateHalf", err)
	}
	flow.shutdown(net.ErrClosed)
}

func TestUDPControlStreamCancelReleasesRegistration(t *testing.T) {
	session, _ := newUDPSetupSession(t, discardUpstream{})
	// Trailing bytes after the target mean the client never reached the FIN
	// setup boundary: the control stream is rejected and its registration
	// must be released on the way out.
	setup := udpControlSetup(t, udpControlHeader(wire.FlowRoleOpen, 7), []byte{0x00})
	done := make(chan struct{})
	go func() {
		defer close(done)
		session.handleStream(context.Background(), &authQUICStream{Reader: bytes.NewReader(setup)}, false)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleStream did not return")
	}
	if got := pendingControlCount(session); got != 0 {
		t.Fatalf("rejected control stream leaked %d pending controls", got)
	}
}

// udpActivationUpstream inspects the session from inside routing, where the
// activated flow is still owned by the session.
type udpActivationUpstream struct {
	routed chan struct{}
}

func (u *udpActivationUpstream) HandleStream(context.Context, net.Conn, net.Addr, wire.Target, FlowReadiness) error {
	return errors.New("unexpected stream flow")
}

func (u *udpActivationUpstream) HandlePacket(_ context.Context, _ net.PacketConn, _ net.Addr, _ wire.Target, readiness FlowReadiness) error {
	if err := readiness.Ready(); err != nil {
		return err
	}
	close(u.routed)
	return nil
}

func TestUDPControlStreamActivationKeepsFlow(t *testing.T) {
	upstream := &udpActivationUpstream{routed: make(chan struct{})}
	session, _ := newUDPSetupSession(t, upstream)
	// A symmetric QUIC UDP flow arrives as a DUPLEX control half: the clean
	// FIN boundary activates it and the registration moves to the live flow.
	setup := udpControlSetup(t, udpControlHeader(wire.FlowRoleDuplex, 7), nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		session.handleStream(context.Background(), &authQUICStream{Reader: bytes.NewReader(setup)}, false)
	}()
	select {
	case <-upstream.routed:
	case <-time.After(5 * time.Second):
		t.Fatal("activated UDP flow was not routed")
	}
	session.mu.Lock()
	flow := session.flows[7]
	controls := len(session.pendingControls)
	session.mu.Unlock()
	if flow == nil {
		t.Fatal("activated UDP flow is missing from the session")
	}
	if controls != 0 {
		t.Fatalf("pending controls = %d, want 0", controls)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleStream did not return")
	}
	flow.shutdown(net.ErrClosed)
}
