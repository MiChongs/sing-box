package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestTCPPairRejectsMismatchedPortalHops(t *testing.T) {
	registry := newClaimRegistry(time.Second, Limits{
		PendingFlowsPerSession:          4,
		UDPFlowsPerSession:              4,
		AuthenticatedTCPIdleConnections: 4,
	})
	sessionID := wire.SessionID{1}
	openServer, openPeer := net.Pipe()
	attachServer, attachPeer := net.Pipe()
	defer openPeer.Close()
	defer attachPeer.Close()

	openDone := make(chan error, 1)
	go func() {
		_, err := registry.Submit(context.Background(), flowClaim{
			SessionID: sessionID,
			FlowID:    1,
			Role:      wire.FlowRoleOpen,
			Carrier:   wire.CarrierTLSTCP,
			Metadata: claimMetadata{
				Kind: wire.FlowKindTCP, Uplink: wire.CarrierTLSTCP,
				Downlink: wire.CarrierQUIC, Hops: 3,
			},
			Stream: openServer,
		})
		openDone <- err
	}()
	waitForPendingClaim(t, registry, sessionID)

	resultDone := make(chan wire.SetupResult, 1)
	go func() {
		result, _ := wire.ReadSetupResult(attachPeer)
		resultDone <- result
	}()
	_, err := registry.Submit(context.Background(), flowClaim{
		SessionID: sessionID,
		FlowID:    1,
		Role:      wire.FlowRoleAttach,
		Carrier:   wire.CarrierQUIC,
		Metadata: claimMetadata{
			Kind: wire.FlowKindTCP, Uplink: wire.CarrierTLSTCP,
			Downlink: wire.CarrierQUIC, Hops: 2,
		},
		Stream: attachServer,
	})
	if !errors.Is(err, ErrMetadataConflict) {
		t.Fatalf("attach error=%v want ErrMetadataConflict", err)
	}
	select {
	case result := <-resultDone:
		if result != wire.SetupResultMetadataConflict {
			t.Fatalf("setup result=%v want=%v", result, wire.SetupResultMetadataConflict)
		}
	case <-time.After(time.Second):
		t.Fatal("metadata conflict result was not written")
	}
	select {
	case err := <-openDone:
		if !errors.Is(err, ErrMetadataConflict) {
			t.Fatalf("open error=%v want ErrMetadataConflict", err)
		}
	case <-time.After(time.Second):
		t.Fatal("open claim did not finish")
	}
}

func TestFlowInfoContextRoundTrip(t *testing.T) {
	ctx := withFlowInfo(context.Background(), FlowInfo{Hops: 5})
	info, ok := FlowInfoFromContext(ctx)
	if !ok || info.Hops != 5 {
		t.Fatalf("FlowInfoFromContext=(%+v,%v)", info, ok)
	}
	if _, ok := FlowInfoFromContext(context.Background()); ok {
		t.Fatal("unexpected FlowInfo on plain context")
	}
}

func TestStartRouteTaskPreservesFlowInfoAfterTransportOwnershipTransfer(t *testing.T) {
	tracker := newTaskTracker()
	transportCtx, ownership, err := tracker.StartTransferableTransport(context.Background(), nil)
	if err != nil {
		t.Fatalf("StartTransferableTransport: %v", err)
	}
	handler := &Handler{tasks: tracker}
	flowCtx := withFlowInfo(withTaskOwnership(transportCtx, ownership), FlowInfo{Hops: 5})
	routeCtx, finish, err := handler.startRouteTask(flowCtx)
	if err != nil {
		t.Fatalf("startRouteTask: %v", err)
	}
	defer finish()
	info, ok := FlowInfoFromContext(routeCtx)
	if !ok || info.Hops != 5 {
		t.Fatalf("FlowInfoFromContext=(%+v,%v), want HOPS=5", info, ok)
	}
}
