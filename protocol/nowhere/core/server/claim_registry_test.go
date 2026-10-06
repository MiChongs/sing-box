package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestClaimTombstoneDropsConnRefsAndAllowsNewPending(t *testing.T) {
	registry := newClaimRegistry(30*time.Millisecond, Limits{PendingFlowsPerSession: 2})
	sessionID := wire.SessionID{1}
	target, err := wire.NewDomainTarget("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}

	openLeft, openRight := net.Pipe()
	defer openLeft.Close()
	defer openRight.Close()

	done := make(chan error, 1)
	go func() {
		_, err := registry.Submit(context.Background(), flowClaim{
			SessionID: sessionID, FlowID: 1,
			Role: wire.FlowRoleOpen, Carrier: wire.CarrierTLSTCP,
			Metadata: claimMetadata{Kind: wire.FlowKindTCP, Uplink: wire.CarrierTLSTCP, Downlink: wire.CarrierQUIC},
			Target:   target, Stream: openLeft,
		})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrPairTimeout) {
			t.Fatalf("open half error = %v, want pair timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("open half did not time out")
	}

	registry.mu.Lock()
	entry := registry.entries[claimKey{sessionID: sessionID, flowID: 1}]
	if entry == nil {
		registry.mu.Unlock()
		t.Fatal("missing tombstone")
	}
	if entry.open != nil || entry.attach != nil || entry.duplex != nil || entry.selected != nil {
		registry.mu.Unlock()
		t.Fatal("tombstone retained connection references")
	}
	registry.mu.Unlock()

	attachLeft, attachRight := net.Pipe()
	defer attachLeft.Close()
	defer attachRight.Close()
	_, err = registry.Submit(context.Background(), flowClaim{
		SessionID: sessionID, FlowID: 1,
		Role: wire.FlowRoleAttach, Carrier: wire.CarrierQUIC,
		Metadata: claimMetadata{Kind: wire.FlowKindTCP, Uplink: wire.CarrierTLSTCP, Downlink: wire.CarrierQUIC},
		Stream:   attachLeft,
	})
	if !errors.Is(err, ErrPairTimeout) {
		t.Fatalf("late attach error = %v, want stored pair timeout", err)
	}

	for flowID := wire.FlowID(2); flowID <= 4; flowID++ {
		left, right := net.Pipe()
		halfDone := make(chan error, 1)
		go func(id wire.FlowID, conn net.Conn) {
			_, err := registry.Submit(context.Background(), flowClaim{
				SessionID: sessionID, FlowID: id,
				Role: wire.FlowRoleOpen, Carrier: wire.CarrierTLSTCP,
				Metadata: claimMetadata{Kind: wire.FlowKindTCP, Uplink: wire.CarrierTLSTCP, Downlink: wire.CarrierQUIC},
				Target:   target, Stream: conn,
			})
			halfDone <- err
		}(flowID, left)
		select {
		case err := <-halfDone:
			if !errors.Is(err, ErrPairTimeout) {
				right.Close()
				t.Fatalf("flow %d error = %v, want pair timeout", flowID, err)
			}
		case <-time.After(time.Second):
			right.Close()
			t.Fatalf("flow %d did not time out", flowID)
		}
		right.Close()
	}

	pendingLeft, pendingRight := net.Pipe()
	defer pendingLeft.Close()
	defer pendingRight.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := make(chan struct{})
	wait := make(chan error, 1)
	go func() {
		close(started)
		_, err := registry.Submit(ctx, flowClaim{
			SessionID: sessionID, FlowID: 99,
			Role: wire.FlowRoleOpen, Carrier: wire.CarrierTLSTCP,
			Metadata: claimMetadata{Kind: wire.FlowKindTCP, Uplink: wire.CarrierTLSTCP, Downlink: wire.CarrierQUIC},
			Target:   target, Stream: pendingLeft,
		})
		wait <- err
	}()
	<-started
	select {
	case err := <-wait:
		if errors.Is(err, ErrPairLimit) {
			t.Fatal("tombstones counted against per-session pending quota")
		}
	case <-time.After(15 * time.Millisecond):
		cancel()
		<-wait
	}
}

func TestClaimTombstoneExpires(t *testing.T) {
	registry := newClaimRegistry(20*time.Millisecond, Limits{PendingFlowsPerSession: 4})
	sessionID := wire.SessionID{2}
	target, err := wire.NewDomainTarget("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	done := make(chan error, 1)
	go func() {
		_, err := registry.Submit(context.Background(), flowClaim{
			SessionID: sessionID, FlowID: 7,
			Role: wire.FlowRoleOpen, Carrier: wire.CarrierTLSTCP,
			Metadata: claimMetadata{Kind: wire.FlowKindTCP, Uplink: wire.CarrierTLSTCP, Downlink: wire.CarrierQUIC},
			Target:   target, Stream: left,
		})
		done <- err
	}()
	if err := <-done; !errors.Is(err, ErrPairTimeout) {
		t.Fatalf("timeout error = %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	registry.mu.Lock()
	registry.expireTerminalsLocked(time.Now())
	_, exists := registry.entries[claimKey{sessionID: sessionID, flowID: 7}]
	registry.mu.Unlock()
	if exists {
		t.Fatal("expired tombstone was not removed")
	}
}
