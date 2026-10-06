package bundle

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestPrimaryPreparationHardTimeoutClosesLateLanes(t *testing.T) {
	primary := resolvedRoute{wire.CarrierQUIC, wire.CarrierQUIC}
	fallback := resolvedRoute{wire.CarrierTLSTCP, wire.CarrierTLSTCP}
	lateClient, lateServer := net.Pipe()
	defer lateServer.Close()
	lateClosed := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := lateServer.Read(one[:])
		lateClosed <- err
	}()

	var calls atomic.Int32
	started := time.Now()
	lanes, _, route, err := prepareWithFallback(
		context.Background(),
		20*time.Millisecond,
		1,
		routePlan{primary: primary, fallback: fallback, hasFallback: true},
		func() (wire.FlowID, error) { return 2, nil },
		func(_ context.Context, _ wire.FlowID, route resolvedRoute) (*preparedLanes, error) {
			if calls.Add(1) == 1 {
				time.Sleep(150 * time.Millisecond) // deliberately ignores context
				return &preparedLanes{up: &physicalLane{mux: lateClient}}, nil
			}
			if route != fallback {
				t.Errorf("fallback route = %s", route.label())
			}
			return &preparedLanes{}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer lanes.Close()
	if route != fallback {
		t.Fatalf("route = %s", route.label())
	}
	if elapsed := time.Since(started); elapsed >= 120*time.Millisecond {
		t.Fatalf("hard timeout returned after %s", elapsed)
	}
	select {
	case err := <-lateClosed:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("late lane close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late primary lane was not closed")
	}
}

func TestCallerCancellationDoesNotAllocateFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var allocCalls atomic.Int32
	go func() {
		<-started
		cancel()
	}()
	_, _, _, err := prepareWithFallback(
		ctx,
		time.Second,
		1,
		routePlan{
			primary:     resolvedRoute{wire.CarrierQUIC, wire.CarrierQUIC},
			fallback:    resolvedRoute{wire.CarrierTLSTCP, wire.CarrierTLSTCP},
			hasFallback: true,
		},
		func() (wire.FlowID, error) {
			allocCalls.Add(1)
			return 2, nil
		},
		func(ctx context.Context, _ wire.FlowID, _ resolvedRoute) (*preparedLanes, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if allocCalls.Load() != 0 {
		t.Fatalf("fallback allocations = %d", allocCalls.Load())
	}
}

func TestCallerCancellationBoundsFallbackAndClosesLateLanes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fallbackStarted := make(chan struct{})
	lateClient, lateServer := net.Pipe()
	defer lateServer.Close()
	lateClosed := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := lateServer.Read(one[:])
		lateClosed <- err
	}()
	go func() {
		<-fallbackStarted
		cancel()
	}()

	started := time.Now()
	_, _, _, err := prepareWithFallback(
		ctx,
		time.Second,
		1,
		routePlan{
			primary:     resolvedRoute{wire.CarrierQUIC, wire.CarrierQUIC},
			fallback:    resolvedRoute{wire.CarrierTLSTCP, wire.CarrierTLSTCP},
			hasFallback: true,
		},
		func() (wire.FlowID, error) { return 2, nil },
		func(_ context.Context, flowID wire.FlowID, _ resolvedRoute) (*preparedLanes, error) {
			if flowID == 1 {
				return nil, errors.New("primary unavailable")
			}
			close(fallbackStarted)
			time.Sleep(150 * time.Millisecond) // deliberately ignores context
			return &preparedLanes{up: &physicalLane{mux: lateClient}}, nil
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed >= 120*time.Millisecond {
		t.Fatalf("caller cancellation returned after %s", elapsed)
	}
	select {
	case err := <-lateClosed:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("late fallback lane close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late fallback lane was not closed")
	}
}

func TestQUICUDPRegistrationFailureTriggersFallback(t *testing.T) {
	session := newTestQUICSessionMux(t, 64, 4)
	existing, err := session.register(1)
	if err != nil {
		t.Fatal(err)
	}
	plan := routePlan{
		primary:     resolvedRoute{wire.CarrierQUIC, wire.CarrierQUIC},
		fallback:    resolvedRoute{wire.CarrierTLSTCP, wire.CarrierTLSTCP},
		hasFallback: true,
	}
	var calls atomic.Int32
	lanes, flowID, route, err := prepareWithFallback(
		context.Background(),
		time.Second,
		1,
		plan,
		func() (wire.FlowID, error) { return 2, nil },
		func(_ context.Context, flowID wire.FlowID, route resolvedRoute) (*preparedLanes, error) {
			calls.Add(1)
			if route == plan.fallback {
				return &preparedLanes{}, nil
			}
			prepared := &preparedLanes{up: &physicalLane{
				carrier: wire.CarrierQUIC,
				quic:    &quicPreparedStream{session: session, id: flowID},
			}}
			if err := prepared.prepareUDPDownlink(wire.FlowKindUDP, route, flowID); err != nil {
				_ = prepared.Close()
				return nil, err
			}
			return prepared, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer lanes.Close()
	if calls.Load() != 2 || flowID != 2 || route != plan.fallback {
		t.Fatalf("calls=%d flow=%d route=%s", calls.Load(), flowID, route.label())
	}
	if session.flows[1] != existing {
		t.Fatal("failed duplicate registration disturbed the existing flow")
	}
	if session.flows[2] != nil {
		t.Fatal("TCP fallback unexpectedly registered a QUIC flow")
	}
}

func TestPrecommitFailureUsesTheOtherRouteAndANewFlowIDOnce(t *testing.T) {
	plan := routePlan{
		primary:     resolvedRoute{wire.CarrierQUIC, wire.CarrierQUIC},
		fallback:    resolvedRoute{wire.CarrierTLSTCP, wire.CarrierTLSTCP},
		hasFallback: true,
	}
	var calls atomic.Int32
	var nextID uint32 = 7
	alloc := func() (wire.FlowID, error) {
		nextID++
		return nextID, nil
	}
	lanes, id, route, err := prepareWithFallback(
		context.Background(),
		time.Second,
		7,
		plan,
		alloc,
		func(_ context.Context, flowID wire.FlowID, route resolvedRoute) (*preparedLanes, error) {
			n := calls.Add(1)
			if n == 1 {
				if flowID != 7 || route != plan.primary {
					t.Errorf("primary call flow=%d route=%s", flowID, route.label())
				}
				return nil, errors.New("primary unavailable")
			}
			if flowID != 8 || route != plan.fallback {
				t.Errorf("fallback call flow=%d route=%s", flowID, route.label())
			}
			return &preparedLanes{}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if lanes == nil {
		t.Fatal("expected lanes")
	}
	if id != 8 {
		t.Fatalf("fallback flow id = %d", id)
	}
	if route != plan.fallback {
		t.Fatalf("route = %s", route.label())
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestMixedPrimaryPreparationTimeoutUsesTheFallbackOnce(t *testing.T) {
	primary := resolvedRoute{wire.CarrierQUIC, wire.CarrierQUIC}
	fallback := resolvedRoute{wire.CarrierTLSTCP, wire.CarrierTLSTCP}
	var calls atomic.Int32
	started := time.Now()
	_, _, route, err := prepareWithFallback(
		context.Background(),
		20*time.Millisecond,
		1,
		routePlan{primary: primary, fallback: fallback, hasFallback: true},
		func() (wire.FlowID, error) { return 2, nil },
		func(ctx context.Context, _ wire.FlowID, route resolvedRoute) (*preparedLanes, error) {
			n := calls.Add(1)
			if n == 1 {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			if route != fallback {
				t.Errorf("fallback route = %s", route.label())
			}
			return &preparedLanes{}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if route != fallback {
		t.Fatalf("route = %s", route.label())
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
	if time.Since(started) >= time.Second {
		t.Fatal("timeout path took too long")
	}
}

func TestFixedRouteAndFailedFallbackNeverCreateAThirdAttempt(t *testing.T) {
	fixed := resolvedRoute{wire.CarrierTLSTCP, wire.CarrierQUIC}
	var calls atomic.Int32
	_, _, _, err := prepareWithFallback(
		context.Background(),
		time.Second,
		1,
		routePlan{primary: fixed},
		func() (wire.FlowID, error) { t.Fatal("alloc"); return 0, nil },
		func(context.Context, wire.FlowID, resolvedRoute) (*preparedLanes, error) {
			calls.Add(1)
			return nil, errors.New("fixed route failed")
		},
	)
	if err == nil || err.Error() != "fixed route failed" {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}

	calls.Store(0)
	_, _, _, err = prepareWithFallback(
		context.Background(),
		time.Second,
		1,
		routePlan{
			primary:     resolvedRoute{wire.CarrierQUIC, wire.CarrierQUIC},
			fallback:    resolvedRoute{wire.CarrierTLSTCP, wire.CarrierTLSTCP},
			hasFallback: true,
		},
		func() (wire.FlowID, error) { return 2, nil },
		func(_ context.Context, _ wire.FlowID, route resolvedRoute) (*preparedLanes, error) {
			calls.Add(1)
			return nil, errors.New(route.label() + " unavailable")
		},
	)
	if err == nil {
		t.Fatal("expected combined error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "QQ unavailable") || !strings.Contains(msg, "TT unavailable") {
		t.Fatalf("error = %s", msg)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
}
