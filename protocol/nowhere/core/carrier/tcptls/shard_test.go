package tcptls

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestMaxMuxCarriersMatchesNowhere2(t *testing.T) {
	if MaxMuxCarriers != 8 {
		t.Fatalf("MaxMuxCarriers=%d want 8 (Nowhere 2)", MaxMuxCarriers)
	}
}

func TestMuxOpenHonorsCanceledContext(t *testing.T) {
	mgr, err := NewMuxManager(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, err = mgr.Open(ctx, 1, MuxUp)
	if !errors.Is(err, context.Canceled) && err == nil {
		t.Fatalf("Open error = %v, want canceled or dial failure", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("canceled Open returned after %s", elapsed)
	}
}

func TestMuxManagerCloseCancelsInFlightDial(t *testing.T) {
	dialer := &blockingTCPDialer{started: make(chan struct{})}
	cfg := boundTestConfig(t, dialer)
	mgr, err := NewMuxManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := mgr.Open(context.Background(), 1, MuxUp)
		errCh <- err
	}()
	select {
	case <-dialer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("mux dial did not start")
	}
	done := make(chan error, 1)
	go func() { done <- mgr.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel in-flight mux dial")
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Open after Close = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Open did not return after Close")
	}
}
