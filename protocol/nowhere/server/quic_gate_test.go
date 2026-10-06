//go:build with_quic

package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQUICStreamGateHoldsFlowsUntilAuthentication(t *testing.T) {
	gate := newQUICStreamGate()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	released := make(chan error, 1)
	go func() { released <- gate.wait(ctx) }()

	select {
	case err := <-released:
		t.Fatalf("gate released before authentication: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	gate.markAuthenticated()
	require.NoError(t, <-released)
}

func TestQUICLegacyStreamLimitCallbackMarksAdapterAuthenticated(t *testing.T) {
	adapter := &quicConnAdapter{streamGate: newQUICStreamGate()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	released := make(chan error, 1)
	go func() { released <- adapter.streamGate.wait(ctx) }()
	require.NoError(t, adapter.SetMaxIncomingStreamLimits(1024, 0))
	require.NoError(t, <-released)
}

func TestQUICStreamGateReleasesAllWaitersAfterAuthentication(t *testing.T) {
	gate := newQUICStreamGate()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	errors := make(chan error, 64)
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- gate.wait(ctx)
		}()
	}
	gate.markAuthenticated()
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}
