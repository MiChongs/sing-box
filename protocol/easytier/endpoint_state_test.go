package easytier

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

func newStateTestEndpoint() *Endpoint {
	endpoint := &Endpoint{stateNotify: make(chan struct{})}
	endpoint.snapshot.Store(newRoutingSnapshot(nil))
	return endpoint
}

func configuredTestInstance(endpoint *Endpoint) *attachedInstance {
	instance := &attachedInstance{endpoint: endpoint, done: make(chan struct{})}
	instance.state.Store(&instanceState{configured: true})
	return instance
}

func TestWaitReadyFollowsHostRestarts(t *testing.T) {
	t.Parallel()
	endpoint := newStateTestEndpoint()
	failure := errors.New("connect EasyTier Web: network is unreachable")

	// A host waiting to restart fails dials at once with its error.
	endpoint.setHostState(hostFailed, failure)
	start := time.Now()
	err := endpoint.waitReady(context.Background())
	require.ErrorIs(t, err, failure)
	require.Less(t, time.Since(start), time.Second)

	// A starting host makes dials wait until an instance is configured.
	endpoint.setHostState(hostStarting, nil)
	result := make(chan error, 1)
	go func() { result <- endpoint.waitReady(context.Background()) }()
	select {
	case err = <-result:
		t.Fatalf("waitReady returned before the instance was ready: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	endpoint.stateAccess.Lock()
	endpoint.instances = []*attachedInstance{configuredTestInstance(endpoint)}
	endpoint.snapshot.Store(newRoutingSnapshot(endpoint.instances))
	endpoint.notifyStateLocked()
	endpoint.stateAccess.Unlock()
	endpoint.setHostState(hostRunning, nil)
	require.NoError(t, <-result)

	// After a restart the endpoint recovers instead of keeping the first
	// failure.
	endpoint.stateAccess.Lock()
	endpoint.instances = nil
	endpoint.snapshot.Store(newRoutingSnapshot(nil))
	endpoint.notifyStateLocked()
	endpoint.stateAccess.Unlock()
	endpoint.setHostState(hostFailed, failure)
	require.ErrorIs(t, endpoint.waitReady(context.Background()), failure)
	endpoint.setHostState(hostStarting, nil)
	go func() { result <- endpoint.waitReady(context.Background()) }()
	endpoint.stateAccess.Lock()
	endpoint.instances = []*attachedInstance{configuredTestInstance(endpoint)}
	endpoint.snapshot.Store(newRoutingSnapshot(endpoint.instances))
	endpoint.notifyStateLocked()
	endpoint.stateAccess.Unlock()
	require.NoError(t, <-result)
}

func TestWaitReadyHonorsCallerContext(t *testing.T) {
	t.Parallel()
	endpoint := newStateTestEndpoint()
	endpoint.setHostState(hostStarting, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	require.ErrorContains(t, endpoint.waitReady(ctx), "not ready")
	endpoint.setHostState(hostRunning, nil)
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	require.ErrorContains(t, endpoint.waitReady(ctx), "no EasyTier instance is running")
}

func TestSuperviseHostRestartsWithBackoff(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	endpoint := newStateTestEndpoint()
	endpoint.ctx = ctx
	endpoint.logger = log.NewNOPFactory().NewLogger("easytier")
	var starts []time.Time
	done := make(chan struct{})
	go func() {
		defer close(done)
		endpoint.superviseHost(func() error {
			starts = append(starts, time.Now())
			require.Equal(t, hostStarting, endpoint.hostState.Load())
			if len(starts) == 4 {
				cancel()
				return nil
			}
			return errors.New("instance stopped")
		}, 20*time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not stop after the endpoint closed")
	}
	require.Len(t, starts, 4)
	// Each restart waits twice as long as the previous one.
	for index, minimum := range []time.Duration{20, 40, 80} {
		require.GreaterOrEqual(t, starts[index+1].Sub(starts[index]), minimum*time.Millisecond)
	}
	require.Equal(t, hostFailed, endpoint.hostState.Load())
	require.ErrorIs(t, endpoint.waitReady(context.Background()), net.ErrClosed)
}
