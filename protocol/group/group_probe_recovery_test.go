package group

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func startRecoveryTestServer(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func shortenRecoveryDelays(t *testing.T) {
	t.Helper()
	previousDelay, previousBackoff := groupFailureProbeDelay, groupStartupProbeBackoff
	groupFailureProbeDelay = 10 * time.Millisecond
	groupStartupProbeBackoff = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}
	t.Cleanup(func() {
		groupFailureProbeDelay, groupStartupProbeBackoff = previousDelay, previousBackoff
	})
}

func TestURLTestColdStartPicksStableRandomMember(t *testing.T) {
	firstPicks := make(map[string]int)
	for range 20 {
		group, _, _ := newProbeTestGroup(t, "", 5)
		instance := &URLTest{group: group}
		selected := instance.Selected(N.NetworkTCP)
		require.NotNil(t, selected)
		for range 5 {
			require.Same(t, selected, instance.Selected(N.NetworkTCP))
		}
		firstPicks[selected.Tag()]++
	}
	require.Greater(t, len(firstPicks), 1, "cold start always picked the same member")
}

func TestRunStartupProbeBackoff(t *testing.T) {
	shortenRecoveryDelays(t)
	var probes atomic.Int32
	runStartupProbeBackoff(context.Background(), nil, time.Hour, func() bool { return false }, func() bool { return false }, func() bool {
		probes.Add(1)
		return false
	})
	require.EqualValues(t, len(groupStartupProbeBackoff), probes.Load())

	probes.Store(0)
	runStartupProbeBackoff(context.Background(), nil, time.Hour, func() bool { return false }, func() bool { return false }, func() bool {
		return probes.Add(1) == 2
	})
	require.EqualValues(t, 2, probes.Load(), "stops once a probe succeeds")

	probes.Store(0)
	runStartupProbeBackoff(context.Background(), nil, time.Hour, func() bool { return true }, func() bool { return false }, func() bool {
		probes.Add(1)
		return false
	})
	require.Zero(t, probes.Load(), "an idle group is not probed")

	probes.Store(0)
	runStartupProbeBackoff(context.Background(), nil, 5*time.Millisecond, func() bool { return false }, func() bool { return false }, func() bool {
		probes.Add(1)
		return false
	})
	require.EqualValues(t, 1, probes.Load(), "retries never exceed the interval")
}

func TestURLTestUnmeasuredFailureSwitchesAway(t *testing.T) {
	shortenRecoveryDelays(t)
	group, history, members := newProbeTestGroup(t, startRecoveryTestServer(t), 3)
	group.idleTimeout = time.Hour
	group.markActive()
	members[0].failing.Store(true)
	group.selectedOutboundTCP.Store(members[0])

	group.onUnmeasuredDialFailed(members[0], N.NetworkTCP)

	require.Eventually(t, func() bool {
		selected := group.selectedOutboundTCP.Load()
		return selected != nil && selected != members[0]
	}, 5*time.Second, 10*time.Millisecond)
	require.Nil(t, history.LoadURLTestHistory(members[0].Tag()))
	// Nothing was alive, so every member is probed again.
	require.Eventually(t, func() bool {
		return history.LoadURLTestHistory(members[1].Tag()) != nil && history.LoadURLTestHistory(members[2].Tag()) != nil
	}, 5*time.Second, 10*time.Millisecond)
	waitProbeRoundsIdle(t, group)
}

func TestURLTestUnmeasuredFailureTrustsAvailableMember(t *testing.T) {
	shortenRecoveryDelays(t)
	group, history, members := newProbeTestGroup(t, startRecoveryTestServer(t), 3)
	group.selectedOutboundTCP.Store(members[0])

	group.onUnmeasuredDialFailed(members[0], N.NetworkTCP)

	require.Eventually(t, func() bool {
		return history.LoadURLTestHistory(members[0].Tag()) != nil && !group.failureProbePending.Load()
	}, 5*time.Second, 10*time.Millisecond)
	require.Same(t, members[0], group.selectedOutboundTCP.Load())
	dials := members[0].dialCount.Load()
	group.onUnmeasuredDialFailed(members[0], N.NetworkTCP)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, dials, members[0].dialCount.Load(), "a member that passed is trusted for a while")
	waitProbeRoundsIdle(t, group)
}

func TestURLTestManualSelectionRejectsUnavailableMember(t *testing.T) {
	group, _, members := newProbeTestGroup(t, startRecoveryTestServer(t), 2)
	instance := &URLTest{ctx: context.Background(), group: group, logger: log.NewNOPFactory().Logger()}
	members[1].failing.Store(true)
	require.False(t, instance.SelectOutbound(members[1].Tag()))
	require.Empty(t, instance.PinnedTag())
	require.True(t, instance.SelectOutbound(members[0].Tag()))
	require.Equal(t, members[0].Tag(), instance.PinnedTag())
}

func TestLoadBalanceFailedMemberIsDroppedAndInterrupted(t *testing.T) {
	shortenRecoveryDelays(t)
	history := urltest.NewHistoryStorage()
	dead := &probeTestOutbound{tag: "dead"}
	alive := &probeTestOutbound{tag: "alive"}
	dead.failing.Store(true)
	group, err := NewLoadBalanceGroup(context.Background(), nil, log.NewNOPFactory().Logger(), []adapter.Outbound{dead, alive}, startRecoveryTestServer(t), time.Minute, time.Hour, 0, StrategyRoundRobin)
	require.NoError(t, err)
	group.history = history
	group.lastActive.Store(time.Now())
	for _, member := range []adapter.Outbound{dead, alive} {
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	}
	deadConn, peer := net.Pipe()
	defer peer.Close()
	tracked := group.newConn(dead.Tag(), deadConn, false, false)
	aliveConn, alivePeer := net.Pipe()
	defer alivePeer.Close()
	aliveTracked := group.newConn(alive.Tag(), aliveConn, false, false)
	defer aliveTracked.Close()

	group.onOutboundFailed(dead)

	require.Eventually(t, func() bool {
		return history.LoadURLTestHistory(dead.Tag()) == nil
	}, 5*time.Second, 10*time.Millisecond)
	_, err = tracked.Read(make([]byte, 1))
	require.Error(t, err, "connections through the dead member are closed")
	require.NotNil(t, history.LoadURLTestHistory(alive.Tag()))
	aliveConn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	_, err = aliveTracked.Read(make([]byte, 1))
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout(), "connections through other members stay open")
}
