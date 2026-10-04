package group

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"

	"github.com/stretchr/testify/require"
)

func TestURLTestPlanBoundsColdMembers(t *testing.T) {
	group, history, members := newProbeTestGroup(t, "", 1000)
	now := time.Now()
	for i, member := range members {
		// Older measurements for higher indexes, so they are refreshed first.
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{
			Time:  now.Add(-time.Hour - time.Duration(i)*time.Second),
			Delay: uint16(100 + i),
		})
	}
	group.rebuildRankedCandidates()
	selected := members[500]
	group.selectedOutboundTCP.Store(selected)

	targets := group.planTargets(group.state.Load(), probeScheduled, now)

	budget := len(members) / coldSweepRounds
	require.Len(t, targets, 1+hotCandidates+budget)
	hot := probeTargetTags(targets[:1+hotCandidates])
	require.Contains(t, hot, selected.Tag())
	for _, member := range members[:hotCandidates] {
		require.Contains(t, hot, member.Tag())
	}
	cold := probeTargetTags(targets[1+hotCandidates:])
	require.Contains(t, cold, members[len(members)-1].Tag())
	require.NotContains(t, cold, members[hotCandidates].Tag())
}

func TestURLTestPlanSmallGroupProbesEveryStaleMember(t *testing.T) {
	group, history, members := newProbeTestGroup(t, "", 20)
	now := time.Now()
	for _, member := range members {
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: now.Add(-group.interval), Delay: 100})
	}
	history.StoreURLTestHistory(members[0].Tag(), &adapter.URLTestHistory{Time: now, Delay: 100})

	targets := group.planTargets(group.state.Load(), probeScheduled, now)

	require.Len(t, targets, len(members)-1)
	require.NotContains(t, probeTargetTags(targets), members[0].Tag())
}

func TestURLTestPlanProbesUnmeasuredMembersWithoutBudget(t *testing.T) {
	group, _, members := newProbeTestGroup(t, "", 300)

	targets := group.planTargets(group.state.Load(), probeScheduled, time.Now())

	require.Len(t, targets, len(members))
}

func TestURLTestPlanBacksOffFailingMembers(t *testing.T) {
	group, _, members := newProbeTestGroup(t, "", 3)
	now := time.Now()
	group.health = map[string]*memberHealth{
		// Third failure: retried four intervals after the last probe.
		members[0].Tag(): {lastProbe: now.Add(-2 * group.interval), failures: 3},
		// First failure: retried one interval after the last probe.
		members[1].Tag(): {lastProbe: now.Add(-group.interval), failures: 1},
		members[2].Tag(): {lastProbe: now.Add(-group.interval)},
	}

	scheduled := probeTargetTags(group.planTargets(group.state.Load(), probeScheduled, now))
	require.NotContains(t, scheduled, members[0].Tag())
	require.Contains(t, scheduled, members[1].Tag())
	require.Contains(t, scheduled, members[2].Tag())

	full := probeTargetTags(group.planTargets(group.state.Load(), probeFull, now))
	require.ElementsMatch(t, outboundTags(members), full)

	group.networkChanged()
	scheduled = probeTargetTags(group.planTargets(group.state.Load(), probeScheduled, now))
	require.Contains(t, scheduled, members[0].Tag())
}

func TestURLTestPlanFocusIgnoresFreshness(t *testing.T) {
	group, history, members := newProbeTestGroup(t, "", 3)
	now := time.Now()
	for _, member := range members {
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: now, Delay: 100})
	}
	focus := members[2].Tag()

	targets := group.planTargets(group.state.Load(), probePlan{focus: map[string]struct{}{focus: {}}}, now)

	require.Equal(t, []string{focus}, probeTargetTags(targets))
}

func TestURLTestFallbackWatchesPriorityPrefix(t *testing.T) {
	group, history, members := newProbeTestGroup(t, "", 20)
	group.fallback = URLTestFallback{enabled: true}
	now := time.Now()
	for _, member := range members {
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: now, Delay: 100})
	}
	group.selectedOutboundTCP.Store(members[5])

	targets := group.planTargets(group.state.Load(), probePlan{forceHot: true}, now)

	require.ElementsMatch(t, outboundTags(members[:7]), probeTargetTags(targets))
}

func TestURLTestSelectionToleratesSingleProbeFailure(t *testing.T) {
	group, history, members := newProbeTestGroup(t, "", 2)
	current, best := members[0], members[1]
	history.StoreURLTestHistory(best.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	group.rebuildRankedCandidates()
	group.selectedOutboundTCP.Store(current)

	group.recordProbe(current.Tag(), false)
	selected, available := group.Select(N.NetworkTCP)
	require.True(t, available)
	require.Same(t, current, selected)

	group.recordProbe(current.Tag(), false)
	selected, available = group.Select(N.NetworkTCP)
	require.True(t, available)
	require.Same(t, best, selected)
}

func TestURLTestUnverifiedLeadersAreReprobed(t *testing.T) {
	group, history, members := newProbeTestGroup(t, "", 3)
	startedAt := time.Now()
	history.StoreURLTestHistory(members[0].Tag(), &adapter.URLTestHistory{Time: startedAt.Add(-time.Hour), Delay: 1})
	history.StoreURLTestHistory(members[1].Tag(), &adapter.URLTestHistory{Time: startedAt, Delay: 50})
	group.rebuildRankedCandidates()
	round := newProbeRound(probeScheduled, nil)
	round.result[members[1].Tag()] = 50

	leaders := group.unverifiedLeaders(round, startedAt)

	require.Equal(t, []string{members[0].Tag()}, probeTargetTags(leaders))
}

func TestURLTestRoundRecordsResults(t *testing.T) {
	server := newNoContentServer(t)
	group, history, members := newProbeTestGroup(t, server.URL, 3)
	members[2].failing.Store(true)
	history.StoreURLTestHistory(members[2].Tag(), &adapter.URLTestHistory{Time: time.Now().Add(-time.Hour), Delay: 1})

	result, err := group.URLTest(context.Background())
	require.NoError(t, err)

	require.Contains(t, result, members[0].Tag())
	require.Contains(t, result, members[1].Tag())
	require.NotContains(t, result, members[2].Tag())
	require.Nil(t, history.LoadURLTestHistory(members[2].Tag()))
	require.EqualValues(t, 1, group.probeFailures(members[2].Tag()))
	require.NotNil(t, group.selectedOutboundTCP.Load())
	require.NotEqual(t, members[2].Tag(), group.selectedOutboundTCP.Load().Tag())
	for _, member := range members {
		require.EqualValues(t, 1, member.dialCount.Load())
	}
}

func TestURLTestRoundsCoalesce(t *testing.T) {
	server := newNoContentServer(t)
	group, _, members := newProbeTestGroup(t, server.URL, 2)
	release := make(chan struct{})
	for _, member := range members {
		member.release = release
	}
	ctx := context.Background()

	full := group.requestRound(ctx, probeFull, true)
	require.NotNil(t, full)
	require.Same(t, full, group.requestRound(ctx, probeFull, true))
	require.Nil(t, group.requestRound(ctx, probeScheduled, false))
	queued := group.requestRound(ctx, probeScheduled, true)
	require.NotSame(t, full, queued)
	focus := members[0].Tag()
	require.Same(t, queued, group.requestRound(ctx, probePlan{focus: map[string]struct{}{focus: {}}}, true))
	require.True(t, queued.plan.cold)
	require.Contains(t, queued.plan.focus, focus)

	close(release)
	<-full.done
	<-queued.done
	// The queued round re-probes only the focused member: the other one,
	// a ranking leader included, was measured moments ago.
	require.EqualValues(t, 2, members[0].dialCount.Load())
	require.EqualValues(t, 1, members[1].dialCount.Load())
}

func TestURLTestRoundStopsWithGroup(t *testing.T) {
	server := newNoContentServer(t)
	group, _, members := newProbeTestGroup(t, server.URL, 1)
	release := make(chan struct{})
	defer close(release)
	members[0].release = release
	ctx, cancel := context.WithCancel(context.Background())
	group.ctx, group.cancel = ctx, cancel
	group.close = make(chan struct{})

	round := group.requestRound(ctx, probeFull, true)
	require.Eventually(t, func() bool { return members[0].dialCount.Load() == 1 }, time.Second, time.Millisecond)
	require.NoError(t, group.Close())

	select {
	case <-round.done:
	case <-time.After(time.Second):
		t.Fatal("round outlived the group")
	}
	// Cancellation is not a verdict on the member.
	require.Zero(t, group.probeFailures(members[0].Tag()))
}

func TestURLTestDialFailureRecheckCooldown(t *testing.T) {
	server := newNoContentServer(t)
	group, _, members := newProbeTestGroup(t, server.URL, 2)
	failing := members[0]
	failing.failing.Store(true)

	for range dialFailureThreshold {
		group.reportDialFailure(failing.Tag())
	}
	waitProbeRoundsIdle(t, group)
	require.EqualValues(t, 1, failing.dialCount.Load())
	require.True(t, group.hasExcessiveDialFailures(failing.Tag()))

	for range 3 * dialFailureThreshold {
		group.reportDialFailure(failing.Tag())
	}
	waitProbeRoundsIdle(t, group)
	require.EqualValues(t, 1, failing.dialCount.Load())

	group.reportDialSuccess(failing.Tag())
	require.False(t, group.hasExcessiveDialFailures(failing.Tag()))
	require.Zero(t, group.dialFailureTracked.Load())
}

func TestURLTestHistoryNotificationsCoalesce(t *testing.T) {
	history := urltest.NewHistoryStorage()
	hook := observable.NewSubscriber[struct{}](128)
	defer hook.Close()
	history.AddUpdateHook(hook)
	updates, _ := hook.Subscription()

	for i := range 100 {
		history.StoreURLTestHistory(strconv.Itoa(i), &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	}
	time.Sleep(500 * time.Millisecond)

	require.Len(t, updates, 2)
}

func newProbeTestGroup(t *testing.T, link string, count int) (*URLTestGroup, *urltest.HistoryStorage, []*probeTestOutbound) {
	t.Helper()
	manager := &recursiveURLTestOutboundManager{outbounds: make(map[string]adapter.Outbound, count)}
	members := make([]*probeTestOutbound, 0, count)
	outbounds := make([]adapter.Outbound, 0, count)
	for i := range count {
		member := &probeTestOutbound{tag: "member-" + strconv.Itoa(i)}
		manager.outbounds[member.tag] = member
		members = append(members, member)
		outbounds = append(outbounds, member)
	}
	history := urltest.NewHistoryStorage()
	group := &URLTestGroup{
		ctx:            context.Background(),
		outbound:       manager,
		logger:         log.NewNOPFactory().Logger(),
		link:           link,
		interval:       time.Minute,
		tolerance:      50,
		history:        history,
		interruptGroup: interrupt.NewGroup(),
	}
	group.storeOutbounds(outbounds)
	return group, history, members
}

func waitProbeRoundsIdle(t *testing.T, group *URLTestGroup) {
	t.Helper()
	require.Eventually(t, func() bool {
		group.roundAccess.Lock()
		defer group.roundAccess.Unlock()
		return group.runningRound == nil
	}, 5*time.Second, time.Millisecond)
}

func newNoContentServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server
}

func probeTargetTags(targets []probeTarget) []string {
	tags := make([]string, 0, len(targets))
	for _, target := range targets {
		tags = append(tags, target.tag)
	}
	return tags
}

func outboundTags(members []*probeTestOutbound) []string {
	tags := make([]string, 0, len(members))
	for _, member := range members {
		tags = append(tags, member.tag)
	}
	return tags
}

type probeTestOutbound struct {
	adapter.Outbound
	tag       string
	failing   atomic.Bool
	release   chan struct{}
	dialCount atomic.Int32
}

func (o *probeTestOutbound) Tag() string {
	return o.tag
}

func (o *probeTestOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (o *probeTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dialCount.Add(1)
	if o.release != nil {
		select {
		case <-o.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if o.failing.Load() {
		return nil, E.New("probe test failure")
	}
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}
