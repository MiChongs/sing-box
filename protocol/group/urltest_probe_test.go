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
	adapterOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"

	"github.com/stretchr/testify/require"
)

func TestURLTestPlanRefreshesColdMembersLessOften(t *testing.T) {
	group, history, members := newProbeTestGroup(t, "", 20)
	now := time.Now()
	for i, member := range members {
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{
			Time:  now.Add(-group.interval),
			Delay: uint16(100 + i),
		})
	}
	group.rebuildRankedCandidates()
	selected := members[10]
	group.selectedOutboundTCP.Store(selected)

	// One interval after the last round only the hot set is due: the
	// selection and the best ranked members.
	hot := append([]string{selected.Tag()}, outboundTags(members[:hotCandidates])...)
	require.ElementsMatch(t, hot, probeTargetTags(group.planTargets(group.state.Load(), probeScheduled, now)))

	// Cold members are refreshed every coldRefreshIntervals intervals.
	stale := members[15]
	history.StoreURLTestHistory(stale.Tag(), &adapter.URLTestHistory{
		Time:  now.Add(-coldRefreshIntervals * group.interval),
		Delay: 200,
	})
	targets := probeTargetTags(group.planTargets(group.state.Load(), probeScheduled, now))
	require.ElementsMatch(t, append(hot, stale.Tag()), targets)
	// Hot members come first.
	require.Equal(t, stale.Tag(), targets[len(targets)-1])

	// Measured half an interval ago: nothing is due.
	for _, member := range members {
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: now.Add(-group.interval / 4), Delay: 100})
	}
	require.Empty(t, group.planTargets(group.state.Load(), probeScheduled, now))
}

func TestURLTestPlanProbesUnmeasuredMembers(t *testing.T) {
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
	require.NotContains(t, scheduled, members[2].Tag())

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
	require.Equal(t, now, targets[0].since)
}

func TestURLTestPlanNetworkChangeProbesHotSet(t *testing.T) {
	group, history, members := newProbeTestGroup(t, "", 10)
	now := time.Now()
	for i, member := range members {
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: now.Add(-time.Second), Delay: uint16(100 + i)})
	}
	group.rebuildRankedCandidates()
	group.selectedOutboundTCP.Store(members[0])

	targets := group.planTargets(group.state.Load(), probePlan{hotBefore: now}, now)

	require.ElementsMatch(t, outboundTags(members[:hotCandidates]), probeTargetTags(targets))
}

func TestURLTestFallbackWatchesPriorityPrefix(t *testing.T) {
	group, history, members := newProbeTestGroup(t, "", 20)
	group.fallback = URLTestFallback{enabled: true}
	now := time.Now()
	for _, member := range members {
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: now.Add(-time.Second), Delay: 100})
	}
	group.selectedOutboundTCP.Store(members[5])

	targets := group.planTargets(group.state.Load(), probePlan{hotBefore: now}, now)

	require.ElementsMatch(t, outboundTags(members[:7]), probeTargetTags(targets))
}

func TestURLTestSelectionToleratesSingleProbeFailure(t *testing.T) {
	group, history, members := newProbeTestGroup(t, "", 2)
	current, best := members[0], members[1]
	history.StoreURLTestHistory(best.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	group.rebuildRankedCandidates()
	group.selectedOutboundTCP.Store(current)

	group.recordProbe(current.Tag(), time.Now(), false)
	selected, available := group.Select(N.NetworkTCP)
	require.True(t, available)
	require.Same(t, current, selected)

	group.recordProbe(current.Tag(), time.Now(), false)
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
	round := newProbeRound(probeScheduled, time.Time{})
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

	// A second user test moments later is served from the fresh results.
	_, err = group.URLTest(context.Background())
	require.NoError(t, err)
	for _, member := range members {
		require.EqualValues(t, 1, member.dialCount.Load())
	}
}

func TestURLTestGroupsShareProbes(t *testing.T) {
	server := newNoContentServer(t)
	first, history, members := newProbeTestGroup(t, server.URL, 4)
	release := make(chan struct{})
	for _, member := range members {
		member.release = release
	}
	second := newProbeTestGroupWith(first.outbound, history, server.URL, members[1:])

	firstDone := make(chan struct{})
	go func() {
		first.CheckOutbounds(false)
		close(firstDone)
	}()
	require.Eventually(t, func() bool { return members[1].dialCount.Load() == 1 }, time.Second, time.Millisecond)
	secondDone := make(chan struct{})
	go func() {
		second.CheckOutbounds(false)
		close(secondDone)
	}()
	time.Sleep(50 * time.Millisecond)
	close(release)
	<-firstDone
	<-secondDone

	for _, member := range members {
		require.EqualValues(t, 1, member.dialCount.Load(), member.Tag())
		require.NotNil(t, history.LoadURLTestHistory(member.Tag()))
	}
	require.NotNil(t, second.selectedOutboundTCP.Load())
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
	require.True(t, queued.plan.scheduled)
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
	group, history, members := newProbeTestGroup(t, server.URL, 3)
	for _, member := range members {
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	}
	failing := members[0]
	failing.failing.Store(true)

	for range dialFailureThreshold {
		group.reportDialFailure(failing.Tag())
	}
	waitProbeRoundsIdle(t, group)
	// Only the failing member is rechecked.
	require.EqualValues(t, 1, failing.dialCount.Load())
	require.Zero(t, members[1].dialCount.Load())
	require.Zero(t, members[2].dialCount.Load())
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

func TestURLTestDialFailuresNeedFailoverConfirmation(t *testing.T) {
	group, history, members := newProbeTestGroup(t, "", 3)
	for i, member := range members {
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: uint16(100 + i)})
	}
	group.rebuildRankedCandidates()
	group.selectedOutboundTCP.Store(members[0])
	instance := &URLTest{
		Adapter: adapterOutbound.NewAdapter(C.TypeURLTest, "test", []string{N.NetworkTCP, N.NetworkUDP}, outboundTags(members)),
		logger:  log.NewNOPFactory().NewLogger("test"),
		group:   group,
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	destination := M.SocksaddrFromNet(listener.Addr())

	// Every member failing points at the destination: nothing is counted.
	for _, member := range members {
		member.failing.Store(true)
	}
	_, err = instance.DialContext(context.Background(), N.NetworkTCP, destination)
	require.Error(t, err)
	require.False(t, group.hasExcessiveDialFailures(members[0].Tag()))
	require.Zero(t, group.dialFailureTracked.Load())
	require.EqualValues(t, 1+maxFailoverCandidates, members[0].dialCount.Load()+members[1].dialCount.Load()+members[2].dialCount.Load())

	// The next member reaching the destination confirms the failure.
	members[1].failing.Store(false)
	conn, err := instance.DialContext(context.Background(), N.NetworkTCP, destination)
	require.NoError(t, err)
	conn.Close()
	require.EqualValues(t, 1, group.dialFailureTracked.Load())
}

func TestURLTestNetworkChangeCooldown(t *testing.T) {
	server := newNoContentServer(t)
	group, history, members := newProbeTestGroup(t, server.URL, 5)
	for i, member := range members {
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: uint16(100 + i)})
	}
	group.rebuildRankedCandidates()
	group.selectedOutboundTCP.Store(members[0])
	group.loopRunning.Store(true)

	group.networkChanged()
	waitProbeRoundsIdle(t, group)
	for i, member := range members {
		if i < hotCandidates {
			require.EqualValues(t, 1, member.dialCount.Load(), member.Tag())
		} else {
			require.Zero(t, member.dialCount.Load(), member.Tag())
		}
	}

	group.networkChanged()
	waitProbeRoundsIdle(t, group)
	require.EqualValues(t, 1, members[0].dialCount.Load())
}

func TestNextTickAlignsGroups(t *testing.T) {
	interval := 50 * time.Millisecond
	delay := nextTick(interval)
	require.Positive(t, delay)
	require.LessOrEqual(t, delay, interval)
	require.Less(t, (urlTestClock()+int64(delay))%int64(interval), int64(5*time.Millisecond))
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
	for i := range count {
		member := &probeTestOutbound{tag: "member-" + strconv.Itoa(i)}
		manager.outbounds[member.tag] = member
		members = append(members, member)
	}
	history := urltest.NewHistoryStorage()
	return newProbeTestGroupWith(manager, history, link, members), history, members
}

func newProbeTestGroupWith(manager adapter.OutboundManager, history *urltest.HistoryStorage, link string, members []*probeTestOutbound) *URLTestGroup {
	outbounds := make([]adapter.Outbound, 0, len(members))
	for _, member := range members {
		outbounds = append(outbounds, member)
	}
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
	return group
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
