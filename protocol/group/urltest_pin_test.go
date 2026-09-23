package group

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	U "github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type urlTestPinOutbound struct {
	adapter.Outbound
	tag     string
	network []string
	fail    bool
	dials   int
}

func newURLTestPinOutbound(tag string) *urlTestPinOutbound {
	return &urlTestPinOutbound{tag: tag, network: []string{N.NetworkTCP, N.NetworkUDP}}
}

func (o *urlTestPinOutbound) Tag() string       { return o.tag }
func (o *urlTestPinOutbound) Type() string      { return "test" }
func (o *urlTestPinOutbound) Network() []string { return o.network }

func (o *urlTestPinOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	o.dials++
	if o.fail {
		return nil, E.New("dial ", o.tag, ": failed")
	}
	conn, peer := net.Pipe()
	_ = peer.Close()
	return conn, nil
}

func (o *urlTestPinOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("not implemented")
}

func newURLTestPinGroup(t *testing.T, outbounds ...adapter.Outbound) *URLTestGroup {
	t.Helper()
	group := &URLTestGroup{
		ctx:            context.Background(),
		logger:         log.NewNOPFactory().NewLogger("test"),
		history:        U.NewHistoryStorage(),
		interruptGroup: interrupt.NewGroup(),
		interval:       time.Minute,
		tolerance:      50,
	}
	group.storeOutbounds(outbounds)
	return group
}

func storeDelay(group *URLTestGroup, tag string, delay uint16) {
	group.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now(), Delay: delay})
}

func TestURLTestManualPinOverridesSelection(t *testing.T) {
	fast, slow := newURLTestPinOutbound("fast"), newURLTestPinOutbound("slow")
	group := newURLTestPinGroup(t, fast, slow)
	storeDelay(group, "fast", 10)
	storeDelay(group, "slow", 300)
	group.performUpdateCheck()
	require.Same(t, fast, group.selectedOutbound(N.NetworkTCP))

	require.False(t, group.setManualPin("missing"))
	require.True(t, group.setManualPin("slow"))
	require.Same(t, slow, group.selectedOutbound(N.NetworkTCP))
	require.Same(t, slow, group.selectedOutbound(N.NetworkUDP))

	// Scheduled checks keep the pin.
	group.performUpdateCheck()
	require.Same(t, slow, group.selectedOutbound(N.NetworkTCP))

	require.True(t, group.clearManualPin())
	group.performUpdateCheck()
	require.Same(t, fast, group.selectedOutbound(N.NetworkTCP))
}

func TestURLTestManualPinRespectsNetwork(t *testing.T) {
	both := newURLTestPinOutbound("both")
	udpOnly := newURLTestPinOutbound("udp")
	udpOnly.network = []string{N.NetworkUDP}
	group := newURLTestPinGroup(t, both, udpOnly)
	storeDelay(group, "both", 10)
	storeDelay(group, "udp", 10)
	group.performUpdateCheck()

	require.True(t, group.setManualPin("udp"))
	require.Same(t, udpOnly, group.selectedOutbound(N.NetworkUDP))
	require.Same(t, both, group.selectedOutbound(N.NetworkTCP))
}

func TestURLTestManualPinFollowsProviderUpdates(t *testing.T) {
	previous := newURLTestPinOutbound("pinned")
	other := newURLTestPinOutbound("other")
	group := newURLTestPinGroup(t, previous, other)
	saved := "pinned"
	group.loadSavedPin = func() string { return saved }
	require.True(t, group.setManualPin("pinned"))

	// A provider update replaces the member instance.
	replacement := newURLTestPinOutbound("pinned")
	group.replaceOutbounds([]adapter.Outbound{replacement, other})
	require.Same(t, replacement, group.selectedOutbound(N.NetworkTCP))

	// While the member is missing the group selects automatically...
	group.replaceOutbounds([]adapter.Outbound{other})
	require.Nil(t, group.manualPin.Load())
	require.Same(t, other, group.selectedOutbound(N.NetworkTCP))

	// ...and the saved selection applies again once it is back.
	back := newURLTestPinOutbound("pinned")
	group.replaceOutbounds([]adapter.Outbound{back, other})
	require.Same(t, back, group.selectedOutbound(N.NetworkTCP))

	// A released selection is not restored.
	group.clearManualPin()
	saved = ""
	group.replaceOutbounds([]adapter.Outbound{newURLTestPinOutbound("pinned"), other})
	require.Nil(t, group.manualPin.Load())
}

func TestURLTestRestoreManualPin(t *testing.T) {
	pinned := newURLTestPinOutbound("pinned")
	group := newURLTestPinGroup(t, newURLTestPinOutbound("other"), pinned)
	group.loadSavedPin = func() string { return "pinned" }
	require.Equal(t, "pinned", group.restoreManualPin())
	require.Same(t, pinned, group.selectedOutboundTCP.Load())

	missing := newURLTestPinGroup(t, newURLTestPinOutbound("other"))
	missing.loadSavedPin = func() string { return "pinned" }
	require.Empty(t, missing.restoreManualPin())
}

func TestURLTestProbeFailureThreshold(t *testing.T) {
	group := newURLTestPinGroup(t)
	for i := 1; i < urlTestFailureThreshold; i++ {
		require.False(t, group.reportProbeFailure("node"))
	}
	require.True(t, group.reportProbeFailure("node"))
	group.reportProbeSuccess("node")
	require.False(t, group.reportProbeFailure("node"))
}

func TestURLTestSelectSkipsFailingMembers(t *testing.T) {
	current, failing, healthy := newURLTestPinOutbound("current"), newURLTestPinOutbound("failing"), newURLTestPinOutbound("healthy")
	group := newURLTestPinGroup(t, current, failing, healthy)
	storeDelay(group, "current", 100)
	storeDelay(group, "failing", 10)
	group.selectedOutboundTCP.Store(current)
	group.reportProbeFailure("failing")

	// The failing member keeps its history but is not picked anew.
	selected, _ := group.Select(N.NetworkTCP)
	require.Same(t, current, selected)

	storeDelay(group, "healthy", 20)
	selected, _ = group.Select(N.NetworkTCP)
	require.Same(t, healthy, selected)

	// A failing current selection is kept while within tolerance.
	group.selectedOutboundTCP.Store(failing)
	selected, _ = group.Select(N.NetworkTCP)
	require.Same(t, failing, selected)
}

func TestURLTestKeepSelectionWithoutHistory(t *testing.T) {
	current, other := newURLTestPinOutbound("current"), newURLTestPinOutbound("other")
	group := newURLTestPinGroup(t, current, other)
	storeDelay(group, "other", 10)
	group.selectedOutboundTCP.Store(current)

	// Never carried traffic: switch to a tested member.
	selected, _ := group.Select(N.NetworkTCP)
	require.Same(t, other, selected)

	// Carries traffic: kept although its history is gone.
	group.reportDialSuccess("current")
	selected, _ = group.Select(N.NetworkTCP)
	require.Same(t, current, selected)

	// Failing dials end the grace.
	for i := 0; i < urlTestDialFailureThreshold; i++ {
		group.failureAccess.Lock()
		if group.dialFailures == nil {
			group.dialFailures = make(map[string]int)
		}
		group.dialFailures["current"]++
		group.failureAccess.Unlock()
	}
	selected, _ = group.Select(N.NetworkTCP)
	require.Same(t, other, selected)
}

func TestURLTestDialFailover(t *testing.T) {
	primary, slow, fast := newURLTestPinOutbound("primary"), newURLTestPinOutbound("slow"), newURLTestPinOutbound("fast")
	primary.fail = true
	group := newURLTestPinGroup(t, primary, slow, fast)
	storeDelay(group, "primary", 5)
	storeDelay(group, "slow", 200)
	storeDelay(group, "fast", 20)
	group.selectedOutboundTCP.Store(primary)
	outbound := &URLTest{group: group, logger: log.NewNOPFactory().NewLogger("test")}

	conn, err := outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Equal(t, 1, fast.dials)
	require.Zero(t, slow.dials)
	group.failureAccess.Lock()
	require.Equal(t, 1, group.dialFailures["primary"])
	group.failureAccess.Unlock()

	fast.fail, slow.fail = true, true
	_, err = outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	require.Error(t, err)
}

func TestURLTestUserTestReleasesManualPin(t *testing.T) {
	a, b := newURLTestPinOutbound("a"), newURLTestPinOutbound("b")
	a.fail, b.fail = true, true
	group := newURLTestPinGroup(t, a, b)
	outbound := &URLTest{ctx: context.Background(), group: group, logger: log.NewNOPFactory().NewLogger("test")}
	require.True(t, outbound.SelectOutbound("b"))
	require.Equal(t, "b", outbound.Selected())
	require.Equal(t, "b", outbound.Now())

	// Scheduled and failure-triggered checks keep the pin.
	group.CheckOutbounds(context.Background(), true)
	require.Equal(t, "b", outbound.Selected())

	// A user-triggered test releases it.
	_, err := outbound.URLTest(context.Background())
	require.NoError(t, err)
	require.Empty(t, outbound.Selected())

	require.True(t, outbound.SelectOutbound("a"))
	require.True(t, outbound.SelectOutbound(""))
	require.Empty(t, outbound.Selected())
	require.False(t, outbound.SelectOutbound("missing"))
}
