package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/puzpuzpuz/xsync/v3"

	"github.com/stretchr/testify/require"
)

func TestSmartLastResortKeepsNetwork(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	s.knownDead = xsync.NewMapOf[string, time.Time]()
	s.breakers = xsync.NewMapOf[string, *circuitBreakerState]()
	tcpOnly := &filterTestOutbound{tag: "tcp-only", typ: "shadowsocks", networks: []string{N.NetworkTCP}}
	both := &filterTestOutbound{tag: "both", typ: "vless", networks: []string{N.NetworkTCP, N.NetworkUDP}}

	// UDP: only the UDP capable member may be returned, even as last resort.
	selected := s.fillProxies("", nil, nil, []adapter.Outbound{tcpOnly, both}, 4, true, false)
	require.Equal(t, []adapter.Outbound{both}, selected)

	// No UDP capable member at all: nothing, rather than a dial bound to fail.
	require.Empty(t, s.fillProxies("", nil, nil, []adapter.Outbound{tcpOnly}, 4, true, false))

	// TCP is unaffected.
	require.Len(t, s.fillProxies("", nil, nil, []adapter.Outbound{tcpOnly, both}, 4, false, false), 2)
}

func storeUDPProbe(history *urltest.HistoryStorage, tag string, failed bool, expire time.Duration) {
	now := time.Now()
	result := &adapter.UDPTestHistory{Time: now, Expire: now.Add(expire), Delay: 30}
	if failed {
		result.Delay = 0
		result.Error = "no UDP response"
	}
	history.StoreUDPTestHistory(tag, result)
}

func TestUDPProbeResultsDriveSelection(t *testing.T) {
	udp := []string{N.NetworkTCP, N.NetworkUDP}
	broken := &filterTestOutbound{tag: "broken", typ: "vless", networks: udp}
	working := &filterTestOutbound{tag: "working", typ: "vless", networks: udp}
	unprobed := &filterTestOutbound{tag: "unprobed", typ: "vless", networks: udp}
	stale := &filterTestOutbound{tag: "stale", typ: "vless", networks: udp}
	history := urltest.NewHistoryStorage()
	storeUDPProbe(history, "broken", true, time.Minute)
	storeUDPProbe(history, "working", false, time.Minute)
	storeUDPProbe(history, "stale", true, -time.Second)
	members := []adapter.Outbound{broken, working, unprobed, stale}

	// group membership with network: udp
	ctx := service.ContextWithPtr(context.Background(), history)
	filter, err := newMemberFilter(ctx, parseGroupOptions(t, `{"network":"udp"}`))
	require.NoError(t, err)
	var kept []string
	for _, member := range members {
		if filter.Match(member) {
			kept = append(kept, member.Tag())
		}
	}
	require.Equal(t, []string{"working", "unprobed", "stale"}, kept,
		"only a valid failed probe removes a node; unprobed and expired ones keep their declared UDP")

	// Smart picks for UDP
	s := newTestSmartForWatchdog(t)
	s.knownDead = xsync.NewMapOf[string, time.Time]()
	s.breakers = xsync.NewMapOf[string, *circuitBreakerState]()
	s.history = history
	for _, ob := range s.fillProxies("", nil, nil, members, 8, true, false) {
		require.NotEqual(t, "broken", ob.Tag())
	}
	require.Len(t, s.fillProxies("", nil, nil, members, 8, false, false), 4, "TCP is unaffected")

	// load-balance liveness for UDP
	history.StoreURLTestHistory("broken", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	history.StoreURLTestHistory("working", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	group := &LoadBalanceGroup{history: history}
	require.False(t, group.aliveForTestURL(broken, N.NetworkUDP, map[string]bool{}))
	require.True(t, group.aliveForTestURL(broken, N.NetworkTCP, map[string]bool{}))
	require.True(t, group.aliveForTestURL(working, N.NetworkUDP, map[string]bool{}))
}
