package group

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

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
