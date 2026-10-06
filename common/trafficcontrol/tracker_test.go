package trafficcontrol

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestTrackerMetadataConnectionDomain(t *testing.T) {
	testCases := []struct {
		name        string
		destination M.Socksaddr
		domain      string
		sniffHost   string
		expected    string
	}{
		{
			name:      "sniff host",
			sniffHost: "sniff.example.com",
			expected:  "sniff.example.com",
		},
		{
			name:      "sniff host before reverse mapped domain",
			domain:    "mapped.example.com",
			sniffHost: "sniff.example.com",
			expected:  "sniff.example.com",
		},
		{
			name:     "reverse mapped domain fallback",
			domain:   "mapped.example.com",
			expected: "mapped.example.com",
		},
		{
			name:        "destination fqdn before cached domains",
			destination: M.ParseSocksaddr("destination.example.com:443"),
			domain:      "mapped.example.com",
			sniffHost:   "sniff.example.com",
			expected:    "destination.example.com",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			metadata := TrackerMetadata{Metadata: adapter.InboundContext{
				Destination: testCase.destination,
				Domain:      testCase.domain,
				SniffHost:   testCase.sniffHost,
			}}
			require.Equal(t, testCase.expected, metadata.ConnectionDomain())
		})
	}
}

type resolvedChainTestOutbound struct {
	adapter.Outbound
	tag          string
	outboundType string
}

func (o *resolvedChainTestOutbound) Tag() string  { return o.tag }
func (o *resolvedChainTestOutbound) Type() string { return o.outboundType }

func TestTrackerMetadataResolvedChain(t *testing.T) {
	proxy := &resolvedChainTestOutbound{tag: "Proxy", outboundType: "selector"}
	smart := &resolvedChainTestOutbound{tag: "Smart", outboundType: "smart"}
	node := &resolvedChainTestOutbound{tag: "HK-01", outboundType: "vless"}

	trace := new(adapter.OutboundDialTrace)
	ctx := adapter.ContextWithOutboundDialTrace(context.Background(), trace)
	metadata := NewManager().newTrackerMetadata(ctx, adapter.InboundContext{
		OutboundChain: []adapter.Outbound{proxy, smart},
	}, nil, proxy, new(atomic.Int64), new(atomic.Int64))

	// Before the group dials, the chain ends at the group itself.
	require.Equal(t, []string{"Smart", "Proxy"}, metadata.ResolvedChain())
	outbound, outboundType := metadata.ResolvedOutbound()
	require.Equal(t, "Smart", outbound)
	require.Equal(t, "smart", outboundType)

	adapter.RecordGroupDial(ctx, "Smart", node)
	require.Equal(t, []string{"HK-01", "Smart", "Proxy"}, metadata.ResolvedChain())
	outbound, outboundType = metadata.ResolvedOutbound()
	require.Equal(t, "HK-01", outbound)
	require.Equal(t, "vless", outboundType)
	// The route-time fields stay as they were.
	require.Equal(t, []string{"Smart", "Proxy"}, metadata.Chain)
	require.Equal(t, "Smart", metadata.Outbound)
}
