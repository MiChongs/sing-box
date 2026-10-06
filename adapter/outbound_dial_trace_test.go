package adapter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type traceTestOutbound struct {
	Outbound
	tag string
}

func (o *traceTestOutbound) Tag() string { return o.tag }

type traceTestDialingGroup struct {
	OutboundGroup
	tag string
}

func (g *traceTestDialingGroup) Tag() string       { return g.tag }
func (g *traceTestDialingGroup) DialThroughGroup() {}

func traceTestTags(chain []Outbound) []string {
	tags := make([]string, 0, len(chain))
	for _, outbound := range chain {
		tags = append(tags, outbound.Tag())
	}
	return tags
}

func TestOutboundDialTraceResolve(t *testing.T) {
	t.Parallel()

	proxy := &traceTestOutbound{tag: "Proxy"}
	smart := &traceTestDialingGroup{tag: "Smart"}
	urlTest := &traceTestOutbound{tag: "URLTest-HK"}
	node := &traceTestOutbound{tag: "HK-01"}
	relay := &traceTestOutbound{tag: "relay"}

	chain := make([]Outbound, 0, 8)
	chain = append(chain, proxy, smart)
	require.True(t, NeedOutboundDialTrace(chain))
	require.False(t, NeedOutboundDialTrace(chain[:1]))

	trace := new(OutboundDialTrace)
	ctx := ContextWithOutboundDialTrace(context.Background(), trace)
	require.Equal(t, []string{"Proxy", "Smart"}, traceTestTags(trace.Resolve(chain)))

	// Nested groups record inner-first; resolution still follows the chain
	// from its tail, and entries off the path (a detour) are ignored.
	RecordGroupDial(ctx, "URLTest-HK", node)
	RecordGroupDial(ctx, "relay-selector", relay)
	RecordGroupDial(ctx, "Smart", urlTest)
	resolved := trace.Resolve(chain)
	require.Equal(t, []string{"Proxy", "Smart", "URLTest-HK", "HK-01"}, traceTestTags(resolved))

	// The route-time chain is shared with the connection metadata and must
	// never be written through, even when it has spare capacity.
	require.Len(t, chain, 2)
	require.Equal(t, []string{"Proxy", "Smart"}, traceTestTags(chain[:2]))
	require.Nil(t, chain[:3][2])
}

func TestOutboundDialTraceResolveCycle(t *testing.T) {
	t.Parallel()

	a := &traceTestOutbound{tag: "A"}
	b := &traceTestOutbound{tag: "B"}
	trace := new(OutboundDialTrace)
	ctx := ContextWithOutboundDialTrace(context.Background(), trace)
	RecordGroupDial(ctx, "A", b)
	RecordGroupDial(ctx, "B", a)
	require.Equal(t, []string{"A", "B", "A"}, traceTestTags(trace.Resolve([]Outbound{a})))
}

func TestOutboundDialTraceWithoutTrace(t *testing.T) {
	t.Parallel()

	chain := []Outbound{&traceTestOutbound{tag: "Proxy"}}
	RecordGroupDial(context.Background(), "Proxy", &traceTestOutbound{tag: "node"})
	var trace *OutboundDialTrace
	require.Equal(t, chain, trace.Resolve(chain))
}
