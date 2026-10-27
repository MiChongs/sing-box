package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type filterTestOutbound struct {
	adapter.Outbound
	tag      string
	typ      string
	networks []string
}

func (o *filterTestOutbound) Tag() string       { return o.tag }
func (o *filterTestOutbound) Type() string      { return o.typ }
func (o *filterTestOutbound) Network() []string { return o.networks }

type filterTestRegistry []string

func (r filterTestRegistry) OptionTypes() []string            { return r }
func (r filterTestRegistry) CreateOptions(string) (any, bool) { return nil, false }

var (
	tcpOnly = []string{N.NetworkTCP}
	tcpUDP  = []string{N.NetworkTCP, N.NetworkUDP}
	members = []adapter.Outbound{
		&filterTestOutbound{tag: "p/HK vless", typ: "vless", networks: tcpUDP},
		&filterTestOutbound{tag: "p/HK ss tcp", typ: "shadowsocks", networks: tcpOnly},
		&filterTestOutbound{tag: "p/JP hy2", typ: "hysteria2", networks: tcpUDP},
		&filterTestOutbound{tag: "p/JP http", typ: "http", networks: tcpOnly},
		&filterTestOutbound{tag: "p/JP wg", typ: "wireguard", networks: tcpUDP},
	}
)

func parseGroupOptions(t *testing.T, content string) option.GroupCommonOption {
	t.Helper()
	var options option.GroupCommonOption
	require.NoError(t, json.Unmarshal([]byte(content), &options))
	return options
}

func matchedTags(filter *memberFilter) []string {
	var tags []string
	for _, detour := range members {
		if filter.Match(detour) {
			tags = append(tags, detour.Tag())
		}
	}
	return tags
}

func TestMemberFilter(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(),
		filterTestRegistry{"vless", "shadowsocks", "hysteria2", "http", "socks"})
	ctx = service.ContextWith[option.EndpointOptionsRegistry](ctx, filterTestRegistry{"wireguard"})

	testCases := []struct {
		name     string
		options  string
		expected []string
	}{
		{"no filter", `{}`, []string{"p/HK vless", "p/HK ss tcp", "p/JP hy2", "p/JP http", "p/JP wg"}},
		{"udp capable", `{"network":"udp"}`, []string{"p/HK vless", "p/JP hy2", "p/JP wg"}},
		{"include type with alias and case", `{"include_type":["VLESS","hy2"]}`, []string{"p/HK vless", "p/JP hy2"}},
		{"exclude type single string", `{"exclude_type":"wg"}`, []string{"p/HK vless", "p/HK ss tcp", "p/JP hy2", "p/JP http"}},
		{"combined with name", `{"include":"JP","exclude_type":["http"],"network":["tcp","udp"]}`, []string{"p/JP hy2", "p/JP wg"}},
		{"exclude type wins over include type", `{"include_type":["ss","vless"],"exclude_type":["shadowsocks"]}`, []string{"p/HK vless"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			filter, err := newMemberFilter(ctx, parseGroupOptions(t, testCase.options))
			require.NoError(t, err)
			require.Equal(t, testCase.expected, matchedTags(filter))
		})
	}
}

func TestMemberFilterRejectsUnknownType(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), filterTestRegistry{"vless"})
	_, err := newMemberFilter(ctx, parseGroupOptions(t, `{"include_type":["vles"]}`))
	require.ErrorContains(t, err, "include_type: unknown outbound type: vles")

	var options option.GroupCommonOption
	require.Error(t, json.Unmarshal([]byte(`{"network":"icmp"}`), &options))
}

func TestCollectProviderOutboundsAppliesMemberFilter(t *testing.T) {
	t.Parallel()
	filter, err := newMemberFilter(context.Background(), parseGroupOptions(t, `{"network":"udp"}`))
	require.NoError(t, err)
	provider := &filterTestProvider{outbounds: members}
	tags, _, _, err := collectProviderOutbounds("p", nil, nil,
		map[string]adapter.Provider{"p": provider}, []string{"p"}, nil, filter)
	require.NoError(t, err)
	require.Equal(t, []string{"p/HK vless", "p/JP hy2", "p/JP wg"}, tags)
}

type filterTestProvider struct {
	adapter.Provider
	outbounds []adapter.Outbound
}

func (p *filterTestProvider) Outbounds() []adapter.Outbound { return p.outbounds }

func TestMemberFilterValidatesInsideRegistry(t *testing.T) {
	t.Parallel()
	registry := outbound.NewRegistry()
	RegisterURLTest(registry)
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), registry)
	done := make(chan error, 1)
	go func() {
		_, err := registry.CreateOutbound(ctx, nil, nil, "group", C.TypeURLTest, &option.URLTestOutboundOptions{
			GroupCommonOption: option.GroupCommonOption{Providers: []string{"p"}, IncludeType: []string{"bogus"}},
		})
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorContains(t, err, "include_type: unknown outbound type: bogus")
	case <-time.After(5 * time.Second):
		t.Fatal("group constructor deadlocked on the outbound registry")
	}
}
