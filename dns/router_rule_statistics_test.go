package dns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json/badoption"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func requireDNSRuleStatistics(t *testing.T, rule adapter.DNSRule, hits uint64, misses uint64) {
	t.Helper()
	require.Equal(t, hits, rule.HitCount(), "hits of %s", rule)
	require.Equal(t, misses, rule.MissCount(), "misses of %s", rule)
}

func domainRouteRule(domain string, server string) option.DNSRule {
	rule := routeRule(server, false)
	rule.DefaultOptions.Domain = badoption.Listable[string]{domain}
	return rule
}

func TestExchangeWithRulesStatistics(t *testing.T) {
	t.Parallel()
	transport := &fakeDNSTransport{tag: "x", immediate: true, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.1")}
	router := raceTestRouter(t, transport)
	rules := raceTestRules(t, []option.DNSRule{
		domainRouteRule("other.org", "x"),
		domainRouteRule("race.example.org", "x"),
		domainRouteRule("race.example.org", "x"),
		domainRouteRule("race.example.org", "x"),
	})
	rules[1].SetDisabled(true)
	result := raceTestExchange(router, rules)
	require.NoError(t, result.err)
	requireDNSRuleStatistics(t, rules[0], 0, 1)
	requireDNSRuleStatistics(t, rules[1], 0, 0)
	requireDNSRuleStatistics(t, rules[2], 1, 0)
	requireDNSRuleStatistics(t, rules[3], 0, 0)
}

// drain 挂起恢复后 walk 会对同一条规则再次 Match，每次查询仍只计一次；
// race 规则在 sweep 中求值并计数。
func TestExchangeWithRulesStatisticsAcrossSuspension(t *testing.T) {
	t.Parallel()
	transportX := &fakeDNSTransport{tag: "x", delay: 50 * time.Millisecond, exchangeErr: context.DeadlineExceeded}
	transportY := &fakeDNSTransport{tag: "y", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, transportX, transportY)
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", true),
		respondRule("x", true, true),
		evaluateRule("y", "y", false),
		respondRule("y", false, true),
	})
	result := raceTestExchange(router, rules)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, result.response))
	requireDNSRuleStatistics(t, rules[0], 1, 0)
	requireDNSRuleStatistics(t, rules[1], 0, 1)
	requireDNSRuleStatistics(t, rules[2], 1, 0)
	requireDNSRuleStatistics(t, rules[3], 1, 0)
}

func testIPCIDR(prefix string) badoption.Listable[*badoption.Prefixable] {
	value := badoption.Prefixable(netip.MustParsePrefix(prefix))
	return badoption.Listable[*badoption.Prefixable]{&value}
}

func legacyTestRules(t *testing.T, rawRules []option.DNSRule) []adapter.DNSRule {
	rules := make([]adapter.DNSRule, 0, len(rawRules))
	for _, rawRule := range rawRules {
		rule, err := R.NewDNSRule(context.Background(), log.NewNOPFactory().Logger(), rawRule, true, true)
		require.NoError(t, err)
		rules = append(rules, rule)
	}
	return rules
}

// legacy 模式下带地址限制的规则在响应通过 MatchAddressLimit 后才算命中，
// 响应被拒绝计未命中并继续匹配后续规则。
func TestExchangeLegacyAddressLimitStatistics(t *testing.T) {
	t.Parallel()
	transportX := &fakeDNSTransport{tag: "x", immediate: true, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.1")}
	transportY := &fakeDNSTransport{tag: "y", immediate: true, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, transportX, transportY)
	// domain 与 ip_cidr 同属目标地址组（OR），地址限制规则只写 ip_cidr
	rejected := routeRule("x", false)
	rejected.DefaultOptions.IPCIDR = testIPCIDR("10.0.0.0/8")
	accepted := routeRule("y", false)
	accepted.DefaultOptions.IPCIDR = testIPCIDR("192.0.2.0/24")
	rules := legacyTestRules(t, []option.DNSRule{
		domainRouteRule("other.org", "x"),
		rejected,
		accepted,
		domainRouteRule("race.example.org", "x"),
	})
	require.True(t, rules[1].WithAddressLimit())

	message := new(mDNS.Msg)
	message.SetQuestion("race.example.org.", mDNS.TypeA)
	metadata := &adapter.InboundContext{Domain: "race.example.org", QueryType: mDNS.TypeA}
	ctx := adapter.WithContext(context.Background(), metadata)
	response, transport, err := router.exchangeLegacy(ctx, &dnsExchangeContext{ctx: ctx, rules: rules, legacyDNSMode: true, metadata: metadata}, message, adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Same(t, transportY, transport)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, response))
	requireDNSRuleStatistics(t, rules[0], 0, 1)
	requireDNSRuleStatistics(t, rules[1], 0, 1)
	requireDNSRuleStatistics(t, rules[2], 1, 0)
	requireDNSRuleStatistics(t, rules[3], 0, 0)
}

func TestLookupLegacyAddressLimitStatistics(t *testing.T) {
	t.Parallel()
	transportX := &fakeDNSTransport{tag: "x", immediate: true, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.1")}
	transportY := &fakeDNSTransport{tag: "y", immediate: true, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, transportX, transportY)
	rejected := routeRule("x", false)
	rejected.DefaultOptions.IPCIDR = testIPCIDR("10.0.0.0/8")
	router.rules = legacyTestRules(t, []option.DNSRule{
		rejected,
		domainRouteRule("race.example.org", "y"),
	})
	router.legacyDNSMode = true
	addresses, err := router.Lookup(context.Background(), "race.example.org", adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.2")}, addresses)
	requireDNSRuleStatistics(t, router.rules[0], 0, 1)
	requireDNSRuleStatistics(t, router.rules[1], 1, 0)
}
