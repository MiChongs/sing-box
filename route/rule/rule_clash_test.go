package rule

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/ipset"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

type clashRuleCase struct {
	name     string
	config   string
	ruleType string
	payload  string
	proxy    string
}

func TestClashRouteRule(t *testing.T) {
	t.Parallel()
	for _, testCase := range []clashRuleCase{
		{
			name:     "single value",
			config:   `{"domain_suffix": "google.com", "outbound": "proxy"}`,
			ruleType: "DomainSuffix",
			payload:  "google.com",
			proxy:    "proxy",
		},
		{
			name:     "same type values merged",
			config:   `{"domain_suffix": ["google.com", "youtube.com", "github.com"], "outbound": "proxy"}`,
			ruleType: "DomainSuffix",
			payload:  "google.com, youtube.com, github.com",
			proxy:    "proxy",
		},
		{
			name:     "rule set",
			config:   `{"rule_set": "geosite-cn", "outbound": "direct"}`,
			ruleType: "RuleSet",
			payload:  "geosite-cn",
			proxy:    "direct",
		},
		{
			name:     "mixed types in destination address group",
			config:   `{"domain": "a.com", "domain_suffix": ["b.com", ".c.com"], "domain_keyword": "kw", "ip_cidr": ["1.1.1.1/32", "10.0.0.0/8"], "ip_is_private": true, "outbound": "proxy"}`,
			ruleType: "OR",
			payload:  "Domain(a.com) | DomainSuffix(b.com, .c.com) | DomainKeyword(kw) | IPCIDR(1.1.1.1/32, 10.0.0.0/8) | GeoIP(lan)",
			proxy:    "proxy",
		},
		{
			name:     "joinable values and port ranges",
			config:   `{"inbound": ["mixed-in", "tun-in"], "network": "udp", "port": [80, 443], "port_range": ["1000:2000", "3000:"], "outbound": "direct"}`,
			ruleType: "AND",
			payload:  "InName(mixed-in, tun-in) & Network(udp) & DstPort(80, 443, 1000-2000, 3000-65535)",
			proxy:    "direct",
		},
		{
			name:     "source groups",
			config:   `{"source_ip_cidr": "10.0.0.0/8", "source_ip_is_private": true, "source_port": 1234, "outbound": "proxy"}`,
			ruleType: "AND",
			payload:  "(SrcIPCIDR(10.0.0.0/8) | SrcGeoIP(lan)) & SrcPort(1234)",
			proxy:    "proxy",
		},
		{
			name:     "value separators",
			config:   `{"process_name": ["curl", "wget"], "user_id": [1000, 1001], "outbound": "proxy"}`,
			ruleType: "AND",
			payload:  "ProcessName(curl, wget) & Uid(1000, 1001)",
			proxy:    "proxy",
		},
		{
			name:     "invert",
			config:   `{"rule_set": ["geosite-cn", "geoip-cn"], "invert": true, "action": "reject", "method": "drop"}`,
			ruleType: "NOT",
			payload:  "RuleSet(geosite-cn, geoip-cn)",
			proxy:    "REJECT-DROP",
		},
		{
			name:     "logical and flattened",
			config:   `{"type": "logical", "mode": "and", "rules": [{"protocol": "quic"}, {"network": "udp", "port": 443}], "action": "reject"}`,
			ruleType: "AND",
			payload:  "Protocol(quic) & Network(udp) & DstPort(443)",
			proxy:    "REJECT",
		},
		{
			name:     "logical or flattened and merged",
			config:   `{"type": "logical", "mode": "or", "rules": [{"rule_set": ["cn", "private"]}, {"domain_keyword": ["ntp", "time"]}, {"domain_suffix": ["mi.com", "miui.com"]}, {"domain": "px.ucweb.com"}, {"domain_suffix": "cygames.cc"}], "outbound": "proxy"}`,
			ruleType: "OR",
			payload:  "RuleSet(cn, private) | DomainKeyword(ntp, time) | DomainSuffix(mi.com, miui.com, cygames.cc) | Domain(px.ucweb.com)",
			proxy:    "proxy",
		},
		{
			name:     "logical keeps nested different operator",
			config:   `{"type": "logical", "mode": "or", "rules": [{"domain_suffix": "a.com", "network": "tcp"}, {"domain_suffix": "b.com"}], "outbound": "proxy"}`,
			ruleType: "OR",
			payload:  "(Network(tcp) & DomainSuffix(a.com)) | DomainSuffix(b.com)",
			proxy:    "proxy",
		},
		{
			name:     "logical invert",
			config:   `{"type": "logical", "mode": "or", "rules": [{"clash_mode": "direct"}, {"domain_regex": "^ad\\."}], "invert": true, "outbound": "proxy"}`,
			ruleType: "NOT",
			payload:  "(ClashMode(direct) | DomainRegex(^ad\\.))",
			proxy:    "proxy",
		},
		{
			name:     "nested invert and flag",
			config:   `{"type": "logical", "mode": "and", "rules": [{"network_is_expensive": true}, {"port": 443, "invert": true}], "outbound": "direct"}`,
			ruleType: "AND",
			payload:  "NetworkIsExpensive & !DstPort(443)",
			proxy:    "direct",
		},
		{
			name:     "match all",
			config:   `{"action": "sniff"}`,
			ruleType: "Match",
			payload:  "",
			proxy:    "SNIFF",
		},
		{
			name:     "hijack dns",
			config:   `{"protocol": "dns", "action": "hijack-dns"}`,
			ruleType: "Protocol",
			payload:  "dns",
			proxy:    "HIJACK-DNS",
		},
		{
			name:     "route options",
			config:   `{"domain": "example.com", "action": "route-options", "tls_fragment": true}`,
			ruleType: "Domain",
			payload:  "example.com",
			proxy:    "ROUTE-OPTIONS",
		},
		{
			name:     "resolve",
			config:   `{"ip_version": 6, "action": "resolve", "server": "local"}`,
			ruleType: "IPVersion",
			payload:  "6",
			proxy:    "RESOLVE",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var options option.Rule
			require.NoError(t, json.UnmarshalContext(context.Background(), []byte(testCase.config), &options))
			rule, err := NewRule(context.Background(), log.NewNOPFactory().NewLogger("test"), options, true)
			require.NoError(t, err)
			requireClashRule(t, testCase, rule)
		})
	}
}

func TestClashDNSRule(t *testing.T) {
	t.Parallel()
	for _, testCase := range []clashRuleCase{
		{
			name:     "route",
			config:   `{"query_type": ["A", "AAAA"], "domain_suffix": "cn", "server": "local"}`,
			ruleType: "AND",
			payload:  "QueryType(A, AAAA) & DomainSuffix(cn)",
			proxy:    "local",
		},
		{
			name:     "predefined",
			config:   `{"rule_set": "geosite-category-ads-all", "action": "predefined", "rcode": "NXDOMAIN"}`,
			ruleType: "RuleSet",
			payload:  "geosite-category-ads-all",
			proxy:    "PREDEFINED",
		},
		{
			name:     "evaluate",
			config:   `{"domain": "example.com", "action": "evaluate", "server": "remote"}`,
			ruleType: "Domain",
			payload:  "example.com",
			proxy:    "remote",
		},
		{
			name:     "reject",
			config:   `{"domain_keyword": "ads", "action": "reject"}`,
			ruleType: "DomainKeyword",
			payload:  "ads",
			proxy:    "REJECT",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var options option.DNSRule
			require.NoError(t, json.UnmarshalContext(context.Background(), []byte(testCase.config), &options))
			rule, err := NewDNSRule(context.Background(), log.NewNOPFactory().NewLogger("test"), options, true, false)
			require.NoError(t, err)
			requireClashRule(t, testCase, rule)
		})
	}
}

func requireClashRule(t *testing.T, testCase clashRuleCase, rule adapter.Rule) {
	t.Helper()
	ruleType, payload := ClashRule(rule)
	require.Equal(t, testCase.ruleType, ruleType)
	require.Equal(t, testCase.payload, payload)
	require.Equal(t, testCase.proxy, ClashProxy(rule.Action()))
	// 结果缓存后保持一致
	cachedType, cachedPayload := ClashRule(rule)
	require.Equal(t, ruleType, cachedType)
	require.Equal(t, payload, cachedPayload)
}

func TestClashRuleItemsWithoutRawValues(t *testing.T) {
	t.Parallel()
	// 规则集条目不保留配置原值，退回从匹配器还原
	domainItem, err := NewDomainItem([]string{"b.com", "a.com"}, []string{"c.com"}, C.DomainMatchStrategyAsIS)
	require.NoError(t, err)
	require.Equal(t, []clashRule{
		{ruleType: "Domain", values: []string{"a.com", "b.com"}},
		{ruleType: "DomainSuffix", values: []string{"c.com"}},
	}, clashItemRules(domainItem))
	require.Equal(t, []clashRule{
		{ruleType: "IPCIDR", values: []string{"10.0.0.0/8"}},
	}, clashItemRules(NewRawIPCIDRItem(false, mustIPSet(t, "10.0.0.0/8"))))
}

func TestClashRuleMergeKeepsSubRules(t *testing.T) {
	t.Parallel()
	// 合并同类型的值时不得写入子规则（及配置）共用的底层数组
	domainSuffixes := make([]string, 1, 4)
	domainSuffixes[0] = "a.com"
	options := option.Rule{
		Type: C.RuleTypeLogical,
		LogicalOptions: option.LogicalRule{
			RawLogicalRule: option.RawLogicalRule{
				Mode: C.LogicalTypeOr,
				Rules: []option.Rule{
					{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RawDefaultRule: option.RawDefaultRule{DomainSuffix: domainSuffixes}}},
					{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RawDefaultRule: option.RawDefaultRule{DomainSuffix: []string{"b.com"}}}},
				},
			},
			RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "proxy"}},
		},
	}
	rule, err := NewRule(context.Background(), log.NewNOPFactory().NewLogger("test"), options, true)
	require.NoError(t, err)
	ruleType, payload := ClashRule(rule)
	require.Equal(t, "DomainSuffix", ruleType)
	require.Equal(t, "a.com, b.com", payload)
	require.Empty(t, domainSuffixes[:2][1])
	_, subPayload := ClashRule(rule.(*LogicalRule).rules[0])
	require.Equal(t, "a.com", subPayload)
}

func mustIPSet(t *testing.T, prefix string) *ipset.Set {
	t.Helper()
	var builder netipx.IPSetBuilder
	builder.AddPrefix(netip.MustParsePrefix(prefix))
	ipSet, err := builder.IPSet()
	require.NoError(t, err)
	return ipset.FromIPSet(ipSet)
}
