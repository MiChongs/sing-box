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
			name:     "rule set",
			config:   `{"rule_set": "geosite-cn", "outbound": "direct"}`,
			ruleType: "RuleSet",
			payload:  "geosite-cn",
			proxy:    "direct",
		},
		{
			name:     "destination address group in config order",
			config:   `{"domain": "a.com", "domain_suffix": ["b.com", ".c.com"], "domain_keyword": "kw", "ip_cidr": "1.1.1.1/32", "ip_is_private": true, "outbound": "proxy"}`,
			ruleType: "OR",
			payload:  "((Domain,a.com) || (DomainSuffix,b.com) || (DomainSuffix,.c.com) || (DomainKeyword,kw) || (IPCIDR,1.1.1.1/32) || (GeoIP,lan))",
			proxy:    "proxy",
		},
		{
			name:     "joinable values and port ranges",
			config:   `{"inbound": ["mixed-in", "tun-in"], "network": "udp", "port": [80, 443], "port_range": ["1000:2000", "3000:"], "outbound": "direct"}`,
			ruleType: "AND",
			payload:  "((InName,mixed-in/tun-in) && (Network,udp) && (DstPort,80/443/1000-2000/3000-65535))",
			proxy:    "direct",
		},
		{
			name:     "source groups",
			config:   `{"source_ip_cidr": "10.0.0.0/8", "source_ip_is_private": true, "source_port": 1234, "outbound": "proxy"}`,
			ruleType: "AND",
			payload:  "((OR,((SrcIPCIDR,10.0.0.0/8) || (SrcGeoIP,lan))) && (SrcPort,1234))",
			proxy:    "proxy",
		},
		{
			name:     "non joinable values expand to OR",
			config:   `{"process_name": ["curl", "wget"], "user_id": [1000, 1001], "outbound": "proxy"}`,
			ruleType: "AND",
			payload:  "((OR,((ProcessName,curl) || (ProcessName,wget))) && (Uid,1000/1001))",
			proxy:    "proxy",
		},
		{
			name:     "invert",
			config:   `{"rule_set": ["geosite-cn", "geoip-cn"], "invert": true, "action": "reject", "method": "drop"}`,
			ruleType: "NOT",
			payload:  "(!(OR,((RuleSet,geosite-cn) || (RuleSet,geoip-cn))))",
			proxy:    "REJECT-DROP",
		},
		{
			name:     "logical",
			config:   `{"type": "logical", "mode": "and", "rules": [{"protocol": "quic"}, {"network": "udp", "port": 443}], "action": "reject"}`,
			ruleType: "AND",
			payload:  "((Protocol,quic) && (AND,((Network,udp) && (DstPort,443))))",
			proxy:    "REJECT",
		},
		{
			name:     "logical invert",
			config:   `{"type": "logical", "mode": "or", "rules": [{"clash_mode": "direct"}, {"domain_regex": "^ad\\."}], "invert": true, "outbound": "proxy"}`,
			ruleType: "NOT",
			payload:  "(!(OR,((ClashMode,direct) || (DomainRegex,^ad\\.))))",
			proxy:    "proxy",
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
			payload:  "((QueryType,A/AAAA) && (DomainSuffix,cn))",
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
		{"Domain", "a.com"},
		{"Domain", "b.com"},
		{"DomainSuffix", "c.com"},
	}, clashItemRules(domainItem))
	require.Equal(t, []clashRule{{"IPCIDR", "10.0.0.0/8"}}, clashItemRules(NewRawIPCIDRItem(false, mustIPSet(t, "10.0.0.0/8"))))
}

func mustIPSet(t *testing.T, prefix string) *ipset.Set {
	t.Helper()
	var builder netipx.IPSetBuilder
	builder.AddPrefix(netip.MustParsePrefix(prefix))
	ipSet, err := builder.IPSet()
	require.NoError(t, err)
	return ipset.FromIPSet(ipSet)
}
