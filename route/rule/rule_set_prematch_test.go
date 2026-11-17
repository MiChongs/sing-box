package rule

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func preMatchPlanFromJSON(t *testing.T, content string) adapter.RuleSetPreMatchPlan {
	t.Helper()
	options, err := json.UnmarshalExtended[[]option.HeadlessRule]([]byte(content))
	require.NoError(t, err)
	rules := make([]adapter.HeadlessRule, 0, len(options))
	for _, ruleOptions := range options {
		rule, err := NewHeadlessRule(context.Background(), ruleOptions)
		require.NoError(t, err)
		rules = append(rules, rule)
	}
	return buildPreMatchPlan(rules)
}

func planContains(plan adapter.RuleSetPreMatchPlan, address string) bool {
	addr := netip.MustParseAddr(address)
	for _, set := range plan.DestinationIPSets {
		if set.Contains(addr) {
			return true
		}
	}
	return false
}

func TestPreMatchPlan(t *testing.T) {
	t.Parallel()
	t.Run("pure ip", func(t *testing.T) {
		plan := preMatchPlanFromJSON(t, `[{"ip_cidr": ["10.0.0.0/8", "fd00::/8"]}]`)
		require.True(t, planContains(plan, "10.1.2.3"))
		require.True(t, planContains(plan, "fd00::1"))
		require.Nil(t, plan.MatchDomain)
		require.False(t, plan.Residual)
		require.False(t, plan.NeedDomain)
	})
	t.Run("domain and ip are one group", func(t *testing.T) {
		plan := preMatchPlanFromJSON(t, `[{"domain_suffix": ["example.com"], "domain_keyword": ["ads"], "domain_regex": ["^cdn[0-9]+\\.net$"], "ip_cidr": ["1.1.1.0/24"]}]`)
		require.True(t, planContains(plan, "1.1.1.1"))
		require.NotNil(t, plan.MatchDomain)
		require.True(t, plan.MatchDomain("www.example.com"))
		require.True(t, plan.MatchDomain("myads.org"))
		require.True(t, plan.MatchDomain("cdn12.net"))
		require.False(t, plan.MatchDomain("example.org"))
		require.False(t, plan.MatchDomain(""))
		require.False(t, plan.Residual)
		require.True(t, plan.NeedDomain)
	})
	t.Run("combined conditions stay in userspace", func(t *testing.T) {
		plan := preMatchPlanFromJSON(t, `[
			{"ip_cidr": ["192.0.2.0/24"], "port": [443]},
			{"domain": ["a.example"], "network": ["tcp"]},
			{"ip_cidr": ["198.51.100.0/24"], "source_ip_cidr": ["10.0.0.0/8"]},
			{"process_name": ["curl"]}
		]`)
		require.Empty(t, plan.DestinationIPSets)
		require.Nil(t, plan.MatchDomain)
		require.True(t, plan.Residual)
		require.True(t, plan.NeedDomain)
	})
	t.Run("invert", func(t *testing.T) {
		plan := preMatchPlanFromJSON(t, `[{"ip_cidr": ["10.0.0.0/8"], "invert": true}]`)
		require.Empty(t, plan.DestinationIPSets)
		require.True(t, plan.Residual)
	})
	t.Run("logical", func(t *testing.T) {
		plan := preMatchPlanFromJSON(t, `[
			{"type": "logical", "mode": "or", "rules": [{"ip_cidr": ["10.0.0.0/8"]}, {"domain": ["b.example"]}]},
			{"type": "logical", "mode": "and", "rules": [{"ip_cidr": ["172.16.0.0/12"]}, {"domain": ["c.example"]}]}
		]`)
		require.True(t, planContains(plan, "10.0.0.1"))
		require.False(t, planContains(plan, "172.16.0.1"))
		require.True(t, plan.MatchDomain("b.example"))
		require.False(t, plan.MatchDomain("c.example"))
		require.True(t, plan.Residual)
		require.True(t, plan.NeedDomain)
	})
}
