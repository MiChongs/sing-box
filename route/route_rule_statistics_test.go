package route

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"

	"github.com/stretchr/testify/require"
)

type statisticsTestRule struct {
	adapter.Rule
	action   adapter.RuleAction
	match    bool
	disabled bool
	hits     int
	misses   int
}

func (r *statisticsTestRule) Match(*adapter.InboundContext) bool { return r.match }

func (r *statisticsTestRule) Disabled() bool { return r.disabled }

func (r *statisticsTestRule) Action() adapter.RuleAction { return r.action }

func (*statisticsTestRule) String() string { return "" }

func (r *statisticsTestRule) Hit() { r.hits++ }

func (r *statisticsTestRule) Miss() { r.misses++ }

func requireRuleStatistics(t *testing.T, rule *statisticsTestRule, hits int, misses int) {
	t.Helper()
	require.Equal(t, hits, rule.hits, "hits")
	require.Equal(t, misses, rule.misses, "misses")
}

// matchRule 对每条参与求值的顶层规则计一次命中或未命中；禁用规则与
// 首个最终规则之后的规则不计数（同 mihomo tunnel.match）。
func TestMatchRuleStatistics(t *testing.T) {
	router, metadata := newPreMatchQUICRouter(t, time.Minute)
	router.outbound = &testL3OutboundManager{outbounds: map[string]adapter.Outbound{}}
	miss := &statisticsTestRule{action: &R.RuleActionRoute{Outbound: "miss"}}
	disabled := &statisticsTestRule{action: &R.RuleActionRoute{Outbound: "disabled"}, match: true, disabled: true}
	sniff := &statisticsTestRule{action: &R.RuleActionSniff{}, match: true}
	hit := &statisticsTestRule{action: &R.RuleActionRoute{Outbound: "hit"}, match: true}
	after := &statisticsTestRule{action: &R.RuleActionRoute{Outbound: "after"}, match: true}
	router.rules = []adapter.Rule{miss, disabled, sniff, hit, after}

	matched, _, _, _, err := router.matchRule(context.Background(), &metadata, nil, nil)
	require.NoError(t, err)
	require.Same(t, hit, matched)
	requireRuleStatistics(t, miss, 0, 1)
	requireRuleStatistics(t, disabled, 0, 0)
	requireRuleStatistics(t, sniff, 1, 0)
	requireRuleStatistics(t, hit, 1, 0)
	requireRuleStatistics(t, after, 0, 0)
}

// PreMatch 给出最终裁决时计数；返回 Continue 时不计数，留给随后的 matchRule，
// 避免同一连接被计两次。
func TestPreMatchRuleStatistics(t *testing.T) {
	t.Run("terminal verdict", func(t *testing.T) {
		router, metadata := newPreMatchQUICRouter(t, time.Minute)
		router.outbound = &testL3OutboundManager{outbounds: map[string]adapter.Outbound{}}
		miss := &statisticsTestRule{action: &R.RuleActionRoute{Outbound: "miss"}}
		bypass := &statisticsTestRule{action: &R.RuleActionBypass{}, match: true}
		after := &statisticsTestRule{action: &R.RuleActionRoute{Outbound: "after"}, match: true}
		router.rules = []adapter.Rule{miss, bypass, after}
		require.Equal(t, adapter.PreMatchBypass, router.PreMatch(metadata, nil).Action)
		requireRuleStatistics(t, miss, 0, 1)
		requireRuleStatistics(t, bypass, 1, 0)
		requireRuleStatistics(t, after, 0, 0)
	})
	t.Run("more rules than inline buffer", func(t *testing.T) {
		router, metadata := newPreMatchQUICRouter(t, time.Minute)
		router.outbound = &testL3OutboundManager{outbounds: map[string]adapter.Outbound{}}
		var misses []*statisticsTestRule
		router.rules = nil
		for range 100 {
			miss := &statisticsTestRule{action: &R.RuleActionRoute{Outbound: "miss"}}
			misses = append(misses, miss)
			router.rules = append(router.rules, miss)
		}
		bypass := &statisticsTestRule{action: &R.RuleActionBypass{}, match: true}
		router.rules = append(router.rules, bypass)
		require.Equal(t, adapter.PreMatchBypass, router.PreMatch(metadata, nil).Action)
		for _, miss := range misses {
			requireRuleStatistics(t, miss, 0, 1)
		}
		requireRuleStatistics(t, bypass, 1, 0)
	})
	t.Run("continue then match", func(t *testing.T) {
		router, metadata := newPreMatchQUICRouter(t, time.Minute)
		router.outbound = &testL3OutboundManager{outbounds: map[string]adapter.Outbound{}}
		miss := &statisticsTestRule{action: &R.RuleActionRoute{Outbound: "miss"}}
		route := &statisticsTestRule{action: &R.RuleActionRoute{Outbound: "missing"}, match: true}
		router.rules = []adapter.Rule{miss, route}
		require.Equal(t, adapter.PreMatchContinue, router.PreMatch(metadata, nil).Action)
		requireRuleStatistics(t, miss, 0, 0)
		requireRuleStatistics(t, route, 0, 0)
		matched, _, _, _, err := router.matchRule(context.Background(), &metadata, nil, nil)
		require.NoError(t, err)
		require.Same(t, route, matched)
		requireRuleStatistics(t, miss, 0, 1)
		requireRuleStatistics(t, route, 1, 0)
	})
}
