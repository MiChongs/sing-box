package clashapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

type testRulesRouter struct {
	adapter.Router
	rules []adapter.Rule
}

func (r *testRulesRouter) Rules() []adapter.Rule {
	return r.rules
}

func (r *testRulesRouter) Rule(uuid string) (adapter.Rule, bool) {
	for _, rule := range r.rules {
		if rule.UUID() == uuid {
			return rule, true
		}
	}
	return nil, false
}

type testRulesDNSRouter struct {
	adapter.DNSRouter
	rules []adapter.DNSRule
}

func (r *testRulesDNSRouter) Rules() []adapter.DNSRule {
	return r.rules
}

func newTestRuleRouters(t *testing.T) (*testRulesRouter, *testRulesDNSRouter) {
	logger := log.NewNOPFactory().NewLogger("test")
	dnsRule, err := R.NewDNSRule(context.Background(), logger, option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{Domain: badoption.Listable[string]{"example.com"}},
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{Server: "local"},
			},
		},
	}, false, false)
	require.NoError(t, err)
	var routeRules []adapter.Rule
	for _, outbound := range []string{"direct", "proxy"} {
		routeRule, err := R.NewRule(context.Background(), logger, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{Domain: badoption.Listable[string]{outbound + ".example.com"}},
				RuleAction: option.RuleAction{
					Action:       C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{Outbound: outbound},
				},
			},
		}, false)
		require.NoError(t, err)
		routeRules = append(routeRules, routeRule)
	}
	return &testRulesRouter{rules: routeRules}, &testRulesDNSRouter{rules: []adapter.DNSRule{dnsRule}}
}

type testRuleExtra struct {
	Disabled  bool      `json:"disabled"`
	HitCount  uint64    `json:"hitCount"`
	HitAt     time.Time `json:"hitAt"`
	MissCount uint64    `json:"missCount"`
	MissAt    time.Time `json:"missAt"`
}

type testRule struct {
	Index    int            `json:"index"`
	Type     string         `json:"type"`
	Payload  string         `json:"payload"`
	Proxy    string         `json:"proxy"`
	Size     int            `json:"size"`
	Extra    *testRuleExtra `json:"extra"`
	Disabled bool           `json:"disabled"`
	UUID     string         `json:"uuid"`
}

func fetchTestRules(t *testing.T, handler http.Handler) []testRule {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	var response struct {
		Rules []testRule `json:"rules"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	return response.Rules
}

func TestGetRulesStatistics(t *testing.T) {
	t.Parallel()
	router, dnsRouter := newTestRuleRouters(t)
	handler := ruleRouter(router, dnsRouter)

	rules := fetchTestRules(t, handler)
	require.Len(t, rules, 3)
	for index, rule := range rules {
		require.Equal(t, index, rule.Index)
		require.Equal(t, -1, rule.Size)
		require.NotNil(t, rule.Extra)
		require.Zero(t, rule.Extra.HitCount)
		require.Zero(t, rule.Extra.MissCount)
		// 与 mihomo 一致：未命中过时为 Unix 纪元
		require.True(t, rule.Extra.HitAt.Equal(time.Unix(0, 0)))
	}
	// 与 mihomo 一致先列路由规则，DNS 规则接在其后
	require.Equal(t, router.rules[0].UUID(), rules[0].UUID)
	require.Equal(t, router.rules[1].UUID(), rules[1].UUID)
	require.Equal(t, dnsRouter.rules[0].UUID(), rules[2].UUID)

	before := time.Now().Round(0).Truncate(time.Second)
	router.rules[0].Hit()
	router.rules[0].Hit()
	router.rules[0].Miss()
	dnsRouter.rules[0].Miss()
	rules = fetchTestRules(t, handler)
	require.Equal(t, uint64(2), rules[0].Extra.HitCount)
	require.Equal(t, uint64(1), rules[0].Extra.MissCount)
	require.False(t, rules[0].Extra.HitAt.Before(before))
	require.False(t, rules[0].Extra.MissAt.Before(before))
	require.Equal(t, uint64(0), rules[1].Extra.HitCount)
	require.Equal(t, uint64(0), rules[2].Extra.HitCount)
	require.Equal(t, uint64(1), rules[2].Extra.MissCount)
}

func TestGetRulesMihomoFormat(t *testing.T) {
	t.Parallel()
	router, dnsRouter := newTestRuleRouters(t)
	rules := fetchTestRules(t, ruleRouter(router, dnsRouter))
	require.Len(t, rules, 3)
	for index, expected := range []struct{ ruleType, payload, proxy string }{
		{"Domain", "direct.example.com", "direct"},
		{"Domain", "proxy.example.com", "proxy"},
		{"Domain", "example.com", "local"},
	} {
		require.Equal(t, expected.ruleType, rules[index].Type)
		require.Equal(t, expected.payload, rules[index].Payload)
		require.Equal(t, expected.proxy, rules[index].Proxy)
	}
}

func TestDisableRulesByIndex(t *testing.T) {
	t.Parallel()
	router, dnsRouter := newTestRuleRouters(t)
	handler := ruleRouter(router, dnsRouter)

	patch := func(body string) int {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPatch, "/disable", strings.NewReader(body)))
		return recorder.Code
	}
	require.Equal(t, http.StatusNoContent, patch(`{"1": true, "2": true, "9": true, "-1": true}`))
	require.False(t, router.rules[0].Disabled())
	require.True(t, router.rules[1].Disabled())
	require.True(t, dnsRouter.rules[0].Disabled())
	rules := fetchTestRules(t, handler)
	require.False(t, rules[0].Extra.Disabled)
	require.True(t, rules[1].Extra.Disabled)
	require.True(t, rules[1].Disabled)
	require.True(t, rules[2].Extra.Disabled)

	require.Equal(t, http.StatusNoContent, patch(`{"2": false}`))
	require.False(t, dnsRouter.rules[0].Disabled())
	require.Equal(t, http.StatusNoContent, patch(`{}`))
	require.Equal(t, http.StatusBadRequest, patch(`not json`))

	// reF1nd 的按 UUID 切换接口保持可用
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/"+router.rules[0].UUID(), nil))
	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.True(t, router.rules[0].Disabled())
}
