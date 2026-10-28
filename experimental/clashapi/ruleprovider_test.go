package clashapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

type ruleProviderTestRuleSet struct {
	adapter.RuleSet
}

func (r *ruleProviderTestRuleSet) Name() string {
	return "remote"
}

func (r *ruleProviderTestRuleSet) Type() string {
	return constant.RuleSetTypeRemote
}

func (r *ruleProviderTestRuleSet) Format() string {
	return constant.RuleSetFormatSource
}

func (r *ruleProviderTestRuleSet) RuleCount() uint64 {
	return 1
}

func (r *ruleProviderTestRuleSet) UpdatedTime() time.Time {
	return time.Unix(0, 0).UTC()
}

func TestGetRuleProviderContentType(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/providers/rules/remote", nil)
	request = request.WithContext(context.WithValue(request.Context(), CtxKeyProvider, &ruleProviderTestRuleSet{}))
	response := httptest.NewRecorder()

	getRuleProvider(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "application/json", response.Header().Get("Content-Type"))
	require.JSONEq(t, `{
		"name": "remote",
		"type": "Rule",
		"vehicleType": "HTTP",
		"behavior": "Classical",
		"format": "JsonRule",
		"ruleCount": 1,
		"updatedAt": "1970-01-01T00:00:00+00:00"
	}`, response.Body.String())
}

func TestRuleSetInfoMihomoShape(t *testing.T) {
	t.Parallel()

	ruleSet, err := R.NewLocalRuleSet(context.Background(), logger.NOP(), "cn", option.RuleSet{
		Type: constant.RuleSetTypeInline,
		InlineOptions: option.PlainRuleSet{Rules: []option.HeadlessRule{{
			Type: constant.RuleTypeDefault,
			DefaultOptions: option.DefaultHeadlessRule{
				Domain:       []string{"a.cn", "b.cn"},
				DomainSuffix: []string{"c.cn"},
			},
		}}},
	})
	require.NoError(t, err)
	require.False(t, ruleSet.UpdatedTime().IsZero())
	info := ruleSetInfo(ruleSet)
	info.Remove("updatedAt")
	content, err := info.MarshalJSON()
	require.NoError(t, err)
	require.JSONEq(t, `{
		"name": "cn",
		"type": "Rule",
		"vehicleType": "Inline",
		"behavior": "Domain",
		"ruleCount": 3
	}`, string(content))
}
