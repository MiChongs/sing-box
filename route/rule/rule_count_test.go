package rule

import (
	"bytes"
	"context"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

const ruleCountTestSource = `{"version":5,"rules":[
	{"domain":["a.com","b.com"],"domain_suffix":["c.com",".d.com"]},
	{"domain_keyword":["kw"],"domain_regex":["^x\\.com$"]},
	{"ip_cidr":["1.0.0.0/24","2.0.0.0/16","3.0.0.0/16","2001:db8::/32"]},
	{"source_ip_cidr":["10.0.0.0/8"]},
	{"port":[80,443],"port_range":["1000:2000"],"source_port":[53]},
	{"process_name":["a","b"],"process_path":["/bin/c"],"process_path_regex":["^/usr/"]},
	{"package_name":["p.a"],"package_name_regex":["^p\\."]},
	{"network":["tcp"],"query_type":["A","AAAA"]},
	{"type":"logical","mode":"or","rules":[{"domain":["e.com"]},{"domain_suffix":["f.com","g.com"]}]}
]}`

// 2+2 +1+1 +4 +1 +2+1+1 +2+1+1 +1+1 +1+2 +1+2
const ruleCountTestExpected = 27

func newRuleCountTestRuleSet(format string) *LocalRuleSet {
	return &LocalRuleSet{
		abstractRuleSet: abstractRuleSet{
			ctx:    context.Background(),
			tag:    "count",
			format: format,
			logger: logger.NOP(),
		},
	}
}

func ruleCountTestBinary(t *testing.T, source string, mutate func(*option.PlainRuleSet)) []byte {
	t.Helper()
	compat, err := json.UnmarshalExtended[option.PlainRuleSetCompat]([]byte(source))
	require.NoError(t, err)
	plain, err := compat.Upgrade()
	require.NoError(t, err)
	if mutate != nil {
		mutate(&plain)
	}
	var buffer bytes.Buffer
	require.NoError(t, srs.Write(&buffer, plain, C.RuleSetVersionCurrent))
	return buffer.Bytes()
}

func TestRuleSetRuleCountSource(t *testing.T) {
	t.Parallel()
	ruleSet := newRuleCountTestRuleSet(C.RuleSetFormatSource)
	require.NoError(t, ruleSet.loadBytes([]byte(ruleCountTestSource), ruleSet))
	require.Equal(t, uint64(ruleCountTestExpected), ruleSet.RuleCount())
	require.Equal(t, RuleSetBehaviorClassical, ruleSet.Behavior())
}

func TestRuleSetRuleCountBinary(t *testing.T) {
	t.Parallel()
	ruleSet := newRuleCountTestRuleSet(C.RuleSetFormatBinary)
	require.NoError(t, ruleSet.loadBytes(ruleCountTestBinary(t, ruleCountTestSource, nil), ruleSet))
	require.Equal(t, uint64(ruleCountTestExpected), ruleSet.RuleCount())
}

func TestRuleSetRuleCountBinaryAdGuard(t *testing.T) {
	t.Parallel()
	content := ruleCountTestBinary(t, `{"version":5,"rules":[{"domain":["placeholder.com"]}]}`, func(plain *option.PlainRuleSet) {
		plain.Rules[0].DefaultOptions = option.DefaultHeadlessRule{
			AdGuardDomain: []string{"||example.com^", "|exact.org^", "ads.*.net"},
		}
	})
	ruleSet := newRuleCountTestRuleSet(C.RuleSetFormatBinary)
	require.NoError(t, ruleSet.loadBytes(content, ruleSet))
	require.Equal(t, uint64(3), ruleSet.RuleCount())
}

func TestRuleSetRuleCountInline(t *testing.T) {
	t.Parallel()
	compat, err := json.UnmarshalExtended[option.PlainRuleSetCompat]([]byte(ruleCountTestSource))
	require.NoError(t, err)
	plain, err := compat.Upgrade()
	require.NoError(t, err)
	ruleSet, err := NewLocalRuleSet(context.Background(), logger.NOP(), "inline", option.RuleSet{
		Type:          C.RuleSetTypeInline,
		InlineOptions: option.PlainRuleSet{Rules: plain.Rules},
	})
	require.NoError(t, err)
	require.Equal(t, uint64(ruleCountTestExpected), ruleSet.RuleCount())
}

func TestRuleSetRuleCountSurvivesCleanup(t *testing.T) {
	t.Parallel()
	ruleSet := newRuleCountTestRuleSet(C.RuleSetFormatBinary)
	require.NoError(t, ruleSet.loadBytes(ruleCountTestBinary(t, ruleCountTestSource, nil), ruleSet))
	ruleSet.Cleanup()
	require.Nil(t, ruleSet.rules)
	require.Equal(t, uint64(ruleCountTestExpected), ruleSet.RuleCount())

	require.NoError(t, ruleSet.loadBytes(ruleCountTestBinary(t, `{"version":5,"rules":[{"domain":["a.com"]}]}`, nil), ruleSet))
	require.Equal(t, uint64(1), ruleSet.RuleCount())
}

func TestRuleSetBehavior(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		source   string
		behavior string
	}{
		{"domain", `{"version":5,"rules":[{"domain":["a.com"],"domain_suffix":["b.com"]},{"domain_suffix":["c.com"]}]}`, RuleSetBehaviorDomain},
		{"ipcidr", `{"version":5,"rules":[{"ip_cidr":["1.1.1.0/24","2001:db8::/32"]}]}`, RuleSetBehaviorIPCIDR},
		{"keyword", `{"version":5,"rules":[{"domain_suffix":["a.com"],"domain_keyword":["b"]}]}`, RuleSetBehaviorClassical},
		{"mixed", `{"version":5,"rules":[{"domain":["a.com"]},{"ip_cidr":["1.1.1.0/24"]}]}`, RuleSetBehaviorClassical},
		{"source-ip", `{"version":5,"rules":[{"source_ip_cidr":["1.1.1.0/24"]}]}`, RuleSetBehaviorClassical},
		{"invert", `{"version":5,"rules":[{"domain":["a.com"],"invert":true}]}`, RuleSetBehaviorClassical},
		{"logical", `{"version":5,"rules":[{"type":"logical","mode":"or","rules":[{"domain":["a.com"]}]}]}`, RuleSetBehaviorClassical},
	} {
		for _, format := range []string{C.RuleSetFormatSource, C.RuleSetFormatBinary} {
			ruleSet := newRuleCountTestRuleSet(format)
			content := []byte(testCase.source)
			if format == C.RuleSetFormatBinary {
				content = ruleCountTestBinary(t, testCase.source, nil)
			}
			require.NoError(t, ruleSet.loadBytes(content, ruleSet), testCase.name)
			require.Equal(t, testCase.behavior, ruleSet.Behavior(), testCase.name+"/"+format)
		}
	}
}
