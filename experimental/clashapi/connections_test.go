package clashapi

import (
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
)

func TestConnectionObjectPreferAndroidPackageName(t *testing.T) {
	connection := connectionObject(trafficcontrol.TrackerMetadata{
		Metadata: adapter.InboundContext{
			ProcessInfo: &adapter.ConnectionOwner{
				UserId:       -1,
				ProcessPaths: []string{"/system/bin/app_process64"},
				PackageNames: []string{"io.nekohasekai.sfa"},
			},
		},
		Upload:   new(atomic.Int64),
		Download: new(atomic.Int64),
	})
	response, err := connection.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var content struct {
		Metadata struct {
			ProcessPath string `json:"processPath"`
		} `json:"metadata"`
	}
	err = json.Unmarshal(response, &content)
	if err != nil {
		t.Fatal(err)
	}
	if content.Metadata.ProcessPath != "io.nekohasekai.sfa" {
		t.Fatalf("unexpected process path: %s", content.Metadata.ProcessPath)
	}
}

func TestConnectionObjectMihomoRule(t *testing.T) {
	router, _ := newTestRuleRouters(t)
	for _, testCase := range []struct {
		rule        adapter.Rule
		ruleType    string
		rulePayload string
	}{
		{router.rules[1], "Domain", "proxy.example.com"},
		// 未命中规则时落到 final 出站，同 mihomo 的 MATCH
		{nil, "Match", ""},
	} {
		connection := connectionObject(trafficcontrol.TrackerMetadata{
			Rule:     testCase.rule,
			Upload:   new(atomic.Int64),
			Download: new(atomic.Int64),
		})
		response, err := connection.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var content struct {
			Rule        string `json:"rule"`
			RulePayload string `json:"rulePayload"`
		}
		err = json.Unmarshal(response, &content)
		if err != nil {
			t.Fatal(err)
		}
		if content.Rule != testCase.ruleType || content.RulePayload != testCase.rulePayload {
			t.Fatalf("unexpected rule: %s %s", content.Rule, content.RulePayload)
		}
	}
}
