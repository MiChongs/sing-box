package group

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// TestGroupHiddenIcon walks every built-in group from its JSON options
// through the constructor to adapter.OutboundGroupHint, which is what the
// Clash API reads to emit the `hidden` / `icon` dashboard hints.
func TestGroupHiddenIcon(t *testing.T) {
	const (
		unsetJSON = `{"outbounds":["a"]}`
		setJSON   = `{"outbounds":["a"],"hidden":true,"icon":"https://example.com/icon.svg"}`
		wantIcon  = "https://example.com/icon.svg"
	)
	logger := log.NewNOPFactory().NewLogger("test")
	build := map[string]func(t *testing.T, content string) adapter.Outbound{
		"selector": func(t *testing.T, content string) adapter.Outbound {
			var options option.SelectorOutboundOptions
			unmarshalGroupOptions(t, content, &options)
			outbound, err := NewSelector(context.Background(), nil, logger, "g", options)
			if err != nil {
				t.Fatal(err)
			}
			return outbound
		},
		"urltest": func(t *testing.T, content string) adapter.Outbound {
			var options option.URLTestOutboundOptions
			unmarshalGroupOptions(t, content, &options)
			outbound, err := NewURLTest(context.Background(), nil, logger, "g", options)
			if err != nil {
				t.Fatal(err)
			}
			return outbound
		},
		"loadbalance": func(t *testing.T, content string) adapter.Outbound {
			var options option.LoadBalanceOutboundOptions
			unmarshalGroupOptions(t, content, &options)
			outbound, err := NewLoadBalance(context.Background(), nil, logger, "g", options)
			if err != nil {
				t.Fatal(err)
			}
			return outbound
		},
		"smart": func(t *testing.T, content string) adapter.Outbound {
			var options option.SmartOutboundOptions
			unmarshalGroupOptions(t, content, &options)
			outbound, err := NewSmart(context.Background(), nil, logger, "g", options)
			if err != nil {
				t.Fatal(err)
			}
			return outbound
		},
	}
	for name, newGroup := range build {
		t.Run(name, func(t *testing.T) {
			unset, isHint := newGroup(t, unsetJSON).(adapter.OutboundGroupHint)
			if !isHint {
				t.Fatal("group does not implement adapter.OutboundGroupHint")
			}
			if unset.Hidden() || unset.Icon() != "" {
				t.Fatalf("default hints = (%v, %q), want (false, \"\")", unset.Hidden(), unset.Icon())
			}
			set := newGroup(t, setJSON).(adapter.OutboundGroupHint)
			if !set.Hidden() || set.Icon() != wantIcon {
				t.Fatalf("configured hints = (%v, %q), want (true, %q)", set.Hidden(), set.Icon(), wantIcon)
			}
		})
	}
}

func unmarshalGroupOptions(t *testing.T, content string, options any) {
	t.Helper()
	err := json.Unmarshal([]byte(content), options)
	if err != nil {
		t.Fatal(err)
	}
}
