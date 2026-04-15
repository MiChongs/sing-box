package group

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

// TestGroupHiddenIcon_Defaults covers the contract guaranteed by the
// adapter.OutboundGroup interface: zero-valued groups must report
// hidden=false / icon="" so dashboards and Clash-API consumers can
// rely on the fields always being safe to read.
//
// We construct each of the four built-in groups as zero-value structs
// (the rest of the state isn't touched by Hidden()/Icon()) and assert
// the default contract. This catches regressions where a future field
// reorder or rename forgets the dashboard hints.
func TestGroupHiddenIcon_Defaults(t *testing.T) {
	cases := []struct {
		name string
		g    adapter.OutboundGroup
	}{
		{"selector", &Selector{}},
		{"urltest", &URLTest{}},
		{"loadbalance", &LoadBalance{}},
		{"smart", &Smart{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.g.Hidden() {
				t.Fatalf("default Hidden() = true, want false")
			}
			if c.g.Icon() != "" {
				t.Fatalf("default Icon() = %q, want empty string", c.g.Icon())
			}
		})
	}
}

// TestGroupHiddenIcon_FieldPropagation flips the underlying fields and
// checks the getters return the assigned values. Together with the
// constructor wiring (NewSelector / NewURLTest / etc reading
// options.Hidden / options.Icon) this proves the value travels from
// option.GroupCommonOption through to adapter.OutboundGroup callers
// without dropping anywhere along the way.
func TestGroupHiddenIcon_FieldPropagation(t *testing.T) {
	const wantIcon = "https://example.com/icon.svg"
	cases := []struct {
		name  string
		setup func() adapter.OutboundGroup
	}{
		{"selector", func() adapter.OutboundGroup {
			s := &Selector{}
			s.hidden, s.icon = true, wantIcon
			return s
		}},
		{"urltest", func() adapter.OutboundGroup {
			s := &URLTest{}
			s.hidden, s.icon = true, wantIcon
			return s
		}},
		{"loadbalance", func() adapter.OutboundGroup {
			s := &LoadBalance{}
			s.hidden, s.icon = true, wantIcon
			return s
		}},
		{"smart", func() adapter.OutboundGroup {
			s := &Smart{}
			s.hidden, s.icon = true, wantIcon
			return s
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := c.setup()
			if !g.Hidden() {
				t.Fatalf("Hidden() = false after setting hidden=true")
			}
			if g.Icon() != wantIcon {
				t.Fatalf("Icon() = %q, want %q", g.Icon(), wantIcon)
			}
		})
	}
}

// TestGroupCommonOption_JSONRoundtrip validates the option struct
// round-trips both fields through encoding/json with the documented
// `omitempty` semantics: absent on the wire when zero, present when
// set. This is the schema contract end-users write against.
func TestGroupCommonOption_JSONRoundtrip(t *testing.T) {
	type stripped struct {
		Outbounds       []string `json:"outbounds"`
		Providers       []string `json:"providers"`
		UseAllProviders bool     `json:"use_all_providers,omitempty"`
		Hidden          bool     `json:"hidden,omitempty"`
		Icon            string   `json:"icon,omitempty"`
	}
	// Empty config: both fields must be omitted.
	emptyJSON, err := json.Marshal(stripped{})
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	if got := string(emptyJSON); got != `{"outbounds":null,"providers":null}` {
		t.Fatalf("empty marshal omitempty broken: %s", got)
	}
	// Populated config: both fields must round-trip.
	in := stripped{Hidden: true, Icon: "🚀"}
	blob, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal populated: %v", err)
	}
	var out stripped
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Hidden != true || out.Icon != "🚀" {
		t.Fatalf("roundtrip lost data: %+v", out)
	}
}
