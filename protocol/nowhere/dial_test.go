package nowhere

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestNextDialerOptions(t *testing.T) {
	t.Parallel()

	t.Run("unset", func(t *testing.T) {
		t.Parallel()
		options, err := NextDialerOptions(&option.NowhereNextOptions{})
		if err != nil {
			t.Fatalf("NextDialerOptions error = %v, want nil", err)
		}
		if options.Inet4BindAddress != nil || options.Inet6BindAddress != nil {
			t.Fatalf("bind addresses = %v/%v, want unset", options.Inet4BindAddress, options.Inet6BindAddress)
		}
	})

	t.Run("auto", func(t *testing.T) {
		t.Parallel()
		options, err := NextDialerOptions(&option.NowhereNextOptions{Dial4: "auto", Dial6: "auto"})
		if err != nil {
			t.Fatalf("NextDialerOptions error = %v, want nil", err)
		}
		if options.Inet4BindAddress != nil || options.Inet6BindAddress != nil {
			t.Fatalf("bind addresses = %v/%v, want unset", options.Inet4BindAddress, options.Inet6BindAddress)
		}
	})

	t.Run("dual-stack", func(t *testing.T) {
		t.Parallel()
		options, err := NextDialerOptions(&option.NowhereNextOptions{
			Dial4: "192.0.2.10",
			Dial6: "2001:db8::10",
		})
		if err != nil {
			t.Fatalf("NextDialerOptions error = %v, want nil", err)
		}
		if options.Inet4BindAddress == nil {
			t.Fatal("inet4 bind address = nil, want 192.0.2.10")
		}
		if got := options.Inet4BindAddress.Build(netip.Addr{}); got != netip.MustParseAddr("192.0.2.10") {
			t.Fatalf("inet4 bind address = %v, want 192.0.2.10", got)
		}
		if options.Inet6BindAddress == nil {
			t.Fatal("inet6 bind address = nil, want 2001:db8::10")
		}
		if got := options.Inet6BindAddress.Build(netip.Addr{}); got != netip.MustParseAddr("2001:db8::10") {
			t.Fatalf("inet6 bind address = %v, want 2001:db8::10", got)
		}
	})

	t.Run("wildcards", func(t *testing.T) {
		t.Parallel()
		options, err := NextDialerOptions(&option.NowhereNextOptions{Dial4: "0.0.0.0", Dial6: "::"})
		if err != nil {
			t.Fatalf("NextDialerOptions error = %v, want nil", err)
		}
		if options.Inet4BindAddress == nil || !options.Inet4BindAddress.Build(netip.Addr{}).IsUnspecified() {
			t.Fatalf("inet4 bind address = %v, want 0.0.0.0", options.Inet4BindAddress)
		}
		if options.Inet6BindAddress == nil || !options.Inet6BindAddress.Build(netip.Addr{}).IsUnspecified() {
			t.Fatalf("inet6 bind address = %v, want ::", options.Inet6BindAddress)
		}
	})

	bad := []struct {
		name        string
		dial4       string
		dial6       string
		wantMessage string
	}{
		{name: "dial4-ipv6-literal", dial4: "2001:db8::1", wantMessage: "dial4 must be auto or an IPv4 literal"},
		{name: "dial4-hostname", dial4: "example.com", wantMessage: "dial4 must be auto or an IPv4 literal"},
		{name: "dial4-ipv4-mapped", dial4: "::ffff:192.0.2.1", wantMessage: "dial4 must be auto or an IPv4 literal"},
		{name: "dial6-ipv4-literal", dial6: "192.0.2.1", wantMessage: "dial6 must be auto or an IPv6 literal"},
		{name: "dial6-hostname", dial6: "example.com", wantMessage: "dial6 must be auto or an IPv6 literal"},
		{name: "dial6-ipv4-mapped", dial6: "::ffff:192.0.2.1", wantMessage: "dial6 must not be an IPv4-mapped IPv6 address"},
	}
	for _, testCase := range bad {
		t.Run("reject-"+testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := NextDialerOptions(&option.NowhereNextOptions{Dial4: testCase.dial4, Dial6: testCase.dial6})
			if err == nil {
				t.Fatalf("NextDialerOptions(dial4=%q, dial6=%q) error = nil, want rejection", testCase.dial4, testCase.dial6)
			}
			if err.Error() != "nowhere: "+testCase.wantMessage {
				t.Fatalf("error = %q, want %q", err.Error(), "nowhere: "+testCase.wantMessage)
			}
		})
	}
}
