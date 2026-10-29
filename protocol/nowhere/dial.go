package nowhere

import (
	"fmt"
	"net/netip"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// dialAuto is the Rust portal URL value that leaves the source address to the
// system. An empty value means the same thing.
const dialAuto = "auto"

// NextDialerOptions maps the Rust portal URL dial4/dial6 parameters onto the
// sing-box dialer source-binding options used when dialing the next Portal.
//
// dial4 accepts "auto" or an IPv4 literal (0.0.0.0 is a valid wildcard) and
// dial6 accepts "auto" or an IPv6 literal; IPv4-mapped IPv6 literals such as
// ::ffff:192.0.2.1 are rejected. The two are independent and may be combined
// for dual-stack binding. They are mutually exclusive with dial, which has no
// equivalent here: sing-box exposes the legacy single-family bind through the
// shared inet4_bind_address / inet6_bind_address dial fields.
//
// A configured bind is never silently downgraded to automatic: the dialer
// carries the source address into every candidate and a failed bind fails the
// dial.
func NextDialerOptions(next *option.NowhereNextOptions) (option.DialerOptions, error) {
	var dialerOptions option.DialerOptions
	if next == nil {
		return dialerOptions, nil
	}
	if value := next.Dial4; value != "" && value != dialAuto {
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is4() {
			return dialerOptions, fmt.Errorf("nowhere: dial4 must be auto or an IPv4 literal")
		}
		bind := badoption.Addr(addr)
		dialerOptions.Inet4BindAddress = &bind
	}
	if value := next.Dial6; value != "" && value != dialAuto {
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is6() {
			return dialerOptions, fmt.Errorf("nowhere: dial6 must be auto or an IPv6 literal")
		}
		if addr.Is4In6() {
			return dialerOptions, fmt.Errorf("nowhere: dial6 must not be an IPv4-mapped IPv6 address")
		}
		bind := badoption.Addr(addr)
		dialerOptions.Inet6BindAddress = &bind
	}
	return dialerOptions, nil
}
