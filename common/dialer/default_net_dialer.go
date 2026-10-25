package dialer

import (
	"net"
	"net/netip"
)

// NetDialer returns a copy of the configured net.Dialer for destination's
// family, for callers that dial sockets themselves (EasyTier binding a local
// address).
func (d *DefaultDialer) NetDialer(destination netip.Addr) net.Dialer {
	if !destination.Is6() {
		return d.dialer4.Dialer
	}
	return d.dialer6.Dialer
}
