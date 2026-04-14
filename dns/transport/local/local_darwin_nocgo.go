//go:build darwin && !cgo

package local

import (
	"context"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"

	mDNS "github.com/miekg/dns"
)

// Exchange provides a cgo-free fallback for darwin builds. It mirrors
// local.go's Exchange path: hosts file lookup first, DHCP fallback if TUN
// is inbound, then generic DNS exchange via the dialer (using
// /etc/resolv.conf servers parsed by local_shared.go).
func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	question := message.Question[0]
	if question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA {
		addresses := t.hosts.Lookup(dns.FqdnToDomain(question.Name))
		if len(addresses) > 0 {
			return dns.FixedResponse(message.Id, question, addresses, C.DefaultDNSTTL), nil
		}
	}
	if t.fallback && t.dhcpTransport != nil {
		dhcpServers := t.dhcpTransport.Fetch()
		if len(dhcpServers) > 0 {
			return t.dhcpTransport.Exchange0(ctx, message, dhcpServers)
		}
	}
	return t.exchange(ctx, message, question.Name)
}
