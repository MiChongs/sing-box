package route

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// matchPreRouteBypass decides an inbound's PreRouteBypass rule before any
// route rule. The rule is matched on a copy of the metadata so the domain it
// completes and any sniff result do not leak into route rules that did not
// ask for them; sniffed payload is returned and replayed to the connection
// either way, and a later sniff rule sniffs that payload again without reading
// the connection. A sniffed host takes precedence over every address-derived
// domain; LookupDomain only serves connections that name no host at all.
func (r *Router) matchPreRouteBypass(
	ctx context.Context, metadata *adapter.InboundContext, bypass *adapter.PreRouteBypass,
	inputConn net.Conn, inputPacketConn N.PacketConn,
) (matched bool, buffers []*buf.Buffer, packetBuffers []*N.PacketBuffer, fatalErr error) {
	if bypass.Rule == nil || bypass.Outbound == nil {
		return
	}
	probe := *metadata
	probe.PreRouteBypass = nil
	// The host a connection actually names is the only exact domain for an
	// address destination: an address shared by many domains (any CDN) maps
	// back to whichever domain resolved it last, so a reverse-mapped or
	// learned domain must never decide before sniffing had its chance.
	if bypass.NeedDomain && !probe.Destination.IsDomain() && probe.SniffHost == "" {
		buffer, newPacketBuffers, err := r.actionSniff(ctx, &probe, &R.RuleActionSniff{}, inputConn, inputPacketConn, nil, nil)
		if buffer != nil {
			buffers = append(buffers, buffer)
		}
		packetBuffers = append(packetBuffers, newPacketBuffers...)
		if err != nil {
			fatalErr = err
			return
		}
		if buffer == nil && len(newPacketBuffers) == 0 && probe.SniffError != nil {
			// Nothing arrived within the sniff timeout (a server-first
			// protocol): record it so an identical sniff rule does not wait
			// for the same silence again.
			metadata.SnifferNames = probe.SnifferNames
			metadata.SniffError = probe.SniffError
		}
	}
	if !preRouteBypassHasDomain(&probe) && bypass.LookupDomain != nil && probe.Destination.IsIP() {
		if domain, loaded := bypass.LookupDomain(probe.Destination.Addr); loaded {
			probe.Domain = domain
		}
	}
	probe.ResetRuleCache()
	if !bypass.Rule.Match(&probe) {
		return
	}
	r.logger.DebugContext(ctx, "match ", bypass.Description, " => route(", bypass.Outbound.Tag(), ")")
	return true, buffers, packetBuffers, nil
}

func preRouteBypassHasDomain(metadata *adapter.InboundContext) bool {
	return metadata.Destination.IsDomain() || metadata.Domain != "" || metadata.SniffHost != ""
}
