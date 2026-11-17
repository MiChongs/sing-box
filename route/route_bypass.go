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
// either way.
func (r *Router) matchPreRouteBypass(
	ctx context.Context, metadata *adapter.InboundContext, bypass *adapter.PreRouteBypass,
	inputConn net.Conn, inputPacketConn N.PacketConn,
) (matched bool, buffers []*buf.Buffer, packetBuffers []*N.PacketBuffer, fatalErr error) {
	if bypass.Rule == nil || bypass.Outbound == nil {
		return
	}
	probe := *metadata
	probe.PreRouteBypass = nil
	if !preRouteBypassHasDomain(&probe) && bypass.LookupDomain != nil && probe.Destination.IsIP() {
		if domain, loaded := bypass.LookupDomain(probe.Destination.Addr); loaded {
			probe.Domain = domain
		}
	}
	if bypass.NeedDomain && !preRouteBypassHasDomain(&probe) {
		buffer, newPacketBuffers, err := r.actionSniff(ctx, &probe, &R.RuleActionSniff{}, inputConn, inputPacketConn, nil, nil)
		if buffer != nil {
			buffers = append(buffers, buffer)
		}
		packetBuffers = append(packetBuffers, newPacketBuffers...)
		if err != nil {
			fatalErr = err
			return
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
