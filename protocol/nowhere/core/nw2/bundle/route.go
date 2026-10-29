package bundle

import (
	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

// resolvedRoute is the concrete carrier pair written to FlowHeader.
type resolvedRoute struct {
	uplink   wire.Carrier
	downlink wire.Carrier
}

func (r resolvedRoute) split() bool { return r.uplink != r.downlink }

func (r resolvedRoute) label() string {
	switch {
	case r.uplink == wire.CarrierTLSTCP && r.downlink == wire.CarrierTLSTCP:
		return "TT"
	case r.uplink == wire.CarrierTLSTCP && r.downlink == wire.CarrierQUIC:
		return "TQ"
	case r.uplink == wire.CarrierQUIC && r.downlink == wire.CarrierTLSTCP:
		return "QT"
	case r.uplink == wire.CarrierQUIC && r.downlink == wire.CarrierQUIC:
		return "QQ"
	default:
		return "??"
	}
}

// planRoute resolves the fixed up/down policies onto the carrier pair written
// to FlowHeader.
func planRoute(up, down CarrierMode) resolvedRoute {
	return resolvedRoute{uplink: up.Selectors(), downlink: down.Selectors()}
}
