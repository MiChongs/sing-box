package bundle

import (
	"encoding/binary"
	"math/bits"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
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

type routePlan struct {
	primary     resolvedRoute
	fallback    resolvedRoute
	hasFallback bool
}

func seedFromSession(sessionID wire.SessionID) uint64 {
	low := binary.LittleEndian.Uint64(sessionID[0:8])
	high := binary.LittleEndian.Uint64(sessionID[8:16])
	return low ^ bits.RotateLeft64(high, 32)
}

func planRoute(up, down CarrierMode, seed uint64, flowID wire.FlowID) routePlan {
	if !up.IsMix() && !down.IsMix() {
		return routePlan{primary: resolveWithChoice(up, down, false)}
	}
	chooseQUIC := splitmix64(seed^uint64(flowID))&1 != 0
	return routePlan{
		primary:     resolveWithChoice(up, down, chooseQUIC),
		fallback:    resolveWithChoice(up, down, !chooseQUIC),
		hasFallback: true,
	}
}

func resolveWithChoice(up, down CarrierMode, chooseQUIC bool) resolvedRoute {
	selected := wire.CarrierTLSTCP
	if chooseQUIC {
		selected = wire.CarrierQUIC
	}
	fixed := func(mode CarrierMode) wire.Carrier {
		switch mode {
		case ModeTCP:
			return wire.CarrierTLSTCP
		case ModeUDP:
			return wire.CarrierQUIC
		default:
			return selected
		}
	}
	return resolvedRoute{uplink: fixed(up), downlink: fixed(down)}
}

func splitmix64(value uint64) uint64 {
	value += 0x9e3779b97f4a7c15
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
	value = (value ^ (value >> 27)) * 0x94d049bb133111eb
	return value ^ (value >> 31)
}
