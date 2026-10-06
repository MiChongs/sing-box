package tcptls

import (
	"net"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// wrapRelay promotes a consumed carrier to active_relay with diagnostic tracking.
func wrapRelay(conn net.Conn, ci *carrierInfo, flowID wire.FlowID, kind wire.FlowKind, target string) net.Conn {
	network := relayNetwork(kind)
	ci.transition(stateActiveRelay)
	ci.logger().Debugf("[Nowhere] [carrier] relay_start flow_id=%d carrier_id=%d network=%s target=%s",
		flowID, ci.id, network, target)
	return newTrackedConn(conn, ci, flowID, network, target)
}
