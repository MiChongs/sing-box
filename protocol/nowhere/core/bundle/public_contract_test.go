package bundle

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

var (
	_ func(*CarrierBundle, context.Context, wire.Target) (net.PacketConn, error)        = (*CarrierBundle).OpenUDP
	_ func(*CarrierBundle, context.Context, wire.Target, []byte) (net.Conn, error)      = (*CarrierBundle).OpenTCPWithPayload
	_ func(*CarrierBundle, context.Context, wire.Target, uint8) (net.Conn, error)       = (*CarrierBundle).OpenTCPWithHops
	_ func(*CarrierBundle, context.Context, wire.Target, uint8) (net.PacketConn, error) = (*CarrierBundle).OpenUDPWithHops
)
