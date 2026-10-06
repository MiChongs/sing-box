package nowhere

import (
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/tcptls"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

type (
	Credentials = wire.Credentials
	SessionID   = wire.SessionID
	Carrier     = wire.Carrier
	FlowHeader  = wire.FlowHeader
	Target      = wire.Target

	TCPConfig  = tcptls.Config
	TCPOptions = tcptls.TCPOptions
	TLSDialer  = tcptls.TLSDialer
)

var (
	NewCredentials = wire.NewCredentials
	NewTCPConfig   = tcptls.NewConfig
)
