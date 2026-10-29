package anyx

import (
	"context"
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	commandWaste               = 0
	commandSYN                 = 1
	commandPSH                 = 2
	commandFIN                 = 3
	commandSettings            = 4
	commandAlert               = 5
	commandUpdatePaddingScheme = 6
	commandSYNACK              = 7
	commandHeartRequest        = 8
	commandHeartResponse       = 9
	commandServerSettings      = 10
)

const (
	protocolVersion       = 2
	frameOverhead         = 7
	maxFrameSize          = 0xffff
	passwordLen           = 32
	sessionReadBufferSize = 4096
)

const (
	settingVersion    = "v"
	settingClient     = "client"
	settingPaddingMD5 = "padding-md5"
)

const DefaultClientMetadata = "anyx"

const (
	defaultIdleSessionCheckInterval = 30 * time.Second
	defaultIdleSessionTimeout       = 30 * time.Second
	minimumIdleSessionInterval      = 5 * time.Second
	streamOpenTimeout               = 3 * time.Second
	controlFrameWriteTimeout        = 5 * time.Second
)

var (
	ErrAuthentication  = E.New("anyx: authentication failed")
	ErrMissingSettings = E.New("anyx: client did not send its settings")
	ErrPaddingScheme   = E.New("anyx: invalid padding scheme")
	ErrFallbackClosed  = E.New("anyx: fallback disabled")
)

type DialOutFunc = func(ctx context.Context) (net.Conn, error)
