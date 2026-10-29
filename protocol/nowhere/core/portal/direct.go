package portal

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const dialTimeout = 15 * time.Second

// Upstream dials targets for a Portal that is not using Egress.
type Upstream interface {
	DialTCP(ctx context.Context, target wire.Target) (net.Conn, error)
	DialUDP(ctx context.Context, target wire.Target) (net.Conn, error)
}

// Direct dials targets from this process. UDP connections are connected.
type Direct struct{}

// DialTCP dials the target with the default dial timeout.
func (Direct) DialTCP(ctx context.Context, target wire.Target) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	return (&net.Dialer{}).DialContext(ctx, "tcp", target.HostPort())
}

// DialUDP dials a connected UDP socket.
func (Direct) DialUDP(ctx context.Context, target wire.Target) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	return (&net.Dialer{}).DialContext(ctx, "udp", target.HostPort())
}
