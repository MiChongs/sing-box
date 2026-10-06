//go:build with_quic

package nowhere

import (
	"context"
	"net"

	quic "github.com/sagernet/sing-box/protocol/nowhere/carrier/quic"
	nwquic "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
)

// QuicBackend wires the sing-box QUIC transport primitives into the vendored
// nw2 core.
type QuicBackend struct {
	client *quic.Client
}

func NewQuicBackend(cfg *quic.QUICConfig) *QuicBackend {
	if cfg == nil {
		return &QuicBackend{}
	}
	configCopy := *cfg
	return &QuicBackend{client: quic.NewClient(&configCopy)}
}

func (b *QuicBackend) AcquireSession(ctx context.Context) (nwquic.Session, error) {
	if b == nil || b.client == nil {
		return nil, net.ErrClosed
	}
	return b.client.AcquireSession(ctx)
}

func (b *QuicBackend) InvalidateSession(session nwquic.Session) {
	if b != nil && b.client != nil {
		b.client.InvalidateSession(session)
	}
}

func (b *QuicBackend) Close() error {
	if b == nil || b.client == nil {
		return nil
	}
	return b.client.Close()
}

var _ nwquic.Backend = (*QuicBackend)(nil)
