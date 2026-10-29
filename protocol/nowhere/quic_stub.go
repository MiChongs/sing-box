//go:build !with_quic

package nowhere

import (
	"context"
	"crypto/tls"
	"net"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/morph"
	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/carrier"
	"github.com/sagernet/sing-box/protocol/nowhere/core/qio"
	"github.com/sagernet/sing-box/protocol/nowhere/internal/quicsettings"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const quicIncluded = false

func newQuicBackend(quicBackendOptions) carrier.QuicBackend { return nil }

// The Nowhere 3 QUIC carriers are host-injected, so a build without QUIC
// support cannot serve or dial them. The constructors stay available with
// untagged-visible signatures; only their bodies need the QUIC stack.
func dialNowhereV3QUICCarrier(ctx context.Context, dialer N.Dialer, destination M.Socksaddr, tlsConfig *tls.Config, quicOptions option.QUICOptions, congestionControl quicsettings.CongestionControl, keys *morph.Keys) (qio.Conn, error) {
	return nil, C.ErrQUICNotIncluded
}

func listenNowhereV3QUIC(ctx context.Context, packetConn net.PacketConn, tlsConfig *tls.Config, quicOptions option.QUICOptions, congestionControl quicsettings.CongestionControl) (qio.Listener, error) {
	return nil, C.ErrQUICNotIncluded
}
