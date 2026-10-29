//go:build !with_quic

package nowhere

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// RegisterEgressInbound registers the Nowhere 3 Egress client. Without QUIC
// support the registration still exists so a configuration naming the type
// fails with the usual build error instead of an unknown inbound type.
func RegisterEgressInbound(registry *inbound.Registry) {
	inbound.Register[option.NowhereEgressInboundOptions](registry, C.TypeNowhereEgress, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NowhereEgressInboundOptions) (adapter.Inbound, error) {
		return nil, C.ErrQUICNotIncluded
	})
}
