//go:build !with_easytier

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerEasyTierEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.EasyTierEndpointOptions](registry, C.TypeEasyTier, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EasyTierEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New(`EasyTier is not included in this build, rebuild with -tags with_easytier`)
	})
}
