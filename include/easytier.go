//go:build with_easytier

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/protocol/easytier"
)

func registerEasyTierEndpoint(registry *endpoint.Registry) {
	easytier.RegisterEndpoint(registry)
}
