package group

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func startNestedTestManager(t *testing.T) (context.Context, *nestedTestManager, *adapter.Scope) {
	t.Helper()
	registry := outbound.NewRegistry()
	direct.RegisterOutbound(registry)
	socks.RegisterOutbound(registry)
	RegisterSelector(registry)
	RegisterNested(registry)
	endpointManager := endpoint.NewManager(nil)
	manager := outbound.NewManager(registry, endpointManager, "")
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	ctx = service.ContextWith[adapter.OutboundRegistry](ctx, registry)
	manager.Initialize(func() (adapter.Outbound, error) {
		return direct.NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "direct", option.DirectOutboundOptions{})
	})
	scope := adapter.NewScope(ctx, logger.NOP())
	t.Cleanup(func() { scope.Close() })
	return ctx, &nestedTestManager{Manager: manager, endpoint: endpointManager}, scope
}

type nestedTestManager struct {
	*outbound.Manager
	endpoint *endpoint.Manager
}

func (m *nestedTestManager) startAll(t *testing.T, scope *adapter.Scope) {
	t.Helper()
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, m.Manager.Start(stage, scope))
		if stage == adapter.StartStateInitialize {
			require.NoError(t, m.endpoint.Start(stage, scope))
		}
	}
}

func createNestedTestSocks(t *testing.T, ctx context.Context, manager *nestedTestManager, tag string, port uint16) {
	t.Helper()
	require.NoError(t, manager.Create(ctx, nil, log.NewNOPFactory().Logger(), tag, C.TypeSOCKS, &option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
	}))
}

func TestNestedCreatesDetouredShadows(t *testing.T) {
	ctx, manager, scope := startNestedTestManager(t)
	createNestedTestSocks(t, ctx, manager, "entry", 1080)
	createNestedTestSocks(t, ctx, manager, "exit-a", 1081)
	createNestedTestSocks(t, ctx, manager, "exit-b", 1082)
	require.NoError(t, manager.Create(ctx, nil, log.NewNOPFactory().Logger(), "chain", C.TypeNested, &option.NestedOutboundOptions{
		SelectorOutboundOptions: option.SelectorOutboundOptions{GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"exit-a", "exit-b"}}, Default: "exit-b"},
		Detour:                  "entry",
	}))
	manager.startAll(t, scope)

	options, loaded := manager.OutboundOption("exit-a")
	require.True(t, loaded)
	require.Equal(t, C.TypeSOCKS, options.Type)

	chain, loaded := manager.Outbound("chain")
	require.True(t, loaded)
	nested := chain.(*Nested)
	require.Equal(t, C.TypeNested, nested.Type())
	require.Equal(t, []string{"exit-a@chain", "exit-b@chain"}, nested.All())
	require.Equal(t, "exit-b@chain", nested.Selected("").Tag())
	require.Contains(t, nested.Dependencies(), "entry")

	for _, tag := range []string{"exit-a@chain", "exit-b@chain"} {
		shadow, loaded := manager.Outbound(tag)
		require.True(t, loaded, tag)
		require.IsType(t, &shadowOutbound{}, shadow)
		require.Contains(t, shadow.(*shadowOutbound).Outbound.Dependencies(), "entry", tag)
	}
	// The originals keep dialing directly.
	original, _ := manager.Outbound("exit-a")
	require.NotContains(t, original.Dependencies(), "entry")

	require.True(t, nested.SelectOutbound("exit-a"))
	require.Equal(t, "exit-a@chain", nested.Selected("").Tag())

	require.NoError(t, nested.Close())
	_, loaded = manager.Outbound("exit-a@chain")
	require.False(t, loaded)
}

func TestNestedRejectsMissingDetour(t *testing.T) {
	ctx, manager, _ := startNestedTestManager(t)
	err := manager.Create(ctx, nil, log.NewNOPFactory().Logger(), "chain", C.TypeNested, &option.NestedOutboundOptions{
		SelectorOutboundOptions: option.SelectorOutboundOptions{GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"exit"}}},
	})
	require.ErrorContains(t, err, "missing detour")
	err = manager.Create(ctx, nil, log.NewNOPFactory().Logger(), "chain", C.TypeNested, &option.NestedOutboundOptions{
		SelectorOutboundOptions: option.SelectorOutboundOptions{GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"exit"}}},
		Detour:                  "chain",
	})
	require.ErrorContains(t, err, "circular detour")
}

func TestNestedBlocksWhenDetourDegraded(t *testing.T) {
	ctx, manager, scope := startNestedTestManager(t)
	createNestedTestSocks(t, ctx, manager, "exit", 1081)
	require.NoError(t, manager.Create(ctx, nil, log.NewNOPFactory().Logger(), "entry-group", C.TypeSelector, &option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"exit"}},
	}))
	require.NoError(t, manager.Create(ctx, nil, log.NewNOPFactory().Logger(), "chain", C.TypeNested, &option.NestedOutboundOptions{
		SelectorOutboundOptions: option.SelectorOutboundOptions{GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"exit"}}},
		Detour:                  "entry-group",
	}))
	manager.startAll(t, scope)
	chain, _ := manager.Outbound("chain")
	require.NoError(t, chain.(*Nested).checkAvailable())
}
