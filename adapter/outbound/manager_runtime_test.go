package outbound

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type runtimeTestOutbound struct {
	Adapter
	stages []adapter.StartStage
	closed int
}

func newRuntimeTestOutbound(tag string) *runtimeTestOutbound {
	return &runtimeTestOutbound{Adapter: NewAdapter("test", tag, []string{N.NetworkTCP}, nil)}
}

func (o *runtimeTestOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error {
			o.closed++
			return nil
		})
	}
	o.stages = append(o.stages, stage)
	return nil
}

func (o *runtimeTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

func (o *runtimeTestOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type runtimeTestRegistry struct {
	created map[string][]*runtimeTestOutbound
}

func (r *runtimeTestRegistry) OptionTypes() []string {
	return []string{"test"}
}

func (r *runtimeTestRegistry) CreateOptions(outboundType string) (any, bool) {
	return nil, outboundType == "test"
}

func (r *runtimeTestRegistry) CreateOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) (adapter.Outbound, error) {
	outbound := newRuntimeTestOutbound(tag)
	r.created[tag] = append(r.created[tag], outbound)
	return outbound, nil
}

func startRuntimeTestManager(t *testing.T) (*Manager, *runtimeTestRegistry, *adapter.Scope) {
	t.Helper()
	registry := &runtimeTestRegistry{created: make(map[string][]*runtimeTestOutbound)}
	endpointManager := endpoint.NewManager(nil)
	manager := NewManager(registry, endpointManager, "")
	manager.Initialize(func() (adapter.Outbound, error) {
		return newRuntimeTestOutbound(C.TypeDirect), nil
	})
	scope := adapter.NewScope(context.Background(), logger.NOP())
	t.Cleanup(func() {
		require.NoError(t, scope.Close())
	})
	require.NoError(t, manager.Create(context.Background(), nil, logger.NOP(), "static", "test", nil))
	require.NoError(t, manager.Start(adapter.StartStateInitialize, scope))
	// The box initializes endpoints before the outbound start stage, which
	// starts lifecycle outbounds through the endpoint manager.
	require.NoError(t, endpointManager.Start(adapter.StartStateInitialize, scope))
	return manager, registry, scope
}

// Outbounds created by providers after startup run every stage on creation and
// are skipped by the stages the box still has to advance through.
func TestManagerRuntimeOutboundStartsAllStages(t *testing.T) {
	manager, registry, scope := startRuntimeTestManager(t)
	require.NoError(t, manager.Create(context.Background(), nil, logger.NOP(), "runtime", "test", nil))
	runtimeOutbound := registry.created["runtime"][0]
	require.Equal(t, adapter.ListStartStages, runtimeOutbound.stages)

	for _, stage := range adapter.ListStartStages[1:] {
		require.NoError(t, manager.Start(stage, scope))
	}
	require.Equal(t, adapter.ListStartStages, runtimeOutbound.stages)
	require.Equal(t, adapter.ListStartStages, registry.created["static"][0].stages)
}

func TestManagerRuntimeOutboundReplaceAndRemove(t *testing.T) {
	manager, registry, _ := startRuntimeTestManager(t)
	require.NoError(t, manager.Create(context.Background(), nil, logger.NOP(), "member", "test", nil))
	require.NoError(t, manager.Create(context.Background(), nil, logger.NOP(), "member", "test", nil))
	oldOutbound, newOutbound := registry.created["member"][0], registry.created["member"][1]
	require.Equal(t, 1, oldOutbound.closed)
	require.Zero(t, newOutbound.closed)
	loaded, found := manager.Outbound("member")
	require.True(t, found)
	require.Same(t, newOutbound, loaded)
	require.Len(t, manager.Outbounds(), 2)

	require.NoError(t, manager.Remove("member"))
	require.Equal(t, 1, newOutbound.closed)
	_, found = manager.Outbound("member")
	require.False(t, found)
	require.Len(t, manager.Outbounds(), 1)
	require.ErrorIs(t, manager.Remove("member"), os.ErrInvalid)
}

func TestManagerRejectsDuplicateTagBeforeStart(t *testing.T) {
	registry := &runtimeTestRegistry{created: make(map[string][]*runtimeTestOutbound)}
	manager := NewManager(registry, endpoint.NewManager(nil), "")
	require.NoError(t, manager.Create(context.Background(), nil, logger.NOP(), "static", "test", nil))
	require.Error(t, manager.Create(context.Background(), nil, logger.NOP(), "static", "test", nil))
}
