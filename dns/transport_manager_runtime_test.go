package dns

import (
	"context"
	"os"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type runtimeTestTransport struct {
	TransportAdapter
	stages atomic.Int32
	closed atomic.Bool
}

func (t *runtimeTestTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	t.stages.Add(1)
	if stage == adapter.StartStateStart {
		scope.Add(func() error {
			t.closed.Store(true)
			return nil
		})
	}
	return nil
}

func (t *runtimeTestTransport) Reset() {}

func (t *runtimeTestTransport) Exchange(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return nil, os.ErrInvalid
}

func (t *runtimeTestTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	callback(t.Exchange(ctx, message))
}

func newRuntimeTestTransport(tag string) *runtimeTestTransport {
	return &runtimeTestTransport{TransportAdapter: NewTransportAdapter(C.DNSTypeProvider, tag, nil)}
}

func TestTransportManagerRuntimeTransports(t *testing.T) {
	t.Parallel()
	manager := NewTransportManager(NewTransportRegistry(), nil, "")
	defaultTransport := newRuntimeTestTransport("default")
	manager.Initialize(func() (adapter.DNSTransport, error) { return defaultTransport, nil })

	// added before start: started with the configured servers, never default
	early := newRuntimeTestTransport("early")
	require.NoError(t, manager.AddTransport(early))
	require.Error(t, manager.AddTransport(newRuntimeTestTransport("early")), "duplicate tag")

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, manager.Start(stage, scope))
	}
	require.Same(t, defaultTransport, manager.Default())
	require.EqualValues(t, len(adapter.ListStartStages), early.stages.Load())

	// added at runtime: started through every stage at once, and skipped by
	// later manager stages
	late := newRuntimeTestTransport("late")
	require.NoError(t, manager.AddTransport(late))
	require.EqualValues(t, len(adapter.ListStartStages), late.stages.Load())
	loaded, found := manager.Transport("late")
	require.True(t, found)
	require.Same(t, late, loaded)

	require.NoError(t, manager.Remove("late"))
	require.True(t, late.closed.Load())
	_, found = manager.Transport("late")
	require.False(t, found)
	require.ErrorIs(t, manager.Remove("late"), os.ErrInvalid)

	require.NoError(t, manager.Remove("early"))
	require.True(t, early.closed.Load())
	require.Error(t, manager.Remove("default"), "the default server stays")
	require.Len(t, manager.Transports(), 1)
	require.NoError(t, scope.Close())
}
