package adapter

import (
	"context"
	"testing"

	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

type runtimeTestComponent struct {
	stages  []StartStage
	failAt  StartStage
	fail    bool
	cleaned int
}

func (c *runtimeTestComponent) Start(stage StartStage, scope *Scope) error {
	if stage == StartStateInitialize {
		scope.Add(func() error {
			c.cleaned++
			return nil
		})
	}
	if c.fail && stage == c.failAt {
		return context.Canceled
	}
	c.stages = append(c.stages, stage)
	return nil
}

func TestStartRuntimeComponentRunsEveryStage(t *testing.T) {
	scope := NewScope(context.Background(), logger.NOP())
	component := new(runtimeTestComponent)
	require.NoError(t, StartRuntimeComponent(scope, "component", component))
	require.Equal(t, ListStartStages, component.stages)
	require.NoError(t, scope.Close())
	require.Equal(t, 1, component.cleaned)
}

func TestStartRuntimeComponentClosesOnFailure(t *testing.T) {
	scope := NewScope(context.Background(), logger.NOP())
	component := &runtimeTestComponent{fail: true, failAt: StartStatePostStart}
	require.Error(t, StartRuntimeComponent(scope, "component", component))
	require.Equal(t, 1, component.cleaned)
	require.Empty(t, scope.cleanups)
	require.NoError(t, scope.Close())
	require.Equal(t, 1, component.cleaned)
}

// A replaced or removed runtime component is closed once, and its cleanup
// does not stay registered in the long-lived parent scope.
func TestScopeCloseChildDropsCleanup(t *testing.T) {
	scope := NewScope(context.Background(), logger.NOP())
	kept, removed := new(runtimeTestComponent), new(runtimeTestComponent)
	require.NoError(t, StartRuntimeComponent(scope, "kept", kept))
	require.NoError(t, StartRuntimeComponent(scope, "removed", removed))
	require.Len(t, scope.cleanups, 2)

	require.NoError(t, CloseRuntimeComponent(scope, removed))
	require.Equal(t, 1, removed.cleaned)
	require.Len(t, scope.cleanups, 1)
	require.NotContains(t, scope.children, Lifecycle(removed))
	require.NoError(t, CloseRuntimeComponent(scope, removed))

	require.NoError(t, scope.Close())
	require.Equal(t, 1, removed.cleaned)
	require.Equal(t, 1, kept.cleaned)
}

func TestCloseRuntimeComponentIgnoresNonLifecycle(t *testing.T) {
	require.NoError(t, CloseRuntimeComponent(NewScope(context.Background(), logger.NOP()), struct{}{}))
	require.NoError(t, CloseRuntimeComponent(nil, new(runtimeTestComponent)))
}
