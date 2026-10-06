package nowhere

import (
	"context"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
)

type SingObserver struct{ L log.ContextLogger }

func (s SingObserver) Observe(ctx context.Context, event diagnostic.Event) {
	if s.L == nil {
		return
	}
	msg := formatDiagnosticEvent(event)
	switch event.Level {
	case diagnostic.LevelDebug:
		s.L.DebugContext(ctx, msg)
	case diagnostic.LevelWarn:
		s.L.WarnContext(ctx, msg)
	case diagnostic.LevelError:
		s.L.ErrorContext(ctx, msg)
	default:
		s.L.InfoContext(ctx, msg)
	}
}

var _ diagnostic.Observer = SingObserver{}
