package adapter

import (
	"context"
	"slices"
	"sync"
)

// OutboundDialTrace records, for one routed connection, the member each
// outbound group actually dialed. The router stops chain resolution at a
// DialingOutboundGroup (Smart, URLTest), so the route-time OutboundChain ends
// at that group; the trace lets connection observers append the real node
// once the group's dial succeeds.
type OutboundDialTrace struct {
	access sync.RWMutex
	dialed map[string]Outbound
}

type outboundDialTraceKey struct{}

func ContextWithOutboundDialTrace(ctx context.Context, trace *OutboundDialTrace) context.Context {
	return context.WithValue(ctx, (*outboundDialTraceKey)(nil), trace)
}

func OutboundDialTraceFromContext(ctx context.Context) *OutboundDialTrace {
	trace, _ := ctx.Value((*outboundDialTraceKey)(nil)).(*OutboundDialTrace)
	return trace
}

// NeedOutboundDialTrace reports whether chain ends at a group that picks its
// member while dialing, i.e. whether the chain can only be completed by a trace.
func NeedOutboundDialTrace(chain []Outbound) bool {
	if len(chain) == 0 {
		return false
	}
	_, isDialing := chain[len(chain)-1].(DialingOutboundGroup)
	return isDialing
}

// RecordGroupDial notes that group successfully dialed member for the
// connection carried by ctx. A later dial by the same group overwrites the
// earlier one, so the trace follows the member currently carrying traffic.
func RecordGroupDial(ctx context.Context, group string, member Outbound) {
	if member == nil {
		return
	}
	trace := OutboundDialTraceFromContext(ctx)
	if trace == nil {
		return
	}
	trace.access.Lock()
	if trace.dialed == nil {
		trace.dialed = make(map[string]Outbound)
	}
	trace.dialed[group] = member
	trace.access.Unlock()
}

// Resolve returns chain (in route order) extended with the members recorded
// after its last outbound. The input slice is never modified.
func (t *OutboundDialTrace) Resolve(chain []Outbound) []Outbound {
	if t == nil || len(chain) == 0 {
		return chain
	}
	t.access.RLock()
	defer t.access.RUnlock()
	resolved := slices.Clip(chain)
	// Each recorded group can extend the chain at most once, which also
	// bounds a malformed cycle.
	for range len(t.dialed) {
		member, loaded := t.dialed[resolved[len(resolved)-1].Tag()]
		if !loaded {
			break
		}
		resolved = append(resolved, member)
	}
	return resolved
}
