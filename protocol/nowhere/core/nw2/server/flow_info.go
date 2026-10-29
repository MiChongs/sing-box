package server

import "context"

// FlowInfo describes protocol metadata associated with an authenticated
// logical flow. It is attached to the context passed to Upstream methods.
type FlowInfo struct {
	// Hops is the remaining native Portal forwarding budget received from the
	// client. Vector-originated flows carry zero.
	Hops uint8
}

type flowInfoContextKey struct{}

func withFlowInfo(ctx context.Context, info FlowInfo) context.Context {
	return context.WithValue(ctx, flowInfoContextKey{}, info)
}

// FlowInfoFromContext returns the logical-flow metadata attached by Handler.
func FlowInfoFromContext(ctx context.Context) (FlowInfo, bool) {
	if ctx == nil {
		return FlowInfo{}, false
	}
	info, ok := ctx.Value(flowInfoContextKey{}).(FlowInfo)
	return info, ok
}
