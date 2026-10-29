package option

import (
	"context"

	"github.com/sagernet/sing/service"
)

// RemoteFetchPolicy controls how remote rule-sets and outbound providers treat
// their local files at startup.
type RemoteFetchPolicy struct {
	// Verify refetches when the cached record was downloaded from another URL.
	// When disabled, an existing local file is always used as is.
	Verify bool
	// ForceFetch fails startup when the initial fetch fails. When disabled, the
	// rule-set or provider starts empty and keeps retrying in the background.
	ForceFetch bool
}

// RemoteFetchPolicy builds the policy from remote_verify / remote_force_fetch.
// remote_force_fetch: false also disables remote_verify.
func (o *Options) RemoteFetchPolicy() RemoteFetchPolicy {
	policy := RemoteFetchPolicy{Verify: true}
	if o.RemoteForceFetch != nil {
		policy.ForceFetch = *o.RemoteForceFetch
		if !policy.ForceFetch {
			policy.Verify = false
		}
	}
	if policy.Verify && o.RemoteVerify != nil {
		policy.Verify = *o.RemoteVerify
	}
	return policy
}

func ContextWithRemoteFetchPolicy(ctx context.Context, policy RemoteFetchPolicy) context.Context {
	return service.ContextWith[*RemoteFetchPolicy](ctx, &policy)
}

func RemoteFetchPolicyFromContext(ctx context.Context) RemoteFetchPolicy {
	policy := service.FromContext[*RemoteFetchPolicy](ctx)
	if policy == nil {
		return RemoteFetchPolicy{Verify: true}
	}
	return *policy
}
