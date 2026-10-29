package option

import (
	"context"
	"testing"

	"github.com/sagernet/sing/common"

	"github.com/stretchr/testify/require"
)

func TestRemoteFetchPolicy(t *testing.T) {
	for _, testCase := range []struct {
		verify, forceFetch *bool
		expected           RemoteFetchPolicy
	}{
		{nil, nil, RemoteFetchPolicy{Verify: true}},
		{common.Ptr(false), nil, RemoteFetchPolicy{}},
		{nil, common.Ptr(true), RemoteFetchPolicy{Verify: true, ForceFetch: true}},
		{common.Ptr(false), common.Ptr(true), RemoteFetchPolicy{ForceFetch: true}},
		{common.Ptr(true), common.Ptr(false), RemoteFetchPolicy{}},
	} {
		options := Options{RemoteVerify: testCase.verify, RemoteForceFetch: testCase.forceFetch}
		require.Equal(t, testCase.expected, options.RemoteFetchPolicy())
	}
	require.Equal(t, RemoteFetchPolicy{Verify: true}, RemoteFetchPolicyFromContext(context.Background()))
	ctx := ContextWithRemoteFetchPolicy(context.Background(), RemoteFetchPolicy{ForceFetch: true})
	require.Equal(t, RemoteFetchPolicy{ForceFetch: true}, RemoteFetchPolicyFromContext(ctx))
}
