package parser

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// override_dialer reaches every dialing protocol, not only the hand-listed
// ones, so provider_domain_resolver covers the whole subscription.
func TestOverrideDialerReachesEveryProtocol(t *testing.T) {
	t.Parallel()
	outbounds, _, err := ParseSubscription(context.Background(), `
proxies:
  - {name: ssh-node, type: ssh, server: ssh.example, port: 22, username: root, password: pass}
`, &option.OverrideDialerOptions{
		DomainResolver: &option.DomainResolveOptions{Server: "sub-dns"},
	}, nil, nil, nil, "sub")
	require.NoError(t, err)
	require.Len(t, outbounds, 1)
	require.Equal(t, C.TypeSSH, outbounds[0].Type)
	options, isWrapper := outbounds[0].Options.(option.DialerOptionsWrapper)
	require.True(t, isWrapper)
	dialerOptions := options.TakeDialerOptions()
	require.NotNil(t, dialerOptions.DomainResolver)
	require.Equal(t, "sub-dns", dialerOptions.DomainResolver.Server)
}
