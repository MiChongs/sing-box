package parser

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"

	"github.com/stretchr/testify/require"
)

func TestOverrideAnyTLSOptions(t *testing.T) {
	testCases := []struct {
		name                   string
		clientMetadata         *string
		disableReuse           bool
		override               *option.OverrideAnyTLSOptions
		expectedClientMetadata *string
		expectedDisableReuse   bool
	}{
		{
			name: "preserve unset",
		},
		{
			name:                   "preserve value",
			clientMetadata:         common.Ptr("original-client/1.0"),
			disableReuse:           true,
			expectedClientMetadata: common.Ptr("original-client/1.0"),
			expectedDisableReuse:   true,
		},
		{
			name:           "clear",
			clientMetadata: common.Ptr("original-client/1.0"),
			disableReuse:   true,
			override: &option.OverrideAnyTLSOptions{
				ClientMetadata: common.Ptr(""),
				DisableReuse:   common.Ptr(false),
			},
			expectedClientMetadata: common.Ptr(""),
		},
		{
			name: "replace",
			override: &option.OverrideAnyTLSOptions{
				ClientMetadata: common.Ptr("custom-client/1.0"),
				DisableReuse:   common.Ptr(true),
			},
			expectedClientMetadata: common.Ptr("custom-client/1.0"),
			expectedDisableReuse:   true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			outbounds := overrideOutbounds([]option.Outbound{{
				Type: C.TypeAnyTLS,
				Options: &option.AnyTLSOutboundOptions{
					ClientMetadata: testCase.clientMetadata,
					DisableReuse:   testCase.disableReuse,
				},
			}}, nil, nil, testCase.override, nil, "")
			options := outbounds[0].Options.(*option.AnyTLSOutboundOptions)
			require.Equal(t, testCase.expectedClientMetadata, options.ClientMetadata)
			require.Equal(t, testCase.expectedDisableReuse, options.DisableReuse)
		})
	}
}

func TestOverrideDialerKeepsDomainResolver(t *testing.T) {
	resolver := &option.DomainResolveOptions{Server: "remote-dns"}
	detour := "front"
	outbounds := overrideOutbounds([]option.Outbound{{
		Type: C.TypeSOCKS,
		Tag:  "node",
		Options: &option.SOCKSOutboundOptions{
			DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{DomainResolver: resolver}},
		},
	}}, &option.OverrideDialerOptions{Detour: &detour}, nil, nil, []string{"node"}, "provider")
	options := outbounds[0].Options.(*option.SOCKSOutboundOptions)
	require.Equal(t, "front", options.Detour)
	require.Equal(t, resolver, options.DomainResolver, "override without domain_resolver must keep the node's own")

	override := &option.DomainResolveOptions{Server: "override-dns"}
	outbounds = overrideOutbounds([]option.Outbound{{
		Type: C.TypeSOCKS,
		Options: &option.SOCKSOutboundOptions{
			DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{DomainResolver: resolver}},
		},
	}}, &option.OverrideDialerOptions{DomainResolver: override}, nil, nil, nil, "")
	require.Equal(t, override, outbounds[0].Options.(*option.SOCKSOutboundOptions).DomainResolver)
}
