package assetdl

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

// ResolveTransport returns the transport for downloads configured by an
// http_client field and the legacy download_detour field, resolved like
// remote rule-sets and providers do: the http_client (a tag or inline
// options, applied in full: dialer, TLS, headers, HTTP version), else a
// client dialing through download_detour, else the default http client.
// A nil transport with nil error means no http client manager is
// available, and the downloader dials directly.
func ResolveTransport(ctx context.Context, logger logger.ContextLogger, httpClient *option.HTTPClientOptions, downloadDetour string) (adapter.HTTPTransport, error) {
	manager := service.FromContext[adapter.HTTPClientManager](ctx)
	if manager == nil {
		return nil, nil
	}
	if httpClient != nil && !httpClient.IsEmpty() {
		if downloadDetour != "" {
			logger.Warn("download_detour is ignored because http_client is set")
		}
		return manager.ResolveTransport(ctx, logger, *httpClient)
	}
	if downloadDetour != "" {
		return manager.ResolveTransport(ctx, logger, option.HTTPClientOptions{
			DialerOptions: option.DialerOptions{
				Detour: downloadDetour,
			},
			DisableEmptyDirectCheck: true,
		})
	}
	transport := manager.DefaultTransport()
	if transport == nil {
		return nil, E.New("default http client transport is not initialized")
	}
	return transport, nil
}
