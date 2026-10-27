package group

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

// Short names accepted by include_type / exclude_type, following the
// spellings used by Clash subscriptions.
var memberTypeAliases = map[string]string{
	"ss":     "shadowsocks",
	"socks5": "socks",
	"hy":     "hysteria",
	"hy2":    "hysteria2",
	"wg":     "wireguard",
}

// memberFilter decides which provider nodes join a group. Nodes listed in
// `outbounds` are always kept, matching how include / exclude behave.
type memberFilter struct {
	include     *regexp.Regexp
	exclude     *regexp.Regexp
	includeType []string
	excludeType []string
	// every listed network must be supported by the node itself
	networks []string
}

func newMemberFilter(ctx context.Context, options option.GroupCommonOption) (*memberFilter, error) {
	includeType, err := normalizeMemberTypes(ctx, "include_type", options.IncludeType)
	if err != nil {
		return nil, err
	}
	excludeType, err := normalizeMemberTypes(ctx, "exclude_type", options.ExcludeType)
	if err != nil {
		return nil, err
	}
	var networks []string
	// Build() of an empty list means "tcp and udp", but an unset field must not
	// filter anything here.
	if options.Network != "" {
		networks = options.Network.Build()
	}
	return &memberFilter{
		include:     (*regexp.Regexp)(options.Include),
		exclude:     (*regexp.Regexp)(options.Exclude),
		includeType: includeType,
		excludeType: excludeType,
		networks:    networks,
	}, nil
}

func normalizeMemberTypes(ctx context.Context, field string, types []string) ([]string, error) {
	if len(types) == 0 {
		return nil, nil
	}
	known := knownMemberTypes(ctx)
	normalized := make([]string, 0, len(types))
	for _, memberType := range types {
		name := strings.ToLower(strings.TrimSpace(memberType))
		if alias, loaded := memberTypeAliases[name]; loaded {
			name = alias
		}
		if known != nil && !slices.Contains(known, name) {
			return nil, E.New(field, ": unknown outbound type: ", memberType)
		}
		if !slices.Contains(normalized, name) {
			normalized = append(normalized, name)
		}
	}
	return normalized, nil
}

// knownMemberTypes returns nil when the registries are unavailable, which
// disables validation instead of rejecting every type.
func knownMemberTypes(ctx context.Context) []string {
	var known []string
	if registry := service.FromContext[option.OutboundOptionsRegistry](ctx); registry != nil {
		known = append(known, registry.OptionTypes()...)
	}
	if registry := service.FromContext[option.EndpointOptionsRegistry](ctx); registry != nil {
		known = append(known, registry.OptionTypes()...)
	}
	return known
}

func (f *memberFilter) Match(detour adapter.Outbound) bool {
	if f == nil {
		return true
	}
	tag := detour.Tag()
	if f.exclude != nil && f.exclude.MatchString(tag) {
		return false
	}
	if f.include != nil && !f.include.MatchString(tag) {
		return false
	}
	if len(f.includeType) > 0 || len(f.excludeType) > 0 {
		memberType := strings.ToLower(detour.Type())
		if slices.Contains(f.excludeType, memberType) {
			return false
		}
		if len(f.includeType) > 0 && !slices.Contains(f.includeType, memberType) {
			return false
		}
	}
	if len(f.networks) > 0 {
		supported := detour.Network()
		for _, network := range f.networks {
			if !slices.Contains(supported, network) {
				return false
			}
		}
	}
	return true
}
