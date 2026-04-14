package option

import "github.com/sagernet/sing/common/json/badoption"

type SelectorOutboundOptions struct {
	GroupCommonOption
	Default                   string `json:"default,omitempty"`
	InterruptExistConnections bool   `json:"interrupt_exist_connections,omitempty"`
}

type URLTestOutboundOptions struct {
	GroupCommonOption
	URL                       string                 `json:"url,omitempty"`
	Interval                  badoption.Duration     `json:"interval,omitempty"`
	Tolerance                 uint16                 `json:"tolerance,omitempty"`
	IdleTimeout               badoption.Duration     `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool                   `json:"interrupt_exist_connections,omitempty"`
	Fallback                  URLTestFallbackOptions `json:"fallback,omitempty"`
}

type GroupCommonOption struct {
	Outbounds       []string          `json:"outbounds"`
	Providers       []string          `json:"providers"`
	Exclude         *badoption.Regexp `json:"exclude,omitempty"`
	Include         *badoption.Regexp `json:"include,omitempty"`
	UseAllProviders bool              `json:"use_all_providers,omitempty"`
}

type URLTestFallbackOptions struct {
	Enabled  bool               `json:"enabled,omitempty"`
	MaxDelay badoption.Duration `json:"max_delay,omitempty"`
}

type LoadBalanceOutboundOptions struct {
	GroupCommonOption
	URL                       string             `json:"url,omitempty"`
	Interval                  badoption.Duration `json:"interval,omitempty"`
	IdleTimeout               badoption.Duration `json:"idle_timeout,omitempty"`
	TTL                       badoption.Duration `json:"ttl,omitempty"`
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
	Strategy                  string             `json:"strategy,omitempty"`
}

type SmartOutboundOptions struct {
	GroupCommonOption
	URL            string             `json:"url,omitempty"`
	Interval       badoption.Duration `json:"interval,omitempty"`
	PolicyPriority string             `json:"policy_priority,omitempty"`
	UseASN         bool               `json:"use_asn,omitempty"`

	// ASNDatabase is a Listable: a single mmdb path OR an array of paths.
	// When empty, Smart falls back to experimental.geox.url.asn (which is
	// also Listable). Multiple sources are queried in order on each lookup;
	// the first hit wins. Use this when one provider's IP coverage has
	// gaps you want filled by another.
	ASNDatabase               badoption.Listable[string] `json:"asn_database,omitempty"`
	DisableUDP                bool                       `json:"disable_udp,omitempty"`
	InterruptExistConnections bool                       `json:"interrupt_exist_connections,omitempty"`

	// Host-level blocking threshold (mihomo: maxFailedTimes). When the
	// failure counter for a wildcard target reaches this value, Smart will
	// stop further node degradation on the theory that the target itself is
	// broken (not the node). Zero uses the default 10.
	MaxHostFailedTimes int `json:"max_host_failed_times,omitempty"`

	// Per-group opt-in flags. Infrastructure (model URL, update interval,
	// collector path, etc.) lives in experimental.smart at the top level and
	// is shared across all Smart groups.
	UseLightGBM bool    `json:"use_lightgbm,omitempty"` // use the shared ML model
	CollectData bool    `json:"collect_data,omitempty"` // emit training samples to shared CSV
	SampleRate  float64 `json:"sample_rate,omitempty"`  // per-group sample rate (0,1]; default 1.0
}
