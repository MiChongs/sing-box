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

	// Hidden hints to dashboards / UI front-ends that this group should
	// not be displayed in the proxy switcher even though it remains
	// fully usable for routing rules. Exposed verbatim through Clash API
	// (GET /proxies) as the boolean `hidden` field — clients decide
	// whether to honour it. mihomo-compatible.
	Hidden bool `json:"hidden,omitempty"`

	// Icon is an opaque string the dashboard renders alongside the
	// group name. Convention is a URL (https://...), data: URI, or a
	// short emoji — sing-box does not interpret the value, it just
	// surfaces it through Clash API as the `icon` field. Empty string
	// means "no icon configured". mihomo-compatible.
	Icon string `json:"icon,omitempty"`
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

	// Algorithm picks the per-target re-ordering strategy applied AFTER
	// the tiered selection (unwrap → prefetch → weight → delay) returns
	// its candidate list. This is a UX knob — the underlying weight model
	// stays the same, only the final reshuffle changes.
	//
	// Recognised values (case-insensitive, "" / "auto" → strict-best):
	//
	//   strict-best     pick the top-weighted node always (default).
	//                   Lowest latency, but concentrates load on one node
	//                   and re-picks the same node after every restart.
	//
	//   weighted-random sample one of the top-K candidates with probability
	//                   proportional to weight. Spreads load across
	//                   comparable nodes; reduces "noisy neighbour" risk.
	//
	//   least-loaded    among comparable candidates, prefer the one with
	//                   fewest active connections RIGHT NOW. Best for
	//                   throughput-heavy workloads (downloads, streaming).
	//
	//   fastest-recent  prefer the candidate whose ShortRTT EWMA is lowest.
	//                   Best for interactive work where a node that JUST
	//                   slowed down should be skipped before the lifetime
	//                   mean catches up.
	//
	//   sticky-session  prefer the same node previously used for this
	//                   target if it's still in the candidate list.
	//                   Maximises connection reuse / TLS resumption.
	//
	//   round-robin     atomic per-group counter, every dial visits the
	//                   next eligible candidate. Even spread, no hot
	//                   node, ignores weight ordering.
	//
	//   weighted-rr     weighted round-robin across the top-K
	//                   candidates with bias proportional to rank.
	//                   Higher rank → more turns. Best when nodes have
	//                   meaningful capacity differences.
	//
	//   p2c             power-of-two-choices: pick two candidates from
	//                   the top-K at random, dial the one with lower
	//                   ShortRTT (or fewer active connections when RTT
	//                   ties). Provably balances load with O(1) work
	//                   per dial — Mitzenmacher 2001.
	//
	//   latency-banded  bucket the top-K candidates into < 50 / 50–150
	//                   / > 150 ms ShortRTT bands; promote a candidate
	//                   from the lowest non-empty band uniformly at
	//                   random. Removes the long tail without locking
	//                   onto the single fastest node.
	//
	// Unknown values silently fall back to strict-best.
	Algorithm string `json:"algorithm,omitempty"`

	// Hysteresis is the anti-flap window. When non-zero, the algorithm
	// will keep returning the previously-picked node for a target
	// during the window — even if a fresh evaluation now scores
	// another candidate higher — UNLESS the previous pick has dropped
	// out of the candidate list entirely (gone dead, blocked, etc.).
	//
	// Eliminates the "constantly switching between two equally-good
	// nodes" pattern that hurts TLS session resumption and produces
	// jagged latency curves on dashboards. Default 0 → no hysteresis
	// (every dial re-evaluates from scratch). Recommended 1–5 s.
	Hysteresis badoption.Duration `json:"hysteresis,omitempty"`
}
