package option

import "github.com/sagernet/sing/common/json/badoption"

type SmartOutboundOptions struct {
	GroupCommonOption
	URL                       string                     `json:"url,omitempty"`
	Interval                  badoption.Duration         `json:"interval,omitempty"`
	ExpectedStatus            string                     `json:"expected_status,omitempty"`
	InterruptExistConnections bool                       `json:"interrupt_exist_connections,omitempty"`
	DisableUDP                bool                       `json:"disable_udp,omitempty"`
	UseASN                    bool                       `json:"use_asn,omitempty"`
	UseLightGBM               bool                       `json:"use_lightgbm,omitempty"`
	CollectData               bool                       `json:"collect_data,omitempty"`
	SampleRate                float64                    `json:"sample_rate,omitempty"`
	MaxHostFailedTimes        int                        `json:"max_host_failed_times,omitempty"`
	Hidden                    bool                       `json:"hidden,omitempty"`
	Icon                      string                     `json:"icon,omitempty"`
	Algorithm                 string                     `json:"algorithm,omitempty"`
	Hysteresis                badoption.Duration         `json:"hysteresis,omitempty"`
	PolicyPriority            string                     `json:"policy_priority,omitempty"`
	ASNDatabase               badoption.Listable[string] `json:"asn_database,omitempty"`
}

// SmartLoadBalanceOutboundOptions configures a smart-loadbalance group: the
// Smart learning engine (every SmartOutboundOptions field keeps its meaning,
// except algorithm and hysteresis, which balance and region replace) that
// sorts its members into region pools and spreads connections across the
// nodes of the chosen pool.
type SmartLoadBalanceOutboundOptions struct {
	SmartOutboundOptions
	Balance SmartBalanceOptions `json:"balance,omitempty"`
	Region  SmartRegionOptions  `json:"region,omitempty"`
}

// SmartBalanceOptions controls how connections are spread across the nodes
// of one region pool.
type SmartBalanceOptions struct {
	Strategy              string             `json:"strategy,omitempty"`
	Affinity              string             `json:"affinity,omitempty"`
	AffinityTTL           badoption.Duration `json:"affinity_ttl,omitempty"`
	MaxNodes              int                `json:"max_nodes,omitempty"`
	MinQuality            float64            `json:"min_quality,omitempty"`
	MaxConnectionsPerNode int                `json:"max_connections_per_node,omitempty"`
}

// SmartRegionOptions controls how members are sorted into regions and which
// region serves a connection.
type SmartRegionOptions struct {
	Mode         string                        `json:"mode,omitempty"`
	Priority     badoption.Listable[string]    `json:"priority,omitempty"`
	Allow        badoption.Listable[string]    `json:"allow,omitempty"`
	Deny         badoption.Listable[string]    `json:"deny,omitempty"`
	Weights      map[string]float64            `json:"weights,omitempty"`
	Fallback     string                        `json:"fallback,omitempty"`
	MinNodes     int                           `json:"min_nodes,omitempty"`
	Sticky       badoption.Duration            `json:"sticky,omitempty"`
	SwitchMargin float64                       `json:"switch_margin,omitempty"`
	Unknown      string                        `json:"unknown,omitempty"`
	Rules        []SmartRegionRule             `json:"rules,omitempty"`
	Destination  SmartRegionDestinationOptions `json:"destination,omitempty"`
	Detect       SmartRegionDetectOptions      `json:"detect,omitempty"`
	Probe        SmartRegionProbeOptions       `json:"probe,omitempty"`
	Outbounds    SmartRegionOutboundsOptions   `json:"outbounds,omitempty"`
}

// SmartRegionRule assigns members to a region ahead of the built-in name
// detection, and names or decorates a region (built-in or custom).
type SmartRegionRule struct {
	Region    string                     `json:"region"`
	Name      string                     `json:"name,omitempty"`
	Icon      string                     `json:"icon,omitempty"`
	Match     *badoption.Regexp          `json:"match,omitempty"`
	Outbounds badoption.Listable[string] `json:"outbounds,omitempty"`
}

// SmartRegionDestinationOptions controls how the destination mode finds the
// country of a connection's target.
type SmartRegionDestinationOptions struct {
	Map            map[string]badoption.Listable[string] `json:"map,omitempty"`
	DisableTLD     bool                                  `json:"disable_tld,omitempty"`
	DisableResolve bool                                  `json:"disable_resolve,omitempty"`
}

// SmartRegionDetectOptions controls member region detection.
type SmartRegionDetectOptions struct {
	DisableName     bool               `json:"disable_name,omitempty"`
	Exit            string             `json:"exit,omitempty"`
	ExitURL         string             `json:"exit_url,omitempty"`
	ExitTTL         badoption.Duration `json:"exit_ttl,omitempty"`
	ExitTimeout     badoption.Duration `json:"exit_timeout,omitempty"`
	ExitConcurrency int                `json:"exit_concurrency,omitempty"`
}

// SmartRegionProbeOptions controls the active per-target region probes the
// auto mode uses to compare regions for frequently visited sites.
type SmartRegionProbeOptions struct {
	Disabled bool               `json:"disabled,omitempty"`
	Interval badoption.Duration `json:"interval,omitempty"`
	Targets  int                `json:"targets,omitempty"`
	Regions  int                `json:"regions,omitempty"`
}

// SmartRegionOutboundsOptions generates one smart-region outbound per region.
type SmartRegionOutboundsOptions struct {
	Enabled  bool                       `json:"enabled,omitempty"`
	Regions  badoption.Listable[string] `json:"regions,omitempty"`
	Auto     bool                       `json:"auto,omitempty"`
	Tag      string                     `json:"tag,omitempty"`
	Hidden   bool                       `json:"hidden,omitempty"`
	Icon     string                     `json:"icon,omitempty"`
	Fallback bool                       `json:"fallback,omitempty"`
	Members  string                     `json:"members,omitempty"`
}

// SmartRegionOutboundOptions configures a smart-region outbound: one region of
// a smart-loadbalance group, usable as a route outbound, a detour or a
// selector member.
type SmartRegionOutboundOptions struct {
	Group    string `json:"group" reference:"outbound"`
	Region   string `json:"region"`
	Fallback bool   `json:"fallback,omitempty"`
	Hidden   bool   `json:"hidden,omitempty"`
	Icon     string `json:"icon,omitempty"`
}

type SmartOptions struct {
	LightGBM  *SmartLightGBMOptions  `json:"lightgbm,omitempty"`
	Collector *SmartCollectorOptions `json:"collector,omitempty"`
}

type SmartLightGBMOptions struct {
	ModelPath      string             `json:"model_path,omitempty"`
	AutoUpdate     bool               `json:"auto_update,omitempty"`
	URL            string             `json:"url,omitempty"`
	UpdateInterval badoption.Duration `json:"update_interval,omitempty"`
	HTTPClient     *HTTPClientOptions `json:"http_client,omitempty"`
	DownloadDetour string             `json:"download_detour,omitempty"`
}

type SmartCollectorOptions struct {
	Path        string `json:"path,omitempty"`
	SizeLimitMB int    `json:"size_limit_mb,omitempty"`
}

type GeoXOptions struct {
	Enabled        bool               `json:"enabled,omitempty"`
	URL            GeoXURLOptions     `json:"url,omitempty"`
	AutoUpdate     bool               `json:"auto_update,omitempty"`
	UpdateInterval badoption.Duration `json:"update_interval,omitempty"`
	HTTPClient     *HTTPClientOptions `json:"http_client,omitempty"`
	DownloadDetour string             `json:"download_detour,omitempty"`
}

type GeoXURLOptions struct {
	GeoIP   string                     `json:"geoip,omitempty"`
	GeoSite string                     `json:"geosite,omitempty"`
	MMDB    string                     `json:"mmdb,omitempty"`
	ASN     badoption.Listable[string] `json:"asn,omitempty"`
}
