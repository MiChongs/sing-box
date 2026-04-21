package option

import "github.com/sagernet/sing/common/json/badoption"

type ExperimentalOptions struct {
	CacheFile           *CacheFileOptions `json:"cache_file,omitempty"`
	ClashAPI            *ClashAPIOptions  `json:"clash_api,omitempty"`
	V2RayAPI            *V2RayAPIOptions  `json:"v2ray_api,omitempty"`
	Smart               *SmartOptions     `json:"smart,omitempty"`
	GeoX                *GeoXOptions      `json:"geox,omitempty"`
	Debug               *DebugOptions     `json:"debug,omitempty"`
	URLTestUnifiedDelay bool              `json:"urltest_unified_delay,omitempty"`
}

// SmartOptions configures global infrastructure shared by all Smart outbound groups:
// the LightGBM model (single .bin file on disk) and the training-sample collector
// (single CSV). Per-group opt-in is done via the Smart outbound's use_lightgbm /
// collect_data flags.
type SmartOptions struct {
	LightGBM  *SmartLightGBMOptions  `json:"lightgbm,omitempty"`
	Collector *SmartCollectorOptions `json:"collector,omitempty"`
}

type SmartLightGBMOptions struct {
	URL            string             `json:"url,omitempty"`             // default: mihomo's Model-large.bin
	AutoUpdate     bool               `json:"auto_update,omitempty"`     // periodic refresh
	UpdateInterval badoption.Duration `json:"update_interval,omitempty"` // default 72h
	ModelPath      string             `json:"model_path,omitempty"`      // default "smart_lgbm_model.bin" under base path
	HTTPClient     *HTTPClientOptions `json:"http_client,omitempty"`     // preferred: tag ref ("name") or inline
	// Deprecated: use http_client instead
	DownloadDetour string `json:"download_detour,omitempty"` // optional outbound tag for fetch
}

type SmartCollectorOptions struct {
	SizeLimitMB int64  `json:"size_limit_mb,omitempty"` // default 100
	Path        string `json:"path,omitempty"`          // default "smart_weight_data.csv"
}

// GeoXOptions configures global Geo data-file downloads (mihomo-style).
// Files are saved under filemanager base path and refreshed on an interval.
// Currently the ASN mmdb is the only file consumed by sing-box itself
// (Smart group's use_asn feature); other files are downloaded for manual
// use or future consumers.
type GeoXOptions struct {
	Enabled        bool               `json:"enabled,omitempty"`     // master switch ("geodata-mode")
	AutoUpdate     bool               `json:"auto_update,omitempty"`
	UpdateInterval badoption.Duration `json:"update_interval,omitempty"` // default 24h
	HTTPClient     *HTTPClientOptions `json:"http_client,omitempty"`     // preferred: tag ref or inline
	// Deprecated: use http_client instead
	DownloadDetour string   `json:"download_detour,omitempty"` // optional outbound tag
	URL            GeoXURLs `json:"url,omitempty"`
}

// GeoXURLs holds remote URLs for the 4 recognised geo asset types.
// Any empty field is skipped.
//
// ASN is a Listable: a single string OR an array of URLs is accepted.
// When multiple ASN sources are configured, GeoXService downloads each
// separately and Smart's lookupASN tries them in order until a hit is
// found — useful because different providers (MaxMind / IPInfo / DBIP /
// Cloudflare) have non-overlapping IP coverage.
type GeoXURLs struct {
	GeoIP   string                     `json:"geoip,omitempty"`
	GeoSite string                     `json:"geosite,omitempty"`
	MMDB    string                     `json:"mmdb,omitempty"`
	ASN     badoption.Listable[string] `json:"asn,omitempty"`
}

type CacheFileOptions struct {
	Enabled     bool               `json:"enabled,omitempty"`
	Path        string             `json:"path,omitempty"`
	CacheID     string             `json:"cache_id,omitempty"`
	StoreFakeIP bool               `json:"store_fakeip,omitempty"`
	StoreRDRC   bool               `json:"store_rdrc,omitempty"`
	RDRCTimeout badoption.Duration `json:"rdrc_timeout,omitempty"`
	StoreDNS    bool               `json:"store_dns,omitempty"`
}

type ClashAPIOptions struct {
	ExternalController               string                     `json:"external_controller,omitempty"`
	ExternalUI                       string                     `json:"external_ui,omitempty"`
	ExternalUIDownloadURL            string                     `json:"external_ui_download_url,omitempty"`
	ExternalUIHTTPClient             *HTTPClientOptions         `json:"external_ui_http_client,omitempty"`
	ExternalUIUpdateInterval         badoption.Duration         `json:"external_ui_update_interval,omitempty"`
	Secret                           string                     `json:"secret,omitempty"`
	DefaultMode                      string                     `json:"default_mode,omitempty"`
	ModeList                         []string                   `json:"-"`
	AccessControlAllowOrigin         badoption.Listable[string] `json:"access_control_allow_origin,omitempty"`
	AccessControlAllowPrivateNetwork bool                       `json:"access_control_allow_private_network,omitempty"`

	// Deprecated: migrated to global cache file
	CacheFile string `json:"cache_file,omitempty"`
	// Deprecated: migrated to global cache file
	CacheID string `json:"cache_id,omitempty"`
	// Deprecated: migrated to global cache file
	StoreMode bool `json:"store_mode,omitempty"`
	// Deprecated: migrated to global cache file
	StoreSelected bool `json:"store_selected,omitempty"`
	// Deprecated: migrated to global cache file
	StoreFakeIP bool `json:"store_fakeip,omitempty"`
	// Deprecated: use external_ui_http_client instead
	ExternalUIDownloadDetour string `json:"external_ui_download_detour,omitempty"`
}

type V2RayAPIOptions struct {
	Listen string                    `json:"listen,omitempty"`
	Stats  *V2RayStatsServiceOptions `json:"stats,omitempty"`
}

type V2RayStatsServiceOptions struct {
	Enabled   bool     `json:"enabled,omitempty"`
	Inbounds  []string `json:"inbounds,omitempty"`
	Outbounds []string `json:"outbounds,omitempty"`
	Users     []string `json:"users,omitempty"`
}
