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
