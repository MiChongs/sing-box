package parser

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// XHTTPOptions mirrors mihomo's xhttp-opts (adapter/outbound/vless.go).
// Range fields are strings there and accept "1000" or "100-1000".
//
//	xhttp-opts:
//	  path: /yyy
//	  host: example.com
//	  mode: packet-up
//	  headers: {User-Agent: ...}
//	  x-padding-bytes: "100-1000"
//	  reuse-settings: {max-connections: "3", ...}   # Xray xmux
//	  download-settings: {server: ..., path: ...}   # upload/download split
//
// no-sse-header and sc-max-buffered-posts are Xray options mihomo lacks; they
// are accepted so subscriptions written for either core convert losslessly.
type XHTTPOptions struct {
	Path                 string                 `yaml:"path,omitempty"`
	Host                 string                 `yaml:"host,omitempty"`
	Mode                 string                 `yaml:"mode,omitempty"`
	Headers              map[string]string      `yaml:"headers,omitempty"`
	NoGRPCHeader         bool                   `yaml:"no-grpc-header,omitempty"`
	NoSSEHeader          bool                   `yaml:"no-sse-header,omitempty"`
	XPaddingBytes        string                 `yaml:"x-padding-bytes,omitempty"`
	XPaddingObfsMode     bool                   `yaml:"x-padding-obfs-mode,omitempty"`
	XPaddingKey          string                 `yaml:"x-padding-key,omitempty"`
	XPaddingHeader       string                 `yaml:"x-padding-header,omitempty"`
	XPaddingPlacement    string                 `yaml:"x-padding-placement,omitempty"`
	XPaddingMethod       string                 `yaml:"x-padding-method,omitempty"`
	UplinkHTTPMethod     string                 `yaml:"uplink-http-method,omitempty"`
	SessionPlacement     string                 `yaml:"session-placement,omitempty"`
	SessionKey           string                 `yaml:"session-key,omitempty"`
	SessionTable         string                 `yaml:"session-table,omitempty"`
	SessionLength        string                 `yaml:"session-length,omitempty"`
	SeqPlacement         string                 `yaml:"seq-placement,omitempty"`
	SeqKey               string                 `yaml:"seq-key,omitempty"`
	UplinkDataPlacement  string                 `yaml:"uplink-data-placement,omitempty"`
	UplinkDataKey        string                 `yaml:"uplink-data-key,omitempty"`
	UplinkChunkSize      string                 `yaml:"uplink-chunk-size,omitempty"`
	ScMaxEachPostBytes   string                 `yaml:"sc-max-each-post-bytes,omitempty"`
	ScMinPostsIntervalMs string                 `yaml:"sc-min-posts-interval-ms,omitempty"`
	ScMaxBufferedPosts   int64                  `yaml:"sc-max-buffered-posts,omitempty"`
	ReuseSettings        *XHTTPReuseSettings    `yaml:"reuse-settings,omitempty"`
	DownloadSettings     *XHTTPDownloadSettings `yaml:"download-settings,omitempty"`
}

// XHTTPReuseSettings is mihomo's reuse-settings, i.e. Xray xmux.
type XHTTPReuseSettings struct {
	MaxConcurrency   string `yaml:"max-concurrency,omitempty"`
	MaxConnections   string `yaml:"max-connections,omitempty"`
	CMaxReuseTimes   string `yaml:"c-max-reuse-times,omitempty"`
	HMaxRequestTimes string `yaml:"h-max-request-times,omitempty"`
	HMaxReusableSecs string `yaml:"h-max-reusable-secs,omitempty"`
	HKeepAlivePeriod int64  `yaml:"h-keep-alive-period,omitempty"`
}

// XHTTPDownloadSettings is mihomo's download-settings. Unlike Xray, every
// unset field inherits the upload side (path, host, headers, xmux, server,
// port and TLS), so build materializes that inheritance into the
// self-contained option.V2RayXHTTPDownloadOptions.
type XHTTPDownloadSettings struct {
	Path              *string             `yaml:"path,omitempty"`
	Host              *string             `yaml:"host,omitempty"`
	Headers           *map[string]string  `yaml:"headers,omitempty"`
	ReuseSettings     *XHTTPReuseSettings `yaml:"reuse-settings,omitempty"`
	Server            *string             `yaml:"server,omitempty"`
	Port              *int                `yaml:"port,omitempty"`
	TLS               *bool               `yaml:"tls,omitempty"`
	ALPN              *[]string           `yaml:"alpn,omitempty"`
	ECHOpts           *ECHOptions         `yaml:"ech-opts,omitempty"`
	RealityOpts       *RealityOptions     `yaml:"reality-opts,omitempty"`
	SkipCertVerify    *bool               `yaml:"skip-cert-verify,omitempty"`
	Fingerprint       *string             `yaml:"fingerprint,omitempty"`
	ServerName        *string             `yaml:"servername,omitempty"`
	ClientFingerprint *string             `yaml:"client-fingerprint,omitempty"`
}

// clashXHTTP carries what the xhttp-opts conversion needs from the proxy
// itself to resolve download-settings inheritance.
type clashXHTTP struct {
	options    XHTTPOptions
	server     string
	port       int
	serverName string // servername / sni as written, before the server fallback
	tls        *TLSOptions
}

func (x clashXHTTP) build() *option.V2RayTransportOptions {
	xhttpOptions := x.options.build()
	if download := x.options.DownloadSettings; download != nil {
		xhttpOptions.DownloadSettings = x.buildDownload(download, xhttpOptions)
	}
	return &option.V2RayTransportOptions{
		Type:  C.V2RayTransportTypeXHTTP,
		Extra: &xhttpOptions,
	}
}

func (x XHTTPOptions) build() option.V2RayXHTTPOptions {
	host, headers := xhttpHostAndHeaders(x.Host, x.Headers)
	return option.V2RayXHTTPOptions{
		Host:                 host,
		Path:                 x.Path,
		Mode:                 x.Mode,
		Headers:              headers,
		XPaddingBytes:        xhttpRange(x.XPaddingBytes),
		XPaddingObfsMode:     x.XPaddingObfsMode,
		XPaddingKey:          x.XPaddingKey,
		XPaddingHeader:       x.XPaddingHeader,
		XPaddingPlacement:    x.XPaddingPlacement,
		XPaddingMethod:       x.XPaddingMethod,
		UplinkHTTPMethod:     x.UplinkHTTPMethod,
		SessionPlacement:     x.SessionPlacement,
		SessionKey:           x.SessionKey,
		SessionIDTable:       x.SessionTable,
		SessionIDLength:      xhttpRange(x.SessionLength),
		SeqPlacement:         x.SeqPlacement,
		SeqKey:               x.SeqKey,
		UplinkDataPlacement:  x.UplinkDataPlacement,
		UplinkDataKey:        x.UplinkDataKey,
		UplinkChunkSize:      xhttpRange(x.UplinkChunkSize),
		NoGRPCHeader:         x.NoGRPCHeader,
		NoSSEHeader:          x.NoSSEHeader,
		ScMaxEachPostBytes:   xhttpRange(x.ScMaxEachPostBytes),
		ScMinPostsIntervalMs: xhttpRange(x.ScMinPostsIntervalMs),
		ScMaxBufferedPosts:   x.ScMaxBufferedPosts,
		Xmux:                 x.ReuseSettings.build(),
	}
}

func (r *XHTTPReuseSettings) build() *option.V2RayXHTTPXmuxOptions {
	if r == nil {
		return nil
	}
	return &option.V2RayXHTTPXmuxOptions{
		MaxConcurrency:   xhttpRange(r.MaxConcurrency),
		MaxConnections:   xhttpRange(r.MaxConnections),
		CMaxReuseTimes:   xhttpRange(r.CMaxReuseTimes),
		HMaxRequestTimes: xhttpRange(r.HMaxRequestTimes),
		HMaxReusableSecs: xhttpRange(r.HMaxReusableSecs),
		HKeepAlivePeriod: r.HKeepAlivePeriod,
	}
}

func (x clashXHTTP) buildDownload(download *XHTTPDownloadSettings, upload option.V2RayXHTTPOptions) *option.V2RayXHTTPDownloadOptions {
	downloadOptions := &option.V2RayXHTTPDownloadOptions{
		ServerOptions: option.ServerOptions{
			Server:     x.server,
			ServerPort: uint16(x.port),
		},
		V2RayXHTTPOptions: upload,
	}
	if download.Server != nil {
		downloadOptions.Server = *download.Server
	}
	if download.Port != nil {
		downloadOptions.ServerPort = uint16(*download.Port)
	}
	if download.Path != nil {
		downloadOptions.Path = *download.Path
	}
	if download.Host != nil || download.Headers != nil {
		host, headers := upload.Host, upload.Headers
		if download.Host != nil {
			host = nil
			if *download.Host != "" {
				host = xhttpHostList(*download.Host)
			}
		}
		if download.Headers != nil {
			var downloadHost badoption.Listable[string]
			downloadHost, headers = xhttpHostAndHeaders("", *download.Headers)
			if download.Host == nil && len(downloadHost) > 0 {
				host = downloadHost
			}
		}
		downloadOptions.Host, downloadOptions.Headers = host, headers
	}
	if download.ReuseSettings != nil {
		downloadOptions.Xmux = download.ReuseSettings.build()
	}

	var tlsOptions TLSOptions
	if x.tls != nil {
		tlsOptions = *x.tls
	}
	if download.TLS != nil {
		tlsOptions.TLS = *download.TLS
	}
	if download.ALPN != nil {
		tlsOptions.ALPN = *download.ALPN
	}
	if download.SkipCertVerify != nil {
		tlsOptions.SkipCertVerify = *download.SkipCertVerify
	}
	if download.Fingerprint != nil {
		tlsOptions.Fingerprint = *download.Fingerprint
	}
	if download.ClientFingerprint != nil {
		tlsOptions.ClientFingerprint = *download.ClientFingerprint
	}
	if download.ECHOpts != nil {
		tlsOptions.ECHOpts = download.ECHOpts
	}
	if download.RealityOpts != nil {
		tlsOptions.RealityOpts = download.RealityOpts
	}
	tlsOptions.SNI = x.serverName
	if download.ServerName != nil {
		tlsOptions.SNI = *download.ServerName
	}
	if tlsOptions.SNI == "" {
		tlsOptions.SNI = downloadOptions.Server
	}
	downloadOptions.TLS = tlsOptions.Build()
	return downloadOptions
}

// v2rayTransportXHTTP builds the XHTTP transport of a V2Ray/Xray share link
// (type=xhttp / net=xhttp). It follows Xray's share link rules: host, path and
// mode come from the link itself, every other setting from the URL-encoded
// xhttpSettings JSON in extra (Xray SplitHTTPConfig.Build ignores host, path
// and mode inside extra).
func v2rayTransportXHTTP(proxy map[string]string) option.V2RayTransportOptions {
	var xhttpOptions option.V2RayXHTTPOptions
	if extra := proxy["extra"]; extra != "" {
		var settings xrayXHTTPSettings
		if json.Unmarshal([]byte(extra), &settings) == nil {
			settings.Host = ""
			// Host now only comes from a Host header inside extra.
			xhttpOptions = settings.build()
		}
	}
	if host := xhttpHostList(proxy["host"]); len(host) > 0 {
		xhttpOptions.Host = host
	}
	xhttpOptions.Path = proxy["path"]
	xhttpOptions.Mode = proxy["mode"]
	return option.V2RayTransportOptions{
		Type:  C.V2RayTransportTypeXHTTP,
		Extra: &xhttpOptions,
	}
}

// xrayXHTTPSettings is Xray's xhttpSettings JSON (infra/conf SplitHTTPConfig).
type xrayXHTTPSettings struct {
	Host                 string              `json:"host"`
	Path                 string              `json:"path"`
	Mode                 string              `json:"mode"`
	Headers              map[string]string   `json:"headers"`
	XPaddingBytes        option.XHTTPRange   `json:"xPaddingBytes"`
	XPaddingObfsMode     bool                `json:"xPaddingObfsMode"`
	XPaddingKey          string              `json:"xPaddingKey"`
	XPaddingHeader       string              `json:"xPaddingHeader"`
	XPaddingPlacement    string              `json:"xPaddingPlacement"`
	XPaddingMethod       string              `json:"xPaddingMethod"`
	UplinkHTTPMethod     string              `json:"uplinkHTTPMethod"`
	SessionIDPlacement   string              `json:"sessionIDPlacement"`
	SessionIDKey         string              `json:"sessionIDKey"`
	SessionIDTable       string              `json:"sessionIDTable"`
	SessionIDLength      option.XHTTPRange   `json:"sessionIDLength"`
	SeqPlacement         string              `json:"seqPlacement"`
	SeqKey               string              `json:"seqKey"`
	UplinkDataPlacement  string              `json:"uplinkDataPlacement"`
	UplinkDataKey        string              `json:"uplinkDataKey"`
	UplinkChunkSize      option.XHTTPRange   `json:"uplinkChunkSize"`
	NoGRPCHeader         bool                `json:"noGRPCHeader"`
	NoSSEHeader          bool                `json:"noSSEHeader"`
	ScMaxEachPostBytes   option.XHTTPRange   `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs option.XHTTPRange   `json:"scMinPostsIntervalMs"`
	ScMaxBufferedPosts   int64               `json:"scMaxBufferedPosts"`
	ScStreamUpServerSecs option.XHTTPRange   `json:"scStreamUpServerSecs"`
	ServerMaxHeaderBytes int32               `json:"serverMaxHeaderBytes"`
	Xmux                 *xrayXmux           `json:"xmux"`
	DownloadSettings     *xrayStreamSettings `json:"downloadSettings"`
}

type xrayXmux struct {
	MaxConcurrency   option.XHTTPRange `json:"maxConcurrency"`
	MaxConnections   option.XHTTPRange `json:"maxConnections"`
	CMaxReuseTimes   option.XHTTPRange `json:"cMaxReuseTimes"`
	HMaxRequestTimes option.XHTTPRange `json:"hMaxRequestTimes"`
	HMaxReusableSecs option.XHTTPRange `json:"hMaxReusableSecs"`
	HKeepAlivePeriod int64             `json:"hKeepAlivePeriod"`
}

// xrayStreamSettings is the subset of Xray streamSettings that
// downloadSettings uses.
//
// ALPN is not an Xray field: some subscription generators write mihomo's
// download-settings.alpn there instead of in tlsSettings (e.g. "alpn": ["h3"]
// for an HTTP/3 download). It is used when tlsSettings sets no ALPN.
type xrayStreamSettings struct {
	Address           string                     `json:"address"`
	Port              uint16                     `json:"port"`
	Network           string                     `json:"network"`
	Security          string                     `json:"security"`
	ALPN              badoption.Listable[string] `json:"alpn"`
	TLSSettings       *xrayTLSSettings           `json:"tlsSettings"`
	REALITYSettings   *xrayRealitySettings       `json:"realitySettings"`
	XHTTPSettings     *xrayXHTTPSettings         `json:"xhttpSettings"`
	SplitHTTPSettings *xrayXHTTPSettings         `json:"splithttpSettings"`
}

type xrayTLSSettings struct {
	ServerName    string                     `json:"serverName"`
	AllowInsecure bool                       `json:"allowInsecure"`
	ALPN          badoption.Listable[string] `json:"alpn"`
	Fingerprint   string                     `json:"fingerprint"`
}

type xrayRealitySettings struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	Password    string `json:"password"`
	ShortID     string `json:"shortId"`
}

func (s xrayXHTTPSettings) build() option.V2RayXHTTPOptions {
	host, headers := xhttpHostAndHeaders(s.Host, s.Headers)
	xhttpOptions := option.V2RayXHTTPOptions{
		Host:                 host,
		Path:                 s.Path,
		Mode:                 s.Mode,
		Headers:              headers,
		XPaddingBytes:        s.XPaddingBytes,
		XPaddingObfsMode:     s.XPaddingObfsMode,
		XPaddingKey:          s.XPaddingKey,
		XPaddingHeader:       s.XPaddingHeader,
		XPaddingPlacement:    s.XPaddingPlacement,
		XPaddingMethod:       s.XPaddingMethod,
		UplinkHTTPMethod:     s.UplinkHTTPMethod,
		SessionPlacement:     s.SessionIDPlacement,
		SessionKey:           s.SessionIDKey,
		SessionIDTable:       s.SessionIDTable,
		SessionIDLength:      s.SessionIDLength,
		SeqPlacement:         s.SeqPlacement,
		SeqKey:               s.SeqKey,
		UplinkDataPlacement:  s.UplinkDataPlacement,
		UplinkDataKey:        s.UplinkDataKey,
		UplinkChunkSize:      s.UplinkChunkSize,
		NoGRPCHeader:         s.NoGRPCHeader,
		NoSSEHeader:          s.NoSSEHeader,
		ScMaxEachPostBytes:   s.ScMaxEachPostBytes,
		ScMinPostsIntervalMs: s.ScMinPostsIntervalMs,
		ScMaxBufferedPosts:   s.ScMaxBufferedPosts,
		ScStreamUpServerSecs: s.ScStreamUpServerSecs,
		ServerMaxHeaderBytes: s.ServerMaxHeaderBytes,
	}
	if s.Xmux != nil {
		xhttpOptions.Xmux = &option.V2RayXHTTPXmuxOptions{
			MaxConcurrency:   s.Xmux.MaxConcurrency,
			MaxConnections:   s.Xmux.MaxConnections,
			CMaxReuseTimes:   s.Xmux.CMaxReuseTimes,
			HMaxRequestTimes: s.Xmux.HMaxRequestTimes,
			HMaxReusableSecs: s.Xmux.HMaxReusableSecs,
			HKeepAlivePeriod: s.Xmux.HKeepAlivePeriod,
		}
	}
	if s.DownloadSettings != nil {
		xhttpOptions.DownloadSettings = s.DownloadSettings.build()
	}
	return xhttpOptions
}

// build converts downloadSettings. As in Xray, nothing is inherited from the
// upload side except the address, which the transport falls back to when
// server is empty.
func (s *xrayStreamSettings) build() *option.V2RayXHTTPDownloadOptions {
	switch s.Network {
	case "", "xhttp", "splithttp":
	default:
		return nil
	}
	downloadOptions := &option.V2RayXHTTPDownloadOptions{
		ServerOptions: option.ServerOptions{
			Server:     s.Address,
			ServerPort: s.Port,
		},
	}
	settings := s.XHTTPSettings
	if settings == nil {
		settings = s.SplitHTTPSettings
	}
	if settings != nil {
		nested := *settings
		nested.DownloadSettings = nil
		downloadOptions.V2RayXHTTPOptions = nested.build()
	}
	switch s.Security {
	case "tls":
		tlsOptions := &option.OutboundTLSOptions{Enabled: true}
		if s.TLSSettings != nil {
			tlsOptions.ServerName = s.TLSSettings.ServerName
			tlsOptions.Insecure = s.TLSSettings.AllowInsecure
			tlsOptions.ALPN = s.TLSSettings.ALPN
			if s.TLSSettings.Fingerprint != "" {
				tlsOptions.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: s.TLSSettings.Fingerprint}
			}
		}
		if len(tlsOptions.ALPN) == 0 {
			tlsOptions.ALPN = s.ALPN
		}
		downloadOptions.TLS = tlsOptions
	case "reality":
		tlsOptions := &option.OutboundTLSOptions{
			Enabled: true,
			UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
			Reality: &option.OutboundRealityOptions{Enabled: true},
		}
		if reality := s.REALITYSettings; reality != nil {
			tlsOptions.ServerName = reality.ServerName
			if reality.Fingerprint != "" {
				tlsOptions.UTLS.Fingerprint = reality.Fingerprint
			}
			tlsOptions.Reality.PublicKey = reality.PublicKey
			if tlsOptions.Reality.PublicKey == "" {
				tlsOptions.Reality.PublicKey = reality.Password
			}
			tlsOptions.Reality.ShortID = reality.ShortID
		}
		downloadOptions.TLS = tlsOptions
	}
	return downloadOptions
}

// xhttpHostAndHeaders splits a comma-separated host list and moves a Host
// header, which XHTTP rejects in headers, into the host list when no host is
// set explicitly.
func xhttpHostAndHeaders(host string, headers map[string]string) (badoption.Listable[string], badoption.HTTPHeader) {
	hostList := xhttpHostList(host)
	var httpHeaders badoption.HTTPHeader
	for key, value := range headers {
		if strings.EqualFold(key, "Host") {
			if len(hostList) == 0 {
				hostList = xhttpHostList(value)
			}
			continue
		}
		if httpHeaders == nil {
			httpHeaders = make(badoption.HTTPHeader)
		}
		httpHeaders[key] = badoption.Listable[string]{value}
	}
	return hostList, httpHeaders
}

func xhttpHostList(host string) badoption.Listable[string] {
	var hostList badoption.Listable[string]
	for _, it := range strings.Split(host, ",") {
		if it = strings.TrimSpace(it); it != "" {
			hostList = append(hostList, it)
		}
	}
	return hostList
}

// xhttpRange parses a mihomo range string; an invalid value falls back to the
// transport default, like any other malformed optional field in this parser.
func xhttpRange(value string) option.XHTTPRange {
	parsed, _ := option.ParseXHTTPRange(value)
	return parsed
}
