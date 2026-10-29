package option

import "github.com/sagernet/sing/common/json/badoption"

type AnyXInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	Transport             *V2RayTransportOptions     `json:"transport,omitempty"`
	Encryption            *AnyXEncryptionOptions     `json:"encryption,omitempty"`
	Users                 []AnyXUser                 `json:"users,omitempty"`
	PaddingScheme         badoption.Listable[string] `json:"padding_scheme,omitempty"`
	PaddingSchemeInterval badoption.Duration         `json:"padding_scheme_interval,omitempty"`
	PaddingLimit          int                        `json:"padding_limit,omitempty"`
	Fallback              *ServerOptions             `json:"fallback,omitempty"`
	FallbackForALPN       map[string]*ServerOptions  `json:"fallback_for_alpn,omitempty"`
}

type AnyXUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

type AnyXOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Transport             *V2RayTransportOptions     `json:"transport,omitempty"`
	Encryption            *AnyXEncryptionOptions     `json:"encryption,omitempty"`
	Password              string                     `json:"password,omitempty"`
	PaddingScheme         badoption.Listable[string] `json:"padding_scheme,omitempty"`
	PaddingSchemeInterval badoption.Duration         `json:"padding_scheme_interval,omitempty"`
	IdleSessionMinTimeout badoption.Duration         `json:"idle_session_min_timeout,omitempty"`
	IdleSessionTimeout    badoption.Duration         `json:"idle_session_timeout,omitempty"`
	MinIdleSession        int                        `json:"min_idle_session,omitempty"`
	ClientMetadata        *string                    `json:"client_metadata,omitempty"`
	DisableReuse          bool                       `json:"disable_reuse,omitempty"`
	Network               NetworkList                `json:"network,omitempty"`

	// Deprecated: replaced by idle_session_min_timeout
	IdleSessionCheckInterval badoption.Duration `json:"idle_session_check_interval,omitempty"`
}

type AnyXEncryptionOptions struct {
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
}
