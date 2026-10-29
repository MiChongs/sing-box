package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

// NowhereOutboundOptions is the SingBox Nowhere client configuration.
// Nowhere 3 (nw3) is the default stack: it speaks only ALPN nw3, uses exactly
// one transport selected by net, requires a 32-character lowercase hex key, and
// turns Morph on by default. Nowhere 2 (nw2) is the legacy stack kept for
// compatibility with pre-nw3 peers: select it by setting tls.alpn to a single
// non-nw3 value (conventionally "nw2"), which keeps every legacy field below
// meaningful. The two stacks share no handshake, so a single endpoint runs
// exactly one stack and the fields of the other stack are rejected.
type NowhereOutboundOptions struct {
	DialerOptions
	ServerOptions
	Password string `json:"password,omitempty"`
	// Pin is the leaf certificate SHA-256 (lowercase hex). When set it overrides
	// SNI/chain verification for Nowhere TLS (TCP and QUIC).
	Pin  string `json:"pin,omitempty"`
	Up   string `json:"up,omitempty"`
	Down string `json:"down,omitempty"`
	Mux  *int   `json:"mux,omitempty"`
	Pool *int   `json:"pool,omitempty"`
	// Morph enables the keyed transport transform for every transport of this
	// endpoint (64-byte TCP prelude below TLS, directional ChaCha20 keys below
	// QUIC). There is no negotiation: both ends of a hop must agree. Nowhere 2
	// defaults to off; Nowhere 3 defaults to on.
	Morph                 *bool              `json:"morph,omitempty"`
	PrewarmOnStart        bool               `json:"prewarm_on_start,omitempty"`
	MaxConcurrentDials    *int               `json:"max_concurrent_dials,omitempty"`
	WarmBackoffInitial    badoption.Duration `json:"warm_backoff_initial,omitempty"`
	WarmBackoffMax        badoption.Duration `json:"warm_backoff_max,omitempty"`
	QUICCongestionControl string             `json:"quic_congestion_control,omitempty"`
	// Net selects the single Nowhere 3 transport: tcp (TLS over TCP) or udp
	// (QUIC). Empty means tcp. It is a Nowhere 3 field: the nw2 stack selects
	// its transports via up/down instead and rejects net.
	Net string `json:"net,omitempty"`
	OutboundTLSOptionsContainer
	QUICOptions
}

// NowhereNextOptions configures native Portal chaining on a Nowhere inbound:
// authenticated flows are forwarded to another Nowhere Portal instead of the
// local router. ServerName/Pin mirror the outbound's tls.server_name and pin.
type NowhereNextOptions struct {
	ServerOptions
	Password   string `json:"password,omitempty"`
	Up         string `json:"up,omitempty"`
	Down       string `json:"down,omitempty"`
	Mux        *int   `json:"mux,omitempty"`
	Pool       *int   `json:"pool,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	// Pin is the leaf certificate SHA-256 (lowercase hex). When set it overrides
	// SNI/chain verification for the chained Portal TLS (TCP and QUIC).
	Pin string `json:"pin,omitempty"`
	// Morph overrides Morph toward the next Portal. Nil inherits the inbound's
	// morph setting.
	Morph *bool `json:"morph,omitempty"`
	// Dial4 binds the IPv4 source address used when dialing the next Portal
	// over IPv4 ("auto" or an empty value leaves the source address unset).
	// Dial6 does the same for IPv6. Both mirror the Rust portal URL parameters
	// dial4/dial6 and are mutually exclusive with dial, which has no equivalent
	// here: sing-box already exposes inet4_bind_address / inet6_bind_address on
	// the outbound's shared dial fields.
	Dial4 string `json:"dial4,omitempty"`
	Dial6 string `json:"dial6,omitempty"`
}

// NowhereInboundOptions is the SingBox Nowhere Portal configuration.
// TLS is always the native SingBox TLS object; plaintext and historical
// numeric tls/crt/key compatibility forms are not accepted. Nowhere 3 (nw3) is
// the default stack: it serves ALPN nw3 only, selects its single transport via
// net, and rejects the nw2-only fields. Nowhere 2 (nw2) is the legacy stack
// kept for compatibility: select it by setting tls.alpn to a single non-nw3
// value (conventionally "nw2"), which keeps next chaining and the up/down/mux
// matrix meaningful.
type NowhereInboundOptions struct {
	ListenOptions
	Password string `json:"password,omitempty"`
	// Morph enables the keyed transport transform for every transport of this
	// endpoint. There is no negotiation: clients must use the same setting.
	// Nowhere 2 defaults to off; Nowhere 3 defaults to on.
	Morph                         *bool               `json:"morph,omitempty"`
	Network                       NetworkList         `json:"network,omitempty"`
	QUICCongestionControl         string              `json:"quic_congestion_control,omitempty"`
	MaxUnauthenticatedConnections *int                `json:"max_unauthenticated_connections,omitempty"`
	MaxUnauthenticatedPerSource   *int                `json:"max_unauthenticated_per_source,omitempty"`
	Next                          *NowhereNextOptions `json:"next,omitempty"`
	// Net selects the single Nowhere 3 transport: tcp (TLS over TCP) or udp
	// (QUIC). Empty means tcp. It is a Nowhere 3 field: the nw2 stack selects
	// its transports via network instead and rejects net.
	Net string `json:"net,omitempty"`
	// Egress turns the Nowhere 3 Portal into an exit bridge: it accepts a
	// single Egress registration over QUIC and forwards every authenticated
	// flow to that exit instead of the local router. Requires net udp.
	Egress bool `json:"egress,omitempty"`
	InboundTLSOptionsContainer
	QUICOptions
}

// NowhereEgressInboundOptions is the Nowhere 3 Egress client. It does not
// listen: it dials a Nowhere 3 Portal over QUIC, registers as the Portal's
// single exit, and serves the flows the Portal opens through the local router.
// A dropped registration returns to the reconnect loop (three-second cooldown,
// matching the reference CLI).
type NowhereEgressInboundOptions struct {
	DialerOptions
	ServerOptions
	Password string `json:"password,omitempty"`
	// Morph seals the QUIC packet socket below QUIC. Nowhere 3 defaults to on.
	Morph *bool `json:"morph,omitempty"`
	// Pin is the leaf certificate SHA-256 (lowercase hex) of the Portal; when
	// set it overrides chain and hostname verification.
	Pin string `json:"pin,omitempty"`
	// Insecure skips Portal certificate verification. Nowhere 3 otherwise
	// verifies against system roots and the endpoint host name.
	Insecure              bool   `json:"insecure,omitempty"`
	ServerName            string `json:"server_name,omitempty"`
	QUICCongestionControl string `json:"quic_congestion_control,omitempty"`
	QUICOptions
}
