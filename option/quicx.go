package option

import (
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

type QUICXInboundOptions struct {
	ListenOptions
	Users             []QUICXUser              `json:"users,omitempty"`
	AuthTimeout       badoption.Duration       `json:"auth_timeout,omitempty"`
	Heartbeat         badoption.Duration       `json:"heartbeat,omitempty"`
	AuthFailurePolicy string                   `json:"auth_failure_policy,omitempty" enum:"h3_close,silent_drop"`
	BBRProfile        string                   `json:"bbr_profile,omitempty" enum:"standard,conservative,aggressive"`
	QLOGDirectory     string                   `json:"qlog_directory,omitempty"`
	QLOGMaxSize       *byteformats.MemoryBytes `json:"qlog_max_size,omitempty"`
	InboundTLSOptionsContainer
	QUICOptions
}

type QUICXUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

type QUICXOutboundOptions struct {
	DialerOptions
	ServerOptions
	Password      string                   `json:"password,omitempty"`
	Heartbeat     badoption.Duration       `json:"heartbeat,omitempty"`
	BBRProfile    string                   `json:"bbr_profile,omitempty" enum:"standard,conservative,aggressive"`
	QLOGDirectory string                   `json:"qlog_directory,omitempty"`
	QLOGMaxSize   *byteformats.MemoryBytes `json:"qlog_max_size,omitempty"`
	Network       NetworkList              `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	QUICOptions
}
