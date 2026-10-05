package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type EasyTierEndpointOptions struct {
	DialerOptions
	InnerDomainResolver    *DomainResolveOptions            `json:"inner_domain_resolver,omitempty"`
	System                 bool                             `json:"system,omitempty"`
	GSO                    *bool                            `json:"gso,omitempty"`
	Name                   string                           `json:"name,omitempty"`
	MTU                    uint32                           `json:"mtu,omitempty"`
	UDPTimeout             badoption.Duration               `json:"udp_timeout,omitempty"`
	UDPMapping             UDPNATBehavior                   `json:"udp_mapping,omitempty"`
	UDPFiltering           UDPNATBehavior                   `json:"udp_filtering,omitempty"`
	UDPNATMax              uint32                           `json:"udp_nat_max,omitempty"`
	NetworkName            string                           `json:"network_name,omitempty"`
	NetworkSecret          string                           `json:"network_secret,omitempty"`
	Hostname               string                           `json:"hostname,omitempty"`
	Address                badoption.Listable[netip.Prefix] `json:"address,omitempty"`
	Peers                  badoption.Listable[string]       `json:"peers,omitempty"`
	Listeners              badoption.Listable[string]       `json:"listeners,omitempty"`
	ProxyNetworks          []EasyTierProxyNetworkOptions    `json:"proxy_networks,omitempty"`
	EnableExitNode         bool                             `json:"enable_exit_node,omitempty"`
	ExitNodes              badoption.Listable[netip.Addr]   `json:"exit_nodes,omitempty"`
	PortForwards           []EasyTierPortForwardOptions     `json:"port_forwards,omitempty"`
	STUNServers            badoption.Listable[string]       `json:"stun_servers,omitempty"`
	STUNServersV6          badoption.Listable[string]       `json:"stun_servers_v6,omitempty"`
	DisableEncryption      bool                             `json:"disable_encryption,omitempty"`
	EncryptionAlgorithm    string                           `json:"encryption_algorithm,omitempty" enum:"aes-gcm,aes-256-gcm,chacha20,xor"`
	SecureMode             *EasyTierSecureModeOptions       `json:"secure_mode,omitempty"`
	DisableP2P             bool                             `json:"disable_p2p,omitempty"`
	LazyP2P                bool                             `json:"lazy_p2p,omitempty"`
	NeedP2P                bool                             `json:"need_p2p,omitempty"`
	P2POnly                bool                             `json:"p2p_only,omitempty"`
	DisableTCPHolePunching bool                             `json:"disable_tcp_hole_punching,omitempty"`
	DisableUDPHolePunching bool                             `json:"disable_udp_hole_punching,omitempty"`
	DisableSymHolePunching bool                             `json:"disable_sym_hole_punching,omitempty"`
	LatencyFirst           bool                             `json:"latency_first,omitempty"`
	PrivateMode            bool                             `json:"private_mode,omitempty"`
	RelayNetworkWhitelist  badoption.Listable[string]       `json:"relay_network_whitelist,omitempty"`
	RelayAllPeerRPC        bool                             `json:"relay_all_peer_rpc,omitempty"`
	Web                    *EasyTierWebOptions              `json:"web,omitempty"`
}

func (o *EasyTierEndpointOptions) TakeInnerDomainResolverOptions() *DomainResolveOptions {
	return o.InnerDomainResolver
}

type EasyTierSecureModeOptions struct {
	Enabled    bool   `json:"enabled,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

type EasyTierProxyNetworkOptions struct {
	CIDR       netip.Prefix      `json:"cidr"`
	MappedCIDR *badoption.Prefix `json:"mapped_cidr,omitempty"`
}

type EasyTierPortForwardOptions struct {
	Network     NetworkList    `json:"network,omitempty"`
	Listen      netip.AddrPort `json:"listen"`
	Destination netip.AddrPort `json:"destination"`
}

type EasyTierWebOptions struct {
	Server     string `json:"server"`
	MachineID  string `json:"machine_id,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	SecureMode bool   `json:"secure_mode,omitempty"`
}
