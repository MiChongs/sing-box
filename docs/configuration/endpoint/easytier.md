# EasyTier

!!! question "Since sing-box 1.15.0"

`easytier` endpoint joins [EasyTier](https://github.com/EasyTier/EasyTier) virtual networks.

The EasyTier core is embedded as WebAssembly and runs inside sing-box, so no external `easytier-core` process or Rust toolchain is required.

!!! quote ""

    EasyTier is not included by default, see [Installation](/installation/build-from-source/#build-tags).

## Structure

```json
{
  "type": "easytier",
  "tag": "easytier-ep",

  "network_name": "",
  "network_secret": "",
  "hostname": "",
  "address": [],
  "peers": [],
  "listeners": [],
  "proxy_networks": [
    {
      "cidr": "",
      "mapped_cidr": ""
    }
  ],
  "enable_exit_node": false,
  "exit_nodes": [],
  "port_forwards": [
    {
      "network": "",
      "listen": "",
      "destination": ""
    }
  ],
  "stun_servers": [],
  "stun_servers_v6": [],
  "disable_encryption": false,
  "encryption_algorithm": "",
  "secure_mode": {
    "enabled": false,
    "private_key": ""
  },
  "disable_p2p": false,
  "lazy_p2p": false,
  "need_p2p": false,
  "p2p_only": false,
  "disable_tcp_hole_punching": false,
  "disable_udp_hole_punching": false,
  "disable_sym_hole_punching": false,
  "latency_first": false,
  "private_mode": false,
  "relay_network_whitelist": [],
  "relay_all_peer_rpc": false,
  "web": {
    "server": "",
    "machine_id": "",
    "hostname": "",
    "secure_mode": false
  },
  "system": false,
  "gso": false,
  "inner_domain_resolver": "", // or {}
  "name": "",
  "mtu": 1380,
  "udp_timeout": "",

  ... // UDP NAT Fields
  ... // Dial Fields
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

## Fields

### network_name

==Required== unless `web` is set.

EasyTier network name.

The network fields below configure this network. When only `web` is set, the networks come from the configuration server instead.

### network_secret

EasyTier network secret.

### hostname

Hostname advertised to other peers, at most 32 characters.

The system hostname is used by default.

### address

Virtual IP prefixes of this node, at most one IPv4 and one IPv6 prefix.

The IPv4 prefix must be shorter than `/32`, for example `10.144.144.1/24`.

When no IPv4 prefix is set, an IPv4 address is assigned automatically (DHCP), and outbound connections wait until it is assigned.

### peers

Peer URLs to connect to, for example `tcp://public.easytier.cn:11010` or `udp://198.51.100.1:11010`.

`txt://` and `srv://` discovery URLs are resolved through the sing-box DNS router.

### listeners

Listener URLs that accept connections from other peers, for example `tcp://0.0.0.0:11010` and `udp://0.0.0.0:11010`.

Listeners always bind directly on the host and are not affected by `detour`.

### proxy_networks

IPv4 networks behind this node that other peers can reach through it (subnet proxy).

Traffic from peers to these networks is handed to sing-box, see [Proxy networks and exit node](#proxy-networks-and-exit-node).

#### cidr

==Required==

The real network.

#### mapped_cidr

Advertise the network to peers under this prefix instead, for example to avoid conflicts between sites using the same private network. It must have the same size as `cidr`.

Peers then use addresses in `mapped_cidr`, which are translated to the corresponding address in `cidr`.

### enable_exit_node

Allow peers to use this node as an exit node.

Their traffic to destinations outside the EasyTier network is handed to sing-box, see [Proxy networks and exit node](#proxy-networks-and-exit-node).

### exit_nodes

Virtual IPs of peers used as exit nodes for destinations outside the EasyTier network.

### port_forwards

Forward a port on the host to an address in the EasyTier network. The forwarding is done by the EasyTier core.

#### network

`tcp` or `udp`.

Both are forwarded by default.

#### listen

==Required==

The host address and port to listen on, for example `127.0.0.1:8080`.

#### destination

==Required==

The address and port in the EasyTier network to forward to, for example `10.144.144.2:80`.

A TCP connection to a destination outside the EasyTier network is routed by sing-box.

### stun_servers

STUN servers used for NAT type detection.

The EasyTier default servers are used by default.

### stun_servers_v6

IPv6 STUN servers used for NAT type detection.

The EasyTier default servers are used by default.

### disable_encryption

Disable encryption of peer traffic.

Must be the same on all peers.

### encryption_algorithm

Encryption algorithm.

Available values: `aes-gcm`, `aes-256-gcm`, `chacha20`, `xor`.

`aes-gcm` is used by default. Must be the same on all peers.

### secure_mode

Enable EasyTier secure mode, which authenticates peers with X25519 keys. Requires `network_secret`.

#### private_key

Base64-encoded X25519 private key.

A new key is generated on every start if empty.

### disable_p2p

Only relay traffic through the configured peers and never establish direct connections.

### lazy_p2p

Only establish direct connections to peers when there is traffic to them.

### need_p2p

Ask other peers to always establish direct connections to this node.

### p2p_only

Only communicate with peers through direct connections and never relay through other peers.

### disable_tcp_hole_punching

Disable TCP hole punching.

### disable_udp_hole_punching

Disable UDP hole punching.

### disable_sym_hole_punching

Disable hole punching for symmetric NAT, which is treated as cone NAT instead.

### latency_first

Prefer routes with the lowest latency instead of the fewest hops.

### private_mode

Refuse handshakes and relaying for peers whose network name and secret differ from this node.

### relay_network_whitelist

Names of foreign networks this node is allowed to relay for. Wildcards are supported.

All networks are allowed by default.

### relay_all_peer_rpc

Relay RPC packets of all peers, including peers of networks not in `relay_network_whitelist`.

### web

Run the networks an EasyTier Web configuration server assigns to this machine, see [Web configuration](#web-configuration).

#### server

==Required==

The configuration server, as a `tcp://` or `udp://` URL whose path is the user name, for example `udp://config.example.com:22020/admin`.

#### machine_id

UUID identifying this machine on the configuration server. It must stay the same across restarts.

By default it is derived from the operating system's machine ID (`/etc/machine-id`), or the hostname where none exists, and the endpoint tag.

#### hostname

Hostname reported to the configuration server.

`hostname`, or the system hostname, is used by default.

#### secure_mode

Use secure mode for the connection to the configuration server.

### system

Use system interface.

Requires privilege and cannot conflict with existing system interfaces.

If disabled, sing-box uses the internal network stack.

### gso

!!! quote ""

    Only supported on Linux.

Attempt to enable generic segmentation offload for the system interface.

Enabled by default when `system` is `true`. Set to `false` to disable.

This option has no effect when `system` is `false`.

### inner_domain_resolver

Set the DNS resolver used for destination domain names when this endpoint is selected as an outbound. Applies to TCP and UDP.

It is also used to resolve unresolved domain destinations when this endpoint is selected for L3 forwarding.

This option uses the same format as [domain_resolver](/configuration/shared/dial/#domain_resolver).

When unset, existing DNS routing rules and the default DNS apply. IP destinations do not require domain resolution.

This option does not affect the resolution of `peers` and `stun_servers`, which continues to use `domain_resolver` from the dial fields.

### name

Custom interface name for system interface.

An automatically generated `easytier` interface name is used by default.

### mtu

Tunnel MTU.

`1380` will be used by default.

### udp_timeout

UDP NAT expiration time.

`5m` will be used by default.

## UDP NAT Fields

See [UDP NAT Fields](/configuration/shared/udp-nat/) for details.

## Dial Fields

Dial fields apply to the connections between this node and other peers.

When `detour` is set, hole punching and other connections that require binding a local address are not available, so `disable_p2p` is recommended.

See [Dial Fields](/configuration/shared/dial/) for details.

## Routing

Connections from peers to the virtual IP of this node are routed with the destination rewritten to the loopback address.

Use the [`preferred_by`](/configuration/route/rule/#preferred_by) rule item to route the virtual subnets, peer addresses and the networks advertised by peers to this endpoint:

```json
{
  "route": {
    "rules": [
      {
        "preferred_by": "easytier-ep",
        "outbound": "easytier-ep"
      }
    ]
  }
}
```

## Proxy networks and exit node

Connections from peers to `proxy_networks`, and to any destination when this node is their exit node, are routed by sing-box as inbound connections of this endpoint, with the peer's virtual IP as source. Route rules, including `inbound`, `source_ip_cidr` and the destination items, apply to them; without a matching rule they use the final outbound.

Destinations in a `mapped_cidr` are translated to the real network before routing.

## Web configuration

With `web`, the endpoint connects to the configuration server and runs every network the server assigns to this machine, together with the network configured locally, if any. Networks are added, replaced and removed as the server changes them.

All networks share this endpoint:

* Connections leave from the address of the network that reaches the destination. Destinations outside every network use the local network, or the first assigned network.
* L3 forwarding is used only for destinations of that first network; connections to the other networks go through the internal network stack.
* With `system` enabled, the operating system selects the source address, so destinations behind other networks' peers may not be reachable.

A network assigned by the server keeps its own proxy settings. When it has proxy networks or serves as an exit node but does not enable "proxy forward by system", the EasyTier core proxies that traffic itself; its TCP and UDP connections are still routed by sing-box, but without the peer as source, and ICMP is not proxied.
