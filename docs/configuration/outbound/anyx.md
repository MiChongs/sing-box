### Structure

```json
{
  "type": "anyx",
  "tag": "anyx-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "password": "8JCsPssfgS8tiRwiMlhARg==",
  "client_metadata": "",
  "encryption": {
    "method": "2022-blake3-aes-128-gcm",
    "password": "8JCsPssfgS8tiRwiMlhARg=="
  },
  "padding_scheme": [],
  "padding_scheme_interval": "30m",
  "disable_reuse": false,
  "idle_session_min_timeout": "30s",
  "idle_session_timeout": "30s",
  "min_idle_session": 0,
  "network": "tcp",
  "pseudo_vpn": {
    "enabled": false,
    "mtu": 1400,
    "tcp_mss_clamping": true,
    "udp": "drop"
  },
  "tls": {},
  "transport": {},

  ... // Dial Fields
}
```

See the [AnyX inbound](/configuration/inbound/anyx/) for the protocol.

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### password

==Required==

The AnyX password.

#### client_metadata

Client identification sent in the handshake, `anyx sing-box/<version>` by default. An empty string sends `anyx`.

#### encryption

Inner session encryption, must match the server. See the [AnyX inbound](/configuration/inbound/anyx/#encryption).

#### padding_scheme

Initial padding scheme, `auto` by default; replaced by the scheme the server sends. Same values as the inbound.

#### padding_scheme_interval

How often `auto` generates a new scheme, at a random point between 70% and 130% of the interval.

#### disable_reuse

Use one connection per stream instead of multiplexing streams over pooled sessions.

#### idle_session_min_timeout

Minimum idle time before a pooled session can be closed. Default: 30s.

#### idle_session_timeout

Close pooled sessions idle for longer than this. Default: 30s.

#### min_idle_session

Number of idle sessions kept open. Default: 0.

#### network

Enabled network, `tcp` or `udp`. Both are enabled by default. Used by groups to filter members by UDP support.

#### tls

Outbound TLS configuration, see [TLS](/configuration/shared/tls/#outbound). REALITY and [Phantom TLS](/configuration/shared/tls/#phantom-fields) are supported. Plain TCP when empty.

#### transport

V2Ray Transport configuration, see [V2Ray Transport](/configuration/shared/v2ray-transport/).

#### pseudo_vpn

Forward IP packets to an AnyX server that enables [`pseudo_vpn`](/configuration/inbound/anyx/#pseudo_vpn). The outbound becomes an L3 target for [pre-match](/configuration/shared/pre-match/) `route`: TCP and ICMP connections from a TUN inbound routed to it are forwarded as IP packets over the AnyX sessions instead of being proxied as streams. The server leases a virtual IPv4 / IPv6 address and the outbound translates between it and the local TUN address.

* `enabled`: enable the pseudo VPN.
* `mtu`: tunnel MTU, `1400` by default; the smaller of this and the server MTU is used.
* `tcp_mss_clamping`: clamp the MSS of TCP SYN packets to fit the MTU, enabled by default.
* `udp`: how UDP is handled, since the pseudo VPN does not carry it.
    * `drop` (default): drop UDP packets locally.
    * `reject`: reply with ICMP port unreachable locally.
    * `transparent`: leave UDP to the regular L4 path (for example UDP over TCP through this outbound or other rules).

The pseudo VPN only works through pre-match: connections must come from a [TUN inbound](/configuration/inbound/tun/) and be routed to this outbound (directly, by `route.final`, or as the selected member of a group) before L3 to L4 translation. Connections that reach the outbound in any other way (SOCKS / HTTP inbounds, or after a rule that needs more connection data such as `sniff` on TCP) are proxied as streams as usual. For example:

```json
{
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "auto_route": true
    }
  ],
  "outbounds": [
    {
      "type": "anyx",
      "tag": "anyx-vpn",
      "server": "example.com",
      "server_port": 443,
      "password": "...",
      "tls": { "enabled": true, "server_name": "example.com" },
      "pseudo_vpn": { "enabled": true, "udp": "transparent" }
    }
  ],
  "route": {
    "rules": [
      { "ip_cidr": ["10.0.0.0/8"], "action": "route", "outbound": "anyx-vpn" }
    ],
    "final": "anyx-vpn"
  }
}
```

The TUN forwards a matched connection to the outbound with the outbound's local port addresses (`192.0.0.8`, the RFC 7600 dummy address, and `fd61:6e79:7876::2`) as source; the outbound translates them to the leased virtual addresses on the way out and back on the way in, rewriting the TCP, UDP and ICMP checksums and the headers embedded in ICMP errors. Both families are always advertised, so a family the server does not lease is dropped instead of leaking through the local stack.

The address is negotiated in the background when the outbound starts and again when the server reports the lease expired; packets are dropped until it is ready. The outbound keeps its client ID and lease token across reconnects and network changes, so it gets the same address back while the lease lasts; after a restart, the server gives the user's previous address back if no other client of the same user holds it. When the session is lost, a new one is established on demand with exponential backoff, without blocking the TUN; established connections keep working over the new session.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
