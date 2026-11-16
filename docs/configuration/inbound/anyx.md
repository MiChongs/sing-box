### Structure

```json
{
  "type": "anyx",
  "tag": "anyx-in",

  ... // Listen Fields

  "users": [
    {
      "name": "sekai",
      "password": "8JCsPssfgS8tiRwiMlhARg=="
    }
  ],
  "encryption": {
    "method": "2022-blake3-aes-128-gcm",
    "password": "8JCsPssfgS8tiRwiMlhARg=="
  },
  "padding_scheme": [],
  "padding_scheme_interval": "30m",
  "padding_limit": 2000,
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 8080
  },
  "fallback_for_alpn": {
    "http/1.1": {
      "server": "127.0.0.1",
      "server_port": 8081
    }
  },
  "pseudo_vpn": {
    "enabled": false,
    "interface_name": "anyx-tun",
    "address": [
      "100.64.0.1/24",
      "fd00::1/64"
    ],
    "mtu": 1400,
    "lease_duration": "72h",
    "tcp_mss_clamping": true
  },
  "tls": {},
  "transport": {}
}
```

AnyX is a multiplexing protocol derived from AnyTLS that does not depend on TLS: it can run over plain TCP, over a [V2Ray Transport](/configuration/shared/v2ray-transport/), and optionally encrypt sessions with a Shadowsocks cipher. It is not compatible with AnyTLS.

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### users

==Required==

AnyX users: `name` is used in logs, `password` authenticates the client.

#### encryption

Inner session encryption, shared by both ends. Disabled when empty or `method` is `none`.

* `method`: `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` or `2022-blake3-chacha20-poly1305`.
* `password`: any string for the legacy AEAD ciphers; a base64 key of 16 or 32 bytes for the 2022 ciphers.

#### padding_scheme

Padding scheme the server sends to clients. `off` when empty.

* `off`: no padding.
* `auto`: a random scheme, generated again every `padding_scheme_interval`.
* A custom scheme in the AnyTLS format, such as `["stop=8", "0=30-30", "1=100-200", "2=300-400,c,500-600"]`.

#### padding_scheme_interval

How often `auto` generates a new scheme, at a random point between 70% and 130% of the interval. `30m` by default.

#### padding_limit

Maximum bytes of handshake padding and waste frames accepted before authentication; connections exceeding it are closed. `2000` by default.

#### fallback

Fallback target (an IP, a domain or a unix socket path in `server`) used when the first packet fails authentication.

#### fallback_for_alpn

Fallback targets selected by the negotiated TLS ALPN. Only used with TLS.

#### tls

Inbound TLS configuration, see [TLS](/configuration/shared/tls/#inbound). REALITY and [Phantom TLS](/configuration/shared/tls/#phantom-fields) are supported. Plain TCP when empty.

#### transport

V2Ray Transport configuration, see [V2Ray Transport](/configuration/shared/v2ray-transport/).

#### pseudo_vpn

Serve the AnyX pseudo VPN: clients whose outbound enables [`pseudo_vpn`](/configuration/outbound/anyx/#pseudo_vpn) get a virtual address and tunnel IP packets (TCP and ICMP) over their AnyX sessions; the server writes them into a system TUN interface, and the host forwards them.

* `enabled`: enable the pseudo VPN.
* `interface_name`: name of the server TUN interface, `anyx-tun` by default.
* `address`: ==Required== virtual subnets, at most one IPv4 and one IPv6 prefix, such as `["100.64.0.1/24", "fd00::1/64"]`. The address of each prefix is the server address in that subnet (the next address when it is the network address); the remaining addresses are leased to clients.
* `mtu`: MTU of the TUN interface and the tunnel, `1400` by default, between `576` and `65527`, and at least `1280` with an IPv6 subnet. Clients use the smaller of their own MTU and this one.
* `lease_duration`: lease of a client address, `72h` by default, clamped to `5m`–`168h`. The lease is renewed while the client sends traffic; a client that reconnects within it keeps its address.
* `tcp_mss_clamping`: clamp the MSS of TCP SYN packets in both directions to fit the MTU, enabled by default.

Address assignment:

* Sticky: a reconnecting client presents its previous address and lease token and gets the same address back while the lease lasts. A restarted client has a new client ID, so the server also remembers addresses per authenticated user (`users[].name`): a new client of the same user gets the user's address back when the previous client is offline or its lease expired; while it is still online (several devices of one user), a new address is assigned.
* Reclaim: leases are renewed while the client sends traffic. Expired leases are swept every 30 seconds together with their routes; packets to the address are dropped afterwards, and the client is told its lease expired the next time it sends and renegotiates automatically.
* Exhaustion: a pool holds at most 65536 leases. When a pool is full, the lease of the client that has been idle longest and has no live session is evicted for a new client; when every holder is online, the new client is rejected. A session carries one client: requesting an address with a different client ID through the same session releases the previous client's addresses.
* Safety: the server only forwards packets whose source is the client's leased address (strict RPF) and rate-limits lease-expired replies; UDP packets are not forwarded through the pseudo VPN.

The host must forward and masquerade the virtual subnets; sing-box only creates the interface and configures its addresses, it does not touch the firewall. With `anyx-tun`, `100.64.0.0/24` and `fd00::/64`, using iptables:

```bash
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
# loose reverse path filtering, so return traffic entering through the interface is not dropped
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.anyx-tun.rp_filter=2

# let clients reach services on the server itself (optional)
iptables -I INPUT 1 -i anyx-tun -j ACCEPT
# accept forwarding and return traffic
iptables -I FORWARD 1 -i anyx-tun -j ACCEPT
iptables -I FORWARD 2 -o anyx-tun -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# masquerade traffic leaving the virtual subnet
iptables -t nat -I POSTROUTING 1 -s 100.64.0.0/24 ! -d 100.64.0.0/24 -j MASQUERADE

ip6tables -I INPUT 1 -i anyx-tun -j ACCEPT
ip6tables -I FORWARD 1 -i anyx-tun -j ACCEPT
ip6tables -I FORWARD 2 -o anyx-tun -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -t nat -I POSTROUTING 1 -s fd00::/64 ! -d fd00::/64 -j MASQUERADE
```

Using nftables:

```
table inet anyx {
  chain input {
    type filter hook input priority filter; policy accept;
    iifname "anyx-tun" accept
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname "anyx-tun" accept
    oifname "anyx-tun" ct state related,established accept
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 100.64.0.0/24 ip daddr != 100.64.0.0/24 masquerade
    ip6 saddr fd00::/64 ip6 daddr != fd00::/64 masquerade
  }
}
```

When the `forward` chain drops by default (Docker or firewalld, for example), these accept rules must come before the drop rules. Creating the TUN interface requires root (or `CAP_NET_ADMIN`).
