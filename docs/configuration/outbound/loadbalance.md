When this group is referenced, all candidate outbounds, including provider members,
are treated as referenced for idle connection management, regardless of health-check
results. This keeps their on-demand dependencies available for selection.

### Structure

```json
{
  "type": "loadbalance",
  "tag": "balance",
  "strategy": "round-robin",

  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "providers": [
    "provider-a",
    "provider-b"
  ],
  "exclude": "",
  "include": "",
  "include_type": [],
  "exclude_type": [],
  "include_transport": [],
  "exclude_transport": [],
  "network": "",
  "url": "",
  "interval": "",
  "idle_timeout": "",
  "ttl": "10m",
  "use_all_providers": false
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

### Fields

#### strategy

Load Balancing Strategies.

* `round-robin` will distribute all requests among different proxy nodes within the strategy group.

* `consistent-hashing` will assign requests with the same `target address` to the same proxy node within the strategy group.

* `sticky-sessions`: requests with the same `source address` and `target address` will be directed to the same proxy node within the strategy group, with a cache expiration of specified ttl.

!!! note
    When the `target address` is a domain, it uses top-level domain matching.

#### outbounds

List of outbound tags to test.

#### providers

List of [Provider](/configuration/provider) tags to test.

#### exclude

Exclude regular expression to filter `providers` nodes.

#### include

Include regular expression to filter `providers` nodes.

#### include_type

List of outbound types to keep among `providers` nodes, such as `vless` or `hysteria2`.

Case-insensitive. Every outbound and endpoint type of the build is accepted, together with the Clash names and short forms `ss`, `socks5`, `hy`, `hy1`, `hy2`, `wg`, `naiveproxy`, `shadow-tls`, `openvpn` and `masque`. Unknown types are rejected at startup.

#### exclude_type

List of outbound types to drop from `providers` nodes. Takes precedence over `include_type`.

#### include_transport

List of transports to keep among `providers` nodes: `tcp` (no transport), `ws`, `httpupgrade`, `http`, `grpc`, `quic`, `xhttp` and other registered plugin transports. The Clash names `websocket`, `h2`, `gun`, `raw` and `splithttp` are accepted.

Only `vmess`, `vless`, `trojan` and `shadowsocks` (whose `v2ray-plugin` counts as `ws` or `quic`) have a transport. Other nodes match neither list: `include_transport` drops them and `exclude_transport` keeps them.

#### exclude_transport

List of transports to drop from `providers` nodes. Takes precedence over `include_transport`.

#### network

`tcp`, `udp`, or a list of both.

Keep only `providers` nodes that support every listed network. The capability comes from the node itself, for example `"network": "tcp"` on a Shadowsocks node or `udp: false` in a Clash subscription, not from its name. When the provider probes UDP (`health_check.udp`), a node whose valid probe failed is removed until a probe succeeds again.

How each protocol reports UDP:

| Protocol | UDP |
|---|---|
| `shadowsocks` `vmess` `vless` `trojan` `socks` `snell` `anytls` `quicx` | from its `network` field, the Clash `udp` flag for subscriptions |
| `hysteria` `hysteria2` `tuic` | yes, unless `network` is `tcp`; always yes from Clash subscriptions, as in Clash |
| `socks` version `4` / `4a`, `naive` | only with `udp_over_tcp` |
| `http` | from its `network` field (CONNECT-UDP); always no from Clash subscriptions |
| `ssh` `shadowtls` `tor` | no |
| `wireguard` `tailscale` `tailcat` `nowhere` and other endpoints | yes |

!!! note ""

    `include`, `exclude`, `include_type`, `exclude_type`, `include_transport`, `exclude_transport` and `network` behave the same in selector, urltest, loadbalance and smart groups, are applied again on every provider update, and all apply to `providers` nodes only, and a node must pass every one of them. Members listed in `outbounds` are always kept.

#### url

The URL to test. `https://www.gstatic.com/generate_204` will be used if empty.

#### interval

The test interval. `3m` will be used if empty.

#### idle_timeout

The idle timeout. `30m` will be used if empty.

#### ttl

The time to live used for `sticky-sessions` strategy  timeout. `10m` will be used if empty.

#### use_all_providers

Whether to use all providers for testing. `false` will be used if empty.
