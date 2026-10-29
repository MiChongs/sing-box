### Structure

```json
{
  "type": "urltest",
  "tag": "auto",
  
  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "providers": [
    "provider-a",
    "provider-b",
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
  "tolerance": 50,
  "idle_timeout": "",
  "use_all_providers": false,
  "fallback": {
    "enabled": false,
    "max_delay": ""
  },
  "interrupt_exist_connections": false
}
```

### Fields

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

Every interval, the current selection and the 3 fastest members are tested, along with members never tested before.
Other members are refreshed every 4 intervals.
A member whose tests keep failing is retried after 1, 2, 4 and up to 8 intervals; a network change resets this.

A member tested recently by another group or the API is not tested again, and groups testing the same member at the same time share one test.
Tests of all groups run at the same moments, so groups with the same interval wake the network once.
After a network change, the current selection and the fastest members are tested again, at most every 30 seconds.

#### tolerance

The test tolerance in milliseconds. `50` will be used if empty.

#### idle_timeout

The idle timeout. `30m` will be used if empty.

#### use_all_providers

Whether to use all providers for testing. `false` will be used if empty.

#### fallback

Fallback selection configuration.

When enabled, the first available outbound is selected in configuration order instead of selecting the outbound with the lowest delay.

##### fallback.enabled

Enable fallback selection.

##### fallback.max_delay

Maximum acceptable delay.

An outbound whose delay exceeds this value is skipped. If every available outbound exceeds the value, the skipped outbound with the lowest delay is selected.

#### interrupt_exist_connections

Interrupt existing connections when the selected outbound has changed.

Only inbound connections are affected by this setting, internal connections will always be interrupted.

### Health check behavior

* **Selection**: the fastest member is found first; the current member is kept while its delay is within `tolerance` of it.
* **Cold start**: until members are measured, a random member supporting the network is picked and kept, so the first connections are not all sent to the first member.
* **Startup**: members are probed once after startup. When none answers (the network is not ready yet), the probe is retried 15s, 35s and 60s after startup, never later than `interval`, until a member is available or the group goes idle.
* **Failed connections**: a failing member is retried on the best measured other members. When no other member is measured, the failed member is probed alone 3s later: if it answers it is trusted for one minute, otherwise it is dropped and another member is selected. When no member is left alive, every member is probed again, at most once every 90s.
* **Manual selection**: selecting a member through the Clash API probes it first and is rejected when it does not answer. The selection is kept by health checks and failures; it is released by a user-triggered speed test or by selecting an empty name.
