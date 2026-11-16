### Structure

```json
{
  "detour": "upstream-out",
  "bind_interface": "en0",
  "inet4_bind_address": "0.0.0.0",
  "inet6_bind_address": "::",
  "routing_mark": 1234,
  "reuse_addr": false,
  "connect_timeout": "5s",
  "tcp_fast_open": false,
  "tcp_multi_path": false,
  "udp_gso": true,
  "udp_fragment": false,
  "domain_resolver": "", // or {}
  "provider_domain_resolver": false, // or {}
  "network_strategy": "default",
  "network_type": [],
  "fallback_network_type": [],
  "fallback_delay": "300ms",
  "tcp_keep_alive": "5m",
  "tcp_keep_alive_interval": "75s",
  "tcp_keep_alive_count": 0,
  "disable_tcp_keep_alive": false,

  // Deprecated

  "domain_strategy": "prefer_ipv6"
}
```

### Fields

`detour` `bind_interface` `inet4_bind_address` `inet6_bind_address` `routing_mark` `reuse_addr` `connect_timeout` `tcp_fast_open` `tcp_multi_path` `udp_gso` `udp_fragment` `domain_resolver` `network_strategy` `network_type` `fallback_network_type` `fallback_delay` `tcp_keep_alive` `tcp_keep_alive_interval` `tcp_keep_alive_count` `disable_tcp_keep_alive` `domain_strategy` see [Dial Fields](/configuration/shared/dial).

#### provider_domain_resolver

Resolve the node server addresses through the DNS servers carried by the subscription itself.

A boolean, or the object form:

```json
{
  "enabled": true,
  "resolver": "",
  "resolver_strategy": "",
  "outbound_strategy": ""
}
```

When enabled, the provider registers a DNS server named `<provider tag>-dns` (type `provider`) and every node's `domain_resolver` points at it. The servers are extracted from the subscription:

* Clash: `dns.proxy-server-nameserver`, else `dns.nameserver`; nothing when `dns.enable` is `false`. The mihomo syntax is supported: plain IP (UDP), `udp://`, `tcp://`, `tls://`, `quic://`, `https://`, `h3://`, and the `#h3=true` / `#skip-cert-verify=true` params. `system`, `dhcp://` and `rcode://` are ignored, and so is a proxy or interface name after `#`: subscription DNS always dials directly.
* sing-box: the server selected by `route.default_domain_resolver`, else `dns.final`, else the first server; a `group` expands to its members.

Only `udp`, `tcp`, `tls`, `quic`, `https` and `h3` servers are kept and duplicates are merged; a server that fails to parse is skipped without failing the node import. Several servers are queried concurrently and the fastest NOERROR / NXDOMAIN answer wins.

Subscription DNS servers never take the `detour` (resolving node addresses through a node loops) and dial with the other `override_dialer` fields (`bind_interface`, `routing_mark`, `inet4_bind_address`, `network_strategy`, ...); dial fields and TLS file paths (`certificate_path`, ...) the subscription sets for its DNS servers are ignored.

The subscription DNS uses at most half of a query's timeout, leaving the rest to the fallback; after none of the subscription DNS servers answered, the fallback answers alone for 30 seconds.

Updating the subscription only swaps the DNS servers: nodes are not recreated for it, and an unchanged list keeps its connections. Remote providers cache the DNS servers together with the nodes.

When the subscription carries no usable server, or all of them fail, queries fall back to `resolver`. Provider DNS servers of several providers falling back to each other fail the query instead of looping.

After disabling this option, cached nodes naming `<provider tag>-dns` or another DNS server that no longer exists use `override_dialer.domain_resolver` (or the default resolution when unset).

##### enabled

Defaults to `true` in the object form.

##### resolver

Tag of the DNS server resolving the subscription DNS server names (such as `doh.pub`) and answering fallback queries.

Defaults to `override_dialer.domain_resolver.server`, then `route.default_domain_resolver`, then the default DNS server.

##### resolver_strategy

Domain strategy for resolving the subscription DNS server names, one of `prefer_ipv4` `prefer_ipv6` `ipv4_only` `ipv6_only`.

Follows the selected fallback server by default.

##### outbound_strategy

Domain strategy the nodes resolve their server addresses with through the subscription DNS, same values.

Defaults to `override_dialer.domain_resolver.strategy`. The other `domain_resolver` fields (`timeout`, `disable_cache`, `client_subnet`, ...) apply as well.
