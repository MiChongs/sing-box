---
icon: material/alert-decagram
---

!!! quote "Changes in sing-box 1.14.0"

    :material-delete-clock: [independent_cache](#independent_cache)  
    :material-plus: [optimistic](#optimistic)  
    :material-plus: [timeout](#timeout)

!!! quote "Changes in sing-box 1.12.0"

    :material-decagram: [servers](#servers)

!!! quote "Changes in sing-box 1.11.0"

    :material-plus: [cache_capacity](#cache_capacity)

# DNS

### Structure

```json
{
  "dns": {
    "servers": [],
    "rules": [],
    "final": "",
    "strategy": "",
    "disable_cache": false,
    "disable_expire": false,
    "independent_cache": false,
    "round_robin_cache": false,
    "cache_capacity": 0,
    "min_cache_ttl": 0,
    "max_cache_ttl": 0,
    "optimistic": false, // or {}
    "timeout": "",
    "reverse_mapping": false,
    "allow_resolver_discovery": false,
    "tcp_concurrent": false, // or {}
    "client_subnet": "",
    "fakeip": {}
  }
}

```

### Fields

| Key      | Format                          |
|----------|---------------------------------|
| `server` | List of [DNS Server](./server/) |
| `rules`  | List of [DNS Rule](./rule/)     |
| `fakeip` | :material-note-remove: [FakeIP](./fakeip/) |

#### final

Default dns server tag.

The first server will be used if empty.

#### strategy

Default domain strategy for resolving the domain names.

One of `prefer_ipv4` `prefer_ipv6` `ipv4_only` `ipv6_only`.

#### disable_cache

Disable dns cache.

Conflict with `optimistic`.

#### disable_expire

Disable dns cache expire.

Conflict with `optimistic`.

#### independent_cache

!!! failure "Deprecated in sing-box 1.14.0"

    `independent_cache` is deprecated and will be removed in sing-box 1.16.0, check [Migration](/migration/#migrate-independent-dns-cache).

Make each DNS server's cache independent for special purposes. If enabled, will slightly degrade performance.

#### round_robin_cache

Make the order of cached response addresses rotated in round robin manner.

#### cache_capacity

!!! question "Since sing-box 1.11.0"

LRU cache capacity.

Value less than 1024 will be ignored.

#### min_cache_ttl

Minimum DNS cache TTL in seconds.

TTL values below this value are increased before a response is cached and returned.

`0` disables the minimum TTL limit.

#### max_cache_ttl

Maximum DNS cache TTL in seconds.

TTL values above this value are reduced before a response is cached and returned.

`0` disables the maximum TTL limit. Leaving both options unset preserves the TTL derived from the DNS response.

If `min_cache_ttl` is greater than a non-zero `max_cache_ttl`, `min_cache_ttl` is used as both limits.

A rule-level `rewrite_ttl` action is applied after these limits and takes precedence over them.

#### optimistic

!!! question "Since sing-box 1.14.0"

Enable optimistic DNS caching. When a cached DNS entry has expired but is still within the timeout window,
the stale response is returned immediately while a background refresh is triggered.

Conflict with `disable_cache` and `disable_expire`.

Accepts a boolean or an object. When set to `true`, the default timeout of `3d` is used.

```json
{
  "enabled": true,
  "timeout": "3d"
}
```

##### enabled

Enable optimistic DNS caching.

##### timeout

The maximum time an expired cache entry can be served optimistically.

`3d` is used by default.

#### timeout

!!! question "Since sing-box 1.14.0"

Default timeout for each DNS query.

`10s` is used by default.

Can be overridden by `rules.[].timeout` (DNS rule action) or `domain_resolver.timeout`.

#### reverse_mapping

Stores a reverse mapping of IP addresses after responding to a DNS query in order to provide domain names when routing.

Since this process relies on the act of resolving domain names by an application before making a request, it can be
problematic in environments such as macOS, where DNS is proxied and cached by the system.

#### allow_resolver_discovery

Allow resolver discovery queries to follow the normal DNS rules and server selection.

Disabled by default. When disabled, SVCB queries whose names start with `_dns.`
(case-insensitive), such as `_dns.resolver.arpa.`, receive an empty successful
response (`NOERROR`) before DNS rules or upstream servers are consulted.

Set to `true` to remove this built-in rejection. DNS rules can still reject these
queries. Other query types and names are unaffected.

#### tcp_concurrent

Race TCP connections to all addresses a domain resolves to, and use the first connection established.

It applies wherever the handshake with the destination is confirmed before the dial returns:

* `direct` outbounds, for domains and for addresses resolved by the `resolve` route action;
* the server address of every outbound;
* VPN endpoints (WireGuard, Tailscale, OpenVPN, OpenConnect, MASQUE, EasyTier) and `tailcat` outbounds, inside the
  tunnel;
* through a `detour` to one of the above, which receives all addresses and races them itself;
* `socks` and `http` outbounds racing route-resolved destinations through the proxy, only with their own
  [`tcp_concurrent`](/configuration/shared/dial/#tcp_concurrent).

It does not apply to UDP, where connecting sends nothing to race; to dialers with `tcp_fast_open`, which defer the
handshake to the first write; or to proxy protocols such as VMess, VLESS, Trojan and Shadowsocks, which return before
their server reached the destination.

Attempts are ordered by connection history and address family: the address that last connected to the destination
goes first, addresses that failed within the last minute go last, and IPv6 and IPv4 addresses alternate, starting with
the family preferred by the domain strategy. Once a connection is established, the remaining attempts are canceled and
connections that complete afterwards are closed. A failed attempt starts the next one immediately. The history is
dropped when the network changes.

The [Clash API](/configuration/experimental/clash-api/) switches it at runtime with the `tcp-concurrent` field of
`PATCH /configs`, reports statistics and history at `GET /dns/tcp-concurrent` and clears the history with
`DELETE /dns/tcp-concurrent`. [Observability](/configuration/experimental/observability/) exports the statistics as
`singbox_tcp_concurrent_*` metrics. Dialers override it with their own
[`tcp_concurrent`](/configuration/shared/dial/#tcp_concurrent).

Accepts a boolean or an object. Disabled by default.

```json
{
  "enabled": true,
  "attempt_delay": "",
  "max_concurrent": 0
}
```

##### enabled

Enable concurrent TCP dialing.

##### attempt_delay

Fixed delay between successive connection attempts. `0s` starts all attempts at once.

When empty, the delay adapts to each destination: a destination without recent history starts all attempts at once,
while a destination that connected within the last 10 minutes starts with the address that won last time and starts
the others when it has not connected within twice its smoothed connect time, between `20ms` and `250ms`. A healthy
destination therefore costs a single handshake.

##### max_concurrent

Maximum number of attempts in progress at the same time. Further attempts start as earlier ones fail.

No limit by default.

#### client_subnet

!!! question "Since sing-box 1.9.0"

Append a `edns0-subnet` OPT extra record with the specified IP prefix to every query by default.

If value is an IP address instead of prefix, `/32` or `/128` will be appended automatically.

Can be overridden by `servers.[].client_subnet` or `rules.[].client_subnet`.
