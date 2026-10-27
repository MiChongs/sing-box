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

Case-insensitive. The aliases `ss`, `socks5`, `hy`, `hy2` and `wg` are accepted. Unknown types are rejected at startup.

#### exclude_type

List of outbound types to drop from `providers` nodes. Takes precedence over `include_type`.

#### network

`tcp`, `udp`, or a list of both.

Keep only `providers` nodes that support every listed network. The capability comes from the node itself, for example `"network": "tcp"` on a Shadowsocks node or `udp: false` in a Clash subscription, not from its name.

`http` outbounds always declare UDP because they can relay it with CONNECT-UDP (MASQUE), which most plain HTTP proxy servers do not support. Add `"exclude_type": ["http"]` when that matters.

!!! note ""

    `include`, `exclude`, `include_type`, `exclude_type` and `network` all apply to `providers` nodes only, and a node must pass every one of them. Members listed in `outbounds` are always kept.

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
