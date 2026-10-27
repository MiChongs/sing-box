### Structure

```json
{
  "type": "selector",
  "tag": "select",
  
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
  "network": "",
  "default": "proxy-c",
  "use_all_providers": false,
  "interrupt_exist_connections": false
}
```

!!! quote ""

    The selector can only be controlled through the [Clash API](/configuration/experimental#clash-api-fields) currently.

### Fields

#### outbounds

List of outbound tags to select.

#### providers

List of [Provider](/configuration/provider) tags to select.

#### use_all_providers

Use all [Provider](/configuration/provider) to fill `outbounds`.

#### exclude

Exclude regular expression to filter `providers` nodes. The priority of the exclude expression is higher than the include expression.

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

#### default

The default outbound tag. The first outbound will be used if empty.

#### use_all_providers

Whether to use all providers for testing. `false` will be used if empty.

#### interrupt_exist_connections

Interrupt existing connections when the selected outbound has changed.

Only inbound connections are affected by this setting, internal connections will always be interrupted.
