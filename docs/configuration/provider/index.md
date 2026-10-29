# Provider

!!! quote "Changes in sing-box 1.14.0"

    :material-plus: [http_client](#http_client)

    :material-delete-clock: [download_detour](#download_detour)

### Structure

List of subscription providers.

=== "Local File"

    ```json
    {
      "providers": [
        {
          "type": "local",
          "tag": "provider",
          "path": "provider.txt",
          "health_check": {
            "enabled": false,
            "url": "",
            "interval": "",
            "timeout": "",
            "udp": {}
          },
          "override_dialer": {},
          "override_tls": {},
          "override_anytls": {},
          "override_transport": {}
        }
      ]
    }
    ```

=== "Remote File"

    ```json
    {
      "providers": [
        {
          "type": "remote",
          "tag": "provider",
          "health_check": {
            "enabled": false,
            "url": "",
            "interval": "",
            "timeout": "",
            "udp": {}
          },
          "url": "",
          "path": "",
          "exclude": "",
          "include": "",
          "user_agent": "",
          "http_client": "", // or {}
          "update_interval": "",
          "override_dialer": {},
          "override_tls": {},

          "override_anytls": {},
          "override_transport": {},

          // Deprecated

          "download_detour": ""
        }
      ]
    }
    ```

=== "Inline"

    ```json
    {
      "providers": [
        {
          "type": "inline",
          "tag": "provider",
          "health_check": {
            "enabled": false,
            "url": "",
            "interval": "",
            "timeout": "",
            "udp": {}
          },
          "outbounds": [],
          "endpoints": []
        }
      ]
    }
    ```

### Fields

#### type

==Required==

Type of the provider. `local`, `remote` or `inline`.

#### tag

==Required==

Tag of the provider.

The node `node_name` from `provider` will be tagged as `provider/node_name`.

### Common Fields

#### health_check

Health check configuration.

##### health_check.enabled

Health check enabled.

##### health_check.url

Health check URL.

##### health_check.interval

Health check interval. The minimum value is `1m`, the default value is `10m`.

##### health_check.timeout

Health check timeout. the default value is `3s`.

##### health_check.udp

Probe the real UDP support of nodes on every health check round, independently of `health_check.enabled`:

```json
{
  "enabled": true,
  "server": "1.1.1.1:53",
  "domain": "www.gstatic.com",
  "timeout": "5s",
  "ttl": ""
}
```

Each node that declares UDP sends a DNS query for `domain` over UDP to `server` through itself, resending every second until `timeout`. A matching answer proves the node relays UDP; no answer within `timeout` marks it as not relaying UDP. Nodes that only declare TCP are not probed.

A result counts for `ttl`, by default three health check intervals. A failed result that is still valid:

* removes the node from groups filtering on `"network": "udp"`, and puts it back once a later probe succeeds;
* keeps urltest, loadbalance and smart groups from choosing the node for UDP connections; manual selections are kept;
* reports the node as `udp: false` in the Clash API, which also returns the latest probe as `udpTest`.

Nodes that were never probed, or whose result expired, keep their declared UDP support.

The probe needs a DNS server reachable from every node; pick one the nodes do not block.

### Local or Remote Fields

#### override_anytls

Override AnyTLS fields of outbounds in provider, see [AnyTLS Fields Override](/configuration/provider/override_anytls/) for details.

#### override_dialer

Override dialer fields of outbounds in provider, see [Dialer Fields Override](/configuration/provider/override_dialer/) for details.

#### override_transport

Override transport fields of outbounds in provider, see [Transport Fields Override](/configuration/provider/override_transport/) for details.

#### override_tls

Override TLS fields of outbounds in provider, see [TLS Fields Override](/configuration/provider/override_tls/) for details.

### Clash Subscriptions

Clash / mihomo `proxies` are converted to sing-box outbounds and endpoints:

| Clash type | sing-box |
|---|---|
| `ss` `vmess` `vless` `trojan` `socks5` `http` `snell` `ssh` `anytls` `hysteria` `hysteria2` `tuic` `direct` | outbound of the same protocol |
| `wireguard` `tailscale` `openvpn` `easytier` | endpoint |

A proxy that needs something this build does not implement is skipped and the reason is logged as a warning, for example `ssr`, `mieru`, `sudoku`, `shadowquic`, `gost-relay`, `trusttunnel`, `zerotier`, Cloudflare WARP `masque`, `restls` / `jls` / `tlsmirror`, the mKCP and mekya transports, TUIC v4, AmneziaWG, SOCKS5 over TLS, the `restls` / `gost-plugin` / `kcptun` plugins and Clash `dns` / `reject` proxies.

`shadow-tls` (the Shadowsocks plugin and `shadow-tls-opts`) becomes an extra shadowtls outbound named `<name> (shadow-tls)` that the proxy dials through. Such outbounds never join groups. A Shadowsocks proxy behind shadow-tls is TCP only unless `udp-over-tcp` is enabled, because sing-box cannot send its native UDP around the detour.

Options without a counterpart are ignored and the node keeps the sing-box default: `ip-version`, gRPC `grpc-user-agent` and connection pool, `v2ray-http-upgrade-fast-open`, Reality `support-x25519mlkem768`, Hysteria 2 `cwnd` / `udp-mtu` / `handshake-timeout` / obfs packet sizes, TUIC tuning beyond the receive windows, WireGuard / OpenVPN `dns` and `ip-stack`, and EasyTier KCP / QUIC proxy switches.

### Local Fields

#### path

==Required==

!!! note ""

    Will be automatically reloaded if file modified since sing-box 1.10.0.

Local file path.

### Inline Fields

#### outbounds

List of [Outbound](/configuration/outbound/) written directly in the configuration.

A `detour` that points to another node of the same provider is rewritten to `provider/node_name`; any other `detour` is kept as is, so inline nodes can be chained through a group defined in `outbounds`.

#### endpoints

List of [Endpoint](/configuration/endpoint/) written directly in the configuration.

### Remote Fields

#### url

==Required==

URL to the provider.

#### path

Path used to store the downloaded provider.

The cache metadata is stored in `cache.db`.

Conflicts with `initial_path`.

#### initial_path

Path to the initial provider content.

It is loaded only when provider caching in `cache.db` is enabled and no cached provider is available. It is not used as the persistent cache path.

Conflicts with `path`.

#### exclude

Exclude regular expression to filter nodes.

The filter is also applied when the provider is restored from `path` or `cache.db`. If `include`, `exclude` or any `override_*` field changed since the cache was written, the cached nodes are served with the current filter and the provider is refreshed in the background once, ignoring the cached ETag.

#### include

Include regular expression to filter nodes.

#### user_agent

User agent used to download the provider.

#### http_client

!!! question "Since sing-box 1.14.0"

HTTP Client for downloading provider.

See [HTTP Client Fields](/configuration/shared/http-client/) for details.

Default transport will be used if empty.

#### download_detour

!!! failure "Deprecated in sing-box 1.14.0"

    `download_detour` is deprecated in sing-box 1.14.0 and will be removed in sing-box 1.16.0, use `http_client` instead.

Tag of the outbound used to download from the provider.

#### update_interval

Update interval. The minimum value is `1h`, the default value is `24h`.
