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
          },
          "override_dialer": {},
          "override_tls": {},
          "override_anytls": {}
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

### Local or Remote Fields

#### override_anytls

Override AnyTLS fields of outbounds in provider, see [AnyTLS Fields Override](/configuration/provider/override_anytls/) for details.

#### override_dialer

Override dialer fields of outbounds in provider, see [Dialer Fields Override](/configuration/provider/override_dialer/) for details.

#### override_tls

Override TLS fields of outbounds in provider, see [TLS Fields Override](/configuration/provider/override_tls/) for details.

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
