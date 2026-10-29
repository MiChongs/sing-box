### Structure

```json
{
  "enabled": true,
  "disable_sni": false,
  "server_name": "example.com",
  "certificate_server_name": "example.com",
  "insecure": false,
  "kernel_tx": false,
  "kernel_rx": false,
  "ech": {
    "enabled": true,
    "config": [],
    "config_path": "",
    "query_server_name": "encryptedsni.com"
  },
  "reality": {
    "key_share": "hybrid",
    "version": "26.3.27"
  }
}
```

### Fields

`enabled` `disable_sni` `server_name` `certificate_server_name` `insecure` `kernel_tx` `kernel_rx` `ech` see [TLS Fields](/configuration/shared/tls/#outbound).

`reality.key_share` and `reality.version` override the [REALITY fields](/configuration/shared/tls/#reality-fields) of nodes that already use REALITY, including the TLS of an XHTTP `download_settings`.
