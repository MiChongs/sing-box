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
  }
}
```

### Fields

`enabled` `disable_sni` `server_name` `certificate_server_name` `insecure` `kernel_tx` `kernel_rx` `ech` see [TLS Fields](/configuration/shared/tls/#outbound).
