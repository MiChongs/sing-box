### 结构

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

### 字段

`enabled` `disable_sni` `server_name` `certificate_server_name` `insecure` `kernel_tx` `kernel_rx` `ech` 详情参阅 [TLS 字段](/zh/configuration/shared/tls/#outbound)。
