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
  },
  "reality": {
    "key_share": "hybrid",
    "version": "26.3.27"
  }
}
```

### 字段

`enabled` `disable_sni` `server_name` `certificate_server_name` `insecure` `kernel_tx` `kernel_rx` `ech` 详情参阅 [TLS 字段](/zh/configuration/shared/tls/#outbound)。

`reality.key_share` 与 `reality.version` 覆写已启用 REALITY 的节点的 [REALITY 字段](/zh/configuration/shared/tls/#reality-字段)，同时作用于 XHTTP `download_settings` 中的 TLS。
