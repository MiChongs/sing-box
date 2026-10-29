### 结构

```json
{
  "use_anyx": false,
  "client_metadata": "",
  "disable_reuse": false,
  "padding_scheme": [],
  "padding_scheme_interval": "30m",
  "min_idle_session": 0,
  "idle_session_timeout": "30s",
  "idle_session_min_timeout": "30s"
}
```

### 字段

作用于 `anytls` 与 `anyx` 节点。

#### use_anyx

把 `anytls` 节点转换为 [AnyX](/zh/configuration/outbound/anyx/) 节点，沿用服务器、密码、TLS 与会话设置。服务端须运行 AnyX。

#### client_metadata / disable_reuse / min_idle_session / idle_session_timeout

参阅 [AnyTLS 出站](/zh/configuration/outbound/anytls/) 与 [AnyX 出站](/zh/configuration/outbound/anyx/)。

#### padding_scheme / padding_scheme_interval / idle_session_min_timeout

仅作用于 AnyX 节点（包括经 `use_anyx` 转换的节点），参阅 [AnyX 出站](/zh/configuration/outbound/anyx/)。

未配置的字段保留订阅中的值。显式配置空的 `client_metadata` 会清空元数据；
`disable_reuse: false` 会显式重新启用复用。
