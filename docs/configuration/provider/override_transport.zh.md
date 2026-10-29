### 结构

```json
{
  "xhttp_download_enabled": true,
  "xhttp_download_detour": ""
}
```

### 字段

作用于使用 XHTTP 传输层并配置了 `download_settings` 的节点。

#### xhttp_download_enabled

启用或关闭 `download_settings` 描述的独立下行连接。关闭后上下行都走上行连接。

#### xhttp_download_detour

拨号下行连接所用出站的标签。
