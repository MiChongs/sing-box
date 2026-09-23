### 结构

```json
{
  "type": "urltest",
  "tag": "auto",
  
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
  "url": "",
  "interval": "",
  "expected_status": "",
  "tolerance": 50,
  "idle_timeout": "",
  "use_all_providers": false,
  "hidden": false,
  "icon": "",
  "fallback": {
    "enabled": false,
    "max_delay": ""
  },
  "interrupt_exist_connections": false
}
```

!!! quote ""

    可以通过 [Clash API](/zh/configuration/experimental/clash-api/) 或图形客户端手动选择成员。
    手动选择在重启和定期测试后保留，由用户下一次手动触发的组测速解除。

### 字段

#### outbounds

用于测试的出站标签列表。

#### providers

用于测试的[订阅](/zh/configuration/provider)标签列表。

#### exclude

排除 `providers` 节点的正则表达式。

#### include

包含 `providers` 节点的正则表达式。

#### url

用于测试的链接。默认使用 `https://www.gstatic.com/generate_204`。

#### interval

测试间隔。 默认使用 `3m`。

#### expected_status

测试链接被视为成功的 HTTP 状态码，兼容 mihomo 的 `expected-status`：
单个状态码 `204`、范围 `200-299`、用 `/` 连接的多个值或范围（如 `200/204`、`200-299/301-302`），或 `*` 表示任意状态码。

留空时，`generate_204` 链接必须返回 `204`，其他链接的状态码需低于 `400`。

#### tolerance

以毫秒为单位的测试容差。 默认使用 `50`。

#### idle_timeout

空闲超时。默认使用 `30m`。

#### use_all_providers

是否使用所有提供者。默认使用 `false`。

#### fallback

回退选择配置。

启用后，将按配置顺序选择首个可用出站，而不是选择延迟最低的出站。

##### fallback.enabled

启用回退选择。

##### fallback.max_delay

可接受的最大延迟。

延迟超过该值的出站会被跳过。如果所有可用出站均超过该值，则选择其中延迟最低的出站。

#### interrupt_exist_connections

当选定的出站发生更改时，中断现有连接。

仅入站连接受此设置影响，内部连接将始终被中断。

#### hidden

在 [Clash API](/zh/configuration/experimental/clash-api/) 面板的代理切换列表中隐藏此组，不影响路由。

#### icon

[Clash API](/zh/configuration/experimental/clash-api/) 面板中显示的组图标，可以是 URL、data URI 或 emoji。
