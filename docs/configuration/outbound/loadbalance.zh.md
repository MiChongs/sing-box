### 结构

```json
{
  "type": "loadbalance",
  "tag": "balance",
  "strategy": "round-robin",

  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "providers": [
    "provider-a",
    "provider-b"
  ],
  "exclude": "",
  "include": "",
  "url": "",
  "interval": "",
  "expected_status": "",
  "idle_timeout": "",
  "ttl": "10m",
  "use_all_providers": false,
  "hidden": false,
  "icon": ""
}
```

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签。

### 字段

#### strategy

负载均衡策略。

* `round-robin` 将在策略组内的不同代理节点之间分配所有请求。

* `consistent-hashing` 将具有相同 `目标地址` 的请求分配给策略组内的同一代理节点。

* `sticky-sessions`：具有相同 `源地址` 和 `目标地址` 的请求将被导向策略组内的同一代理节点，缓存过期时间为指定的 ttl。

!!! note
    当 `目标地址` 是域名时，使用顶级域名匹配。

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

#### idle_timeout

空闲超时。默认使用 `30m`。

#### expected_status

测试链接被视为成功的 HTTP 状态码，兼容 mihomo 的 `expected-status`：
单个状态码 `204`、范围 `200-299`、用 `/` 连接的多个值或范围（如 `200/204`、`200-299/301-302`），或 `*` 表示任意状态码。

留空时，`generate_204` 链接必须返回 `204`，其他链接的状态码需低于 `400`。

#### ttl

用于 `sticky-sessions` 策略超时的生存时间。默认使用 `10m`。

#### use_all_providers

是否使用所有提供者。默认使用 `false`。

#### hidden

在 [Clash API](/zh/configuration/experimental/clash-api/) 面板的代理切换列表中隐藏此组，不影响路由。

#### icon

[Clash API](/zh/configuration/experimental/clash-api/) 面板中显示的组图标，可以是 URL、data URI 或 emoji。
