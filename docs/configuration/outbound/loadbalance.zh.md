当此组被引用时，所有候选出站（包括 provider 成员）都会在空闲连接管理中被视为已引用，
不受健康检查结果影响，以保持它们依赖的按需端点可供选择。

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
  "include_type": [],
  "exclude_type": [],
  "network": "",
  "url": "",
  "interval": "",
  "idle_timeout": "",
  "ttl": "10m",
  "use_all_providers": false
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

#### include_type

`providers` 节点中保留的出站类型列表，例如 `vless`、`hysteria2`。

不区分大小写，并接受别名 `ss`、`socks5`、`hy`、`hy2`、`wg`。未知类型会在启动时报错。

#### exclude_type

从 `providers` 节点中排除的出站类型列表，优先于 `include_type`。

#### network

`tcp`、`udp` 或二者组成的列表。

只保留支持全部所列网络的 `providers` 节点。能力取自节点本身，例如 Shadowsocks 节点上的 `"network": "tcp"`、Clash 订阅中的 `udp: false`，而不是节点名称。

`http` 出站始终声明支持 UDP，因为它可以通过 CONNECT-UDP（MASQUE）转发 UDP，但多数普通 HTTP 代理服务端并不支持。需要时请配合 `"exclude_type": ["http"]`。

!!! note ""

    `include`、`exclude`、`include_type`、`exclude_type`、`network` 都只作用于 `providers` 节点，节点需全部满足才会加入；`outbounds` 中列出的成员始终保留。

#### url

用于测试的链接。默认使用 `https://www.gstatic.com/generate_204`。

#### interval

测试间隔。 默认使用 `3m`。

#### idle_timeout

空闲超时。默认使用 `30m`。

#### ttl

用于 `sticky-sessions` 策略超时的生存时间。默认使用 `10m`。

#### use_all_providers

是否使用所有提供者。默认使用 `false`。
