### 结构

```json
{
  "type": "selector",
  "tag": "select",

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
  "include_type": [],
  "exclude_type": [],
  "network": "",
  "default": "proxy-c",
  "use_all_providers": false,
  "interrupt_exist_connections": false
}
```

!!! quote ""

    选择器目前只能通过 [Clash API](/zh/configuration/experimental/clash-api/) 来控制。

### 字段

#### outbounds

用于选择的出站标签列表。

#### providers

用于选择的[订阅](/zh/configuration/provider)标签列表。

#### exclude

排除 `providers` 节点的正则表达式。

#### include

包含 `providers` 节点的正则表达式。

#### include_type

`providers` 节点中保留的出站类型列表，例如 `vless`、`hysteria2`。

不区分大小写。接受当前构建中的所有出站与端点类型，以及 Clash 名称和简写 `ss`、`socks5`、`hy`、`hy1`、`hy2`、`wg`、`naiveproxy`、`shadow-tls`、`openvpn`、`masque`。未知类型会在启动时报错。

#### exclude_type

从 `providers` 节点中排除的出站类型列表，优先于 `include_type`。

#### network

`tcp`、`udp` 或二者组成的列表。

只保留支持全部所列网络的 `providers` 节点。能力取自节点本身，例如 Shadowsocks 节点上的 `"network": "tcp"`、Clash 订阅中的 `udp: false`，而不是节点名称。

各协议的 UDP 能力：

| 协议 | UDP |
|---|---|
| `shadowsocks` `vmess` `vless` `trojan` `socks` `snell` `anytls` `quicx` | 取自其 `network` 字段，订阅中取自 Clash 的 `udp` 字段 |
| `hysteria` `hysteria2` `tuic` | 支持，除非 `network` 为 `tcp`；来自 Clash 订阅时与 Clash 一致，始终支持 |
| `socks` 版本 `4` / `4a`、`naive` | 仅在启用 `udp_over_tcp` 时支持 |
| `http` | 取自其 `network` 字段（CONNECT-UDP）；来自 Clash 订阅时始终不支持 |
| `ssh` `shadowtls` `tor` | 不支持 |
| `wireguard` `tailscale` `tailcat` `nowhere` 等端点 | 支持 |

!!! note ""

    `include`、`exclude`、`include_type`、`exclude_type`、`network` 都只作用于 `providers` 节点，节点需全部满足才会加入；`outbounds` 中列出的成员始终保留。

#### default

默认的出站标签。默认使用第一个出站。

#### use_all_providers

是否使用所有提供者。默认使用 `false`。

#### interrupt_exist_connections

当选定的出站发生更改时，中断现有连接。

仅入站连接受此设置影响，内部连接将始终被中断。