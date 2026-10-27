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

不区分大小写，并接受别名 `ss`、`socks5`、`hy`、`hy2`、`wg`。未知类型会在启动时报错。

#### exclude_type

从 `providers` 节点中排除的出站类型列表，优先于 `include_type`。

#### network

`tcp`、`udp` 或二者组成的列表。

只保留支持全部所列网络的 `providers` 节点。能力取自节点本身，例如 Shadowsocks 节点上的 `"network": "tcp"`、Clash 订阅中的 `udp: false`，而不是节点名称。

`http` 出站始终声明支持 UDP，因为它可以通过 CONNECT-UDP（MASQUE）转发 UDP，但多数普通 HTTP 代理服务端并不支持。需要时请配合 `"exclude_type": ["http"]`。

!!! note ""

    `include`、`exclude`、`include_type`、`exclude_type`、`network` 都只作用于 `providers` 节点，节点需全部满足才会加入；`outbounds` 中列出的成员始终保留。

#### default

默认的出站标签。默认使用第一个出站。

#### use_all_providers

是否使用所有提供者。默认使用 `false`。

#### interrupt_exist_connections

当选定的出站发生更改时，中断现有连接。

仅入站连接受此设置影响，内部连接将始终被中断。