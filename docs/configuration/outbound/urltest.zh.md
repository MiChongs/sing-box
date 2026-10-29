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
  "include_type": [],
  "exclude_type": [],
  "include_transport": [],
  "exclude_transport": [],
  "network": "",
  "url": "",
  "interval": "",
  "tolerance": 50,
  "idle_timeout": "",
  "use_all_providers": false,
  "fallback": {
    "enabled": false,
    "max_delay": ""
  },
  "interrupt_exist_connections": false
}
```

### 字段

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

不区分大小写。接受当前构建中的所有出站与端点类型，以及 Clash 名称和简写 `ss`、`socks5`、`hy`、`hy1`、`hy2`、`wg`、`naiveproxy`、`shadow-tls`、`openvpn`、`masque`。未知类型会在启动时报错。

#### exclude_type

从 `providers` 节点中排除的出站类型列表，优先于 `include_type`。

#### include_transport

`providers` 节点中保留的传输方式列表：`tcp`（无传输层）、`ws`、`httpupgrade`、`http`、`grpc`、`quic`、`xhttp` 以及其他已注册的插件传输。接受 Clash 名称 `websocket`、`h2`、`gun`、`raw`、`splithttp`。

只有 `vmess`、`vless`、`trojan` 和 `shadowsocks`（其 `v2ray-plugin` 视为 `ws` 或 `quic`）有传输方式。其他节点不属于任何传输：`include_transport` 会排除它们，`exclude_transport` 会保留它们。

#### exclude_transport

从 `providers` 节点中排除的传输方式列表，优先于 `include_transport`。

#### network

`tcp`、`udp` 或二者组成的列表。

只保留支持全部所列网络的 `providers` 节点。能力取自节点本身，例如 Shadowsocks 节点上的 `"network": "tcp"`、Clash 订阅中的 `udp: false`，而不是节点名称。若订阅源开启了 UDP 探测（`health_check.udp`），探测失败且结果仍有效的节点会被移除，直到再次探测成功。

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

    `include`、`exclude`、`include_type`、`exclude_type`、`include_transport`、`exclude_transport`、`network` 在 selector、urltest、loadbalance、smart 分组中行为一致，每次订阅更新后重新应用，且都只作用于 `providers` 节点，节点需全部满足才会加入；`outbounds` 中列出的成员始终保留。

#### url

用于测试的链接。默认使用 `https://www.gstatic.com/generate_204`。

#### interval

测试间隔。 默认使用 `3m`。

每个间隔都会测试当前选择、延迟最低的 3 个成员以及从未测试过的成员。
其余成员每 4 个间隔刷新一次。
连续测试失败的成员按 1、2、4 直至 8 个间隔退避重试；网络变化时重置退避。

其他组或 API 刚测过的成员不会重复测试，多个组同时测试同一成员时只发起一次测试。
所有组的测试在同一时刻进行，间隔相同的组每个间隔只唤醒一次网络。
网络变化后会重新测试当前选择和延迟最低的成员，最多每 30 秒一次。

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

### 健康检查行为

* **选择**：先找出延迟最低的成员；当前成员的延迟在其 `tolerance` 以内时保持不变。
* **冷启动**：成员尚未测速时，在支持该网络的成员中随机选一个并固定，避免首批连接全部压到第一个成员。
* **启动**：启动后先探测一次。若没有任何成员可用（网络尚未就绪），在启动后 15s、35s、60s 重试（不晚于 `interval`），直到有成员可用或分组进入闲置。
* **连接失败**：失败的成员会在测速最优的其他成员上重试。没有其他已测速成员时，3 秒后单独探测失败的成员：可用则 1 分钟内信任它，否则移除其测速记录并改选其他成员。全部成员失效时重新探测所有成员，最多每 90 秒一次。
* **手动选择**：通过 Clash API 选择成员时会先探测，不可用则拒绝。手动选择不会被周期检测或连接失败解除，用户主动测速或选择空名称时才恢复自动选择。
