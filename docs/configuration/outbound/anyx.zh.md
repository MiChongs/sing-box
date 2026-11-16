### 结构

```json
{
  "type": "anyx",
  "tag": "anyx-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "password": "8JCsPssfgS8tiRwiMlhARg==",
  "client_metadata": "",
  "encryption": {
    "method": "2022-blake3-aes-128-gcm",
    "password": "8JCsPssfgS8tiRwiMlhARg=="
  },
  "padding_scheme": [],
  "padding_scheme_interval": "30m",
  "disable_reuse": false,
  "idle_session_min_timeout": "30s",
  "idle_session_timeout": "30s",
  "min_idle_session": 0,
  "network": "tcp",
  "pseudo_vpn": {
    "enabled": false,
    "mtu": 1400,
    "tcp_mss_clamping": true,
    "udp": "drop"
  },
  "tls": {},
  "transport": {},

  ... // 拨号字段
}
```

协议说明参阅 [AnyX 入站](/zh/configuration/inbound/anyx/)。

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### password

==必填==

AnyX 密码。

#### client_metadata

握手中上报的客户端标识，默认 `anyx sing-box/<版本>`。设为空字符串时上报 `anyx`。

#### encryption

会话内层加密，须与服务端一致。参阅 [AnyX 入站](/zh/configuration/inbound/anyx/#encryption)。

#### padding_scheme

初始填充方案，默认 `auto`；收到服务端下发的方案后以其为准。取值与入站相同。

#### padding_scheme_interval

`auto` 重新生成方案的间隔，实际在该间隔的 70%–130% 之间随机取时间点。

#### disable_reuse

每个流独占一条连接，不在连接池会话上复用。

#### idle_session_min_timeout

连接池中空闲会话被关闭前的最短空闲时间。默认 30s。

#### idle_session_timeout

关闭空闲超过该时间的连接池会话。默认 30s。

#### min_idle_session

保持打开的空闲会话数量。默认 0。

#### network

启用的网络协议，`tcp` 或 `udp`，默认两者都启用。分组按 UDP 能力筛选成员时以此为准。

#### tls

出站 TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#出站)。支持 REALITY 与 [幻影 TLS](/zh/configuration/shared/tls/#phantom-字段)。为空时为明文 TCP。

#### transport

V2Ray 传输层配置，参阅 [V2Ray 传输层](/zh/configuration/shared/v2ray-transport/)。

#### pseudo_vpn

把 IP 报文转发到启用了 [`pseudo_vpn`](/zh/configuration/inbound/anyx/#pseudo_vpn) 的 AnyX 服务端。启用后该出站成为[预匹配](/zh/configuration/shared/pre-match/) `route` 的 L3 目标：从 TUN 入站路由到它的 TCP 与 ICMP 连接以 IP 报文经 AnyX 会话转发，而不是作为流代理。服务端租给客户端一个虚拟 IPv4 / IPv6 地址，出站在它与本地 TUN 地址之间做转换。

* `enabled`：启用伪 VPN。
* `mtu`：隧道 MTU，默认 `1400`；实际取该值与服务端 MTU 的较小者。
* `tcp_mss_clamping`：钳制 TCP SYN 报文的 MSS 以适配 MTU，默认启用。
* `udp`：UDP 的处理方式，伪 VPN 不承载 UDP。
    * `drop`（默认）：在本地丢弃 UDP 报文。
    * `reject`：在本地回复 ICMP 端口不可达。
    * `transparent`：交还常规 L4 路径（例如经本出站的 UDP over TCP 或其他规则）。

伪 VPN 只在预匹配中生效：连接必须来自 [TUN 入站](/zh/configuration/inbound/tun/)，并在 L3 到 L4 转换之前被路由到该出站（直接匹配、`route.final`，或作为出站组当前选中的成员）。以其他方式到达该出站的连接（SOCKS / HTTP 入站，或在 TCP 上经过 `sniff` 等需要更多连接数据的规则之后）照常作为流代理。例如：

```json
{
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "auto_route": true
    }
  ],
  "outbounds": [
    {
      "type": "anyx",
      "tag": "anyx-vpn",
      "server": "example.com",
      "server_port": 443,
      "password": "...",
      "tls": { "enabled": true, "server_name": "example.com" },
      "pseudo_vpn": { "enabled": true, "udp": "transparent" }
    }
  ],
  "route": {
    "rules": [
      { "ip_cidr": ["10.0.0.0/8"], "action": "route", "outbound": "anyx-vpn" }
    ],
    "final": "anyx-vpn"
  }
}
```

TUN 把命中的连接转发给出站时，源地址是出站的本地端口地址（RFC 7600 的 IPv4 dummy 地址 `192.0.0.8` 与 `fd61:6e79:7876::2`）；出站在上行时把它换成租到的虚拟地址、下行时换回，并修正 TCP、UDP、ICMP 校验和以及 ICMP 差错报文的内嵌头。两个地址族总是都通告，服务端未分配的地址族会被丢弃，而不会经本地协议栈泄漏。

出站启动时以及服务端报告租约失效时在后台协商地址，就绪前的报文会被丢弃。出站在重连与网络切换之间保留客户端 ID 与租约凭据，租约有效期内重新获得同一地址；重启后，只要同一用户的其他客户端没有占用，服务端会把该用户先前的地址还给它。会话丢失时按需重建，失败后指数退避，不会阻塞 TUN；已建立的连接在新会话上继续工作。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
