### 结构

```json
{
  "type": "anyx",
  "tag": "anyx-in",

  ... // 监听字段

  "users": [
    {
      "name": "sekai",
      "password": "8JCsPssfgS8tiRwiMlhARg=="
    }
  ],
  "encryption": {
    "method": "2022-blake3-aes-128-gcm",
    "password": "8JCsPssfgS8tiRwiMlhARg=="
  },
  "padding_scheme": [],
  "padding_scheme_interval": "30m",
  "padding_limit": 2000,
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 8080
  },
  "fallback_for_alpn": {
    "http/1.1": {
      "server": "127.0.0.1",
      "server_port": 8081
    }
  },
  "pseudo_vpn": {
    "enabled": false,
    "interface_name": "anyx-tun",
    "address": [
      "100.64.0.1/24",
      "fd00::1/64"
    ],
    "mtu": 1400,
    "lease_duration": "72h",
    "tcp_mss_clamping": true
  },
  "tls": {},
  "transport": {}
}
```

AnyX 是在 AnyTLS 基础上改造的多路复用协议，不再依赖 TLS：可以跑在明文 TCP 或 [V2Ray 传输层](/zh/configuration/shared/v2ray-transport/) 上，并可用 Shadowsocks 加密方式加密会话。与 AnyTLS 不互通。

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### users

==必填==

AnyX 用户：`name` 用于日志，`password` 用于认证客户端。

#### encryption

会话内层加密，两端须一致。为空或 `method` 为 `none` 时不加密。

* `method`：`aes-128-gcm`、`aes-192-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`xchacha20-ietf-poly1305`、`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm` 或 `2022-blake3-chacha20-poly1305`。
* `password`：传统 AEAD 可用任意字符串；2022 系列需填 16 或 32 字节的 base64 密钥。

#### padding_scheme

服务端下发给客户端的填充方案。为空时为 `off`。

* `off`：不填充。
* `auto`：随机生成的方案，每隔 `padding_scheme_interval` 重新生成。
* AnyTLS 格式的自定义方案，例如 `["stop=8", "0=30-30", "1=100-200", "2=300-400,c,500-600"]`。

#### padding_scheme_interval

`auto` 重新生成方案的间隔，实际在该间隔的 70%–130% 之间随机取时间点。默认 `30m`。

#### padding_limit

认证前允许的握手填充与 waste 帧的最大字节数，超出即断开，用于防御慢速耗尽。默认 `2000`。

#### fallback

首包认证失败时的回落目标（`server` 可为 IP、域名或 unix socket 路径）。

#### fallback_for_alpn

按协商出的 TLS ALPN 选择的回落目标，仅在启用 TLS 时生效。

#### tls

入站 TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#入站)。支持 REALITY 与 [幻影 TLS](/zh/configuration/shared/tls/#phantom-字段)。为空时为明文 TCP。

#### transport

V2Ray 传输层配置，参阅 [V2Ray 传输层](/zh/configuration/shared/v2ray-transport/)。

#### pseudo_vpn

提供 AnyX 伪 VPN：出站启用了 [`pseudo_vpn`](/zh/configuration/outbound/anyx/#pseudo_vpn) 的客户端获得一个虚拟地址，经 AnyX 会话透传三层 IP 报文（TCP 与 ICMP）；服务端把报文写入系统 TUN 网卡，由主机转发。

* `enabled`：启用伪 VPN。
* `interface_name`：服务端 TUN 网卡名，默认 `anyx-tun`。
* `address`：==必填== 虚拟子网，最多一个 IPv4 与一个 IPv6 前缀，如 `["100.64.0.1/24", "fd00::1/64"]`。前缀中的地址即服务端在该子网的地址（为网络地址时顺延到下一个），其余地址租给客户端。
* `mtu`：TUN 网卡与隧道的 MTU，默认 `1400`，取值 `576`–`65527`，配置 IPv6 子网时不低于 `1280`。客户端取自身 MTU 与该值的较小者。
* `lease_duration`：客户端地址租约时长，默认 `72h`，限制在 `5m`–`168h`。客户端有流量时自动续约；在租约内重连的客户端保留原地址。
* `tcp_mss_clamping`：双向钳制 TCP SYN 报文的 MSS 以适配 MTU，默认启用。

地址分配：

* 粘性：客户端重连时带上原地址与租约凭据，租约有效期内拿回同一地址。客户端重启后客户端 ID 会变，服务端按认证用户（`users[].name`）记住其地址：同一用户的旧客户端已离线、或其租约已过期时，新客户端拿回该地址；旧客户端仍在线时（同一用户的多台设备）分配新地址。
* 回收：租约在客户端有流量时续约，过期后每 30 秒清扫一次，地址与路由一并回收；之后发往该地址的报文被丢弃，客户端再发包时会收到租约失效通知并自动重新协商。
* 耗尽：单个地址池最多持有 65536 条租约。地址池占满时，为新客户端驱逐最久未活动且没有存活会话的客户端租约；所有租约的持有者都在线时拒绝新客户端。一个会话只承载一个客户端：同一会话以不同的客户端 ID 申请地址时，先前客户端的地址会被回收。
* 安全：服务端只转发源地址属于该客户端租约的报文（严格 RPF），并限速回复租约失效通知；UDP 报文不经伪 VPN 转发。

主机需要开启转发并伪装虚拟子网。sing-box 只创建网卡并配置地址，不修改防火墙。以 `anyx-tun`、`100.64.0.0/24` 与 `fd00::/64` 为例，iptables：

```bash
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
# 反向路径过滤取宽松模式，避免内核丢弃经虚拟网卡进入的回程报文
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.anyx-tun.rp_filter=2

# 允许客户端访问服务端本机服务（可选）
iptables -I INPUT 1 -i anyx-tun -j ACCEPT
# 放行转发与回程
iptables -I FORWARD 1 -i anyx-tun -j ACCEPT
iptables -I FORWARD 2 -o anyx-tun -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# 出站源地址伪装（排除虚拟子网内部互访）
iptables -t nat -I POSTROUTING 1 -s 100.64.0.0/24 ! -d 100.64.0.0/24 -j MASQUERADE

ip6tables -I INPUT 1 -i anyx-tun -j ACCEPT
ip6tables -I FORWARD 1 -i anyx-tun -j ACCEPT
ip6tables -I FORWARD 2 -o anyx-tun -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -t nat -I POSTROUTING 1 -s fd00::/64 ! -d fd00::/64 -j MASQUERADE
```

nftables：

```
table inet anyx {
  chain input {
    type filter hook input priority filter; policy accept;
    iifname "anyx-tun" accept
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname "anyx-tun" accept
    oifname "anyx-tun" ct state related,established accept
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 100.64.0.0/24 ip daddr != 100.64.0.0/24 masquerade
    ip6 saddr fd00::/64 ip6 daddr != fd00::/64 masquerade
  }
}
```

若 `forward` 链默认策略为 `drop`（例如装有 Docker 或 firewalld），上述放行规则必须排在拒绝规则之前。创建 TUN 网卡需要 root（或 `CAP_NET_ADMIN`）权限。
