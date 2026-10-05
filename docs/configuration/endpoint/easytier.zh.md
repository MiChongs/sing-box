# EasyTier

!!! question "自 sing-box 1.15.0 起"

`easytier` 端点用于加入 [EasyTier](https://github.com/EasyTier/EasyTier) 虚拟网络。

EasyTier 内核以 WebAssembly 形式内嵌并运行在 sing-box 中，不需要外部 `easytier-core` 进程或 Rust 工具链。

!!! quote ""

    默认安装不包含 EasyTier，参阅 [安装](/zh/installation/build-from-source/#构建标记)。

## 结构

```json
{
  "type": "easytier",
  "tag": "easytier-ep",

  "network_name": "",
  "network_secret": "",
  "hostname": "",
  "tld_dns_zone": "",
  "address": [],
  "peers": [],
  "listeners": [],
  "proxy_networks": [
    {
      "cidr": "",
      "mapped_cidr": ""
    }
  ],
  "enable_exit_node": false,
  "exit_nodes": [],
  "port_forwards": [
    {
      "network": "",
      "listen": "",
      "destination": ""
    }
  ],
  "stun_servers": [],
  "stun_servers_v6": [],
  "disable_encryption": false,
  "encryption_algorithm": "",
  "secure_mode": {
    "enabled": false,
    "private_key": ""
  },
  "disable_p2p": false,
  "lazy_p2p": false,
  "need_p2p": false,
  "p2p_only": false,
  "disable_tcp_hole_punching": false,
  "disable_udp_hole_punching": false,
  "disable_sym_hole_punching": false,
  "latency_first": false,
  "private_mode": false,
  "relay_network_whitelist": [],
  "relay_all_peer_rpc": false,
  "web": {
    "server": "",
    "machine_id": "",
    "hostname": "",
    "secure_mode": false
  },
  "system": false,
  "gso": false,
  "inner_domain_resolver": "", // 或 {}
  "name": "",
  "mtu": 1380,
  "udp_timeout": "",

  ... // UDP NAT 字段
  ... // 拨号字段
}
```

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签

## 字段

### network_name

未设置 `web` 时==必填==。

EasyTier 网络名称。

下面的网络字段用于配置该网络。只设置 `web` 时，网络改由配置服务器下发。

### network_secret

EasyTier 网络密钥。

### hostname

向其他节点通告的主机名，最多 32 个字符。

默认使用系统主机名。

其他节点通过 [Magic DNS](#magic-dns) 以 `<hostname>.<tld_dns_zone>` 解析本节点。

### tld_dns_zone

此网络 [Magic DNS](#magic-dns) 名称所在的区域。

默认使用 `et.net`。

### address

本节点的虚拟 IP 前缀，最多一个 IPv4 前缀和一个 IPv6 前缀。

IPv4 前缀必须短于 `/32`，例如 `10.144.144.1/24`。

未设置 IPv4 前缀时，自动分配 IPv4 地址（DHCP），出站连接会等待地址分配完成。

### peers

要连接的节点 URL，例如 `tcp://public.easytier.cn:11010` 或 `udp://198.51.100.1:11010`。

`txt://` 和 `srv://` 发现 URL 通过 sing-box DNS 路由解析。

### listeners

接受其他节点连接的监听 URL，例如 `tcp://0.0.0.0:11010` 和 `udp://0.0.0.0:11010`。

监听器始终直接绑定在本机上，不受 `detour` 影响。

### proxy_networks

本节点后方、允许其他节点经由本节点访问的 IPv4 网段（子网代理）。

其他节点访问这些网段的流量会交给 sing-box 处理，参阅 [子网代理与出口节点](#子网代理与出口节点)。

#### cidr

==必填==

实际网段。

#### mapped_cidr

改用该前缀向其他节点通告此网段，例如用于避免多个站点使用相同私有网段时的冲突。大小必须与 `cidr` 相同。

其他节点随后使用 `mapped_cidr` 内的地址访问，这些地址会被转换为 `cidr` 内对应的地址。

### enable_exit_node

允许其他节点将本节点用作出口节点。

它们访问 EasyTier 网络之外目标的流量会交给 sing-box 处理，参阅 [子网代理与出口节点](#子网代理与出口节点)。

### exit_nodes

用作出口节点的节点虚拟 IP，用于访问 EasyTier 网络之外的目标。

### port_forwards

将本机端口转发到 EasyTier 网络中的地址。转发由 EasyTier 内核完成。

#### network

`tcp` 或 `udp`。

默认两者都转发。

#### listen

==必填==

本机监听的地址和端口，例如 `127.0.0.1:8080`。

#### destination

==必填==

转发到的 EasyTier 网络中的地址和端口，例如 `10.144.144.2:80`。

目标位于 EasyTier 网络之外时，TCP 连接由 sing-box 路由。

### stun_servers

用于检测 NAT 类型的 STUN 服务器。

默认使用 EasyTier 内置服务器。

### stun_servers_v6

用于检测 NAT 类型的 IPv6 STUN 服务器。

默认使用 EasyTier 内置服务器。

### disable_encryption

禁用节点间流量加密。

所有节点必须一致。

### encryption_algorithm

加密算法。

可用值：`aes-gcm`、`aes-256-gcm`、`chacha20`、`xor`。

默认使用 `aes-gcm`。所有节点必须一致。

### secure_mode

启用 EasyTier 安全模式，使用 X25519 密钥认证节点。需要设置 `network_secret`。

#### private_key

Base64 编码的 X25519 私钥。

为空时每次启动生成新密钥。

### disable_p2p

仅通过配置的节点中转流量，不建立直连。

### lazy_p2p

仅在有流量时才与节点建立直连。

### need_p2p

要求其他节点始终与本节点建立直连。

### p2p_only

仅通过直连与节点通信，不经其他节点中转。

### disable_tcp_hole_punching

禁用 TCP 打洞。

### disable_udp_hole_punching

禁用 UDP 打洞。

### disable_sym_hole_punching

禁用对称型 NAT 打洞，将其视为锥型 NAT。

### latency_first

优先选择延迟最低的路由，而不是跳数最少的路由。

### private_mode

拒绝与网络名称和密钥不同的节点握手，也不为其中转。

### relay_network_whitelist

允许本节点为其中转的外部网络名称，支持通配符。

默认允许所有网络。

### relay_all_peer_rpc

中转所有节点的 RPC 数据包，包括不在 `relay_network_whitelist` 中的网络的节点。

### web

运行 EasyTier Web 配置服务器分配给本机的网络，参阅 [Web 配置](#web-配置)。

#### server

==必填==

配置服务器，格式为以用户名作为路径的 `tcp://` 或 `udp://` URL，例如 `udp://config.example.com:22020/admin`。

#### machine_id

在配置服务器上标识本机的 UUID，重启后必须保持不变。

默认由操作系统的机器 ID（`/etc/machine-id`，不存在时使用主机名）和端点标签派生。

#### hostname

上报给配置服务器的主机名。

默认使用 `hostname` 或系统主机名。

#### secure_mode

与配置服务器之间的连接使用安全模式。

### system

使用系统接口。

需要特权且不能与已有系统接口冲突。

如果禁用，sing-box 使用内部网络栈。

### gso

!!! quote ""

    仅支持 Linux。

尝试为系统接口启用通用分段卸载。

当 `system` 为 `true` 时默认启用。设为 `false` 以禁用。

当 `system` 为 `false` 时此选项无效。

### inner_domain_resolver

设置当此端点被选为出站时，用于目标域名的 DNS 解析器。适用于 TCP 和 UDP。

当此端点被选用于 L3 转发时，也用于解析尚未解析的域名目标。

此选项使用与 [domain_resolver](/zh/configuration/shared/dial/#domain_resolver) 相同的格式。

未设置时，使用现有 DNS 路由规则和默认 DNS。IP 目标不需要域名解析。

此选项不影响 `peers` 和 `stun_servers` 的解析，它们继续使用拨号字段中的 `domain_resolver`。

### name

系统接口的自定义接口名。

默认使用自动生成的 `easytier` 接口名。

### mtu

隧道 MTU。

默认使用 `1380`。

### udp_timeout

UDP NAT 过期时间。

默认使用 `5m`。

## UDP NAT 字段

参阅 [UDP NAT 字段](/zh/configuration/shared/udp-nat/)。

## 拨号字段

拨号字段作用于本节点与其他节点之间的连接。

设置 `detour` 时，打洞以及其他需要绑定本地地址的连接不可用，建议同时启用 `disable_p2p`。

参阅 [拨号字段](/zh/configuration/shared/dial/)。

## 路由

其他节点访问本节点虚拟 IP 的连接，会将目标改写为回环地址后进行路由。

使用 [`preferred_by`](/zh/configuration/route/rule/#preferred_by) 规则项将虚拟子网、节点地址以及节点通告的网段路由到此端点：

```json
{
  "route": {
    "rules": [
      {
        "preferred_by": "easytier-ep",
        "outbound": "easytier-ep"
      }
    ]
  }
}
```

## Magic DNS

配置 [EasyTier DNS 服务器](/zh/configuration/dns/server/easytier/) 后，网络中的每个节点都可以通过 `<hostname>.<zone>` 解析；路由到此端点的、目标为这些名称的连接由端点自行解析：

```json
{
  "dns": {
    "servers": [
      {
        "type": "easytier",
        "tag": "easytier-dns",
        "endpoint": "easytier-ep"
      }
    ],
    "rules": [
      {
        "preferred_by": "easytier-dns",
        "server": "easytier-dns"
      }
    ]
  }
}
```

## 子网代理与出口节点

其他节点访问 `proxy_networks` 的连接，以及本节点作为其出口节点时访问任意目标的连接，都会作为此端点的入站连接交给 sing-box 路由，来源为对方节点的虚拟 IP。路由规则（包括 `inbound`、`source_ip_cidr` 以及各类目标规则项）对其生效；没有匹配的规则时使用最终出站。

`mapped_cidr` 内的目标会在路由前转换为实际网段内的地址。

## Web 配置

设置 `web` 后，端点会连接配置服务器，并运行服务器分配给本机的所有网络；如果同时配置了本地网络，也会一并运行。服务器修改配置时，网络会随之添加、替换或移除。

所有网络共享此端点：

* 连接从能够到达目标的网络的地址发出。不属于任何网络的目标使用本地网络，没有本地网络时使用第一个分配的网络。
* 只有该第一个网络的目标会使用 L3 转发；访问其他网络的连接经过内部网络栈。
* 启用 `system` 时由操作系统选择源地址，因此可能无法访问其他网络中节点后方的目标。

服务器分配的网络保留自己的代理设置。如果它配置了子网代理或作为出口节点，但没有启用“系统转发”（proxy forward by system），则由 EasyTier 内核自行代理这些流量；其中的 TCP 和 UDP 连接仍由 sing-box 路由，但不带对方节点作为来源，且不代理 ICMP。
