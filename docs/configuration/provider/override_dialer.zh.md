### 结构

```json
{
  "detour": "upstream-out",
  "bind_interface": "en0",
  "inet4_bind_address": "0.0.0.0",
  "inet6_bind_address": "::",
  "routing_mark": 1234,
  "reuse_addr": false,
  "connect_timeout": "5s",
  "tcp_fast_open": false,
  "tcp_multi_path": false,
  "udp_gso": true,
  "udp_fragment": false,
  "domain_resolver": "", // 或 {}
  "provider_domain_resolver": false, // 或 {}
  "network_strategy": "default",
  "network_type": [],
  "fallback_network_type": [],
  "fallback_delay": "300ms",
  "tcp_keep_alive": "5m",
  "tcp_keep_alive_interval": "75s",
  "tcp_keep_alive_count": 0,
  "disable_tcp_keep_alive": false,

  // 废弃的

  "domain_strategy": "prefer_ipv6"
}
```

### 字段

`detour` `bind_interface` `inet4_bind_address` `inet6_bind_address` `routing_mark` `reuse_addr` `connect_timeout` `tcp_fast_open` `tcp_multi_path` `udp_gso` `udp_fragment` `domain_resolver` `network_strategy` `network_type` `fallback_network_type` `fallback_delay` `tcp_keep_alive` `tcp_keep_alive_interval` `tcp_keep_alive_count` `disable_tcp_keep_alive` `domain_strategy` 详情参阅 [拨号字段](/zh/configuration/shared/dial)。

#### provider_domain_resolver

使用订阅自带的 DNS 服务器解析节点的服务器地址。

可以填写布尔值，或下面的对象：

```json
{
  "enabled": true,
  "resolver": "",
  "resolver_strategy": "",
  "outbound_strategy": ""
}
```

启用后，订阅会注册一个名为 `<订阅 tag>-dns` 的 DNS 服务器（类型 `provider`），所有节点的 `domain_resolver` 指向它。DNS 服务器从订阅中提取：

* Clash 订阅：`dns.proxy-server-nameserver`，为空时使用 `dns.nameserver`；`dns.enable: false` 时不提取。支持 mihomo 写法：纯 IP（UDP）、`udp://`、`tcp://`、`tls://`、`quic://`、`https://`、`h3://`，以及 `#h3=true`、`#skip-cert-verify=true` 参数。`system`、`dhcp://`、`rcode://` 被忽略；`#` 后的代理 / 网卡名被忽略，订阅 DNS 始终直连。
* sing-box 订阅：`route.default_domain_resolver` 指向的服务器，不存在时使用 `dns.final`，再不存在时使用第一个服务器；指向 `group` 时使用它的成员。

只保留 `udp`、`tcp`、`tls`、`quic`、`https`、`h3` 服务器，重复项会合并；单个服务器解析失败只会被跳过，不会影响节点导入。多个服务器并发查询并采用最快的 NOERROR / NXDOMAIN 应答。

订阅 DNS 服务器不经过 `detour`（通过节点解析节点地址会形成环路），使用 `override_dialer` 的其余拨号字段（`bind_interface`、`routing_mark`、`inet4_bind_address`、`network_strategy` 等）；订阅里为 DNS 服务器指定的拨号字段和 TLS 文件路径（`certificate_path` 等）会被忽略。

订阅 DNS 最多使用一次查询一半的超时时间，剩余时间留给回落；所有订阅 DNS 服务器都没有响应时，之后 30 秒内的查询直接使用回落。

订阅更新时只替换 DNS 服务器本身，节点不会因此重建；DNS 列表没有变化时，已有连接保持不变。远程订阅的 DNS 服务器会和节点一起写入缓存。

当订阅中没有可用的 DNS 服务器，或所有服务器都失败时，查询回落到 `resolver`。多个订阅的 provider DNS 互相回落时，查询会直接报错而不会循环。

关闭本选项后，缓存中指向 `<订阅 tag>-dns` 等已不存在服务器的节点会改用 `override_dialer.domain_resolver`（未设置时使用默认解析）。

##### enabled

是否启用，对象形式下默认为 `true`。

##### resolver

用于解析订阅 DNS 服务器域名（如 `doh.pub`），以及回落查询的 DNS 服务器 tag。

默认依次使用 `override_dialer.domain_resolver.server`、`route.default_domain_resolver`、默认 DNS 服务器。

##### resolver_strategy

解析订阅 DNS 服务器域名时使用的域名策略，可选 `prefer_ipv4` `prefer_ipv6` `ipv4_only` `ipv6_only`。

默认跟随所选回落服务器的设置。

##### outbound_strategy

节点通过订阅 DNS 解析服务器地址时使用的域名策略，可选值同上。

默认使用 `override_dialer.domain_resolver.strategy`。`domain_resolver` 中的 `timeout`、`disable_cache`、`client_subnet` 等其他字段同样生效。
