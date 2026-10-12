---
icon: material/alert-decagram
---

!!! quote "sing-box 1.14.0 中的更改"

    :material-delete-clock: [independent_cache](#independent_cache)  
    :material-plus: [optimistic](#optimistic)  
    :material-plus: [timeout](#timeout)

!!! quote "sing-box 1.12.0 中的更改"

    :material-decagram: [servers](#servers)

!!! quote "sing-box 1.11.0 中的更改"

    :material-plus: [cache_capacity](#cache_capacity)

# DNS

### 结构

```json
{
  "dns": {
    "servers": [],
    "rules": [],
    "final": "",
    "strategy": "",
    "disable_cache": false,
    "disable_expire": false,
    "independent_cache": false,
    "round_robin_cache": false,
    "cache_capacity": 0,
    "min_cache_ttl": 0,
    "max_cache_ttl": 0,
    "optimistic": false, // or {}
    "timeout": "",
    "reverse_mapping": false,
    "allow_resolver_discovery": false,
    "tcp_concurrent": false, // 或 {}
    "client_subnet": "",
    "fakeip": {}
  }
}

```

### 字段

| 键        | 格式                      |
|----------|-------------------------|
| `server` | 一组 [DNS 服务器](./server/) |
| `rules`  | 一组 [DNS 规则](./rule/)    |

#### final

默认 DNS 服务器的标签。

默认使用第一个服务器。

#### strategy

默认解析域名策略。

可选值: `prefer_ipv4` `prefer_ipv6` `ipv4_only` `ipv6_only`。

#### disable_cache

禁用 DNS 缓存。

与 `optimistic` 冲突。

#### disable_expire

禁用 DNS 缓存过期。

与 `optimistic` 冲突。

#### independent_cache

!!! failure "已在 sing-box 1.14.0 废弃"

    `independent_cache` 已在 sing-box 1.14.0 废弃，且将在 sing-box 1.16.0 中被移除，参阅[迁移指南](/zh/migration/#迁移-independent-dns-cache)。

使每个 DNS 服务器的缓存独立，以满足特殊目的。如果启用，将轻微降低性能。

#### round_robin_cache

响应缓存时轮转缓存地址的顺序。

#### cache_capacity

!!! question "自 sing-box 1.11.0 起"

LRU 缓存容量。

小于 1024 的值将被忽略。

#### min_cache_ttl

DNS 缓存的最小 TTL，单位为秒。

缓存并返回 DNS 响应前，低于此值的 TTL 将被延长。

设为 `0` 时不限制最小 TTL。

#### max_cache_ttl

DNS 缓存的最大 TTL，单位为秒。

缓存并返回 DNS 响应前，高于此值的 TTL 将被缩短。

设为 `0` 时不限制最大 TTL。两个选项均未设置时，将保留从 DNS 响应中计算出的 TTL。

当 `min_cache_ttl` 大于非零的 `max_cache_ttl` 时，将使用 `min_cache_ttl` 作为两者的有效值。

规则级 `rewrite_ttl` 动作在这些限制之后应用，并拥有更高优先级。

#### optimistic

!!! question "自 sing-box 1.14.0 起"

启用乐观 DNS 缓存。当缓存的 DNS 条目已过期但仍在超时窗口内时，
立即返回过期的响应，同时在后台触发刷新。

与 `disable_cache` 和 `disable_expire` 冲突。

接受布尔值或对象。当设置为 `true` 时，使用默认超时 `3d`。

```json
{
  "enabled": true,
  "timeout": "3d"
}
```

##### enabled

启用乐观 DNS 缓存。

##### timeout

过期缓存条目可被乐观提供的最长时间。

默认使用 `3d`。

#### timeout

!!! question "自 sing-box 1.14.0 起"

每次 DNS 查询的默认超时时间。

默认使用 `10s`。

可被 `rules.[].timeout`（DNS 规则动作）或 `domain_resolver.timeout` 覆盖。

#### reverse_mapping

在响应 DNS 查询后存储 IP 地址的反向映射以为路由目的提供域名。

由于此过程依赖于应用程序在发出请求之前解析域名的行为，因此在 macOS 等 DNS 由系统代理和缓存的环境中可能会出现问题。

#### allow_resolver_discovery

允许解析器发现查询按正常的 DNS 规则和服务器选择流程处理。

默认关闭。关闭时，以 `_dns.` 开头（不区分大小写）的 SVCB 查询，
例如 `_dns.resolver.arpa.`，会在匹配 DNS 规则或查询上游服务器之前收到
空的成功响应（`NOERROR`）。

设为 `true` 可取消这层内置拒绝，DNS 规则仍可拒绝此类查询。
其他查询类型和名称不受影响。

#### tcp_concurrent

并发拨号域名解析出的全部地址，使用最先建立的 TCP 连接。

适用于拨号返回前已确认与目标握手的场景：

* `direct` 出站，包括域名与 `resolve` 路由动作解析出的地址；
* 所有出站的服务器地址；
* VPN 端点（WireGuard、Tailscale、OpenVPN、OpenConnect、MASQUE、EasyTier）与 `tailcat` 出站在隧道内的连接；
* 经由 `detour` 交给上述出站的连接，由该出站接收全部地址并自行并发拨号；
* `socks` 与 `http` 出站经由代理服务器并发拨号路由已解析的目标地址，仅当该出站自身设置了
  [`tcp_concurrent`](/zh/configuration/shared/dial/#tcp_concurrent)。

不适用于 UDP（建立连接时不发送任何数据，无从竞速）、启用 `tcp_fast_open` 的拨号器（握手推迟到首次写入），
以及 VMess、VLESS、Trojan、Shadowsocks 等在服务器到达目标之前即返回的代理协议。

连接尝试按连接历史与地址族排序：最近一次连上该目标的地址最先尝试，一分钟内失败过的地址最后尝试，其余地址按域名策略
优先的地址族开始，IPv6 与 IPv4 交替排列。连接建立后，其余尝试立即取消，此后才完成的连接会被关闭。任一尝试失败时
立即开始下一个尝试。网络变化时清空连接历史。

[Clash API](/zh/configuration/experimental/clash-api/) 可通过 `PATCH /configs` 的 `tcp-concurrent` 字段在运行时
开关，通过 `GET /dns/tcp-concurrent` 查看统计与连接历史，通过 `DELETE /dns/tcp-concurrent` 清空连接历史。
[可观测性](/zh/configuration/experimental/observability/) 以 `singbox_tcp_concurrent_*` 指标导出统计数据。
拨号器可通过自身的 [`tcp_concurrent`](/zh/configuration/shared/dial/#tcp_concurrent) 覆盖此选项。

接受布尔值或对象。默认禁用。

```json
{
  "enabled": true,
  "attempt_delay": "",
  "max_concurrent": 0
}
```

##### enabled

启用 TCP 并发拨号。

##### attempt_delay

相邻两次连接尝试之间的固定间隔。`0s` 表示同时开始全部尝试。

为空时按目标自适应：近期没有连接记录的目标同时开始全部尝试；10 分钟内连接过的目标先只尝试上次胜出的地址，
若它在其平滑连接耗时的两倍（介于 `20ms` 与 `250ms` 之间）内仍未连上，再开始其余尝试。因此连接正常的目标
只需一次握手。

##### max_concurrent

同时进行的连接尝试数量上限。先前的尝试失败后再开始后续尝试。

默认不限制。

#### client_subnet

!!! question "自 sing-box 1.9.0 起"

默认情况下，将带有指定 IP 前缀的 `edns0-subnet` OPT 附加记录附加到每个查询。

如果值是 IP 地址而不是前缀，则会自动附加 `/32` 或 `/128`。

可以被 `servers.[].client_subnet` 或 `rules.[].client_subnet` 覆盖。

#### fakeip :material-note-remove:

[FakeIP](./fakeip/) 设置。
