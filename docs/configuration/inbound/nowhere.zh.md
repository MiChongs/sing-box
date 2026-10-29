---
icon: material/new-box
---

### 结构

```json
{
  "type": "nowhere",
  "tag": "nw3-in",

  ... // 监听字段

  "listen_port": 2080,
  "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
  "net": "tcp",
  "morph": true,
  "tls": {},
  "quic_congestion_control": "bbr",

  ... // QUIC 字段
}
```

Nowhere Portal 是 SingBox 的 Nowhere 入站。Nowhere 3（`nw3`）是默认协议栈：
只服务 `nw3` ALPN，通过 `net` 选择恰好一个传输，并要求 32 个 lowercase
十六进制字符密钥。

协议栈统一由 `tls.alpn` 区分——客户端与服务端使用同一规则，没有独立的版本字段：

| `tls.alpn` | 协议栈 |
| --- | --- |
| 省略（或 `[""]`） | Nowhere 3（`nw3`）——默认 |
| `["nw3"]` | Nowhere 3（`nw3`） |
| `["nw2"]` 或其它任意单个值 | Nowhere 2.2.1（`nw2`）——兼容旧版 |

两套协议栈没有共同握手：单个入站只能运行一个协议栈，另一协议栈的字段会被拒绝。
Nowhere 2 仅为兼容 pre-nw3 对端而保留——参阅下文
[旧版 Nowhere 2（nw2）](#旧版-nowhere-2nw2)。

不允许明文入站，必须启用 TLS。

!!! note "路由 sniff"

    Nowhere 客户端要等 Portal 返回 READY 才发送 UDP 数据，而 READY 在路由出站建立之后
    才会发出。因此入站 UDP flow 上的 `sniff` 拿不到任何载荷，只会等满嗅探超时
    （默认 300ms）后按原目标继续。服务端无需按域名分流时，不要给 Nowhere 入站配置 `sniff`。

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### password

==必填==

用于派生认证材料的共享密钥，必须与出站 `password` 一致。

Nowhere 3 要求恰好 32 个 lowercase 十六进制字符（`[0-9a-f]{32}`），密钥文本
直接作为 HKDF 输入，不会再次做十六进制解码。旧版规则（URL 百分号解码后 32–64 个
lowercase 十六进制字符、允许奇数长度）只适用于 `nw2` 协议栈。可使用
`nowhere generate-key` 生成。

#### morph

为本端点的所有传输启用密钥变换。Morph 不会在带内协商：客户端必须使用相同设置。
默认：Nowhere 3 为 `true`，Nowhere 2 为 `false`。

两套协议栈的变换派生不同，因此同一跳上的所有对端必须运行相同协议栈。

#### net

Nowhere 3 传输：`"tcp"`（TLS over TCP，UDP 流量以 UoT 承载）或 `"udp"`
（QUIC/UDP，stream + DATAGRAM）。为空时按 `"tcp"` 处理。

`net` 是 Nowhere 3 字段：在 `nw2` 协议栈上会被拒绝（旧版通过 `network` 选择
传输）。`"udp"` 需要构建标签 `with_quic`。

#### network

监听传输。默认：`["tcp", "udp"]`。

| 值 | 行为 |
| --- | --- |
| `["tcp"]` | TLS/TCP 监听（TCP 中继 + UoT）。 |
| `["udp"]` | QUIC 监听（stream + DATAGRAM）。需要构建标签 `with_quic`。 |
| `["tcp", "udp"]` | 两者都开。 |

无 `with_quic` 时，启用 UDP 的配置会返回
`QUIC is not included in this build`。

在 Nowhere 3 下传输由 `net` 选择，因此显式配置的 `network` 只能填写该传输：
`net: "tcp"` 对应 `["tcp"]`，`net: "udp"` 对应 `["udp"]`。

#### egress

Nowhere 3 出口桥接模式。设为 `true` 时，Portal 不在本地路由流量：它通过 QUIC
接受唯一的 [Nowhere Egress](/configuration/inbound/nowhere-egress/) 注册，
并把所有已认证 flow 转发给该出口。

需要 `net: "udp"`——注册握手只存在于 QUIC 传输上。在 `nw2` 协议栈上会被拒绝。

#### tls

==必填==

使用原生 SingBox TLS 对象。参阅 [TLS](/zh/configuration/shared/tls/#入站)。

Nowhere 固定使用 TLS 1.3。ALPN 决定协议栈：

- 省略：Nowhere 3，ALPN 固定为 `nw3`。
- `["nw3"]`：Nowhere 3，与省略相同。
- `["nw2"]` 或其它任意单个值：旧版 Nowhere 2 协议栈，服务配置的 ALPN。

显式配置时只能提供一个 ALPN。Nowhere 3 还要求静态证书，并拒绝 `tls.acme` /
`tls.certificate_provider`、`tls.utls` / `tls.ech` / `tls.reality` 以及
`tls.min_version` / `tls.max_version`。

推荐原生示例：

```json
{
  "enabled": true,
  "alpn": ["nw3"],
  "min_version": "1.3",
  "max_version": "1.3",
  "certificate_path": "/path/cert.pem",
  "key_path": "/path/key.pem"
}
```

#### quic_congestion_control

入站发送方向使用的 QUIC 拥塞控制器。默认：`bbr`。

可选值：`bbr`、`bbr_standard`、`bbr2`、`bbr2_variant`、`cubic`、`reno`。
未知值会在构造入站时被拒绝。该配置只影响 QUIC/UDP 传输，不提供带宽限速；
入站和出站可以使用不同的控制器。

### Nowhere 3（nw3）

Nowhere 3 是默认协议栈，是一套与 `nw2` 完全不同的线级格式。与上述旧版字段的
差异如下：

| 方面 | Nowhere 3 行为 |
| --- | --- |
| ALPN | `nw3`。省略或 `["nw3"]` 即选择本协议栈；其它任意单个 ALPN 选择 `nw2`。 |
| TLS 版本 | 固定 TLS 1.3。配置 `tls.min_version` / `tls.max_version` 会被拒绝。 |
| TLS 实现 | 仅标准库。`tls.utls` / `tls.ech` / `tls.reality` 会被拒绝；`tls.acme` / `tls.certificate_provider` 会被拒绝（必须使用静态证书）。 |
| 密钥 | 恰好 32 个 lowercase 十六进制字符（`[0-9a-f]{32}`）。`nw2` 的宽松规则（32–64、允许奇数长度）不适用。 |
| Morph | 默认**开启**。显式配置 `morph` 仍然优先。Nowhere 3 的 Morph 变换与 `nw2` 使用不同派生，因此跳的两端必须运行相同协议栈。 |
| 传输 | 每个端点恰好一个，由 `net` 选择。 |
| 链式转发 | `next` 会被拒绝；Nowhere 3 没有原生 Portal 链式转发。 |
| 准入上限 | `max_unauthenticated_connections` / `max_unauthenticated_per_source` 会被拒绝；内建 Portal 自行管理准入。 |
| network | 显式配置的 `network` 必须与 `net` 的传输一致：`tcp` 对应 `["tcp"]`，`udp` 对应 `["udp"]`。 |

一个最简的 TCP 传输 Nowhere 3 Portal：

```json
{
  "type": "nowhere",
  "tag": "nw3-in",
  "listen_port": 2080,
  "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
  "net": "tcp",
  "tls": {
    "enabled": true,
    "certificate_path": "/path/cert.pem",
    "key_path": "/path/key.pem"
  }
}
```

启动时 Portal 会打印叶子证书的 SHA-256 指纹，便于为对应的
[出站](/configuration/outbound/nowhere/#nowhere-3-nw3) 获取 `pin=` 取值。

### 旧版 Nowhere 2（nw2）

Nowhere 2.2.1（`nw2`）是兼容旧版协议栈，仅为兼容 pre-nw3 对端而保留。将
`tls.alpn` 设为 `["nw2"]`（或旧版客户端协商的其它任意单个 ALPN 值）即可选用；
该协议栈上 `net` 与 `egress` 会被拒绝。它仅协商配置的 ALPN，与旧版 1.8 端点
不互通。

它接受 TLS/TCP，以及（在 `with_quic` 构建下）QUIC/UDP 传输，完成认证后把
TCP/UDP 目标交给 SingBox 路由（除非通过 `next` 链式转发到另一个 Portal）。
认证使用绑定 TLS exporter 的 AuthFrame；FlowHeader 为 5 字节，携带 0..7 的
HOPS 转发预算；QUIC UDP 头为打包格式。AuthFrame 之后，入站 TLS 会自动识别
专用通道（`mux=0`）与基于信用窗口的标记 Mux 分片（`mux=1`）。

`morph` 为本 Portal 的所有传输启用 Nowhere 2 Morph 密钥变换：认证开始之前，会在
TLS 之下先接收一个 64 字节随机 TCP prelude；TLS 与 QUIC 之下都会使用由共享
密钥派生的方向性 ChaCha20 密钥。默认：`false`。

TCP prelude 策略默认为 `full8`（每个 prelude 字节的 8 位全部随机）。可将环境
变量 `NOW_MORPH_TCP_PRELUDE` 设为 `low7` 以沿用旧策略（清除每个字节的高位）；
设置为空串会被拒绝。跳的两端必须使用相同策略。

Morph 不会在带内协商：`morph` 必须与客户端一致。链式转发时，除非被
`next.morph` 覆盖，每一跳都会继承该设置。Nowhere 2.2.1 的 Morph 变换与
2.0.x Morph 线级不兼容，因此 `morph=1` 跳上的所有对端都必须运行 Nowhere 2.2.1。

#### max_unauthenticated_connections

未完成认证（含 TLS 握手阶段）的全局连接上限。省略或 `0` 时默认 `256`，与
Rust Portal 一致。

#### max_unauthenticated_per_source

每个来源的未认证连接上限。IPv4 按 `/32`，IPv6 按 `/64` 聚合。省略或 `0` 时
默认 `32`。不得超过全局上限。

#### next

可选的原生 Portal 链式转发。配置后，本 Portal 会将**所有**已接受的 flow 转发到
下一个 Nowhere Portal，而不再自行拨号：完全绕过 SingBox 路由与 detour，且没有
回退。省略时按正常路由处理。

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `server` | ==必填== | 下一个 Portal 的地址。 |
| `server_port` | ==必填== | 下一个 Portal 的端口。 |
| `password` | ==必填== | 下一个 Portal 的共享密钥。与入站 `password` 执行同一套 Portal 密钥规则：URL 百分号解码后 32–64 个 lowercase 十六进制字符。 |
| `up`, `down` | `udp` / `udp` | 通往下一个 Portal 的传输选择（`tcp` 或 `udp`）；必须同时设置或同时省略。任何可能选择 `udp` 的矩阵都需要构建标签 `with_quic`。 |
| `mux` | `0` | `0` 专用 TLS 通道，`1` 基于信用窗口的 TLS Mux（当可能走到 TCP 时）。`udp/udp&mux=1` 会规范为 `0`。 |
| `pool` | 专用 `tcp` / `tcp` 时为 `5`，否则为 `0` | 通往下一个 Portal 的 TLS/TCP 预热连接池。超过 `256` 的值会钳制为 `256`；`mux=1` 与可走到 QUIC 的矩阵忽略 `pool`。 |
| `server_name` | 无 | 用于校验下一个 Portal TLS 证书的 DNS 名称。省略、为空或字面量 `"none"` 时关闭证书校验；端点主机名仍可能作为 ClientHello SNI 发送。 |
| `pin` | 无 | 下一个 Portal 叶子证书的 SHA-256 十六进制指纹。省略、为空或 `"none"` 时关闭证书固定；设置有效 pin 时优先于 `server_name` 与证书链校验。 |
| `morph` | 继承入站 `morph` | 通往下一个 Portal 的方向上启用 Nowhere 2 Morph 密钥变换。省略（`nil`）时继承入站 `morph`；设置为 `true` / `false` 可按跳覆盖。跳的两端必须一致。 |
| `dial4` | `auto` | 通过 IPv4 拨号下一个 Portal 时绑定的 IPv4 源地址。接受 `auto`（由系统决定源地址）或 IPv4 字面量；`0.0.0.0` 是合法的通配地址。 |
| `dial6` | `auto` | 通过 IPv6 拨号下一个 Portal 时绑定的 IPv6 源地址。接受 `auto` 或 IPv6 字面量；拒绝 `::ffff:192.0.2.1` 这类 IPv4-mapped 字面量，`::` 是合法的通配地址。 |

`dial4` 与 `dial6` 相互独立，可以组合使用以实现双栈源地址绑定。它们对应 Rust
portal URL 参数 `dial4` / `dial6`，并与 `dial` 互斥：本构建的下一跳没有 `dial`
选项，出站侧的等效传统单协议族绑定是共享的 `inet4_bind_address` /
`inet6_bind_address` 拨号字段。已配置的绑定绝不会静默降级为自动——绑定失败会
让本次拨号失败，并尝试下一个候选地址。

链式上游客户端继承入站的 TLS ALPN。

跳数预算：第一个转发 Portal 将 HOPS 初始化为 7，每一跳 Portal 间转发将其递减 1；
当需要继续转发预算耗尽的 flow（HOPS=1）时，Portal 会在开启下一跳之前以
`FLOW_LIMIT` 拒绝。上游 Portal 的 setup 拒绝码会原样传回下游。链中的每个
Portal 都必须运行 Nowhere 2.2.1（`nw2`）。

### QUIC 字段

若存在共享 QUIC 选项，参阅 [QUIC](/zh/configuration/shared/quic/)。
Nowhere 入站和出站会一致应用窗口、idle timeout、keepalive、stream 上限、
初始包大小与 PMTU 配置。
