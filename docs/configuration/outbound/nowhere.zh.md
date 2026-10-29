---
icon: material/new-box
---

### 结构

```json
{
  "type": "nowhere",
  "tag": "nw3-out",

  "server": "example.com",
  "server_port": 2077,
  "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
  "net": "tcp",
  "morph": true,
  "tls": {},
  "quic_congestion_control": "bbr",

  ... // 拨号字段
  ... // QUIC 字段
}
```

Nowhere 出站是 SingBox 的 Nowhere 客户端。Nowhere 3（`nw3`）是默认协议栈：
只协商 `nw3` ALPN，通过 `net` 选择恰好一个传输，要求 32 个 lowercase 十六进制
字符密钥，且默认开启 Morph。

协议栈统一由 `tls.alpn` 区分——客户端与服务端使用同一规则，没有独立的版本字段：

| `tls.alpn` | 协议栈 |
| --- | --- |
| 省略（或 `[""]`） | Nowhere 3（`nw3`）——默认 |
| `["nw3"]` | Nowhere 3（`nw3`） |
| `["nw2"]` 或其它任意单个值 | Nowhere 2.2.1（`nw2`）——兼容旧版 |

两套协议栈没有共同握手：单个出站只能运行一个协议栈，另一协议栈的字段会被拒绝。
Nowhere 2 仅为兼容 pre-nw3 对端而保留：既有 `nw2` 配置在显式设置 ALPN 后行为
不变——参阅下文[旧版 Nowhere 2（nw2）](#旧版-nowhere-2nw2)。

`morph` 为本端点的所有传输启用密钥变换。Morph 不会在带内协商：跳的两端必须
使用相同设置，且两套协议栈的变换派生不同，因此同一跳上的所有对端必须运行相同
协议栈。

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### password

==必填==

共享密钥，必须与入站 `password` 一致。

Nowhere 3 要求恰好 32 个 lowercase 十六进制字符（`[0-9a-f]{32}`）。宽松的旧版
规则（URL 百分号解码后 1–255 字节、不限字符）只适用于 `nw2` 协议栈——两套协议栈
的 Portal 侧规则参阅
[Nowhere 入站](/configuration/inbound/nowhere/) 的 `password` 字段。

#### net

Nowhere 3 传输：`"tcp"`（TLS over TCP，UDP 流量以 UoT 承载）或 `"udp"`
（QUIC/UDP，stream + DATAGRAM）。为空时按 `"tcp"` 处理。

`net` 是 Nowhere 3 字段：在 `nw2` 协议栈上会被拒绝（旧版通过 `up` / `down`
选择传输）。`"udp"` 需要构建标签 `with_quic`。

#### morph

为本端点的所有传输启用密钥变换（TLS 之下的 64 字节 TCP prelude、TLS 与 QUIC
之下的方向性 ChaCha20 密钥）。默认：Nowhere 3 为 `true`，Nowhere 2 为 `false`。

Morph 不会在带内协商：跳的两端（客户端与 Portal，或 Portal 与下一跳 Portal）
必须使用相同设置；且两套协议栈的变换派生不同，因此同一跳上的所有对端必须运行
相同协议栈。

#### tls

==必填==

TLS 配置，参阅 [TLS](/configuration/shared/tls/#出站)。

必须启用 TLS。Nowhere 固定使用 TLS 1.3。ALPN 决定协议栈：

- 省略：Nowhere 3，ALPN 固定为 `nw3`。
- `["nw3"]`：Nowhere 3，与省略相同。
- `["nw2"]` 或其它任意单个值：旧版 Nowhere 2 协议栈，协商配置的 ALPN。

显式配置时只能提供一个 ALPN。Nowhere 3 还会拒绝 `tls.utls` / `tls.ech` /
`tls.reality` 以及 `tls.min_version` / `tls.max_version`（内置实现使用标准库
TLS 并固定 TLS 1.3）。

对接自签服务端时，需设置 `insecure: true`，或显式固定证书 / 指纹。

#### quic_congestion_control

出站发送方向使用的 QUIC 拥塞控制器。默认：`bbr`。

可选值：`bbr`、`bbr_standard`、`bbr2`、`bbr2_variant`、`cubic`、`reno`。
未知值会在构造出站时被拒绝，包括仅使用 TCP 传输的配置。该配置只影响 QUIC/UDP
传输，不提供带宽限速；入站和出站可以使用不同的控制器。

### Nowhere 3（nw3）

Nowhere 3 是默认协议栈，是一套与 `nw2` 完全不同的线级格式。与上述旧版字段的
差异如下：

| 方面 | Nowhere 3 行为 |
| --- | --- |
| ALPN | `nw3`。省略或 `["nw3"]` 即选择本协议栈；其它任意单个 ALPN 选择 `nw2`。 |
| TLS 版本 | 固定 TLS 1.3。配置 `tls.min_version` / `tls.max_version` 会被拒绝。 |
| TLS 实现 | 仅标准库。`tls.utls` / `tls.ech` / `tls.reality` 会被拒绝。 |
| 密钥 | 恰好 32 个 lowercase 十六进制字符（`[0-9a-f]{32}`）。`nw2` 客户端的宽松规则（解码后 1–255 字节）不适用。 |
| Morph | 默认**开启**。显式配置 `morph` 仍然优先。Nowhere 3 的 Morph 变换与 `nw2` 使用不同派生，因此跳的两端必须运行相同协议栈。 |
| 传输 | 每个端点恰好一个，由 `net` 选择。 |
| 被拒绝的 `nw2` 字段 | `up`、`down`、`mux`、`pool`、`prewarm_on_start`、`max_concurrent_dials`、`warm_backoff_initial`、`warm_backoff_max` 全部会被拒绝：Nowhere 3 只使用单一传输，连接池策略固定。 |

信任规则遵循 Nowhere 3：默认使用系统根证书与端点主机名；`pin` 优先于一切；
`insecure: true` 跳过校验。

一个最简的 UDP（QUIC）传输 Nowhere 3 客户端：

```json
{
  "type": "nowhere",
  "tag": "nw3-out",
  "server": "example.com",
  "server_port": 2077,
  "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
  "net": "udp",
  "tls": {
    "enabled": true,
    "insecure": true
  }
}
```

### 旧版 Nowhere 2（nw2）

Nowhere 2.2.1（`nw2`）是兼容旧版协议栈，仅为兼容 pre-nw3 对端而保留。将
`tls.alpn` 设为 `["nw2"]`（或旧版 Portal 协商的其它任意单个 ALPN 值）即可选用；
该协议栈上 `net` 会被拒绝。上传与下载传输通过 `up` / `down` 独立选择。

它仅协商配置的 ALPN，与旧版 1.8 端点不互通。认证使用绑定 TLS exporter 的
AuthFrame；FlowHeader 为 5 字节，携带 0..7 的 HOPS 转发预算；TLS Mux 基于信用
窗口（`mux=0` 专用通道，`mux=1` 标记分片）；QUIC UDP 头为打包格式。

`morph` 为本端点的所有传输启用 Nowhere 2 Morph 密钥变换：TLS 握手完成、认证
开始之前，会在 TLS 之下先发送一个 64 字节随机 TCP prelude；TLS 与 QUIC 之下
都会使用由共享密钥派生的方向性 ChaCha20 密钥。默认：`false`。

TCP prelude 策略默认为 `full8`（每个 prelude 字节的 8 位全部随机）。可将环境
变量 `NOW_MORPH_TCP_PRELUDE` 设为 `low7` 以沿用旧策略（清除每个字节的高位）；
设置为空串会被拒绝。跳的两端必须使用相同策略。

Morph 不会在带内协商。跳的两端（客户端与 Portal，或 Portal 与下一跳 Portal）
必须同时启用 `morph`；且 Nowhere 2.2.1 的 Morph 变换与 2.0.x Morph 线级不兼容，
因此 `morph=1` 跳上的所有对端都必须运行 Nowhere 2.2.1。

#### up, down

传输选择：`"tcp"` 或 `"udp"`。

必须同时设置，或同时省略（默认 `udp` / `udp`）。

| 矩阵 | TCP 流量 | UDP 流量 | 说明 |
| --- | --- | --- | --- |
| `tcp` / `tcp` | 一条 TLS 连接 | TLS 上的 UoT | `mux=0` 时 `pool` 生效（默认 `5`，最大 `256`）。 |
| `udp` / `udp` | 一条 QUIC stream | QUIC DATAGRAM | 需要 `with_quic`。`mux=1` 会规范为 `0`。 |
| `tcp` / `udp` | TLS 上传 + QUIC 下载 | UoT 上传 + DATAGRAM 下载 | 非对称；需要 `with_quic`。 |
| `udp` / `tcp` | QUIC 上传 + TLS 下载 | DATAGRAM 上传 + UoT 下载 | 非对称；需要 `with_quic`。 |

任何可能选择 QUIC（`udp`）的矩阵都会强制 `pool=0`。显式配置非零值时
会归一化为零，并记录一次配置警告。

无 `with_quic` 时只能构造 `tcp` / `tcp`；其它矩阵返回
`QUIC is not included in this build`。

#### mux

TLS 通道成帧。`0`（默认）使用专用 TLS 通道；`1` 启用 Mux 分片。任一方向为 `tcp`
时生效；`udp/udp&mux=1` 会规范为 `0`。

#### pool

TLS/TCP 预热连接池大小。仅对 `mux=0` 的 `tcp` / `tcp` 生效。

在专用 `tcp` / `tcp` 下省略时默认 `5`。负数会被拒绝；超过 `256` 的值会钳制为
`256`。`mux=1` 以及任何可能选择 QUIC 的矩阵都会忽略 `pool`。

`pool=0` 只关闭预热，**不会**限制业务 fresh dial。`tcp` / `tcp` 下每个用户
TCP/UoT flow 仍会消耗一条独立 TLS/TCP 传输。

#### max_concurrent_dials

每个 outbound 同时进行的物理 TLS/TCP 建连上限（含 dial、TLS、auth）。省略或
`0` 时默认 `16`。负数会被拒绝。

该上限同时约束业务 fresh dial 与 warm prepare；warm prepare 只会非阻塞占用空闲
slot，不会抢占业务建连。

#### warm_backoff_initial, warm_backoff_max

warm prepare 失败后的指数退避区间。省略时默认 `1s` / `30s`。初始值不得大于
最大值。失败期间不会在退避窗口内继续补池；业务 fresh 成功后才会再次尝试补池。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。

共享的 `inet4_bind_address` / `inet6_bind_address` 字段按协议族为本出站绑定源
地址，它们是 Rust `dial` 参数的 sing-box 等价形式，并与 Rust 的 `dial4` /
`dial6` 组合互斥；本构建只在入站 `next` 跳上暴露 `dial4` / `dial6`，参阅
[Nowhere 入站](/configuration/inbound/nowhere/#next)。

### QUIC 字段

若存在共享 QUIC 选项，参阅 [QUIC](/zh/configuration/shared/quic/)。
Nowhere 入站和出站会一致应用窗口、idle timeout、keepalive、stream 上限、
初始包大小与 PMTU 配置。
