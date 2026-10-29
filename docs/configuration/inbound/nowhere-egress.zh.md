---
icon: material/new-box
---

`nowhere-egress` 入站是 Nowhere 3 出口桥。它不监听任何端口：通过 QUIC 拨号
[Nowhere 3 Portal](/configuration/inbound/nowhere/#nowhere-3-nw3)，注册成为该
Portal 的唯一出口，并通过本地 SingBox 路由服务 Portal 转发过来的 flow。

处于出口模式的 Portal（`"egress": true`）同一时刻只接受一个注册。第二个
Egress 会被告知出口繁忙，并以 3 秒冷却持续重试——绝不会抢占当前所有者。若所有
者的连接断开，等待中的 Egress 会自动接管，无需人工干预。

需要构建标签 `with_quic`（仅支持 QUIC carrier）。

### 结构

```json
{
  "type": "nowhere-egress",
  "tag": "nw3-egress",

  "server": "portal.example.com",
  "server_port": 2080,
  "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
  "morph": true,
  "insecure": true,

  ... // 拨号字段
  ... // QUIC 字段
}
```

### 字段

#### server

==必填==

Portal 地址。

#### server_port

==必填==

Portal 端口。

#### password

==必填==

Portal 的共享密钥。Nowhere 3 密钥规则：恰好 32 个 lowercase 十六进制字符
（`[0-9a-f]{32}`）。

#### morph

启用 Nowhere 3 Morph 密钥变换，在 QUIC 之下密封 UDP 包 socket。默认：`true`
（Nowhere 3 默认值；显式配置优先）。

Morph 不会在带内协商：`morph` 必须与 Portal 一致。Nowhere 3 的 Morph 变换与
Nowhere 2 使用不同派生，因此两端必须运行相同版本。

#### pin

Portal 叶子证书的 SHA-256 十六进制指纹。设置后优先于证书链与主机名校验。

#### insecure

跳过 Portal 证书校验。Nowhere 3 默认使用系统根证书与端点主机名校验。

#### server_name

用于校验 Portal TLS 证书的 DNS 名称。默认为端点主机名。

#### quic_congestion_control

Egress 发送方向使用的 QUIC 拥塞控制器。默认：`bbr`。

可选值：`bbr`、`bbr_standard`、`bbr2`、`bbr2_variant`、`cubic`、`reno`。
未知值会在构造入站时被拒绝。该配置不提供带宽限速。

### 拨号字段

参阅 [拨号字段](/configuration/shared/dial/)。

共享的 `inet4_bind_address` / `inet6_bind_address` 字段按地址族绑定出口拨号
（通往目标）的源地址。Portal 连接本身始终使用系统选择的源地址。

### QUIC 字段

若存在共享 QUIC 选项，参阅 [QUIC](/configuration/shared/quic/)。
Portal 与 Egress 会一致应用窗口、idle timeout、keepalive、stream 上限、
初始包大小与 PMTU 配置。
