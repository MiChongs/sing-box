### 结构

```json
{
  "type": "vless",
  "tag": "vless-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
  "flow": "xtls-rprx-vision",
  "encryption": "",
  "network": "tcp",
  "tls": {},
  "packet_encoding": "",
  "multiplex": {},
  "transport": {},
  
  ... // 拨号字段
}
```

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### uuid

==必填==

VLESS 用户 ID。

#### flow

VLESS 子协议。

可用值：

* `xtls-rprx-vision`

未启用 `encryption` 时，`xtls-rprx-vision` 要求连接直接使用 TLS 或 REALITY（不能使用 `transport`）。

#### encryption

VLESS Encryption，与 Xray-core 兼容。

格式：`mlkem768x25519plus.<外观>.<rtt>.[填充.]<客户端密钥>`

| 部分    | 取值                                                                       |
|-------|--------------------------------------------------------------------------|
| 外观    | `native`（TLS 记录形态）、`xorpub`（混淆公钥）或 `random`（完全随机字节），必须与服务端一致 |
| rtt   | `0rtt` 使用服务端签发的票据复用会话，或 `1rtt`                                         |
| 填充    | 可选的填充长度与间隔参数，如 `100-111-1111.75-0-111.50-0-3333`                      |
| 客户端密钥 | X25519 密码或 ML-KEM-768 客户端密钥，由 `sing-box generate vless-encryption` 生成 |

启用加密后，`xtls-rprx-vision` 可用于任意传输层，也可不启用 TLS。

留空或 `none` 表示禁用。

#### network

启用的网络协议。

`tcp` 或 `udp`。

默认所有。

#### tls

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#出站)。

#### packet_encoding

UDP 包编码，默认使用 xudp。

| 编码         | 描述            |
|------------|---------------|
| (空)        | 禁用            |
| packetaddr | 由 v2ray 5+ 支持 |
| xudp       | 由 xray 支持     |

#### multiplex

参阅 [多路复用](/zh/configuration/shared/multiplex#出站)。

#### transport

V2Ray 传输配置，参阅 [V2Ray 传输层](/zh/configuration/shared/v2ray-transport/)。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
