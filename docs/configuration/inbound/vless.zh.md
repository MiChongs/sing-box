### 结构

```json
{
  "type": "vless",
  "tag": "vless-in",

  ... // 监听字段

  "users": [
    {
      "name": "sekai",
      "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
      "flow": ""
    }
  ],
  "decryption": "",
  "tls": {},
  "multiplex": {},
  "transport": {}
}
```

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### users

==必填==

VLESS 用户。

#### users.uuid

==必填==

VLESS 用户 ID。

#### users.flow

VLESS 子协议。

可用值：

* `xtls-rprx-vision`

未启用 `decryption` 时，`xtls-rprx-vision` 要求连接直接使用 TLS 或 REALITY（不能使用 `transport`）。

#### decryption

VLESS Encryption，与 Xray-core 兼容。

格式：`mlkem768x25519plus.<外观>.<票据有效期>.[填充.]<服务端密钥>`

| 部分    | 取值                                                                        |
|-------|---------------------------------------------------------------------------|
| 外观    | `native`（TLS 记录形态）、`xorpub`（混淆公钥）或 `random`（完全随机字节），必须与客户端一致   |
| 票据有效期 | 签发给客户端的 0-RTT 票据有效期，如 `600s` 或范围 `300-600s`；`0s` 表示禁用 0-RTT            |
| 填充    | 可选的填充长度与间隔参数，如 `100-111-1111.75-0-111.50-0-3333`                       |
| 服务端密钥 | X25519 私钥或 ML-KEM-768 种子，由 `sing-box generate vless-encryption` 生成        |

启用解密后，`xtls-rprx-vision` 可用于任意传输层，也可不启用 TLS。

留空或 `none` 表示禁用。

#### tls

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#入站)。

#### multiplex

参阅 [多路复用](/zh/configuration/shared/multiplex#入站)。

#### transport

V2Ray 传输配置，参阅 [V2Ray 传输层](/zh/configuration/shared/v2ray-transport/)。
