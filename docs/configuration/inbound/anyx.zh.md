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
