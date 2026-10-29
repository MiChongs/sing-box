### 结构

```json
{
  "type": "anyx",
  "tag": "anyx-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "password": "8JCsPssfgS8tiRwiMlhARg==",
  "client_metadata": "",
  "encryption": {
    "method": "2022-blake3-aes-128-gcm",
    "password": "8JCsPssfgS8tiRwiMlhARg=="
  },
  "padding_scheme": [],
  "padding_scheme_interval": "30m",
  "disable_reuse": false,
  "idle_session_min_timeout": "30s",
  "idle_session_timeout": "30s",
  "min_idle_session": 0,
  "network": "tcp",
  "tls": {},
  "transport": {},

  ... // 拨号字段
}
```

协议说明参阅 [AnyX 入站](/zh/configuration/inbound/anyx/)。

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### password

==必填==

AnyX 密码。

#### client_metadata

握手中上报的客户端标识，默认 `anyx sing-box/<版本>`。设为空字符串时上报 `anyx`。

#### encryption

会话内层加密，须与服务端一致。参阅 [AnyX 入站](/zh/configuration/inbound/anyx/#encryption)。

#### padding_scheme

初始填充方案，默认 `auto`；收到服务端下发的方案后以其为准。取值与入站相同。

#### padding_scheme_interval

`auto` 重新生成方案的间隔，实际在该间隔的 70%–130% 之间随机取时间点。

#### disable_reuse

每个流独占一条连接，不在连接池会话上复用。

#### idle_session_min_timeout

连接池中空闲会话被关闭前的最短空闲时间。默认 30s。

#### idle_session_timeout

关闭空闲超过该时间的连接池会话。默认 30s。

#### min_idle_session

保持打开的空闲会话数量。默认 0。

#### network

启用的网络协议，`tcp` 或 `udp`，默认两者都启用。分组按 UDP 能力筛选成员时以此为准。

#### tls

出站 TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#出站)。支持 REALITY 与 [幻影 TLS](/zh/configuration/shared/tls/#phantom-字段)。为空时为明文 TCP。

#### transport

V2Ray 传输层配置，参阅 [V2Ray 传输层](/zh/configuration/shared/v2ray-transport/)。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
