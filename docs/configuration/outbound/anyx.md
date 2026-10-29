### Structure

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

  ... // Dial Fields
}
```

See the [AnyX inbound](/configuration/inbound/anyx/) for the protocol.

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### password

==Required==

The AnyX password.

#### client_metadata

Client identification sent in the handshake, `anyx sing-box/<version>` by default. An empty string sends `anyx`.

#### encryption

Inner session encryption, must match the server. See the [AnyX inbound](/configuration/inbound/anyx/#encryption).

#### padding_scheme

Initial padding scheme, `auto` by default; replaced by the scheme the server sends. Same values as the inbound.

#### padding_scheme_interval

How often `auto` generates a new scheme, at a random point between 70% and 130% of the interval.

#### disable_reuse

Use one connection per stream instead of multiplexing streams over pooled sessions.

#### idle_session_min_timeout

Minimum idle time before a pooled session can be closed. Default: 30s.

#### idle_session_timeout

Close pooled sessions idle for longer than this. Default: 30s.

#### min_idle_session

Number of idle sessions kept open. Default: 0.

#### network

Enabled network, `tcp` or `udp`. Both are enabled by default. Used by groups to filter members by UDP support.

#### tls

Outbound TLS configuration, see [TLS](/configuration/shared/tls/#outbound). REALITY and [Phantom TLS](/configuration/shared/tls/#phantom-fields) are supported. Plain TCP when empty.

#### transport

V2Ray Transport configuration, see [V2Ray Transport](/configuration/shared/v2ray-transport/).

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
