### Structure

```json
{
  "type": "anyx",
  "tag": "anyx-in",

  ... // Listen Fields

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

AnyX is a multiplexing protocol derived from AnyTLS that does not depend on TLS: it can run over plain TCP, over a [V2Ray Transport](/configuration/shared/v2ray-transport/), and optionally encrypt sessions with a Shadowsocks cipher. It is not compatible with AnyTLS.

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### users

==Required==

AnyX users: `name` is used in logs, `password` authenticates the client.

#### encryption

Inner session encryption, shared by both ends. Disabled when empty or `method` is `none`.

* `method`: `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` or `2022-blake3-chacha20-poly1305`.
* `password`: any string for the legacy AEAD ciphers; a base64 key of 16 or 32 bytes for the 2022 ciphers.

#### padding_scheme

Padding scheme the server sends to clients. `off` when empty.

* `off`: no padding.
* `auto`: a random scheme, generated again every `padding_scheme_interval`.
* A custom scheme in the AnyTLS format, such as `["stop=8", "0=30-30", "1=100-200", "2=300-400,c,500-600"]`.

#### padding_scheme_interval

How often `auto` generates a new scheme, at a random point between 70% and 130% of the interval. `30m` by default.

#### padding_limit

Maximum bytes of handshake padding and waste frames accepted before authentication; connections exceeding it are closed. `2000` by default.

#### fallback

Fallback target (an IP, a domain or a unix socket path in `server`) used when the first packet fails authentication.

#### fallback_for_alpn

Fallback targets selected by the negotiated TLS ALPN. Only used with TLS.

#### tls

Inbound TLS configuration, see [TLS](/configuration/shared/tls/#inbound). REALITY and [Phantom TLS](/configuration/shared/tls/#phantom-fields) are supported. Plain TCP when empty.

#### transport

V2Ray Transport configuration, see [V2Ray Transport](/configuration/shared/v2ray-transport/).
