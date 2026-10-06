---
icon: material/new-box
---

### Structure

```json
{
  "type": "quicx",
  "tag": "quicx-out",

  "server": "127.0.0.1",
  "server_port": 443,
  "password": "hello",
  "heartbeat": "10s",
  "bbr_profile": "",
  "qlog_directory": "",
  "qlog_max_size": "300MB",
  "network": "tcp",
  "tls": {
    "enabled": true,
    "server_name": "example.com",
    "alpn": ["h3"]
  },

  ... // QUIC Fields

  ... // Dial Fields
}
```

Requires build tag `with_quic`.

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### password

==Required==

QUICX user password.

#### heartbeat

Interval for sending heartbeat packets to keep the connection alive.

`10s` is used by default.

#### bbr_profile

BBR congestion control profile, one of `conservative` `standard` `aggressive`.

`conservative` is used by default.

#### qlog_directory

Write one [qlog](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/)
trace per QUIC connection into this directory, named
`<connection id>_client.sqlog`.

Disabled by default. Relative paths are resolved against the working directory,
and environment variables are expanded. The directory is created at startup; a
path that cannot be used fails sing-box startup instead of silently disabling
tracing.

Traces can be analysed with [qvis](https://qvis.quictools.info/).

#### qlog_max_size

Total size limit of the qlog directory, either as a byte count or with a unit
such as `300MB`.

`300MB` is used by default.

Once the directory exceeds the limit, completed traces are deleted oldest
first, so the directory never grows forever. A trace that is still being
recorded is never deleted or truncated, so the directory may temporarily exceed
the limit while connections are open and falls back under it as they close.
Endpoints tracing into the same directory share one limit, the smallest of the
configured values.

#### network

Enabled network.

One of `tcp` `udp`.

Both are enabled by default.

#### tls

==Required==

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

The ALPN should be `h3`; `h3` is used when it is omitted.

### 0-RTT

When a session ticket from a previous connection is available, QUICX attempts
a 0-RTT handshake, saving one round trip when the tunnel is re-established. The
protocol is fully multiplexed, so only the first request after re-establishing
benefits, and that is exactly what the client's 0-RTT data carries: the
authentication request, the CONNECT request (destination address) and the first
payload of the proxied connection all go out in the first flight.

When the server rejects 0-RTT (for example after a server restart, a session
ticket key change, or an anti-replay rejection), the client re-sends the
authentication and the first request once the handshake completes, without
closing the connection.

The client generates a random nonce per connection and sends it with the
authentication request; the server remembers the nonces of authenticated
sessions and rejects another session authenticating with the same nonce (see
0-RTT and replay in the inbound documentation). A replayed 0-RTT flight
therefore fails authentication and no proxied connection to the destination is
made.

!!! warning ""

    0-RTT data is inherently replayable: whoever captures a client's 0-RTT flight can send it to the server again, and the transport cannot tell the copy from the original. An attacker gains no usable tunnel from it (without the handshake keys they can neither decrypt responses nor produce 1-RTT data), but without the nonce check above the server would authenticate again, connect to the destination again and deliver the first payload a second time, which is a real risk for non-idempotent requests (for example a plaintext HTTP POST).

### QUIC Fields

See [QUIC Fields](/configuration/shared/quic/) for details.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
