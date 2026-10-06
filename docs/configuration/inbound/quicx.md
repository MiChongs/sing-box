---
icon: material/new-box
---

### Structure

```json
{
  "type": "quicx",
  "tag": "quicx-in",

  ... // Listen Fields

  "users": [
    {
      "name": "sekai",
      "password": "hello"
    }
  ],
  "auth_timeout": "3s",
  "heartbeat": "10s",
  "auth_failure_policy": "h3_close",
  "bbr_profile": "",
  "qlog_directory": "",
  "qlog_max_size": "300MB",
  "tls": {
    "enabled": true,
    "certificate_path": "/path/to/certificate.crt",
    "key_path": "/path/to/private.key",
    "alpn": ["h3"]
  },

  ... // QUIC Fields
}
```

QUICX is a QUIC proxy protocol that looks like a standard HTTP/3 server on the
wire: TCP is relayed over bidirectional QUIC streams, UDP over QUIC DATAGRAM
frames (fragmented when needed), and the authentication and first request can
ride in the 0-RTT flight.

Requires build tag `with_quic`.

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### users

QUICX users.

#### users.name

User name, used in logs and by the `auth_user` route rule.

#### users.password

==Required==

QUICX user password.

#### auth_timeout

How long the server waits for the client to send the authentication command.

`3s` is used by default.

#### heartbeat

Interval for sending heartbeat packets to keep the connection alive.

`10s` is used by default.

#### auth_failure_policy

How the server handles a failed QUICX authentication and standard HTTP/3
requests that are not QUICX traffic, while keeping the transport
indistinguishable from a standard HTTP/3 server.

| Policy        | Description                                                                                                                                                                                                                       |
|---------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `h3_close`    | Close the QUIC connection with `H3_NO_ERROR`, the same as a normal standard HTTP/3 close.                                                                                                                                          |
| `silent_drop` | Drop the connection silently without sending `CONNECTION_CLOSE`, so a prober only observes a timeout. The server keeps the connection for a grace period (30 seconds) and then reclaims it locally, so peer keepalives cannot pin resources. |

`h3_close` is used by default.

#### bbr_profile

BBR congestion control profile, one of `conservative` `standard` `aggressive`.

`conservative` is used by default.

#### qlog_directory

Write one [qlog](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/)
trace per QUIC connection into this directory, named
`<connection id>_server.sqlog`.

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

#### tls

==Required==

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).

The ALPN should be `h3`; `h3` is used when it is omitted.

### 0-RTT and replay

The server accepts 0-RTT data so that the transport stays indistinguishable
from a standard HTTP/3 server. QUIC 0-RTT data has no replay protection of its
own, so the client attaches a random per-connection nonce to its authentication
request, and the server remembers the nonces of authenticated sessions:

- another session authenticating with the same nonce is treated as a replayed
  0-RTT flight and closed according to `auth_failure_policy`, so no proxied
  connection to the destination is made;
- a session reusing its own nonce (a client racing two authentication streams,
  or re-sending authentication after 0-RTT was rejected) is not a replay.

The server only remembers the nonces of the latest 65536 authenticated
sessions, for at most 24 hours; outside that window a repeated nonce is no
longer guaranteed to be rejected. The state is in memory and per instance:
multi-instance deployments and process restarts reset the window.

### QUIC Fields

See [QUIC Fields](/configuration/shared/quic/) for details.

Standard HTTP/3 requests that are not QUICX proxy traffic do not create a
proxied connection and are closed according to `auth_failure_policy`: a
standard `H3_NO_ERROR` close for `h3_close`, a silent drop (no close frame
during the grace period) for `silent_drop`.
