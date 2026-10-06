---
icon: material/new-box
---

### Structure

```json
{
  "type": "nowhere",
  "tag": "nw-in",

  ... // Listen Fields

  "password": "secret",
  "morph": false,
  "network": [
    "tcp",
    "udp"
  ],
  "tls": {},
  "quic_congestion_control": "bbr",
  "next": {
    "server": "origin.example",
    "server_port": 2080,
    "password": "origin-key",
    "up": "tcp",
    "down": "tcp",
    "pool": 5,
    "server_name": "origin.example",
    "pin": "<leaf cert sha256 hex>"
  },

  ... // QUIC Fields
}
```

Nowhere Portal is the SingBox inbound for the Nowhere protocol. It accepts
TLS/TCP and (with `with_quic`) QUIC/UDP carriers, authenticates clients, and
routes TCP/UDP targets through the SingBox router (unless chained to another
Portal via `next`).

Plaintext inbound is not allowed. TLS must be enabled.

This is a Nowhere 2.1 (`nw2`) implementation. It negotiates the `nw2` ALPN
only and does not interoperate with legacy 1.8 peers. Authentication is an
exporter-bound AuthFrame, the FlowHeader is 5 bytes and carries a HOPS
forwarding budget of 0..7, and QUIC UDP headers are packed. After AuthFrame,
inbound TLS auto-detects dedicated lanes (`mux=0`) versus credit-windowed
marked Mux shards (`mux=1`), and `mix` remains a
client-side policy resolving to TT / TQ / QT / QQ.

`morph` enables the Nowhere 2 Morph keyed transform for every carrier of this
endpoint. Morph is not negotiated in-band: `morph=1` must be enabled on both
ends of a hop, because the Nowhere 2.1 Morph transform is wire-incompatible
with the 2.0.x Morph.

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### password

==Required==

Shared key used to derive auth material. Must match the outbound `password`.

#### morph

Enable the Nowhere 2 Morph keyed transform for every carrier of this Portal:
a 64-byte random TCP prelude is consumed below TLS before authentication, and
directional ChaCha20 keys derived from the shared key unwrap traffic below
both TLS and QUIC. Default: `false`.

There is no in-band negotiation: `morph` must match the client. For a chained
Portal, each hop inherits this setting unless `next.morph` overrides it. The
Nowhere 2.1 Morph transform is wire-incompatible with the 2.0.x Morph, so
every peer on a `morph=1` hop must run Nowhere 2.1.

#### network

Listen transports. Default: `["tcp", "udp"]`.

| Value | Behavior |
| --- | --- |
| `["tcp"]` | TLS/TCP listener (TCP relay + UoT). |
| `["udp"]` | QUIC listener (streams + DATAGRAM). Requires build tag `with_quic`. |
| `["tcp", "udp"]` | Both. |

Without `with_quic`, any configuration that enables UDP returns
`QUIC is not included in this build`.

#### max_unauthenticated_connections

Process-wide limit for connections that have not finished authentication
(including the TLS handshake stage). Omitted or `0` defaults to `256`, matching
the Rust Portal.

#### max_unauthenticated_per_source

Per-source unauthenticated connection limit. IPv4 uses `/32`; IPv6 is grouped
by `/64`. Omitted or `0` defaults to `32`. Must not exceed the global limit.

#### tls

==Required==

Use the native SingBox TLS object. See [TLS](/configuration/shared/tls/#inbound).

Nowhere always uses TLS 1.3. If ALPN is omitted, it is normalized to `nw2`;
otherwise exactly one ALPN value is required.

Recommended native example:

```json
{
  "enabled": true,
  "alpn": ["nw2"],
  "min_version": "1.3",
  "max_version": "1.3",
  "certificate_path": "/path/cert.pem",
  "key_path": "/path/key.pem"
}
```

#### quic_congestion_control

QUIC congestion controller used by the inbound sender. Default: `bbr`.

Available values: `bbr`, `bbr_standard`, `bbr2`, `bbr2_variant`, `cubic`, and
`reno`. An unknown value is rejected while constructing the inbound. This
setting only affects QUIC/UDP carriers and does not implement a bandwidth rate
limit. The inbound and outbound may use different controllers.

#### next

Optional native Portal chaining. When set, the Portal forwards **every**
accepted flow to the next Nowhere Portal instead of dialing the target itself:
SingBox routing and detour are bypassed entirely, with no fallback. When
omitted, flows are routed normally.

| Field | Default | Description |
| --- | --- | --- |
| `server` | ==Required== | Next Portal address. |
| `server_port` | ==Required== | Next Portal port. |
| `password` | ==Required== | Shared key of the next Portal. |
| `up`, `down` | `udp` / `udp` | Carrier selectors toward the next Portal (`tcp`, `udp`, or `mix`); both must be set, or both omitted. `mix` is a client-side policy. Any matrix that can select `udp`/`mix` requires build tag `with_quic`. |
| `mux` | `0` | `0` dedicated TLS lanes, `1` credit-windowed TLS Mux when TCP is possible. `udp/udp&mux=1` canonicalizes to `0`. |
| `pool` | `5` for dedicated `tcp` / `tcp`, otherwise `0` | TLS/TCP warm pool toward the next Portal. Values above `256` are clamped to `256`; `mux=1` and QUIC-capable matrices ignore `pool`. |
| `mix_fallback_timeout` | `1s` | Primary mix-route preparation budget. |
| `server_name` | none | DNS name used to verify the next Portal's TLS certificate. Omitted, empty, or the literal `"none"` disables certificate verification; the endpoint host may still be sent as the ClientHello SNI. |
| `pin` | none | SHA-256 hex fingerprint of the next Portal's leaf certificate. Omitted, empty, or `"none"` disables pinning; a real pin overrides `server_name` and chain verification. |
| `morph` | inherit inbound `morph` | Enable the Nowhere 2 Morph keyed transform toward the next Portal. Omitted (`nil`) inherits the inbound `morph`; set `true` / `false` to override the hop. Both ends of the hop must agree. |

The chained upstream client inherits the inbound TLS ALPN.

Hop budget: the first forwarding Portal initializes HOPS to 7, each
Portal-to-Portal hop decrements it by one, and a Portal that would forward an
exhausted flow (HOPS=1) rejects it with `FLOW_LIMIT` before opening the next
hop. Setup rejection codes from an upstream Portal propagate downstream
unchanged. Every Portal in a chain must run Nowhere 2.1 (`nw2`).

### QUIC Fields

See [QUIC](/configuration/shared/quic/) for shared QUIC options when present.
The same window, idle timeout, keepalive, stream-limit, packet-size, and PMTU
settings are applied by both Nowhere inbound and outbound.
