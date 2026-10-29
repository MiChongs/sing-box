---
icon: material/new-box
---

### Structure

```json
{
  "type": "nowhere",
  "tag": "nw3-in",

  ... // Listen Fields

  "listen_port": 2080,
  "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
  "net": "tcp",
  "morph": true,
  "tls": {},
  "quic_congestion_control": "bbr",

  ... // QUIC Fields
}
```

Nowhere Portal is the SingBox inbound for the Nowhere protocol. Nowhere 3
(`nw3`) is the default stack: it serves ALPN `nw3` only, speaks exactly one
transport selected by `net`, and requires a 32-character lowercase hex key.

The protocol stack is selected uniformly by `tls.alpn` on both client and
server — there is no separate version field:

| `tls.alpn` | Stack |
| --- | --- |
| omitted (or `[""]`) | Nowhere 3 (`nw3`) — the default |
| `["nw3"]` | Nowhere 3 (`nw3`) |
| `["nw2"]`, or any other single value | Nowhere 2.2.1 (`nw2`) — the legacy stack |

The two stacks share no handshake: a single inbound runs exactly one stack, and
the fields of the other stack are rejected. Nowhere 2 is kept for compatibility
with pre-nw3 peers — see [Legacy Nowhere 2 (nw2)](#legacy-nowhere-2-nw2) below.

Plaintext inbound is not allowed. TLS must be enabled.

!!! note "Route sniff"

    Nowhere clients wait for the Portal's READY result before sending UDP data, and
    READY is only sent after the routed outbound is established. A `sniff` action on
    inbound UDP flows therefore never sees a payload; it waits for the sniff timeout
    (300ms by default) and then continues with the original destination. Do not
    configure `sniff` for Nowhere inbounds unless domain-based routing is needed.

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### password

==Required==

Shared key used to derive auth material. Must match the outbound `password`.

Nowhere 3 requires exactly 32 lowercase hexadecimal characters
(`[0-9a-f]{32}`), never hex-decoded. The legacy rule (32–64 lowercase
hexadecimal characters after URL percent-decoding, odd lengths accepted)
applies only on the `nw2` stack. Generate one with `nowhere generate-key`.

#### morph

Enable the keyed transport transform for every transport of this endpoint.
There is no negotiation: clients must use the same setting. Default: `true` on
Nowhere 3, `false` on Nowhere 2.

Morph is not negotiated in-band: it must match the client. The two stacks
derive the transform differently, so every peer on a hop must run the same
stack.

#### net

Nowhere 3 transport: `"tcp"` (TLS over TCP, UDP flows carried as UoT) or
`"udp"` (QUIC/UDP, streams + DATAGRAM). Empty means `"tcp"`.

`net` is a Nowhere 3 field: it is rejected on the `nw2` stack, which selects
its transports via `network` instead. `"udp"` requires the build tag
`with_quic`.

#### network

Listen transports. Default: `["tcp", "udp"]`.

| Value | Behavior |
| --- | --- |
| `["tcp"]` | TLS/TCP listener (TCP relay + UoT). |
| `["udp"]` | QUIC listener (streams + DATAGRAM). Requires build tag `with_quic`. |
| `["tcp", "udp"]` | Both. |

Without `with_quic`, any configuration that enables UDP returns
`QUIC is not included in this build`.

On Nowhere 3 the transport is selected by `net`, so an explicit `network` may
only name that one transport: `net: "tcp"` implies `["tcp"]`, `net: "udp"`
implies `["udp"]`.

#### egress

Nowhere 3 exit-bridge mode. When `true`, the Portal does not route flows
locally: it accepts a single
[Nowhere Egress](/configuration/inbound/nowhere-egress/) registration over
QUIC and forwards every authenticated flow to that exit.

Requires `net: "udp"` — the registration handshake only exists on the QUIC
transport. Rejected on the `nw2` stack.

#### tls

==Required==

Use the native SingBox TLS object. See [TLS](/configuration/shared/tls/#inbound).

Nowhere always uses TLS 1.3. The ALPN selects the protocol stack:

- Omitted: Nowhere 3, ALPN fixed to `nw3`.
- `["nw3"]`: Nowhere 3, same as omitted.
- `["nw2"]` or any other single value: the legacy Nowhere 2 stack, which
  serves exactly that ALPN.

Exactly one ALPN value may be configured. Nowhere 3 additionally requires a
static certificate and rejects `tls.acme` / `tls.certificate_provider`,
`tls.utls` / `tls.ech` / `tls.reality` and `tls.min_version` /
`tls.max_version`.

Recommended native example:

```json
{
  "enabled": true,
  "alpn": ["nw3"],
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
setting only affects QUIC/UDP transports and does not implement a bandwidth
rate limit. The inbound and outbound may use different controllers.

### Nowhere 3 (nw3)

Nowhere 3 is the default stack, a ground-up rewrite that shares no wire format
with `nw2`. Differences from the legacy fields:

| Aspect | Nowhere 3 behavior |
| --- | --- |
| ALPN | `nw3`. Omitted or `["nw3"]` selects this stack; any other single ALPN selects `nw2`. |
| TLS version | Pinned to TLS 1.3. `tls.min_version` / `tls.max_version` are rejected. |
| TLS stack | Standard library only. `tls.utls` / `tls.ech` / `tls.reality` are rejected; `tls.acme` / `tls.certificate_provider` are rejected (a static certificate is required). |
| Key | Exactly 32 lowercase hex characters (`[0-9a-f]{32}`). The lenient `nw2` rules (32–64, odd lengths) do not apply. |
| Morph | Defaults to **on**. An explicit `morph` still wins. The Nowhere 3 Morph transform uses a different derivation than `nw2`, so both ends of a hop must run the same stack. |
| Transports | Exactly one per endpoint, selected by `net`. |
| Chaining | `next` is rejected; Nowhere 3 has no native Portal chaining. |
| Admission limits | `max_unauthenticated_connections` / `max_unauthenticated_per_source` are rejected; the vendored Portal owns its own limits. |
| Networks | An explicit `network` must equal the transport of `net`: `tcp` implies `["tcp"]`, `udp` implies `["udp"]`. |

A minimal Nowhere 3 Portal over the TCP transport:

```json
{
  "type": "nowhere",
  "tag": "nw3-in",
  "listen_port": 2080,
  "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
  "net": "tcp",
  "tls": {
    "enabled": true,
    "certificate_path": "/path/cert.pem",
    "key_path": "/path/key.pem"
  }
}
```

On startup the Portal logs the leaf certificate's SHA-256 fingerprint so a
`pin=` value can be obtained for the matching
[outbound](/configuration/outbound/nowhere/#nowhere-3-nw3).

### Legacy Nowhere 2 (nw2)

Nowhere 2.2.1 (`nw2`) is the legacy stack, kept for compatibility with pre-nw3
peers. Select it by setting `tls.alpn` to `["nw2"]` (or any other single ALPN
value the legacy clients negotiate); `net` and `egress` are rejected on this
stack. It negotiates exactly the configured ALPN and does not interoperate with
legacy 1.8 peers.

It accepts TLS/TCP and (with `with_quic`) QUIC/UDP transports, authenticates
clients, and routes TCP/UDP targets through the SingBox router (unless chained
to another Portal via `next`). Authentication is an exporter-bound AuthFrame,
the FlowHeader is 5 bytes and carries a HOPS forwarding budget of 0..7, and
QUIC UDP headers are packed. After AuthFrame, inbound TLS auto-detects
dedicated lanes (`mux=0`) versus credit-windowed marked Mux shards (`mux=1`).

#### max_unauthenticated_connections

Process-wide limit for connections that have not finished authentication
(including the TLS handshake stage). Omitted or `0` defaults to `256`, matching
the Rust Portal.

#### max_unauthenticated_per_source

Per-source unauthenticated connection limit. IPv4 uses `/32`; IPv6 is grouped
by `/64`. Omitted or `0` defaults to `32`. Must not exceed the global limit.

#### next

Optional native Portal chaining. When set, the Portal forwards **every**
accepted flow to the next Nowhere Portal instead of dialing the target itself:
SingBox routing and detour are bypassed entirely, with no fallback. When
omitted, flows are routed normally.

| Field | Default | Description |
| --- | --- | --- |
| `server` | ==Required== | Next Portal address. |
| `server_port` | ==Required== | Next Portal port. |
| `password` | ==Required== | Shared key of the next Portal. Subject to the same Portal key rule as the inbound `password`: 32–64 lowercase hexadecimal characters after URL percent-decoding. |
| `up`, `down` | `udp` / `udp` | Transport selectors toward the next Portal (`tcp` or `udp`); both must be set, or both omitted. Any matrix that can select `udp` requires build tag `with_quic`. |
| `mux` | `0` | `0` dedicated TLS lanes, `1` credit-windowed TLS Mux when TCP is possible. `udp/udp&mux=1` canonicalizes to `0`. |
| `pool` | `5` for dedicated `tcp` / `tcp`, otherwise `0` | TLS/TCP warm pool toward the next Portal. Values above `256` are clamped to `256`; `mux=1` and QUIC-capable matrices ignore `pool`. |
| `server_name` | none | DNS name used to verify the next Portal's TLS certificate. Omitted, empty, or the literal `"none"` disables certificate verification; the endpoint host may still be sent as the ClientHello SNI. |
| `pin` | none | SHA-256 hex fingerprint of the next Portal's leaf certificate. Omitted, empty, or `"none"` disables pinning; a real pin overrides `server_name` and chain verification. |
| `morph` | inherit inbound `morph` | Enable the Nowhere 2 Morph keyed transform toward the next Portal. Omitted (`nil`) inherits the inbound `morph`; set `true` / `false` to override the hop. Both ends of the hop must agree. |
| `dial4` | `auto` | IPv4 source address bound when dialing the next Portal over IPv4. Accepts `auto` (leave the source address to the system) or an IPv4 literal; `0.0.0.0` is a valid wildcard. |
| `dial6` | `auto` | IPv6 source address bound when dialing the next Portal over IPv6. Accepts `auto` or an IPv6 literal; IPv4-mapped literals such as `::ffff:192.0.2.1` are rejected and `::` is a valid wildcard. |

`dial4` and `dial6` are independent and may be combined for dual-stack source
binding. They mirror the Rust portal URL parameters `dial4` / `dial6` and are
mutually exclusive with `dial`: this build has no `dial` option for the next
hop, and the equivalent legacy single-family binding on an outbound is the
shared `inet4_bind_address` / `inet6_bind_address` dial field. A configured
bind is never silently downgraded to automatic — a failed bind fails the
dial and the next candidate is tried.

The chained upstream client inherits the inbound TLS ALPN.

Hop budget: the first forwarding Portal initializes HOPS to 7, each
Portal-to-Portal hop decrements it by one, and a Portal that would forward an
exhausted flow (HOPS=1) rejects it with `FLOW_LIMIT` before opening the next
hop. Setup rejection codes from an upstream Portal propagate downstream
unchanged. Every Portal in a chain must run Nowhere 2.2.1 (`nw2`).

### QUIC Fields

See [QUIC](/configuration/shared/quic/) for shared QUIC options when present.
The same window, idle timeout, keepalive, stream-limit, packet-size, and PMTU
settings are applied by both Nowhere inbound and outbound.
