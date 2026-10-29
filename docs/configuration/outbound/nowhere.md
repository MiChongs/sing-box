---
icon: material/new-box
---

### Structure

```json
{
  "type": "nowhere",
  "tag": "nw3-out",

  "server": "example.com",
  "server_port": 2077,
  "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
  "net": "tcp",
  "morph": true,
  "tls": {},
  "quic_congestion_control": "bbr",

  ... // Dial Fields
  ... // QUIC Fields
}
```

Nowhere outbound is the SingBox client for the Nowhere protocol. Nowhere 3
(`nw3`) is the default stack: it negotiates the `nw3` ALPN, speaks exactly one
transport selected by `net`, requires a 32-character lowercase hex key, and
turns Morph on by default.

The protocol stack is selected uniformly by `tls.alpn` on both client and
server — there is no separate version field:

| `tls.alpn` | Stack |
| --- | --- |
| omitted (or `[""]`) | Nowhere 3 (`nw3`) — the default |
| `["nw3"]` | Nowhere 3 (`nw3`) |
| `["nw2"]`, or any other single value | Nowhere 2.2.1 (`nw2`) — the legacy stack |

The two stacks share no handshake: a single outbound runs exactly one stack,
and the fields of the other stack are rejected. Nowhere 2 is kept for
compatibility with pre-nw3 peers; every existing `nw2` configuration keeps
working unchanged once its ALPN is set explicitly — see
[Legacy Nowhere 2 (nw2)](#legacy-nowhere-2-nw2) below.

`morph` enables the keyed transport transform for every transport of this
endpoint. Morph is not negotiated in-band: `morph` must be enabled on both ends
of a hop, and the Nowhere 3 transform uses a different derivation than the
Nowhere 2 one, so every peer on a hop must run the same stack.

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### password

==Required==

Shared key. Must match the inbound `password`.

Nowhere 3 requires exactly 32 lowercase hexadecimal characters
(`[0-9a-f]{32}`). The lenient legacy rule (1–255 URL-percent-decoded bytes,
no character rule) applies only on the `nw2` stack — see the
[Nowhere inbound](/configuration/inbound/nowhere/) `password` field for the
Portal-side rules of both stacks.

#### net

Nowhere 3 transport: `"tcp"` (TLS over TCP, UDP flows carried as UoT) or
`"udp"` (QUIC/UDP, streams + DATAGRAM). Empty means `"tcp"`.

`net` is a Nowhere 3 field: it is rejected on the `nw2` stack, which selects
its transports via `up` / `down` instead. `"udp"` requires the build tag
`with_quic`.

#### morph

Enable the keyed transport transform for every transport of this endpoint
(64-byte TCP prelude below TLS, directional ChaCha20 keys below QUIC). Default:
`true` on Nowhere 3, `false` on Nowhere 2.

There is no in-band negotiation: `morph` must be enabled on both ends of a hop
(client and Portal, or Portal and next Portal), and the two stacks derive the
transform differently, so every peer on a hop must run the same stack.

#### tls

==Required==

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

Must enable TLS. Nowhere forces TLS 1.3. The ALPN selects the protocol stack:

- Omitted: Nowhere 3, ALPN fixed to `nw3`.
- `["nw3"]`: Nowhere 3, same as omitted.
- `["nw2"]` or any other single value: the legacy Nowhere 2 stack, which
  negotiates exactly that ALPN.

Exactly one ALPN value may be configured. Nowhere 3 additionally rejects
`tls.utls` / `tls.ech` / `tls.reality` and `tls.min_version` /
`tls.max_version` (the vendored stack uses the standard library TLS and pins
TLS 1.3).

For a self-signed server, set `insecure: true` or pin the certificate /
fingerprint explicitly.

#### quic_congestion_control

QUIC congestion controller used by the outbound sender. Default: `bbr`.

Available values: `bbr`, `bbr_standard`, `bbr2`, `bbr2_variant`, `cubic`, and
`reno`. An unknown value is rejected while constructing the outbound, including
TCP-only transport configurations. This setting only affects QUIC/UDP transports
and does not implement a bandwidth rate limit. The inbound and outbound may use
different controllers.

### Nowhere 3 (nw3)

Nowhere 3 is the default stack, a ground-up rewrite that shares no wire format
with `nw2`. Differences from the legacy fields:

| Aspect | Nowhere 3 behavior |
| --- | --- |
| ALPN | `nw3`. Omitted or `["nw3"]` selects this stack; any other single ALPN selects `nw2`. |
| TLS version | Pinned to TLS 1.3. `tls.min_version` / `tls.max_version` are rejected. |
| TLS stack | Standard library only. `tls.utls` / `tls.ech` / `tls.reality` are rejected. |
| Key | Exactly 32 lowercase hex characters (`[0-9a-f]{32}`). The lenient `nw2` client rule (1–255 decoded bytes) does not apply. |
| Morph | Defaults to **on**. An explicit `morph` still wins. The Nowhere 3 Morph transform uses a different derivation than `nw2`, so both ends of a hop must run the same stack. |
| Transports | Exactly one per endpoint, selected by `net`. |
| Rejected `nw2` fields | `up`, `down`, `mux`, `pool`, `prewarm_on_start`, `max_concurrent_dials`, `warm_backoff_initial`, `warm_backoff_max` are all rejected: Nowhere 3 speaks one transport with fixed pooling. |

Trust follows Nowhere 3: system roots plus the endpoint host name by default,
`pin` overrides everything, and `insecure: true` skips verification.

A minimal Nowhere 3 client over the UDP (QUIC) transport:

```json
{
  "type": "nowhere",
  "tag": "nw3-out",
  "server": "example.com",
  "server_port": 2077,
  "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
  "net": "udp",
  "tls": {
    "enabled": true,
    "insecure": true
  }
}
```

### Legacy Nowhere 2 (nw2)

Nowhere 2.2.1 (`nw2`) is the legacy stack, kept for compatibility with pre-nw3
peers. Select it by setting `tls.alpn` to `["nw2"]` (or any other single ALPN
value the legacy Portal negotiates); `net` is rejected on this stack. Upload
and download transports are selected independently via `up` / `down`.

It negotiates exactly the configured ALPN and does not interoperate with legacy
1.8 peers. Authentication is an exporter-bound AuthFrame, the FlowHeader is 5
bytes and carries a HOPS forwarding budget of 0..7, TLS Mux is credit-windowed
(`mux=0` dedicated lanes, `mux=1` marked shards), and QUIC UDP headers are
packed.

`morph` enables the Nowhere 2 Morph keyed transform for every transport of this
endpoint: a 64-byte random TCP prelude is sent below TLS before authentication,
and directional ChaCha20 keys derived from the shared key wrap traffic below
both TLS and QUIC. Default: `false`.

The TCP prelude policy is `full8` by default (all eight bits of each prelude
byte are random). Set the `NOW_MORPH_TCP_PRELUDE` environment variable to
`low7` for the older policy that clears each byte's high bit; a set-but-empty
value is rejected. Both ends of a hop must use the same policy.

There is no in-band negotiation. `morph` must be enabled on both ends of a hop
(client and Portal, or Portal and next Portal), and the Nowhere 2.2.1 Morph
transform is wire-incompatible with the 2.0.x Morph, so every peer on a
`morph=1` hop must run Nowhere 2.2.1.

#### up, down

Transport selectors: `"tcp"` or `"udp"`.

Both must be set, or both omitted (default `udp` / `udp`).

| Matrix | TCP traffic | UDP traffic | Notes |
| --- | --- | --- | --- |
| `tcp` / `tcp` | One TLS connection | UoT on TLS | `pool` applies for `mux=0` (default `5`, max `256`). |
| `udp` / `udp` | One QUIC stream | QUIC DATAGRAM | Requires `with_quic`. `mux=1` canonicalizes to `0`. |
| `tcp` / `udp` | TLS upload + QUIC download | UoT upload + DATAGRAM download | Asymmetric; requires `with_quic`. |
| `udp` / `tcp` | QUIC upload + TLS download | DATAGRAM upload + UoT download | Asymmetric; requires `with_quic`. |

Any matrix that can select QUIC (`udp`) forces `pool=0`. A non-zero
configured value is normalized to zero and reported once as a configuration
warning.

Without `with_quic`, only `tcp` / `tcp` can be constructed; other matrices
return `QUIC is not included in this build`.

#### mux

TLS lane framing. `0` (default) uses dedicated TLS lanes; `1` enables marked Mux
shards. Mux applies when either direction is `tcp`. `udp/udp&mux=1`
canonicalizes to `0`.

#### pool

TLS/TCP warm pool size. Effective only for dedicated (`mux=0`) `tcp` / `tcp`.

Default `5` when omitted on dedicated `tcp` / `tcp`. Negative values are rejected and
values above `256` are clamped to `256`. `mux=1` and any matrix that can select
QUIC ignore `pool`.

`pool=0` only disables warm preconnect; it does **not** cap business fresh
dials. On `tcp` / `tcp`, each user TCP/UoT flow still consumes one dedicated
TLS/TCP transport.

#### max_concurrent_dials

Maximum in-flight physical TLS/TCP dials per outbound (dial + TLS + auth).
Omitted or `0` defaults to `16`. Negative values are rejected.

The cap applies to both business fresh dials and warm prepare. Warm prepare
only takes an idle slot non-blockingly and never preempts business dials.

#### warm_backoff_initial, warm_backoff_max

Exponential backoff window after warm-prepare failures. Defaults are `1s` /
`30s` when omitted. The initial value must not exceed the max. Warm replenish
is skipped during the backoff window; the pool only retries after a successful
business fresh dial.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.

The shared `inet4_bind_address` / `inet6_bind_address` fields bind the source
address per address family for this outbound. They are the sing-box equivalent
of the Rust `dial` parameter and are mutually exclusive with the Rust `dial4` /
`dial6` pair, which this build exposes only on the inbound `next` hop (see
[Nowhere inbound](/configuration/inbound/nowhere/#next).

### QUIC Fields

See [QUIC](/configuration/shared/quic/) for shared QUIC options when present.
The same window, idle timeout, keepalive, stream-limit, packet-size, and PMTU
settings are applied by both Nowhere inbound and outbound.
