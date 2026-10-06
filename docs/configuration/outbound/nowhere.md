---
icon: material/new-box
---

### Structure

```json
{
  "type": "nowhere",
  "tag": "nw-out",

  "server": "example.com",
  "server_port": 2077,
  "password": "secret",
  "up": "udp",
  "down": "udp",
  "morph": false,
  "pool": 0,
  "prewarm_on_start": false,
  "pin": "",
  "tls": {},
  "quic_congestion_control": "bbr",

  ... // Dial Fields
  ... // QUIC Fields
}
```

Nowhere outbound is the SingBox client for the Nowhere protocol. Upload and
download carriers are selected independently via `up` / `down`.

This is a Nowhere 2.1 (`nw2`) implementation. It negotiates the `nw2` ALPN
only and does not interoperate with legacy 1.8 peers. Authentication is an
exporter-bound AuthFrame, the FlowHeader is 5 bytes and carries a HOPS
forwarding budget of 0..7, TLS Mux is credit-windowed (`mux=0` dedicated
lanes, `mux=1` marked shards), QUIC UDP headers are packed, and `mix` remains
a client-side policy resolving to TT / TQ / QT / QQ.

`morph` enables the Nowhere 2 Morph keyed transform for every carrier of this
endpoint. Morph is not negotiated in-band: `morph=1` must be enabled on both
ends of a hop, because the Nowhere 2.1 Morph transform is wire-incompatible
with the 2.0.x Morph.

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

#### up, down

Carrier selectors: `"tcp"`, `"udp"`, or `"mix"`.

Both must be set, or both omitted (default `udp` / `udp`).
`mix` is a client-side policy resolved per flow before FlowHeader.
`mix/mix` resolves only to `tcp/tcp` or `udp/udp`. A one-sided mix can resolve
to a split pair. The primary pair has a one-second preparation budget, then the
other allowed pair is tried once with a new flow ID.

| Matrix | TCP traffic | UDP traffic | Notes |
| --- | --- | --- | --- |
| `tcp` / `tcp` | One TLS connection | UoT on TLS | `pool` applies for `mux=0` (default `5`, max `256`). |
| `udp` / `udp` | One QUIC stream | QUIC DATAGRAM | Requires `with_quic`. `mux=1` canonicalizes to `0`. |
| `tcp` / `udp` | TLS upload + QUIC download | UoT upload + DATAGRAM download | Asymmetric; requires `with_quic`. |
| `udp` / `tcp` | QUIC upload + TLS download | DATAGRAM upload + UoT download | Asymmetric; requires `with_quic`. |
| `mix` / `mix` | Per-flow `tcp/tcp` or `udp/udp` | Same as the resolved pair | Client policy; requires `with_quic`. |

Any matrix that can select QUIC (`udp` or `mix`) forces `pool=0`. A non-zero
configured value is normalized to zero and reported once as a configuration
warning.

Without `with_quic`, only `tcp` / `tcp` can be constructed; other matrices
return `QUIC is not included in this build`.

#### mux

TLS lane framing. `0` (default) uses dedicated TLS lanes; `1` enables marked Mux
shards. Mux applies when either direction is `tcp` or `mix`. `udp/udp&mux=1`
canonicalizes to `0`.

#### mix_fallback_timeout

Primary mix-route preparation budget. Omitted or `0` uses `1s`.

#### pool

TLS/TCP warm pool size. Effective only for dedicated (`mux=0`) `tcp` / `tcp`.

Default `5` when omitted on dedicated `tcp` / `tcp`. Negative values are rejected and
values above `256` are clamped to `256`. `mux=1` and any matrix that can select
QUIC ignore `pool`.

`pool=0` only disables warm preconnect; it does **not** cap business fresh
dials. On `tcp` / `tcp`, each user TCP/UoT flow still consumes one dedicated
TLS/TCP carrier.

#### morph

Enable the Nowhere 2 Morph keyed transform for every carrier of this endpoint:
a 64-byte random TCP prelude is sent below TLS before authentication, and
directional ChaCha20 keys derived from the shared key wrap traffic below both
TLS and QUIC. Default: `false`.

There is no in-band negotiation. `morph` must be enabled on both ends of a hop
(client and Portal, or Portal and next Portal), and the Nowhere 2.1 Morph
transform is wire-incompatible with the 2.0.x Morph, so every peer on a
`morph=1` hop must run Nowhere 2.1.

#### prewarm_on_start

Fill the TLS/TCP warm pool up to `pool` once sing-box has started, instead of
on the first connection. Only effective when `pool` is effective (dedicated
`tcp` / `tcp`). Default: `false`.

The pool is also refilled after a network change, on the next connection.

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

#### tls

==Required==

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

Must enable TLS. Nowhere forces TLS 1.3. If ALPN is omitted, it is normalized
to `nw2`; otherwise exactly one ALPN value is required.

For a self-signed server, set `insecure: true` or pin the certificate /
fingerprint explicitly.

#### pin

SHA-256 fingerprint of the server's leaf certificate, as 64 lowercase hex
characters. When set, it replaces SNI and certificate chain verification for
both TLS and QUIC carriers. Omitted, empty, or `"none"` disables pinning.

Pinning requires the standard TLS engine; it cannot be combined with uTLS or
Reality.

#### quic_congestion_control

QUIC congestion controller used by the outbound sender. Default: `bbr`.

Available values: `bbr`, `bbr_standard`, `bbr2`, `bbr2_variant`, `cubic`, and
`reno`. An unknown value is rejected while constructing the outbound, including
TCP-only carrier configurations. This setting only affects QUIC/UDP carriers
and does not implement a bandwidth rate limit. The inbound and outbound may use
different controllers.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.

### QUIC Fields

See [QUIC](/configuration/shared/quic/) for shared QUIC options when present.
The same window, idle timeout, keepalive, stream-limit, packet-size, and PMTU
settings are applied by both Nowhere inbound and outbound.
