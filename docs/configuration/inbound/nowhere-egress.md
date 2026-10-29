---
icon: material/new-box
---

`nowhere-egress` inbound is the Nowhere 3 exit bridge. It never listens: it
dials a [Nowhere 3 Portal](/configuration/inbound/nowhere/#nowhere-3-nw3) over
QUIC, registers as that Portal's single exit, and serves the flows the Portal
opens through the local SingBox router.

A Portal in egress mode (`"egress": true`) accepts exactly one registration at
a time. A second Egress is told the exit is busy and keeps retrying on a
three-second cooldown — it never preempts the current owner. If the owner's
connection drops, the waiting Egress takes over without operator action.

Requires the build tag `with_quic` (the QUIC carrier only).

### Structure

```json
{
  "type": "nowhere-egress",
  "tag": "nw3-egress",

  "server": "portal.example.com",
  "server_port": 2080,
  "password": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
  "morph": true,
  "insecure": true,

  ... // Dial Fields
  ... // QUIC Fields
}
```

### Fields

#### server

==Required==

The Portal address.

#### server_port

==Required==

The Portal port.

#### password

==Required==

Shared key of the Portal. Nowhere 3 key rule: exactly 32 lowercase hexadecimal
characters (`[0-9a-f]{32}`).

#### morph

Enable the Nowhere 3 Morph keyed transform, sealing the QUIC packet socket
below QUIC. Default: `true` (the Nowhere 3 default; an explicit value wins).

There is no in-band negotiation: `morph` must match the Portal's setting. The
Nowhere 3 Morph transform uses a different derivation than Nowhere 2, so both
ends must run the same version.

#### pin

SHA-256 hex fingerprint of the Portal's leaf certificate. When set it
overrides chain and hostname verification.

#### insecure

Skip Portal certificate verification. Nowhere 3 otherwise verifies against
system roots and the endpoint host name.

#### server_name

DNS name used to verify the Portal's TLS certificate. Defaults to the
endpoint host.

#### quic_congestion_control

QUIC congestion controller used by the Egress sender. Default: `bbr`.

Available values: `bbr`, `bbr_standard`, `bbr2`, `bbr2_variant`, `cubic`, and
`reno`. An unknown value is rejected while constructing the inbound. This
setting does not implement a bandwidth rate limit.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.

The shared `inet4_bind_address` / `inet6_bind_address` fields bind the source
address per address family for the exit dials toward targets. The Portal
connection itself always uses the system-selected source address.

### QUIC Fields

See [QUIC](/configuration/shared/quic/) for shared QUIC options when present.
The same window, idle timeout, keepalive, stream-limit, packet-size, and PMTU
settings are applied by both the Portal and the Egress.
