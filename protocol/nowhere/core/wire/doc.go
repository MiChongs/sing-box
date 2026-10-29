// Package wire implements the Nowhere 3 (`nw3`) wire format.
//
// It is intentionally separate from the Nowhere 2 wire package. Setup-result
// values overlap numerically but do not mean the same thing, and an nw3 peer
// authenticates with a 16-byte role tag rather than a 32-byte session frame.
// ALPN is exactly "nw3"; this package does not negotiate or fall back.
package wire

// ALPN is the only protocol identifier an nw3 carrier offers or accepts.
const ALPN = "nw3"
