// Package wire implements the Nowhere 2.0 (`nw2`) wire format.
//
// The codec mirrors the Rust oracle in Nowhere/src/protocol one-to-one:
//   - 32-byte connection-bound authentication frame
//   - optional TLS Mux marker 0xff followed by 7-byte Mux frames
//   - 5-byte flow header (flags with HOPS + 30-bit big-endian flow id)
//   - SOCKS5-style typed target address
//   - single-byte setup result
//   - u16-length UoT packet framing
//   - packed DATA / FRAGMENT / CLOSE QUIC datagram frames with bounded reassembly
//
// Runtime packages in this module must remain free of third-party
// dependencies; HKDF is implemented over the standard library.
package wire

// DefaultALPN is the sole ALPN every Nowhere 2 carrier negotiates.
const DefaultALPN = "nw2"

// SessionIDLen is the fixed length of a logical session identifier.
const SessionIDLen = 16

// SessionID identifies one logical session shared by a transport bundle.
type SessionID = [SessionIDLen]byte
