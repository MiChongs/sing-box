// Package server implements the inbound side of the Nowhere v1.8 protocol.
//
// Handler supports host-owned TLS/TCP and QUIC listeners, while Server provides
// standalone listener orchestration. Both authenticate physical carriers,
// auto-detect dedicated vs marked Mux TLS after AuthFrame, validate and pair
// logical flows, enforce bounded session and UDP resources, and hand established
// streams or packet connections to an injected Upstream. PortalUpstream forwards
// those flows through a caller-owned CarrierBundle for native, hop-limited
// Portal-to-Portal chains.
// Graceful shutdown closes flow admission before draining READY relays within
// one caller-owned deadline. Concrete QUIC implementations and product routing
// remain host-owned.
package server
