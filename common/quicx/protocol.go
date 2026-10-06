//go:build with_quic

package quicx

const (
	Version = 1

	// AuthNonceLen is the length of the random nonce a client attaches to its
	// authentication request, which is what makes an authentication request
	// unusable for anyone but the session it was created for.
	//
	// QUIC 0-RTT data is not replay protected: an attacker who captured a
	// client's 0-RTT flight can send it to the server again, and the transport
	// has no way to tell the copy from the original. The nonce lets the server
	// tell them apart, because it remembers the nonce of every recently
	// authenticated session and rejects a nonce another session already used. A
	// replayed flight therefore fails authentication and never reaches the
	// handler, so the CONNECT request and the first payload of the proxied
	// connection it carries are not delivered to the destination a second time.
	AuthNonceLen = 16
)

const (
	CommandAuthenticate = iota
	CommandConnect
	CommandPacket
	CommandDissociate
	CommandHeartbeat
)
