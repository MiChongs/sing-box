//go:build with_quic

package quicx

import (
	"testing"

	"github.com/sagernet/sing/common/buf"
)

// TestServerDropsMessageWithoutDestination covers a UDP message which cannot be
// routed: the session of a sessionID is created from the first message received
// for it, so a message without a destination used to create a session routed to
// ":0" (and to dial an outbound packet connection for it). Such a message is
// dropped whole now — the fragments of one message all carry the same
// destination — and no session is created for it.
func TestServerDropsMessageWithoutDestination(t *testing.T) {
	session := &serverSession[int]{udpConnMap: make(map[uint16]*udpPacketConn)}
	message := allocMessage()
	*message = udpMessage{
		sessionID:     1,
		packetID:      1,
		fragmentTotal: 1,
		data:          buf.As([]byte{1, 2, 3}),
	}
	if err := session.handleUDPMessage(message); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(session.udpConnMap) != 0 {
		t.Fatal("a session was created for a message without a destination")
	}
}
