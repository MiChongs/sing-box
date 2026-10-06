//go:build with_quic

package quicx

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func testUDPMessage(data []byte) *udpMessage {
	message := allocMessage()
	*message = udpMessage{
		sessionID:     1,
		packetID:      1,
		fragmentTotal: 1,
		destination:   M.ParseSocksaddrHostPort("example.com", 443),
		data:          buf.As(data),
	}
	return message
}

func TestDatagramMTURejectsInvalidPeerLimit(t *testing.T) {
	headerSize := (&udpMessage{destination: M.ParseSocksaddrHostPort("example.com", 443)}).headerSize()
	tests := []struct {
		name     string
		reported int64
		wantErr  bool
		expected int
	}{
		{name: "zero", reported: 0, wantErr: true},
		{name: "negative", reported: -1, wantErr: true},
		{name: "one", reported: 1, wantErr: true},
		{name: "below header", reported: int64(headerSize), wantErr: true},
		{name: "header only", reported: int64(headerSize + udpMTUSafetyMargin), wantErr: true},
		{name: "minimum usable", reported: int64(headerSize + udpMTUSafetyMargin + 1), expected: headerSize + 1},
		{name: "standard", reported: 1200, expected: 1200 - udpMTUSafetyMargin},
		{name: "huge", reported: 1 << 62, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			udpMTU, err := datagramMTU(test.reported, headerSize)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error for a reported payload size of %d, got MTU %d", test.reported, udpMTU)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if udpMTU != test.expected {
				t.Fatalf("expected MTU %d, got %d", test.expected, udpMTU)
			}
		})
	}
}

// TestInitialUDPPacketSize covers the seed of the fragmentation packet size
// from the connection's DATAGRAM limit: the QUIC minimum is the fallback for a
// limit which is missing or unusable, and a usable limit is used as-is minus
// the safety margin instead of waiting for a rejected DATAGRAM.
func TestInitialUDPPacketSize(t *testing.T) {
	tests := []struct {
		name     string
		reported int64
		expected int
	}{
		{name: "unset", reported: 0, expected: initialUDPMTU},
		{name: "negative", reported: -1, expected: initialUDPMTU},
		{name: "below margin", reported: udpMTUSafetyMargin, expected: initialUDPMTU},
		{name: "quic minimum", reported: 1200, expected: 1200 - udpMTUSafetyMargin},
		{name: "path mtu", reported: 1441, expected: 1441 - udpMTUSafetyMargin},
		{name: "peer frame limit", reported: 16383, expected: 16383 - udpMTUSafetyMargin},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if udpMTU := initialUDPPacketSize(test.reported); udpMTU != test.expected {
				t.Fatalf("expected MTU %d for a reported payload size of %d, got %d", test.expected, test.reported, udpMTU)
			}
		})
	}
}

// TestFragUDPMessageRejectsInvalidPacketSize covers the packet size a peer can
// force through a forged max_datagram_frame_size: a non-positive fragment size
// used to panic with "slice bounds out of range" or to loop forever while
// allocating fragments.
func TestFragUDPMessageRejectsInvalidPacketSize(t *testing.T) {
	message := testUDPMessage(bytes.Repeat([]byte{1}, 100))
	defer message.releaseMessage()
	headerSize := message.headerSize()
	for _, maxPacketSize := range []int{-3, 0, 1, headerSize - 1, headerSize} {
		fragments, err := fragUDPMessage(message, maxPacketSize)
		if err == nil {
			t.Fatalf("expected an error for a packet size of %d, got %d fragments", maxPacketSize, len(fragments))
		}
	}
}

// TestFragUDPMessageFragmentCountLimit covers a message which cannot be split
// into the 255 fragments the uint8 fragmentTotal field can express.
func TestFragUDPMessageFragmentCountLimit(t *testing.T) {
	message := testUDPMessage(bytes.Repeat([]byte{1}, 65535))
	defer message.releaseMessage()
	for _, maxPacketSize := range []int{message.headerSize() + 1, message.headerSize() + 8} {
		fragments, err := fragUDPMessage(message, maxPacketSize)
		if err == nil {
			t.Fatalf("expected an error for a packet size of %d, got %d fragments", maxPacketSize, len(fragments))
		}
	}
}

func TestFragUDPMessageRoundTrip(t *testing.T) {
	origin := make([]byte, 3000)
	for index := range origin {
		origin[index] = byte(index)
	}
	message := testUDPMessage(origin)
	defer message.releaseMessage()
	fragments, err := fragUDPMessage(message, 1200)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fragments) != 3 {
		t.Fatalf("expected 3 fragments, got %d", len(fragments))
	}
	defragger := newUDPDefragger()
	var assembled *udpMessage
	for index, fragment := range fragments {
		if fragment.fragmentID != uint8(index) {
			t.Fatalf("expected fragment id %d, got %d", index, fragment.fragmentID)
		}
		if fragment.fragmentTotal != 3 {
			t.Fatalf("expected 3 fragments in total, got %d", fragment.fragmentTotal)
		}
		assembled, err = defragger.feed(fragment)
		if err != nil {
			t.Fatalf("unexpected error on fragment %d: %v", index, err)
		}
		if index < len(fragments)-1 && assembled != nil {
			t.Fatalf("reassembly completed after fragment %d", index)
		}
	}
	if assembled == nil {
		t.Fatal("reassembly did not complete")
	}
	defer assembled.releaseMessage()
	if !bytes.Equal(assembled.data.Bytes(), origin) {
		t.Fatal("reassembled message differs from the original")
	}
	if assembled.fragmentTotal != 1 {
		t.Fatalf("expected the reassembled message to be marked complete, got fragmentTotal %d", assembled.fragmentTotal)
	}
	if defragger.packetMap.Exist(1) {
		t.Fatal("the completed reassembly is still tracked by the defragger")
	}
}

// TestFragUDPMessageKeepsDestination covers the destination every fragment has
// to carry: the peer creates its session, and makes the routing decision for it,
// from the first DATAGRAM it receives, while DATAGRAM frames are neither
// retransmitted nor reordered back into place, so the first fragment to arrive
// may well be a tail one. Fragments used to carry the destination in the head
// fragment only, which created sessions routed to ":0" whenever the head
// fragment arrived late or was lost.
func TestFragUDPMessageKeepsDestination(t *testing.T) {
	message := testUDPMessage(bytes.Repeat([]byte{1}, 3000))
	defer message.releaseMessage()
	fragments, err := fragUDPMessage(message, 1200)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fragments) < 2 {
		t.Fatalf("expected a fragmented message, got %d fragments", len(fragments))
	}
	for index, fragment := range fragments {
		if fragment.destination != message.destination {
			t.Fatalf("fragment %d of %d carries destination %v instead of %v", index, len(fragments), fragment.destination, message.destination)
		}
	}
}

// TestDefraggerRejectsOversizedReassembly covers fragments whose real total
// length exceeds the uint16 length field of the wire format: the accumulated
// length used to wrap around and panic with "short buffer".
func TestDefraggerRejectsOversizedReassembly(t *testing.T) {
	const (
		fragmentTotal = 50
		fragmentSize  = 1350
	)
	defragger := newUDPDefragger()
	var lastErr error
	for index := 0; index < fragmentTotal; index++ {
		fragment := testUDPMessage(bytes.Repeat([]byte{byte(index)}, fragmentSize))
		fragment.packetID = 7
		fragment.fragmentTotal = fragmentTotal
		fragment.fragmentID = uint8(index)
		var assembled *udpMessage
		assembled, lastErr = defragger.feed(fragment)
		if assembled != nil {
			assembled.releaseMessage()
			t.Fatal("reassembly completed although the total length exceeds the protocol limit")
		}
		if lastErr != nil {
			break
		}
	}
	if lastErr == nil {
		t.Fatalf("expected an error for %d fragments of %d bytes", fragmentTotal, fragmentSize)
	}
}

func TestDefraggerRejectsInvalidFragmentID(t *testing.T) {
	defragger := newUDPDefragger()
	message := testUDPMessage([]byte{1, 2, 3})
	message.fragmentTotal = 2
	message.fragmentID = 2
	if _, err := defragger.feed(message); err == nil {
		t.Fatal("expected an error for a fragment id outside of fragmentTotal")
	}
}

func TestDefraggerCacheBound(t *testing.T) {
	defragger := newUDPDefragger()
	for index := 0; index < maxDefragmentEntries*2; index++ {
		message := testUDPMessage([]byte{1, 2, 3})
		message.packetID = uint16(index)
		message.fragmentTotal = 4
		message.fragmentID = 0
		_, err := defragger.feed(message)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	var tracked int
	defragger.packetMap.Range(func(_ uint16, _ *packetItem) {
		tracked++
	})
	if tracked > maxDefragmentEntries {
		t.Fatalf("expected at most %d tracked reassemblies, got %d", maxDefragmentEntries, tracked)
	}
}
