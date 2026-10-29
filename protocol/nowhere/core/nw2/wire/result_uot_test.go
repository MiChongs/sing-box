package wire

import (
	"bytes"
	"testing"
)

func TestSetupResultWireBytes(t *testing.T) {
	for b := 0; b <= 7; b++ {
		result := SetupResult(b)
		encoded, err := EncodeSetupResult(result)
		if err != nil {
			t.Fatalf("encode %d: %v", b, err)
		}
		if encoded[0] != byte(b) {
			t.Fatalf("wire byte %d want %d", encoded[0], b)
		}
		decoded, err := DecodeSetupResult(encoded[:])
		if err != nil {
			t.Fatalf("decode %d: %v", b, err)
		}
		if decoded != result {
			t.Fatalf("decoded %d want %d", decoded, b)
		}
	}
}

func TestSetupResultRejects(t *testing.T) {
	if _, err := DecodeSetupResult(nil); err == nil {
		t.Fatal("empty accepted")
	}
	if _, err := DecodeSetupResult([]byte{0, 1}); err == nil {
		t.Fatal("two bytes accepted")
	}
	if _, err := DecodeSetupResult([]byte{8}); err == nil {
		t.Fatal("unknown value accepted")
	}
	if _, err := EncodeSetupResult(SetupResult(8)); err == nil {
		t.Fatal("unknown value encoded")
	}
}

func TestSetupResultIsReadyAndString(t *testing.T) {
	if !SetupResultReady.IsReady() {
		t.Fatal("ready not ready")
	}
	if SetupResultDialFailed.IsReady() {
		t.Fatal("dial_failed marked ready")
	}
	if SetupResultPairTimeout.String() != "pair timeout" {
		t.Fatalf("string %q", SetupResultPairTimeout.String())
	}
}

func TestUoTPacketCodec(t *testing.T) {
	// zero-length
	got, err := EncodeUDPPacket(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0, 0}) {
		t.Fatalf("zero packet %x", got)
	}
	// small payload
	got, err = EncodeUDPPacket([]byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0, 3, 'a', 'b', 'c'}) {
		t.Fatalf("abc packet %x", got)
	}
	// header
	hdr, err := EncodeUDPPacketHeader(0x1234)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hdr[:], []byte{0x12, 0x34}) {
		t.Fatalf("header %x", hdr[:])
	}
	if _, err := EncodeUDPPacketHeader(UoTPacketMax + 1); err == nil {
		t.Fatal("oversize header accepted")
	}
	if _, err := EncodeUDPPacketHeader(-1); err == nil {
		t.Fatal("negative header accepted")
	}
}

func TestUoTReadCleanEOFVsTruncated(t *testing.T) {
	// clean EOF on empty reader
	pkt, err := ReadUDPPacket(bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("empty read: %v", err)
	}
	if pkt != nil {
		t.Fatalf("expected nil on EOF, got %x", pkt)
	}
	// truncated length (one byte)
	_, err = ReadUDPPacket(bytes.NewReader([]byte{0}))
	if err == nil {
		t.Fatal("truncated length accepted")
	}
	// truncated payload
	_, err = ReadUDPPacket(bytes.NewReader([]byte{0, 3, 'a', 'b'}))
	if err == nil {
		t.Fatal("truncated payload accepted")
	}
}

func TestUoTConsecutivePackets(t *testing.T) {
	a, _ := EncodeUDPPacket([]byte{})
	b, _ := EncodeUDPPacket([]byte("abc"))
	stream := append(append([]byte{}, a...), b...)
	r := bytes.NewReader(stream)
	pkt, err := ReadUDPPacket(r)
	if err != nil || len(pkt) != 0 {
		t.Fatalf("first packet: %v %x", err, pkt)
	}
	pkt, err = ReadUDPPacket(r)
	if err != nil || string(pkt) != "abc" {
		t.Fatalf("second packet: %v %x", err, pkt)
	}
	pkt, err = ReadUDPPacket(r)
	if err != nil || pkt != nil {
		t.Fatalf("third read: %v %x", err, pkt)
	}
}
