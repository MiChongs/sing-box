package wire

import (
	"bytes"
	"testing"
)

func FuzzValidateAuthFrame(f *testing.F) {
	credentials, err := NewCredentials("fuzz-secret")
	if err != nil {
		f.Fatal(err)
	}
	var exporter TLSExporter
	for index := range exporter {
		exporter[index] = byte(index)
	}
	frame, err := EncodeAuthFrame(credentials, AuthTransportTLSTCP, exporter, SessionID{1})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(frame[:])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ValidateAuthFrame(input, credentials, AuthTransportTLSTCP, exporter)
	})
}

func FuzzReadFlowHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ReadFlowHeader(bytes.NewReader(input))
	})
}

func FuzzTarget(f *testing.F) {
	f.Add([]byte{TargetIPv4, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{TargetDomain, 3, 'a', '.', 'b', 1, 187})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		target, consumed, err := DecodeTarget(input)
		if err != nil {
			return
		}
		encoded, err := EncodeTarget(target)
		if err != nil {
			t.Fatalf("re-encode decoded target: %v", err)
		}
		if consumed <= 0 || consumed > len(input) {
			t.Fatalf("invalid consumed length %d for %d bytes", consumed, len(input))
		}
		if !bytes.Equal(encoded, input[:consumed]) {
			t.Fatalf("target round trip mismatch: got %x want %x", encoded, input[:consumed])
		}
	})
}

func FuzzDecodeUDPFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeUDPFrame(input)
	})
}

func FuzzReadUDPPacket(f *testing.F) {
	f.Add([]byte{0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ReadUDPPacket(bytes.NewReader(input))
	})
}
