package wire

import (
	"bytes"
	"testing"
)

func TestMuxHeaderStableSevenByteVectors(t *testing.T) {
	openH, err := OpenMuxHeader(0x01020304, 0x0506)
	if err != nil {
		t.Fatal(err)
	}
	dataH, err := DataMuxHeader(0x01020304, 0x0506)
	if err != nil {
		t.Fatal(err)
	}
	windowH, err := WindowMuxHeader(0, 0x0506)
	if err != nil {
		t.Fatal(err)
	}
	finH, err := FinMuxHeader(0x01020304)
	if err != nil {
		t.Fatal(err)
	}
	resetH, err := ResetMuxHeader(0x01020304)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		header MuxHeader
		want   [MuxHeaderLen]byte
	}{
		{openH, [MuxHeaderLen]byte{1, 5, 6, 1, 2, 3, 4}},
		{dataH, [MuxHeaderLen]byte{2, 5, 6, 1, 2, 3, 4}},
		{windowH, [MuxHeaderLen]byte{3, 5, 6, 0, 0, 0, 0}},
		{finH, [MuxHeaderLen]byte{4, 0, 0, 1, 2, 3, 4}},
		{resetH, [MuxHeaderLen]byte{5, 0, 0, 1, 2, 3, 4}},
	}
	for _, tc := range cases {
		encoded, err := EncodeMuxHeader(tc.header)
		if err != nil {
			t.Fatal(err)
		}
		if encoded != tc.want {
			t.Fatalf("got %x want %x", encoded[:], tc.want[:])
		}
		decoded, err := DecodeMuxHeader(encoded[:])
		if err != nil {
			t.Fatal(err)
		}
		if decoded != tc.header {
			t.Fatalf("decoded %+v want %+v", decoded, tc.header)
		}
	}
}

func TestMuxHeaderWindowAcceptsZeroFlowID(t *testing.T) {
	if _, err := WindowMuxHeader(0, 1); err != nil {
		t.Fatalf("connection window: %v", err)
	}
	if _, err := OpenMuxHeader(0, 1); err == nil {
		t.Fatal("open accepted zero flow id")
	}
	if _, err := DataMuxHeader(0, 1); err == nil {
		t.Fatal("data accepted zero flow id")
	}
	if _, err := FinMuxHeader(0); err == nil {
		t.Fatal("fin accepted zero flow id")
	}
}

func TestMuxHeaderRejectsInvalidCodesAndValues(t *testing.T) {
	if _, err := DataMuxHeader(1, 0); err == nil {
		t.Fatal("empty DATA accepted")
	}
	if _, err := WindowMuxHeader(1, 0); err == nil {
		t.Fatal("zero WINDOW accepted")
	}
	if _, err := FinMuxHeader(1); err != nil {
		t.Fatalf("fin: %v", err)
	}
	if _, err := ResetMuxHeader(1); err != nil {
		t.Fatalf("reset: %v", err)
	}
}

func TestMuxHeaderFlowIDsMustFitThirtyBits(t *testing.T) {
	kinds := []MuxFrameKind{MuxFrameOpen, MuxFrameData, MuxFrameWindow, MuxFrameFin, MuxFrameReset}
	for _, kind := range kinds {
		value := 0
		if kind == MuxFrameData || kind == MuxFrameWindow {
			value = 1
		}
		header, err := newMuxHeader(kind, value, MaxFlowID)
		if err != nil {
			t.Fatalf("kind %d max id: %v", kind, err)
		}
		encoded, err := EncodeMuxHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeMuxHeader(encoded[:])
		if err != nil {
			t.Fatal(err)
		}
		if decoded != header {
			t.Fatalf("kind %d round trip mismatch", kind)
		}
		for _, flowID := range []FlowID{MaxFlowID + 1, 0xffffffff} {
			if _, err := newMuxHeader(kind, value, flowID); err == nil {
				t.Fatalf("kind %d accepted flow %x", kind, flowID)
			}
			invalid := encoded
			encodeUint32BE(invalid[3:], flowID)
			if _, err := DecodeMuxHeader(invalid[:]); err == nil {
				t.Fatalf("kind %d decoded overflow flow %x", kind, flowID)
			}
		}
		for length := 0; length < MuxHeaderLen; length++ {
			if _, err := DecodeMuxHeader(encoded[:length]); err == nil {
				t.Fatalf("kind %d accepted short header %d", kind, length)
			}
		}
	}
}

func TestMuxHeaderDecoderRejectsUnknownKindsAndNonzeroTerminals(t *testing.T) {
	for _, kind := range []byte{0, 6, 0xff} {
		if _, err := DecodeMuxHeader([]byte{kind, 0, 0, 0, 0, 0, 1}); err == nil {
			t.Fatalf("unknown kind %d accepted", kind)
		}
	}
	for _, kind := range []byte{4, 5} {
		if _, err := DecodeMuxHeader([]byte{kind, 0, 1, 0, 0, 0, 1}); err == nil {
			t.Fatalf("terminal kind %d accepted nonzero value", kind)
		}
	}
}

func TestMuxMarkerCannotBeFlowHeaderFlags(t *testing.T) {
	if _, err := DecodeFlowHeader([]byte{MuxMarker, 0, 0, 0, 1}); err == nil {
		t.Fatal("0xff decoded as a flow header")
	}
}

func TestReadMuxHeaderLeavesPayload(t *testing.T) {
	header, err := OpenMuxHeader(7, 0)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeMuxHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	input := append(encoded[:], []byte("payload")...)
	decoded, err := ReadMuxHeader(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if decoded != header {
		t.Fatalf("decoded %+v want %+v", decoded, header)
	}
}
