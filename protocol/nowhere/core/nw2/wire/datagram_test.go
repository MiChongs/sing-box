package wire

import (
	"bytes"
	"testing"
	"time"
)

func TestDatagramDataAndCloseFixedHeaders(t *testing.T) {
	data, err := EncodeUDPData(0x01020304, []byte{0xaa, 0xbb})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte{0x01, 2, 3, 4, 0xaa, 0xbb}) {
		t.Fatalf("data %x", data)
	}
	dataZero, err := EncodeUDPData(0x01020304, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dataZero, []byte{0x01, 2, 3, 4}) {
		t.Fatalf("data-zero %x", dataZero)
	}
	close, err := EncodeUDPClose(0x01020304)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(close[:], []byte{0x81, 2, 3, 4}) {
		t.Fatalf("close %x", close[:])
	}
	if UDPHeaderLen != 4 {
		t.Fatalf("UDPHeaderLen %d", UDPHeaderLen)
	}
}

func TestDatagramFragmentFixedHeader(t *testing.T) {
	payload := make([]byte, 2500)
	for i := range payload {
		payload[i] = 0x5a
	}
	frames, err := EncodeUDPDataFragments(0x01020304, 0x11223344, payload, 1200)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 {
		t.Fatalf("frame count %d want 3", len(frames))
	}
	want := []byte{0x41, 2, 3, 4, 0x11, 0x22, 0x33, 0x44, 0, 3, 0x09, 0xc4}
	if !bytes.Equal(frames[0][:UDPFragmentHeaderLen], want) {
		t.Fatalf("leading fragment header %x want %x", frames[0][:UDPFragmentHeaderLen], want)
	}
	if UDPFragmentHeaderLen != 12 {
		t.Fatalf("UDPFragmentHeaderLen %d", UDPFragmentHeaderLen)
	}
	// decode + reassemble
	reassembler := mustNewDatagramReassembler(t, DefaultReassemblyConfig())
	var assembled []byte
	for i, frame := range frames {
		if len(frame) > 1200 {
			t.Fatalf("frame %d exceeds mtu", i)
		}
		decoded, err := DecodeUDPFrame(frame)
		if err != nil {
			t.Fatalf("decode frame %d: %v", i, err)
		}
		if decoded.Type != UDPFrameTypeFragment || decoded.FlowID != 0x01020304 {
			t.Fatalf("frame %d fields mismatch", i)
		}
		if decoded.Fragment.FragmentIndex != uint8(i) {
			t.Fatalf("frame %d index %d", i, decoded.Fragment.FragmentIndex)
		}
		outcome := reassembler.Push(0x01020304, decoded.Fragment, testNow)
		if outcome.Done {
			assembled = outcome.Payload
		} else if outcome.DropReason != ReassemblyDropNone {
			t.Fatalf("unexpected drop frame %d: %s", i, outcome.DropReason)
		}
	}
	if !bytes.Equal(assembled, payload) {
		t.Fatal("reassembled payload mismatch")
	}
}

func TestDatagramRejectsShortReservedUnknownClosePayload(t *testing.T) {
	rejects := [][]byte{
		{},
		{0},
		{0, 0, 0},
		{0, 0, 0, 0},       // zero flow id
		{0xc0, 0, 0, 1},    // type 0b11
		{0x80, 0, 0, 1, 0}, // CLOSE with payload
	}
	for _, raw := range rejects {
		if _, err := DecodeUDPFrame(raw); err == nil {
			t.Fatalf("expected decode error for %x", raw)
		}
	}
}

func TestDatagramZeroFlowAndPacketIDsReject(t *testing.T) {
	if _, err := EncodeUDPData(0, []byte("x")); err == nil {
		t.Fatal("zero flow id data accepted")
	}
	if _, err := EncodeUDPClose(0); err == nil {
		t.Fatal("zero flow id close accepted")
	}
	if _, err := EncodeUDPDataFragments(0, 1, []byte("x"), 64); err == nil {
		t.Fatal("zero flow id fragments accepted")
	}
	if _, err := EncodeUDPFragmentHeader(1, UDPFragment{PacketID: 0, FragmentIndex: 0, FragmentCount: 2, TotalLen: 2}); err == nil {
		t.Fatal("zero packet id fragment accepted")
	}
}

func TestDatagramFragmentMetadataReject(t *testing.T) {
	if _, err := EncodeUDPFragmentHeader(1, UDPFragment{PacketID: 1, FragmentIndex: 0, FragmentCount: 1, TotalLen: 1}); err == nil {
		t.Fatal("count<2 accepted")
	}
	if _, err := EncodeUDPFragmentHeader(1, UDPFragment{PacketID: 1, FragmentIndex: 2, FragmentCount: 2, TotalLen: 1}); err == nil {
		t.Fatal("index>=count accepted")
	}
	if _, err := EncodeUDPFragmentHeader(1, UDPFragment{PacketID: 1, FragmentIndex: 0, FragmentCount: 2, TotalLen: 0}); err == nil {
		t.Fatal("zero total accepted")
	}
	if _, err := EncodeUDPFragmentHeader(1, UDPFragment{PacketID: 1, FragmentIndex: 0, FragmentCount: 3, TotalLen: 2}); err == nil {
		t.Fatal("total<count accepted")
	}
}

func TestDatagramFitsInOneFrameNotFragmented(t *testing.T) {
	frames, err := EncodeUDPDataFragments(7, 11, make([]byte, 95), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	decoded, err := DecodeUDPFrame(frames[0])
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != UDPFrameTypeData {
		t.Fatalf("expected DATA, got %v", decoded.Type)
	}
}

func TestReassemblerRejectsDuplicateConflict(t *testing.T) {
	now := testNow
	reassembler := mustNewDatagramReassembler(t, DefaultReassemblyConfig())
	original := UDPFragment{PacketID: 7, FragmentIndex: 0, FragmentCount: 2, TotalLen: 2, Payload: []byte("a")}
	if outcome := reassembler.Push(1, original, now); outcome.Done || outcome.DropReason != ReassemblyDropNone {
		t.Fatalf("first push outcome %+v", outcome)
	}
	conflict := original
	conflict.Payload = []byte("b")
	if outcome := reassembler.Push(1, conflict, now); outcome.DropReason != ReassemblyDropDuplicateConflict {
		t.Fatalf("expected duplicate_conflict, got %+v", outcome)
	}
	if reassembler.SlotCount() != 0 {
		t.Fatalf("slot count %d after drop", reassembler.SlotCount())
	}
}

func TestReassemblerRejectsMetadataConflict(t *testing.T) {
	now := testNow
	reassembler := mustNewDatagramReassembler(t, DefaultReassemblyConfig())
	original := UDPFragment{PacketID: 7, FragmentIndex: 0, FragmentCount: 2, TotalLen: 2, Payload: []byte("a")}
	reassembler.Push(1, original, now)
	conflict := original
	conflict.FragmentCount = 3
	conflict.TotalLen = 3
	if outcome := reassembler.Push(1, conflict, now); outcome.DropReason != ReassemblyDropMetadataConflict {
		t.Fatalf("expected metadata_conflict, got %+v", outcome)
	}
}

func TestReassemblerIgnoresIdenticalDuplicate(t *testing.T) {
	now := testNow
	reassembler := mustNewDatagramReassembler(t, DefaultReassemblyConfig())
	original := UDPFragment{PacketID: 7, FragmentIndex: 0, FragmentCount: 2, TotalLen: 2, Payload: []byte("a")}
	if outcome := reassembler.Push(1, original, now); outcome.Done {
		t.Fatal("first push unexpected complete")
	}
	if outcome := reassembler.Push(1, original, now); outcome.Done || outcome.DropReason != ReassemblyDropNone {
		t.Fatalf("identical duplicate outcome %+v", outcome)
	}
}

func TestReassemblerEnforcesByteAndSlotLimits(t *testing.T) {
	now := testNow
	cfg := ReassemblyConfig{MaxSlots: 1, MaxBytes: 4, TTL: time.Second}
	reassembler := mustNewDatagramReassembler(t, cfg)
	first := UDPFragment{PacketID: 1, FragmentIndex: 0, FragmentCount: 2, TotalLen: 4, Payload: []byte("aa")}
	if outcome := reassembler.Push(1, first, now); outcome.DropReason != ReassemblyDropNone {
		t.Fatalf("first push %+v", outcome)
	}
	if reassembler.ReservedBytes() != 4 {
		t.Fatalf("reserved %d want 4", reassembler.ReservedBytes())
	}
	// second flow evicts the oldest partial
	second := UDPFragment{PacketID: 2, FragmentIndex: 0, FragmentCount: 2, TotalLen: 4, Payload: []byte("aa")}
	outcome := reassembler.Push(2, second, now)
	if !outcome.EvictedPartial {
		t.Fatal("expected eviction")
	}
	reassembler.RemoveFlow(2)
	if reassembler.ReservedBytes() != 0 {
		t.Fatalf("reserved after remove %d", reassembler.ReservedBytes())
	}
	// oversized total rejected
	tooLarge := UDPFragment{PacketID: 3, FragmentIndex: 0, FragmentCount: 2, TotalLen: 5, Payload: []byte("aa")}
	if outcome := reassembler.Push(3, tooLarge, now); outcome.DropReason != ReassemblyDropByteLimit {
		t.Fatalf("expected byte_limit, got %+v", outcome)
	}
}

// testNow is the shared fixed instant used by reassembly tests; per-test
// callers pass offsets from it when exercising TTL eviction.
var testNow = time.Unix(1_700_000_000, 0)

func mustNewDatagramReassembler(t *testing.T, cfg ReassemblyConfig) *DatagramReassembler {
	t.Helper()
	reassembler, err := NewDatagramReassembler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return reassembler
}

func TestReassemblyDefaultsAndStrictConfig(t *testing.T) {
	cfg := DefaultReassemblyConfig()
	if cfg.MaxSlots != 64 || cfg.MaxBytes != 1024*1024 || cfg.TTL != 10*time.Second {
		t.Fatalf("defaults changed: %+v", cfg)
	}
	for _, cfg := range []ReassemblyConfig{
		{MaxSlots: 0, MaxBytes: 1, TTL: time.Second},
		{MaxSlots: 1, MaxBytes: 0, TTL: time.Second},
		{MaxSlots: 1, MaxBytes: 1, TTL: 0},
		{MaxSlots: -1, MaxBytes: 1, TTL: time.Second},
	} {
		if _, err := NewDatagramReassembler(cfg); err == nil {
			t.Fatalf("invalid config accepted: %+v", cfg)
		}
	}
}

func TestDatagramUnfragmentedAllowsZeroPacketID(t *testing.T) {
	frames, err := EncodeUDPDataFragments(7, 0, []byte("fits"), 1200)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("frame count %d", len(frames))
	}
	if _, err := EncodeUDPDataFragments(7, 0, make([]byte, 1200), 1200); err == nil {
		t.Fatal("fragmented packet accepted zero packet id")
	}
}

func TestDatagramPackedMaximumIDs(t *testing.T) {
	data, err := EncodeUDPData(MaxFlowID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte{0x3f, 0xff, 0xff, 0xff}) {
		t.Fatalf("data %x", data)
	}
	close, err := EncodeUDPClose(MaxFlowID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(close[:], []byte{0xbf, 0xff, 0xff, 0xff}) {
		t.Fatalf("close %x", close[:])
	}
	header, err := EncodeUDPFragmentHeader(MaxFlowID, UDPFragment{PacketID: 0xffffffff, FragmentIndex: 0, FragmentCount: 2, TotalLen: 2, Payload: []byte{42}})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 2, 0, 2}
	if !bytes.Equal(header[:], want) {
		t.Fatalf("fragment %x want %x", header[:], want)
	}
	for _, flowID := range []FlowID{0, MaxFlowID + 1, 0xffffffff} {
		if _, err := EncodeUDPData(flowID, nil); err == nil {
			t.Fatalf("data accepted %x", flowID)
		}
		if _, err := EncodeUDPClose(flowID); err == nil {
			t.Fatalf("close accepted %x", flowID)
		}
	}
}
