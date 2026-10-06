package quic

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

type fakeTransport struct {
	max int
}

func (f *fakeTransport) current() int { return f.max }

func TestDatagramProberStartsAtTransportLimit(t *testing.T) {
	transport := &fakeTransport{max: 1200}
	prober := NewDatagramProber(transport.current)
	if got := prober.MaxDatagramSize(); got != 1200 {
		t.Fatalf("initial MaxDatagramSize = %d, want 1200", got)
	}
}

func TestDatagramProberSmallPacketSkipsProbe(t *testing.T) {
	transport := &fakeTransport{max: 1200}
	prober := NewDatagramProber(transport.current)
	payload := make([]byte, 1000)
	frames, probedSize, err := prober.EncodeUDPDataFragments(1, 1, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if probedSize != 0 {
		t.Fatalf("probedSize = %d, want 0 for fitting packet", probedSize)
	}
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want single DATA frame", len(frames))
	}
	frame, err := wire.DecodeUDPFrame(frames[0])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if frame.Type != wire.UDPFrameTypeData || len(frame.Payload) != len(payload) {
		t.Fatalf("frame type=%d payload=%d, want DATA/%d", frame.Type, len(frame.Payload), len(payload))
	}
}

func TestDatagramProberOversizedPacketProbesOnce(t *testing.T) {
	transport := &fakeTransport{max: 1200}
	prober := NewDatagramProber(transport.current)
	now := time.Unix(1000, 0)
	prober.now = func() time.Time { return now }

	payload := make([]byte, 1400)
	frames, probedSize, err := prober.EncodeUDPDataFragments(1, 1, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := len(payload) + wire.UDPHeaderLen
	if probedSize != want {
		t.Fatalf("probedSize = %d, want %d", probedSize, want)
	}
	if len(frames) != 1 {
		t.Fatalf("probe frames = %d, want single DATA frame", len(frames))
	}

	// Rate limit: a second oversized packet inside the interval fragments.
	frames, probedSize, err = prober.EncodeUDPDataFragments(1, 2, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if probedSize != 0 {
		t.Fatalf("probedSize = %d, want 0 inside probe interval", probedSize)
	}
	if len(frames) < 2 {
		t.Fatalf("frames = %d, want fragmented packet inside probe interval", len(frames))
	}

	// After the interval the probe is allowed again.
	now = now.Add(2 * DatagramProbeInterval)
	_, probedSize, err = prober.EncodeUDPDataFragments(1, 3, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if probedSize != want {
		t.Fatalf("probedSize = %d after interval, want %d", probedSize, want)
	}
}

func TestDatagramProberSuccessRaisesLimit(t *testing.T) {
	transport := &fakeTransport{max: 1200}
	prober := NewDatagramProber(transport.current)
	prober.NoteProbeSuccess(1405)
	if got := prober.MaxDatagramSize(); got != 1405 {
		t.Fatalf("MaxDatagramSize = %d, want 1405 after probe success", got)
	}
	// 1400-byte payload now fits without probing or fragmenting.
	frames, probedSize, err := prober.EncodeUDPDataFragments(1, 1, make([]byte, 1400))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if probedSize != 0 || len(frames) != 1 {
		t.Fatalf("probedSize=%d frames=%d, want unprobed single frame", probedSize, len(frames))
	}
}

func TestDatagramProberFailureFoldsToTransport(t *testing.T) {
	transport := &fakeTransport{max: 1200}
	prober := NewDatagramProber(transport.current)
	prober.NoteProbeSuccess(1405)
	// Transport reports a shrink (it clamps itself on TooLarge).
	transport.max = 1245
	prober.NoteProbeFailure()
	if got := prober.MaxDatagramSize(); got != 1245 {
		t.Fatalf("MaxDatagramSize = %d, want 1245 after probe failure", got)
	}
}

func TestDatagramProberRespectsCeiling(t *testing.T) {
	transport := &fakeTransport{max: 1200}
	prober := NewDatagramProber(transport.current)
	payload := make([]byte, DatagramProbeCeiling) // frame exceeds ceiling
	frames, probedSize, err := prober.EncodeUDPDataFragments(1, 1, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if probedSize != 0 {
		t.Fatalf("probedSize = %d, want 0 beyond ceiling", probedSize)
	}
	if len(frames) < 2 {
		t.Fatalf("frames = %d, want fragmentation beyond ceiling", len(frames))
	}
}

func TestDatagramProberTransportAboveProbedWins(t *testing.T) {
	transport := &fakeTransport{max: 9000}
	prober := NewDatagramProber(transport.current)
	prober.NoteProbeSuccess(1405)
	if got := prober.MaxDatagramSize(); got != 9000 {
		t.Fatalf("MaxDatagramSize = %d, want transport value 9000", got)
	}
	// Large payload fits transport limit: single frame, no probe.
	frames, probedSize, err := prober.EncodeUDPDataFragments(1, 1, make([]byte, 4000))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if probedSize != 0 || len(frames) != 1 {
		t.Fatalf("probedSize=%d frames=%d, want unprobed single frame", probedSize, len(frames))
	}
}

func TestDatagramProberNilCurrent(t *testing.T) {
	prober := NewDatagramProber(nil)
	if got := prober.MaxDatagramSize(); got != 0 {
		t.Fatalf("MaxDatagramSize = %d, want 0 without transport", got)
	}
	// Must not panic: with no transport reading, a packet becomes a probe.
	frames, probedSize, err := prober.EncodeUDPDataFragments(1, 1, make([]byte, 100))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if probedSize != 100+wire.UDPHeaderLen || len(frames) != 1 {
		t.Fatalf("probedSize=%d frames=%d, want probe frame (100+header)/1", probedSize, len(frames))
	}
}
