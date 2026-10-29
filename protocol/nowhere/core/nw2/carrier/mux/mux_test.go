package mux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

func startPair(t *testing.T) (*Handle, *Incoming, *Handle, *Incoming) {
	t.Helper()
	return startPairConfig(t, DefaultConfig())
}

func startPairConfig(t *testing.T, config Config) (*Handle, *Incoming, *Handle, *Incoming) {
	t.Helper()
	left, right := net.Pipe()
	client, clientIn, err := Start(left, config)
	if err != nil {
		t.Fatal(err)
	}
	server, serverIn, err := Start(right, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, clientIn, server, serverIn
}

func TestStreamRoundTripAndHalfClose(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	outgoing, err := client.OpenStream(7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outgoing.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := outgoing.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	incoming, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(incoming)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("hello")) {
		t.Fatalf("got %q", payload)
	}
}

func TestIdleDeadlineResetsWhenStreamBecomesActive(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	idleDone := make(chan bool, 1)
	go func() {
		idleDone <- client.IdleFor(ctx, 80*time.Millisecond)
	}()
	time.Sleep(40 * time.Millisecond)
	outgoing, err := client.OpenStream(1)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-idleDone:
		t.Fatal("idle completed while a stream was active")
	case <-time.After(50 * time.Millisecond):
	}
	_ = outgoing.Close()
	_ = accepted.Close()
	select {
	case idle := <-idleDone:
		if !idle {
			t.Fatal("expected idle after streams closed")
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("idle did not complete")
	}
}

func TestManySmallWritesCrossCreditWindow(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	outgoing, err := client.OpenStream(8)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accepted, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packet := bytes.Repeat([]byte{0x5a}, 1202)
	const count = 1024
	type readResult struct {
		got []byte
		err error
	}
	done := make(chan readResult, 1)
	go func() {
		got, err := io.ReadAll(io.LimitReader(accepted, int64(len(packet)*count)))
		done <- readResult{got: got, err: err}
	}()
	for i := 0; i < count; i++ {
		if _, err := outgoing.Write(packet); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := outgoing.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatal(res.err)
		}
		if len(res.got) != len(packet)*count {
			t.Fatalf("len=%d want %d", len(res.got), len(packet)*count)
		}
		for _, b := range res.got {
			if b != 0x5a {
				t.Fatal("payload mismatch")
			}
		}
	case <-ctx.Done():
		t.Fatal("credit window stalled")
	}
}

func TestCarrierCloseFailsEveryFlow(t *testing.T) {
	client, _, server, serverIn := startPair(t)
	outgoing, err := client.OpenStream(9)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := serverIn.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	server.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := outgoing.Write([]byte("closed")); err != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("write kept succeeding after peer close")
}

func TestRapidStreamDropDoesNotCloseCarrier(t *testing.T) {
	client, _, server, serverIn := startPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for flowID := uint32(1); flowID <= 200; flowID++ {
		outgoing, err := client.OpenStream(flowID)
		if err != nil {
			t.Fatalf("open %d: %v", flowID, err)
		}
		accepted, err := serverIn.Accept(ctx)
		if err != nil {
			t.Fatalf("accept %d: %v", flowID, err)
		}
		_ = outgoing.Close()
		_ = accepted.Close()
	}
	if client.IsClosed() || server.IsClosed() {
		t.Fatal("carrier closed after rapid open/drop")
	}
}

func TestAcceptReturnsAfterHandleClose(t *testing.T) {
	client, clientIn, _, _ := startPair(t)
	done := make(chan error, 1)
	go func() {
		_, err := clientIn.Accept(context.Background())
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	client.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept returned nil after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after handle close")
	}
}

func TestCloseInterruptsBlockedRead(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	outgoing, err := client.OpenStream(3)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	incoming, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := incoming.Read(make([]byte, 8))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := incoming.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked Read returned nil after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not interrupt blocked Read")
	}
	_ = outgoing.Close()
}

func TestSetReadDeadlineInterruptsBlockedRead(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	outgoing, err := client.OpenStream(4)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	incoming, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := incoming.Read(make([]byte, 8))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := incoming.SetReadDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !isTimeout(err) {
			t.Fatalf("Read error = %v, want timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SetReadDeadline did not interrupt blocked Read")
	}
	_ = outgoing.Close()
	_ = incoming.Close()
}

func TestDataAfterLocalCloseDoesNotTearDownCarrier(t *testing.T) {
	client, _, server, serverIn := startPair(t)
	first, err := client.OpenStream(5)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write(bytes.Repeat([]byte("x"), 1024)); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	_ = accepted.Close()

	second, err := client.OpenStream(6)
	if err != nil {
		t.Fatal(err)
	}
	other, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(other, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ok" {
		t.Fatalf("second stream = %q", got)
	}
	if client.IsClosed() || server.IsClosed() {
		t.Fatal("carrier closed after DATA on a locally closed stream")
	}
	_ = second.Close()
	_ = other.Close()
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func readFrame(t *testing.T, r io.Reader) wire.MuxHeader {
	t.Helper()
	var buf [wire.MuxHeaderLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		t.Fatal(err)
	}
	header, err := wire.DecodeMuxHeader(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n := wire.MuxPayloadLen(header); n > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
			t.Fatal(err)
		}
	}
	return header
}

func writeFrame(t *testing.T, w io.Writer, header wire.MuxHeader, payload []byte) {
	t.Helper()
	encoded, err := wire.EncodeMuxHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(encoded[:]); err != nil {
		t.Fatal(err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

// Flow-state assertions must read flowState fields while holding flowsMu,
// so each check evaluates entirely inside the lock instead of inspecting a
// pointer returned from it.
func (h *Handle) hasFlow(flowID uint32) bool {
	h.shared.flowsMu.Lock()
	defer h.shared.flowsMu.Unlock()
	return h.shared.flows[flowID] != nil
}

func (h *Handle) hasGeneration(flowID uint32, generation uint64) bool {
	return h.shared.isCurrentFlow(flowID, generation)
}

func (h *Handle) flowRetainedLocallyFinished(flowID uint32) bool {
	h.shared.flowsMu.Lock()
	defer h.shared.flowsMu.Unlock()
	flow := h.shared.flows[flowID]
	return flow != nil && flow.localFinSent && flow.localParts == 0
}

func (h *Handle) flowReceiveCredit(flowID uint32) (int, bool) {
	h.shared.flowsMu.Lock()
	defer h.shared.flowsMu.Unlock()
	flow, ok := h.shared.flows[flowID]
	if !ok {
		return 0, false
	}
	return flow.receiveCredit, true
}

func (h *Handle) connRecvUnits() int {
	h.shared.connRecvMu.Lock()
	defer h.shared.connRecvMu.Unlock()
	return h.shared.connRecv
}

// startRawCarrier pairs one Mux handle with a raw test peer that speaks
// bare frames on the other pipe end.
func startRawCarrier(t *testing.T) (*Handle, net.Conn) {
	t.Helper()
	return startRawCarrierConfig(t, DefaultConfig())
}

// startRawCarrierConfig is startRawCarrier with a caller-supplied budget.
func startRawCarrierConfig(t *testing.T, config Config) (*Handle, net.Conn) {
	t.Helper()
	left, right := net.Pipe()
	handle, _, err := Start(left, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		handle.Close()
		right.Close()
	})
	return handle, right
}

func TestUnknownFlowDataResetsOnlyThatFlow(t *testing.T) {
	client, raw := startRawCarrier(t)
	payload := []byte("bad")
	header, err := wire.DataMuxHeader(999, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, header, payload)
	// The unknown flow is reset to the peer; the carrier survives.
	waitFor(t, 2*time.Second, func() bool {
		return readFrameTimeout(t, raw, 50*time.Millisecond, func(h wire.MuxHeader) bool {
			return h.Kind == wire.MuxFrameReset && h.FlowID == 999
		})
	})
	if client.IsClosed() {
		t.Fatal("carrier closed by DATA for an unknown flow")
	}
	openHeader, err := wire.OpenMuxHeader(7, 0)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, openHeader, nil)
	waitFor(t, 2*time.Second, func() bool { return client.ActiveStreams() == 1 })
	if client.IsClosed() {
		t.Fatal("carrier closed after a later OPEN")
	}
}

// readFrameTimeout reads frames until accept reports true, the deadline
// passes, or the raw peer fails.
func readFrameTimeout(t *testing.T, r net.Conn, timeout time.Duration, accept func(wire.MuxHeader) bool) bool {
	t.Helper()
	if err := r.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.SetReadDeadline(time.Time{}) }()
	for {
		var buf [wire.MuxHeaderLen]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return false
		}
		header, err := wire.DecodeMuxHeader(buf[:])
		if err != nil {
			return false
		}
		if n := wire.MuxPayloadLen(header); n > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
				return false
			}
		}
		if accept(header) {
			return true
		}
	}
}

func TestDataAfterFinResetsOnlyThatFlow(t *testing.T) {
	client, raw := startRawCarrier(t)
	openHeader, err := wire.OpenMuxHeader(8, 0)
	if err != nil {
		t.Fatal(err)
	}
	openOther, err := wire.OpenMuxHeader(9, 0)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, openHeader, nil)
	writeFrame(t, raw, openOther, nil)
	waitFor(t, 2*time.Second, func() bool { return client.ActiveStreams() == 2 })

	finHeader, err := wire.FinMuxHeader(8)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, finHeader, nil)
	payload := []byte("late")
	dataHeader, err := wire.DataMuxHeader(8, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, dataHeader, payload)

	gotReset := readFrameTimeout(t, raw, 2*time.Second, func(h wire.MuxHeader) bool {
		return h.Kind == wire.MuxFrameReset && h.FlowID == 8
	})
	if !gotReset {
		t.Fatal("DATA after FIN did not reset the flow")
	}
	if client.IsClosed() {
		t.Fatal("carrier closed by DATA after FIN")
	}
	// The sibling flow still receives DATA.
	maxStream := creditUnits(DefaultConfig().StreamWindowBytes)
	siblingPayload := []byte("ok!")
	sibHeader, err := wire.DataMuxHeader(9, len(siblingPayload))
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, sibHeader, siblingPayload)
	waitFor(t, 2*time.Second, func() bool {
		credit, ok := client.flowReceiveCredit(9)
		return ok && credit == maxStream-1
	})
	if client.IsClosed() {
		t.Fatal("carrier closed by DATA after FIN")
	}
	if client.ActiveStreams() != 1 {
		t.Fatalf("active streams = %d, want 1 (sibling only)", client.ActiveStreams())
	}
}

func TestStreamWindowOverflowResetsOnlyThatFlow(t *testing.T) {
	client, raw := startRawCarrier(t)
	openBad, err := wire.OpenMuxHeader(7, 0)
	if err != nil {
		t.Fatal(err)
	}
	openHealthy, err := wire.OpenMuxHeader(9, 0)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, openBad, nil)
	writeFrame(t, raw, openHealthy, nil)
	waitFor(t, 2*time.Second, func() bool { return client.ActiveStreams() == 2 })

	// Fill the per-flow window exactly, then overflow it by one frame.
	maxStream := creditUnits(DefaultConfig().StreamWindowBytes)
	frames := maxStream * creditUnitBytes / FrameBytes
	dataHeader, err := wire.DataMuxHeader(7, FrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x11}, FrameBytes)
	for i := 0; i < frames; i++ {
		writeFrame(t, raw, dataHeader, payload)
	}
	writeFrame(t, raw, dataHeader, payload)

	if !readFrameTimeout(t, raw, 3*time.Second, func(h wire.MuxHeader) bool {
		return h.Kind == wire.MuxFrameReset && h.FlowID == 7
	}) {
		t.Fatal("per-flow window overflow did not reset the flow")
	}
	if client.IsClosed() {
		t.Fatal("carrier closed by per-flow window overflow")
	}
	if client.hasFlow(7) {
		t.Fatal("flow state survived a per-flow window overflow")
	}
	// The sibling flow still admits DATA.
	sibHeader, err := wire.DataMuxHeader(9, 1)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, sibHeader, []byte{0x42})
	waitFor(t, 2*time.Second, func() bool {
		credit, ok := client.flowReceiveCredit(9)
		return ok && credit == maxStream-1
	})
	if client.IsClosed() {
		t.Fatal("carrier closed after a sibling flowed past a resetted flow")
	}
}

func TestOpenStreamWindowOverflowResetsTheNewFlow(t *testing.T) {
	client, raw := startRawCarrier(t)
	openHeader, err := wire.OpenMuxHeader(7, 0xffff)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, openHeader, nil)
	if !readFrameTimeout(t, raw, 2*time.Second, func(h wire.MuxHeader) bool {
		return h.Kind == wire.MuxFrameReset && h.FlowID == 7
	}) {
		t.Fatal("OPEN with an overflowing window extension did not reset the flow")
	}
	if client.IsClosed() {
		t.Fatal("carrier closed by OPEN window extension overflow")
	}
	if client.hasFlow(7) {
		t.Fatal("flow state survived an OPEN window extension overflow")
	}
}

func TestConnectionReceiveOverflowIsCarrierFatal(t *testing.T) {
	client, raw := startRawCarrier(t)
	openA, err := wire.OpenMuxHeader(7, 0)
	if err != nil {
		t.Fatal(err)
	}
	openB, err := wire.OpenMuxHeader(9, 0)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, openA, nil)
	writeFrame(t, raw, openB, nil)
	waitFor(t, 2*time.Second, func() bool { return client.ActiveStreams() == 2 })

	// Fill both stream windows to the connection window without a reader
	// draining, then overflow the connection window. The raw peer owns the
	// pipe, so every frame is written in order.
	perStream := creditUnits(DefaultConfig().StreamWindowBytes)
	frames := perStream * creditUnitBytes / FrameBytes
	dataHeader, err := wire.DataMuxHeader(7, FrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	dataHeader9, err := wire.DataMuxHeader(9, FrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x22}, FrameBytes)
	for i := 0; i < frames; i++ {
		writeFrame(t, raw, dataHeader, payload)
		writeFrame(t, raw, dataHeader9, payload)
	}
	overflow, err := wire.DataMuxHeader(7, 1)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, overflow, []byte{0})
	select {
	case <-client.Closed():
	case <-time.After(3 * time.Second):
		t.Fatal("connection receive overflow did not close the carrier")
	}
	if reason := client.CloseReason(); reason != CloseReasonProtocolViolation {
		t.Fatalf("close reason = %v, want protocol error", reason)
	}
}

func TestResetDiscardsQueuedDataAndRestoresConnectionCredit(t *testing.T) {
	client, raw := startRawCarrier(t)
	stream, err := client.OpenStream(7)
	if err != nil {
		t.Fatal(err)
	}
	for {
		if header := readFrame(t, raw); header.Kind == wire.MuxFrameOpen && header.FlowID == 7 {
			break
		}
	}
	maxConn := creditUnits(DefaultConfig().ConnectionWindowBytes)
	// Queue DATA the application never reads, then reset the flow.
	payload := bytes.Repeat([]byte{0x33}, 4096)
	dataHeader, err := wire.DataMuxHeader(7, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, dataHeader, payload)
	waitFor(t, 2*time.Second, func() bool { return client.connRecvUnits() == maxConn-4 })

	resetHeader, err := wire.ResetMuxHeader(7)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, resetHeader, nil)
	waitFor(t, 2*time.Second, func() bool { return !client.hasFlow(7) })
	// Buffered DATA returns its connection credit exactly once.
	waitFor(t, 2*time.Second, func() bool {
		pending := int(client.shared.pendingConn.Load())
		return client.connRecvUnits()+pending >= maxConn
	})
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4)
		_, err := stream.Read(buf)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errReset) {
			t.Fatalf("read after reset = %v, want mux flow reset", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reset did not wake the blocked reader")
	}
	if client.IsClosed() {
		t.Fatal("carrier closed by flow reset")
	}
}

func TestReusedFlowIDIsolatedFromStaleStream(t *testing.T) {
	client, raw := startRawCarrier(t)
	stale, err := client.OpenStream(7)
	if err != nil {
		t.Fatal(err)
	}
	for {
		if header := readFrame(t, raw); header.Kind == wire.MuxFrameOpen && header.FlowID == 7 {
			break
		}
	}
	// Peer RESET retires the flow; reopening the ID gets a new generation.
	resetHeader, err := wire.ResetMuxHeader(7)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, resetHeader, nil)
	waitFor(t, 2*time.Second, func() bool { return !client.hasFlow(7) })

	replacement, err := client.OpenStream(7)
	if err != nil {
		t.Fatal(err)
	}
	for {
		if header := readFrame(t, raw); header.Kind == wire.MuxFrameOpen && header.FlowID == 7 {
			break
		}
	}
	if _, err := stale.Write([]byte("stale")); !errors.Is(err, errClosed) {
		t.Fatalf("stale write = %v, want closed", err)
	}
	if err := stale.CloseWrite(); !errors.Is(err, errClosed) {
		t.Fatalf("stale CloseWrite = %v, want closed", err)
	}
	_ = stale.Close()
	if client.ActiveStreams() != 1 {
		t.Fatalf("active streams = %d, want 1 (replacement only)", client.ActiveStreams())
	}
	if !client.hasFlow(7) {
		t.Fatal("replacement flow lost its state")
	}
	// The replacement still works and the stale FIN never lands.
	if _, err := replacement.Write([]byte("fresh")); err != nil {
		t.Fatal(err)
	}
	if !readFrameTimeout(t, raw, 2*time.Second, func(h wire.MuxHeader) bool {
		return h.Kind == wire.MuxFrameData && h.FlowID == 7
	}) {
		t.Fatal("replacement stream could not write")
	}
	_ = replacement.Close()
}

// startQuietRawCarrier is startRawCarrier with a configuration whose initial
// connection WINDOW batch is empty, so the writer stays idle and read-loop
// close reasons are deterministic.
func startQuietRawCarrier(t *testing.T) (*Handle, net.Conn) {
	t.Helper()
	return startRawCarrierConfig(t, Config{
		StreamWindowBytes:     BaseStreamWindowBytes,
		ConnectionWindowBytes: BaseConnectionWindowBytes,
		MaxStreams:            64,
		OutboundFrames:        64,
	})
}

// startQuietPair pairs two handles configured so neither side queues an
// initial connection WINDOW batch: the writer stays idle, which makes
// read-loop close reasons deterministic.
func startQuietPair(t *testing.T) (*Handle, *Incoming, *Handle, *Incoming) {
	t.Helper()
	return startPairConfig(t, Config{
		StreamWindowBytes:     BaseStreamWindowBytes,
		ConnectionWindowBytes: BaseConnectionWindowBytes,
		MaxStreams:            64,
		OutboundFrames:        64,
	})
}

// drainFrames consumes frames from a raw peer until the pipe fails.
func drainFrames(raw net.Conn) {
	for {
		var buf [wire.MuxHeaderLen]byte
		if _, err := io.ReadFull(raw, buf[:]); err != nil {
			return
		}
		header, err := wire.DecodeMuxHeader(buf[:])
		if err != nil {
			return
		}
		if n := wire.MuxPayloadLen(header); n > 0 {
			if _, err := io.CopyN(io.Discard, raw, int64(n)); err != nil {
				return
			}
		}
	}
}

func TestPendingResetReservesFlowID(t *testing.T) {
	client, raw := startRawCarrier(t)
	// Nobody reads the raw end, so the queued RESET stays pending and the
	// flow ID remains reserved until the frame reaches the wire.
	payload := []byte("x")
	dataHeader, err := wire.DataMuxHeader(55, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, dataHeader, payload)
	waitFor(t, 2*time.Second, func() bool {
		client.shared.pendingResetsMu.Lock()
		defer client.shared.pendingResetsMu.Unlock()
		_, pending := client.shared.pendingResets[55]
		return pending
	})
	if client.CanOpenFlow(55) {
		t.Fatal("pending RESET did not reserve the flow ID")
	}
	if _, err := client.PrepareStream(55); !errors.Is(err, errFlowExists) {
		t.Fatalf("PrepareStream on a reserved ID = %v, want flow exists", err)
	}
	// Draining the wire lets the RESET land and releases the ID. The batch
	// can carry WINDOW updates behind the RESET, so the drain keeps running
	// until the reservation is released.
	go drainFrames(raw)
	waitFor(t, 2*time.Second, func() bool {
		client.shared.pendingResetsMu.Lock()
		defer client.shared.pendingResetsMu.Unlock()
		_, pending := client.shared.pendingResets[55]
		return !pending
	})
	if !client.CanOpenFlow(55) {
		t.Fatal("flow ID stayed reserved after the RESET was written")
	}
}

func TestCloseReasonFirstWins(t *testing.T) {
	client, _, _, _ := startPair(t)
	// Idle retirement and application close race; the first reason wins.
	client.CloseWithReason(CloseReasonIdleTimeout)
	client.CloseWithReason(CloseReasonApplication)
	client.Close()
	if reason := client.CloseReason(); reason != CloseReasonIdleTimeout {
		t.Fatalf("close reason = %v, want idle timeout", reason)
	}
}

func TestPeerEOFCloseReason(t *testing.T) {
	// A quiet pair keeps both writers idle, so the peer close is observed by
	// the reader loop only.
	client, _, server, _ := startQuietPair(t)
	server.Close()
	select {
	case <-client.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("carrier did not close after peer EOF")
	}
	if reason := client.CloseReason(); reason != CloseReasonPeerEof {
		t.Fatalf("close reason = %v, want unexpected EOF", reason)
	}
}

func TestApplicationCloseReason(t *testing.T) {
	client, _, _, _ := startPair(t)
	client.Close()
	if got := client.CloseReason(); got != CloseReasonApplication {
		t.Fatalf("close reason = %v, want application closed", got)
	}
	if got := client.CloseReason().String(); got != "application closed" {
		t.Fatalf("reason text = %q", got)
	}
}

func TestMalformedFrameClosesCarrierWithProtocolViolation(t *testing.T) {
	client, raw := startRawCarrier(t)
	// A header byte no frame kind claims is a protocol violation.
	if _, err := raw.Write([]byte{0x7f, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("malformed frame did not close the carrier")
	}
	if reason := client.CloseReason(); reason != CloseReasonProtocolViolation {
		t.Fatalf("close reason = %v, want protocol error", reason)
	}
}

func TestTruncatedFrameClosesCarrier(t *testing.T) {
	client, raw := startQuietRawCarrier(t)
	// A DATA header that promises a payload the peer never finishes.
	dataHeader, err := wire.DataMuxHeader(7, 16)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := wire.EncodeMuxHeader(dataHeader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write(append(encoded[:], 1, 2, 3, 4, 5, 6, 7, 8)); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("truncated frame did not close the carrier")
	}
	if reason := client.CloseReason(); reason != CloseReasonPeerEof {
		t.Fatalf("close reason = %v, want unexpected EOF", reason)
	}
}

// blockWriter occupies every outbound slot so later frame enqueues block. It
// relies on the writer being stuck writing to the unread raw pipe, which is
// what startRawCarrier guarantees.
func blockWriter(h *Handle) {
	for i := 0; i <= cap(h.shared.dataTx); i++ {
		select {
		case h.shared.dataTx <- outbound{}:
		case <-h.shared.closedCh:
			return
		}
	}
}

// startBlockedRawCarrier returns a handle whose writer can never drain its
// outbound queue, so an OPEN enqueue blocks until the caller's context ends.
func startBlockedRawCarrier(t *testing.T, config Config) *Handle {
	t.Helper()
	client, _ := startRawCarrierConfig(t, config)
	go blockWriter(client)
	waitFor(t, 2*time.Second, func() bool {
		return len(client.shared.dataTx) == cap(client.shared.dataTx)
	})
	return client
}

func TestCancelledOpenRollsBackReservation(t *testing.T) {
	config := DefaultConfig()
	config.OutboundFrames = 1
	client := startBlockedRawCarrier(t, config)

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := client.PrepareStream(3)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	opening := make(chan error, 1)
	go func() { opening <- client.OpenPrepared(ctx, stream) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-opening:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("OpenPrepared = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled OpenPrepared did not return")
	}
	if client.hasFlow(3) {
		t.Fatal("cancelled open leaked the flow reservation")
	}
	if client.IsClosed() {
		t.Fatal("cancelled open closed the carrier")
	}
	// The flow ID is reusable after the rollback.
	replacement, err := client.PrepareStream(3)
	if err != nil {
		t.Fatal(err)
	}
	if !client.hasGeneration(3, replacement.generation) {
		t.Fatal("flow ID was not reusable after the rollback")
	}
}

func TestCancelledOpenRollbackPreservesReusedFlowID(t *testing.T) {
	config := DefaultConfig()
	config.OutboundFrames = 1
	client := startBlockedRawCarrier(t, config)

	stale, err := client.PrepareStream(3)
	if err != nil {
		t.Fatal(err)
	}
	staleGeneration := stale.generation
	ctx, cancel := context.WithCancel(context.Background())
	opening := make(chan error, 1)
	go func() { opening <- client.OpenPrepared(ctx, stale) }()
	time.Sleep(20 * time.Millisecond)
	// Retire and reuse the ID while the open is still blocked.
	client.shared.removeCurrentFlow(3, staleGeneration)
	replacement, err := client.PrepareStream(3)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	if err := <-opening; !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenPrepared = %v, want context.Canceled", err)
	}
	if !client.hasGeneration(3, replacement.generation) {
		t.Fatal("stale rollback removed the reused flow")
	}
}

func TestFinHalfCloseKeepsReverseDirection(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	outgoing, err := client.OpenStream(11)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := outgoing.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := outgoing.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	incoming, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(incoming)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "ping" {
		t.Fatalf("payload = %q", payload)
	}
	if _, err := incoming.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(outgoing, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong" {
		t.Fatalf("reverse data = %q", got)
	}
	_ = outgoing.Close()
	_ = incoming.Close()
}

func TestAbandonedReadHalfReturnsFullCredit(t *testing.T) {
	client, _, server, serverIn := startPair(t)
	outgoing, err := client.OpenStream(12)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	incoming, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := outgoing.CloseRead(); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x33}, 4096)
	if _, err := incoming.Write(payload); err != nil {
		t.Fatal(err)
	}
	maxStream := creditUnits(DefaultConfig().StreamWindowBytes)
	waitFor(t, 2*time.Second, func() bool {
		credit, ok := client.flowReceiveCredit(12)
		return ok && credit == maxStream
	})
	if client.IsClosed() || server.IsClosed() {
		t.Fatal("carrier closed after DATA on an abandoned read half")
	}
	_ = outgoing.Close()
	_ = incoming.Close()
}

func TestDiscardedDataRetainsFlowUntilPeerFin(t *testing.T) {
	client, raw := startRawCarrier(t)
	stream, err := client.OpenStream(5)
	if err != nil {
		t.Fatal(err)
	}
	// Skip control frames until the OPEN for flow 5 surfaces.
	for {
		if header := readFrame(t, raw); header.Kind == wire.MuxFrameOpen && header.FlowID == 5 {
			break
		}
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	// Drain frames until the FIN surfaces; the write only completes once
	// the raw peer reads it.
	frames := make(chan wire.MuxHeader, 8)
	go func() {
		defer close(frames)
		for {
			header, err := wire.ReadMuxHeader(raw)
			if err != nil {
				return
			}
			if n := wire.MuxPayloadLen(header); n > 0 {
				if _, err := io.CopyN(io.Discard, raw, int64(n)); err != nil {
					return
				}
			}
			frames <- header
			if header.Kind == wire.MuxFrameFin {
				return
			}
		}
	}()
	for header := range frames {
		if header.Kind == wire.MuxFrameFin && header.FlowID == 5 {
			break
		}
	}
	// The FIN is on the wire while the flow stays retained: the peer has
	// not half-closed yet, so protocol state survives for reverse DATA.
	waitFor(t, 2*time.Second, func() bool {
		return client.flowRetainedLocallyFinished(5)
	})
	if client.CanOpenFlow(5) {
		t.Fatal("retained flow state still admits the same flow ID")
	}

	payload := bytes.Repeat([]byte{0x77}, 2048)
	dataHeader, err := wire.DataMuxHeader(5, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, dataHeader, payload)

	maxStream := creditUnits(DefaultConfig().StreamWindowBytes)
	maxConn := creditUnits(DefaultConfig().ConnectionWindowBytes)
	waitFor(t, 2*time.Second, func() bool {
		credit, ok := client.flowReceiveCredit(5)
		return ok && credit == maxStream-2
	})
	if got := client.connRecvUnits(); got != maxConn {
		t.Fatalf("connection credit = %d, want full %d", got, maxConn)
	}
	if client.IsClosed() {
		t.Fatal("carrier closed by discarded DATA")
	}

	finHeader, err := wire.FinMuxHeader(5)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, finHeader, nil)
	waitFor(t, 2*time.Second, func() bool {
		return !client.hasFlow(5)
	})
	if !client.CanOpenFlow(5) {
		t.Fatal("retired flow state still refuses the flow ID")
	}
	if client.IsClosed() {
		t.Fatal("carrier closed after flow retirement")
	}
}

func TestResetRemovesFlowImmediately(t *testing.T) {
	client, raw := startRawCarrier(t)
	stream, err := client.OpenStream(6)
	if err != nil {
		t.Fatal(err)
	}
	for {
		if header := readFrame(t, raw); header.Kind == wire.MuxFrameOpen && header.FlowID == 6 {
			break
		}
	}
	resetHeader, err := wire.ResetMuxHeader(6)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, resetHeader, nil)
	waitFor(t, 2*time.Second, func() bool {
		return !client.hasFlow(6)
	})
	if client.IsClosed() {
		t.Fatal("carrier closed by peer RESET")
	}
	if _, err := stream.Write([]byte("after")); err == nil {
		t.Fatal("write after RESET succeeded")
	}
}
