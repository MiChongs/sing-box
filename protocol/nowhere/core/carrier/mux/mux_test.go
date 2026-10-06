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

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func startPair(t *testing.T) (*Handle, *Incoming, *Handle, *Incoming) {
	t.Helper()
	left, right := net.Pipe()
	client, clientIn, err := Start(left, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	server, serverIn, err := Start(right, DefaultConfig())
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
	left, right := net.Pipe()
	handle, _, err := Start(left, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		handle.Close()
		right.Close()
	})
	return handle, right
}

func TestUnknownFlowDataTearsDownCarrier(t *testing.T) {
	client, raw := startRawCarrier(t)
	payload := []byte("bad")
	header, err := wire.DataMuxHeader(999, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, raw, header, payload)
	waitFor(t, 2*time.Second, client.IsClosed)
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
