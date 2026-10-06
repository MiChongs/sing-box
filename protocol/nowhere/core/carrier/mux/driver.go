package mux

import (
	"io"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func (s *shared) runReader(r io.Reader) {
	_ = s.readLoop(r)
	s.close()
}

func (s *shared) readLoop(r io.Reader) error {
	var headerBuf [wire.MuxHeaderLen]byte
	for {
		if _, err := io.ReadFull(r, headerBuf[:]); err != nil {
			return err
		}
		header, err := wire.DecodeMuxHeader(headerBuf[:])
		if err != nil {
			return err
		}
		payloadLen := wire.MuxPayloadLen(header)
		var payload []byte
		if payloadLen > 0 {
			payload = make([]byte, payloadLen)
			if _, err := io.ReadFull(r, payload); err != nil {
				return err
			}
		}
		switch header.Kind {
		case wire.MuxFrameOpen:
			if err := s.receiveOpen(header); err != nil {
				return err
			}
		case wire.MuxFrameData:
			if err := s.receiveData(header, payload); err != nil {
				return err
			}
		case wire.MuxFrameWindow:
			if err := s.receiveWindow(header); err != nil {
				return err
			}
		case wire.MuxFrameFin, wire.MuxFrameReset:
			s.receiveClose(header)
		}
	}
}

func (s *shared) receiveOpen(header wire.MuxHeader) error {
	stream, err := s.insertFlow(header.FlowID, true)
	if err != nil {
		return err
	}
	extra := int(header.Value)
	if extra != 0 {
		s.flowsMu.Lock()
		flow := s.flows[header.FlowID]
		if flow == nil {
			s.flowsMu.Unlock()
			return errClosed
		}
		if flow.sendCredit.availablePermits()+extra > creditUnits(maxStreamWindowBytes) {
			s.flowsMu.Unlock()
			return errWindowOverflow
		}
		flow.sendCredit.add(extra)
		s.flowsMu.Unlock()
	}
	return s.offerIncoming(stream)
}

func (s *shared) receiveData(header wire.MuxHeader, payload []byte) error {
	charge := frameCharge(len(payload))
	target, ch, err := s.admitReceive(header.FlowID, charge)
	if err != nil {
		return err
	}
	switch target {
	case receiveDiscard:
		// Keep the per-stream debit so a peer cannot send an unbounded
		// amount after the application has finished with this flow.
		s.releaseConnReceive(charge)
		return nil
	case receiveAbandoned:
		// The local read half was abandoned while its writer is still
		// live. Return credit for the discarded bytes without killing
		// other flows.
		s.releaseReceive(header.FlowID, charge)
		return nil
	}
	select {
	case <-s.closedCh:
		return errClosed
	case ch <- inbound{kind: inboundData, payload: payload, charge: charge}:
		return nil
	}
}

func (s *shared) receiveClose(header wire.MuxHeader) {
	if header.Kind == wire.MuxFrameReset {
		if flow := s.removeFlow(header.FlowID); flow != nil {
			select {
			case flow.inbound <- inbound{kind: inboundReset}:
			case <-s.closedCh:
			}
		}
		return
	}
	s.flowsMu.Lock()
	flow := s.flows[header.FlowID]
	var ch chan inbound
	var removed *flowState
	if flow != nil && !flow.remoteFin {
		if flow.localParts == 0 && flow.localFinSent {
			// Both application halves are gone and our FIN reached the
			// wire; nothing can legitimately follow on this flow.
			delete(s.flows, header.FlowID)
			removed = flow
		} else {
			flow.remoteFin = true
			ch = flow.inbound
		}
	}
	s.flowsMu.Unlock()
	if removed != nil {
		removed.sendCredit.close()
		removed.sendSlot.close()
	}
	s.notifyActive()
	if ch != nil {
		select {
		case ch <- inbound{kind: inboundFin}:
		case <-s.closedCh:
		}
	}
}

func (s *shared) receiveWindow(header wire.MuxHeader) error {
	credit := int(header.Value)
	if header.FlowID == 0 {
		if s.connSend.availablePermits()+credit > creditUnits(maxConnectionWindowBytes) {
			return errWindowOverflow
		}
		s.connSend.add(credit)
		if n := s.connSend.availablePermits(); int64(n) > s.connSendPeak.Load() {
			s.connSendPeak.Store(int64(n))
		}
		return nil
	}
	s.flowsMu.Lock()
	flow := s.flows[header.FlowID]
	if flow == nil {
		s.flowsMu.Unlock()
		return nil
	}
	if flow.sendCredit.availablePermits()+credit > creditUnits(maxStreamWindowBytes) {
		s.flowsMu.Unlock()
		return errWindowOverflow
	}
	flow.sendCredit.add(credit)
	s.flowsMu.Unlock()
	return nil
}

func (s *shared) runWriter(w io.Writer) {
	_ = s.writeLoop(w)
	s.close()
}

func (s *shared) writeLoop(w io.Writer) error {
	for {
		if s.closed.Load() {
			return errClosed
		}
		select {
		case <-s.closedCh:
			return errClosed
		case <-s.control:
			if err := s.writePendingWindows(w); err != nil {
				return err
			}
		default:
		}
		select {
		case <-s.closedCh:
			return errClosed
		case <-s.control:
			if err := s.writePendingWindows(w); err != nil {
				return err
			}
		case item, ok := <-s.dataTx:
			if !ok {
				return errClosed
			}
			if err := s.writeItem(w, item); err != nil {
				return err
			}
		}
	}
}

func (s *shared) writeItem(w io.Writer, item outbound) error {
	if item.flushed != nil && item.header.Kind == 0 && len(item.payload) == 0 {
		err := flushWriter(w)
		select {
		case item.flushed <- err:
		default:
		}
		return err
	}
	encoded, err := wire.EncodeMuxHeader(item.header)
	if err != nil {
		return err
	}
	if err := writeFull(w, encoded[:]); err != nil {
		return err
	}
	if len(item.payload) > 0 {
		if err := writeFull(w, item.payload); err != nil {
			return err
		}
	}
	if item.header.Kind == wire.MuxFrameFin {
		// The FIN is on the wire; retained state for this flow may retire.
		s.finishLocalFin(item.header.FlowID)
	}
	if item.release != nil {
		item.release.add(1)
	}
	return nil
}

func (s *shared) writePendingWindows(w io.Writer) error {
	connection := int(s.pendingConn.Swap(0))
	s.readyMu.Lock()
	ready := append([]uint32(nil), s.ready...)
	s.ready = s.ready[:0]
	s.readyMu.Unlock()

	var frames []byte
	var err error
	frames, err = appendWindows(frames, 0, connection)
	if err != nil {
		return err
	}
	s.flowsMu.Lock()
	for _, flowID := range ready {
		flow := s.flows[flowID]
		if flow == nil {
			continue
		}
		credit := flow.pendingReceive
		flow.pendingReceive = 0
		flow.windowQueued = false
		if credit == 0 {
			continue
		}
		frames, err = appendWindows(frames, flowID, credit)
		if err != nil {
			s.flowsMu.Unlock()
			return err
		}
	}
	s.flowsMu.Unlock()
	if len(frames) == 0 {
		return nil
	}
	return writeFull(w, frames)
}

func appendWindows(encoded []byte, flowID uint32, credit int) ([]byte, error) {
	for credit > 0 {
		delta := credit
		if delta > 0xffff {
			delta = 0xffff
		}
		header, err := wire.WindowMuxHeader(flowID, delta)
		if err != nil {
			return encoded, err
		}
		frame, err := wire.EncodeMuxHeader(header)
		if err != nil {
			return encoded, err
		}
		encoded = append(encoded, frame[:]...)
		credit -= delta
	}
	return encoded, nil
}

func (s *shared) sendData(st *Stream, payload []byte) error {
	charge := frameCharge(len(payload))
	s.flowsMu.Lock()
	flow := s.flows[st.flowID]
	s.flowsMu.Unlock()
	if flow == nil {
		return errClosed
	}
	if err := st.acquireCredits(flow, charge); err != nil {
		return err
	}
	wait, _, closed := st.writeSnapshot()
	if closed {
		flow.sendSlot.add(1)
		flow.sendCredit.add(charge)
		s.connSend.add(charge)
		return errClosed
	}
	header, err := wire.DataMuxHeader(st.flowID, len(payload))
	if err != nil {
		flow.sendSlot.add(1)
		flow.sendCredit.add(charge)
		s.connSend.add(charge)
		return err
	}
	copied := append([]byte(nil), payload...)
	if err := s.sendOutbound(outbound{header: header, payload: copied, release: flow.sendSlot}, wait); err != nil {
		flow.sendSlot.add(1)
		flow.sendCredit.add(charge)
		s.connSend.add(charge)
		return err
	}
	return nil
}

func (st *Stream) acquireCredits(flow *flowState, charge int) error {
	for {
		if err := st.checkWriteDeadline(); err != nil {
			return err
		}
		wait, deadline, closed := st.writeSnapshot()
		if closed {
			return errClosed
		}
		if err := flow.sendSlot.acquireUntil(1, st.shared.closedCh, wait, deadline); err != nil {
			if err == errInterrupted {
				continue
			}
			return err
		}
		break
	}
	for {
		if err := st.checkWriteDeadline(); err != nil {
			flow.sendSlot.add(1)
			return err
		}
		wait, deadline, closed := st.writeSnapshot()
		if closed {
			flow.sendSlot.add(1)
			return errClosed
		}
		if err := flow.sendCredit.acquireUntil(charge, st.shared.closedCh, wait, deadline); err != nil {
			if err == errInterrupted {
				continue
			}
			flow.sendSlot.add(1)
			return err
		}
		break
	}
	for {
		if err := st.checkWriteDeadline(); err != nil {
			flow.sendSlot.add(1)
			flow.sendCredit.add(charge)
			return err
		}
		wait, deadline, closed := st.writeSnapshot()
		if closed {
			flow.sendSlot.add(1)
			flow.sendCredit.add(charge)
			return errClosed
		}
		if err := st.shared.connSend.acquireUntil(charge, st.shared.closedCh, wait, deadline); err != nil {
			if err == errInterrupted {
				continue
			}
			flow.sendSlot.add(1)
			flow.sendCredit.add(charge)
			return err
		}
		return nil
	}
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func flushWriter(w io.Writer) error {
	type flusher interface{ Flush() error }
	if f, ok := w.(flusher); ok {
		return f.Flush()
	}
	return nil
}
