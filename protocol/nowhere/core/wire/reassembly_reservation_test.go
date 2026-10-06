package wire

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingReservation struct {
	once     sync.Once
	released *atomic.Int32
}

func (r *countingReservation) Release() {
	r.once.Do(func() { r.released.Add(1) })
}

func TestReassemblyReservationTransfersOnCompletion(t *testing.T) {
	reassembler := mustNewDatagramReassembler(t, DefaultReassemblyConfig())
	var released atomic.Int32
	reserveCalls := 0
	reserve := func(n int) (ByteReservation, bool) {
		reserveCalls++
		if n != 2 {
			t.Fatalf("reservation = %d, want 2", n)
		}
		return &countingReservation{released: &released}, true
	}
	first := UDPFragment{PacketID: 1, FragmentIndex: 0, FragmentCount: 2, TotalLen: 2, Payload: []byte("a")}
	second := UDPFragment{PacketID: 1, FragmentIndex: 1, FragmentCount: 2, TotalLen: 2, Payload: []byte("b")}
	if outcome := reassembler.PushWithReservation(1, first, testNow, reserve); outcome.Done {
		t.Fatal("first fragment completed")
	}
	outcome := reassembler.PushWithReservation(1, second, testNow, reserve)
	if !outcome.Done || string(outcome.Payload) != "ab" || outcome.Reservation == nil {
		t.Fatalf("completion = %+v", outcome)
	}
	if reserveCalls != 1 || released.Load() != 0 {
		t.Fatalf("reserve calls=%d released=%d", reserveCalls, released.Load())
	}
	outcome.Reservation.Release()
	outcome.Reservation.Release()
	if released.Load() != 1 {
		t.Fatalf("released = %d", released.Load())
	}
}

func TestReassemblyReservationReleasesOnConflictExpiryAndClear(t *testing.T) {
	for _, action := range []string{"conflict", "expire", "clear"} {
		t.Run(action, func(t *testing.T) {
			cfg := DefaultReassemblyConfig()
			cfg.TTL = time.Second
			reassembler := mustNewDatagramReassembler(t, cfg)
			var released atomic.Int32
			reserve := func(int) (ByteReservation, bool) {
				return &countingReservation{released: &released}, true
			}
			first := UDPFragment{PacketID: 1, FragmentIndex: 0, FragmentCount: 2, TotalLen: 2, Payload: []byte("a")}
			reassembler.PushWithReservation(1, first, testNow, reserve)
			switch action {
			case "conflict":
				conflict := first
				conflict.FragmentCount = 3
				conflict.TotalLen = 3
				reassembler.PushWithReservation(1, conflict, testNow, reserve)
			case "expire":
				reassembler.Expire(testNow.Add(2 * time.Second))
			case "clear":
				reassembler.Clear()
			}
			if released.Load() != 1 {
				t.Fatalf("released = %d", released.Load())
			}
		})
	}
}

func TestReassemblyNormalPushCopiesFragment(t *testing.T) {
	reassembler := mustNewDatagramReassembler(t, DefaultReassemblyConfig())
	payload := []byte("a")
	first := UDPFragment{PacketID: 1, FragmentIndex: 0, FragmentCount: 2, TotalLen: 2, Payload: payload}
	reassembler.Push(1, first, testNow)
	payload[0] = 'z'
	outcome := reassembler.Push(1, UDPFragment{
		PacketID: 1, FragmentIndex: 1, FragmentCount: 2, TotalLen: 2, Payload: []byte("b"),
	}, testNow)
	if !outcome.Done || string(outcome.Payload) != "ab" {
		t.Fatalf("payload = %q", outcome.Payload)
	}
}
