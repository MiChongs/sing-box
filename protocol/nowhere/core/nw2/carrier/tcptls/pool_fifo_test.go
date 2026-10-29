package tcptls

import (
	"testing"
)

func TestIdlePoolUsesOldestLaneFirst(t *testing.T) {
	cfg := boundTestConfig(t, testTCPDialer{})
	pool, err := NewTCPPool(cfg, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	first := &warmConn{carrier: newCarrierInfo(nil)}
	second := &warmConn{carrier: newCarrierInfo(nil)}
	third := &warmConn{carrier: newCarrierInfo(nil)}
	pool.mu.Lock()
	pool.idle = append(pool.idle, first, second, third)
	pool.mu.Unlock()

	got := make([]*warmConn, 0, 3)
	for i := 0; i < 3; i++ {
		pool.mu.Lock()
		if len(pool.idle) == 0 {
			pool.mu.Unlock()
			t.Fatal("idle pool empty early")
		}
		wc := pool.idle[0]
		pool.idle = pool.idle[1:]
		pool.mu.Unlock()
		got = append(got, wc)
	}
	if got[0] != first || got[1] != second || got[2] != third {
		t.Fatalf("FIFO order broken: got %p %p %p want %p %p %p",
			got[0], got[1], got[2], first, second, third)
	}
}
