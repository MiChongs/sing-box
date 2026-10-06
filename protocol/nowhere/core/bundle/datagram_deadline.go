package bundle

import (
	"net"
	"os"
	"sync"
	"time"
)

var errDatagramDeadline = os.ErrDeadlineExceeded

// datagramDeadline wakes blocked operations when a deadline changes or expires.
// Close is terminal: it stops the timer and permanently closes the current signal.
type datagramDeadline struct {
	mu       sync.Mutex
	at       time.Time
	signal   chan struct{}
	signaled bool
	timer    *time.Timer
	closed   bool
}

func newDatagramDeadline() *datagramDeadline {
	return &datagramDeadline{signal: make(chan struct{})}
}

func (d *datagramDeadline) set(at time.Time) error {
	if d == nil {
		return net.ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return net.ErrClosed
	}
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.signalLocked()
	d.at = at
	d.signal = make(chan struct{})
	d.signaled = false
	if !at.IsZero() {
		delay := time.Until(at)
		if delay <= 0 {
			d.signalLocked()
		} else {
			signal := d.signal
			d.timer = time.AfterFunc(delay, func() {
				d.mu.Lock()
				if d.signal == signal {
					d.signalLocked()
					d.timer = nil
				}
				d.mu.Unlock()
			})
		}
	}
	return nil
}

func (d *datagramDeadline) snapshot() (time.Time, <-chan struct{}, bool) {
	if d == nil {
		return time.Time{}, nil, false
	}
	d.mu.Lock()
	at, signal, closed := d.at, d.signal, d.closed
	d.mu.Unlock()
	return at, signal, closed
}

func (d *datagramDeadline) expired() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	at := d.at
	d.mu.Unlock()
	return deadlineExpired(at)
}

func (d *datagramDeadline) close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.at = time.Time{}
	d.signalLocked()
}

func (d *datagramDeadline) signalLocked() {
	if !d.signaled {
		close(d.signal)
		d.signaled = true
	}
}

func deadlineExpired(at time.Time) bool {
	return !at.IsZero() && !time.Now().Before(at)
}
