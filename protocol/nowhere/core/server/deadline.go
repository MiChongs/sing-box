package server

import (
	"os"
	"sync"
	"time"
)

type deadlineSignal struct {
	mu    sync.Mutex
	timer *time.Timer
	ch    chan struct{}
}

func (d *deadlineSignal) set(deadline time.Time) {
	d.mu.Lock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.ch = nil
	if !deadline.IsZero() {
		d.ch = make(chan struct{})
		delay := time.Until(deadline)
		if delay <= 0 {
			close(d.ch)
		} else {
			ch := d.ch
			d.timer = time.AfterFunc(delay, func() { close(ch) })
		}
	}
	d.mu.Unlock()
}

func (d *deadlineSignal) stop() {
	d.mu.Lock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.ch = nil
	d.mu.Unlock()
}

func (d *deadlineSignal) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ch
}

func deadlineError() error { return os.ErrDeadlineExceeded }
