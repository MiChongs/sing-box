package mux

import (
	"os"
	"sync"
	"time"
)

type semaphore struct {
	mu        sync.Mutex
	available int
	closed    bool
	waiters   []chan struct{}
}

func newSemaphore(n int) *semaphore {
	return &semaphore{available: n}
}

func (s *semaphore) acquire(n int, stop <-chan struct{}) error {
	return s.acquireUntil(n, stop, nil, time.Time{})
}

func (s *semaphore) acquireUntil(n int, stopA, stopB <-chan struct{}, deadline time.Time) error {
	if n < 0 {
		n = 0
	}
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return errClosed
		}
		if s.available >= n {
			s.available -= n
			s.mu.Unlock()
			return nil
		}
		ch := make(chan struct{})
		s.waiters = append(s.waiters, ch)
		s.mu.Unlock()

		timer, timeout := deadlineChan(deadline)
		var err error
		select {
		case <-ch:
		case <-stopA:
			err = errClosed
		case <-stopB:
			err = errInterrupted
		case <-timeout:
			err = os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
		if err != nil {
			return err
		}
	}
}

func (s *semaphore) add(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	s.available += n
	s.wake()
	s.mu.Unlock()
}

func (s *semaphore) availablePermits() int {
	s.mu.Lock()
	n := s.available
	s.mu.Unlock()
	return n
}

func (s *semaphore) close() {
	s.mu.Lock()
	s.closed = true
	s.wake()
	s.mu.Unlock()
}

func (s *semaphore) wake() {
	waiters := s.waiters
	s.waiters = nil
	for _, ch := range waiters {
		close(ch)
	}
}
