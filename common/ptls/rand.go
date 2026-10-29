package ptls

import (
	"crypto/rand"
	"io"
	"sync"
	"time"
)

type ptlsRand struct {
	psk    [32]byte
	mu     sync.Mutex
	step   int
	random [32]byte
}

func newPTLSRand(psk [32]byte) *ptlsRand {
	return &ptlsRand{psk: psk}
}

func (r *ptlsRand) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch r.step {
	case 0:
		if len(p) == 32 {
			n, err := io.ReadFull(rand.Reader, p)
			if err != nil {
				return n, err
			}
			copy(r.random[:], p)
			r.step = 1
			return 32, nil
		}
	case 1:
		if len(p) == 32 {
			injectedID := PackSessionID(&r.psk, r.random[:], time.Now())
			copy(p, injectedID[:])
			r.step = 2
			return 32, nil
		}
	}

	return rand.Reader.Read(p)
}