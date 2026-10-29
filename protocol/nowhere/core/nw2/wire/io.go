package wire

import (
	"io"
)

// WriteFull writes every byte in p. It preserves the writer's original error
// identity and returns io.ErrNoProgress when a broken writer repeatedly claims
// success without consuming input.
func WriteFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
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
