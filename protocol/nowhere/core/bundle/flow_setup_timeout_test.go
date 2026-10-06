package bundle

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

type deadlinePipe struct {
	net.Conn
}

func (c *deadlinePipe) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func TestReadSetupResultAcceptsDelayedREADYWithinTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		time.Sleep(50 * time.Millisecond)
		frame, err := wire.EncodeSetupResult(wire.SetupResultReady)
		if err != nil {
			return
		}
		_, _ = server.Write(frame[:])
	}()

	if err := readSetupResultWithTimeout(&deadlinePipe{Conn: client}, 500*time.Millisecond); err != nil {
		t.Fatalf("delayed READY within timeout: %v", err)
	}
}

func TestReadSetupResultTimesOutAndMapsDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	start := time.Now()
	err := readSetupResultWithTimeout(&deadlinePipe{Conn: client}, 80*time.Millisecond)
	if !errors.Is(err, ErrFlowSetupTimeout) {
		t.Fatalf("timeout err = %v, want ErrFlowSetupTimeout", err)
	}
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Fatalf("returned too quickly: %v", elapsed)
	}
}
