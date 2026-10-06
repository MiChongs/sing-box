package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/quicx"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// The reordering this test injects: every holdEvery-th datagram the service
// sends is held back until holdFor further datagrams have gone out. Six packets
// is what the packet threshold has to tolerate: RFC 9002 declares a packet lost
// once three later packets are acknowledged, so a packet overtaken by six is
// declared lost although it arrives immediately after them.
const (
	quicxTestHoldEvery = 8
	quicxTestHoldFor   = 6
)

// TestQUICXReorderingTolerance covers loss detection on a path which reorders
// packets. The service sends through a socket which holds back every
// quicxTestHoldEvery-th datagram, the client echoes enough data back to keep
// packets in flight, and the test then reads the service's qlog:
//
//   - a packet the service declared lost while it was only late is a spurious
//     loss, and every one of them spent a retransmission and a congestion event;
//   - the adaptive packet threshold has to raise itself above the reordering
//     the trace proves, which recovery:reordering_window_updated reports.
//
// Before the threshold adapted, this trace holds a reordering_threshold
// spurious loss for nearly every held datagram (hundreds of them); afterwards
// the threshold has to stop declaring them lost within a handful.
func TestQUICXReorderingTolerance(t *testing.T) {
	ctx := context.Background()
	qlogDir := t.TempDir()
	t.Setenv("QLOGDIR", qlogDir)
	const transferSize = 8 << 20
	reordering := &quicxTestReorderingPacketConn{holdEvery: quicxTestHoldEvery, holdFor: quicxTestHoldFor}
	server := startQUICXTestServerWithOptions(
		t,
		ctx,
		[]string{quicxTestPassword},
		logger.NOP(),
		quicxTestTracer,
		func(packetConn net.PacketConn) net.PacketConn {
			reordering.PacketConn = packetConn
			return reordering
		},
		func(options *quicx.ServiceOptions) {
			// One QUIC packet per datagram keeps the injected reordering
			// proportional to the number of datagrams held back instead of to
			// the size of a GSO batch.
			options.QUICOptions.DisableGSO = true
		},
	)
	client, _ := newQUICXTestClientWithDialer(t, ctx, server.address, quicxTestPassword, &quicxTestDialer{}, quicxTestTracer)
	conn, err := client.DialConn(ctx, quicxTestDestination)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Minute)))
	go func() {
		payload := make([]byte, 32<<10)
		for written := 0; written < transferSize; {
			length := min(len(payload), transferSize-written)
			if _, err := conn.Write(payload[:length]); err != nil {
				return
			}
			written += length
		}
	}()
	_, err = io.CopyN(io.Discard, conn, transferSize)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	traces, err := filepath.Glob(filepath.Join(qlogDir, "*_server.sqlog"))
	require.NoError(t, err)
	require.NotEmpty(t, traces, "the service wrote no qlog trace")
	held := reordering.heldDatagrams()
	require.Greater(t, held, 100, "the transfer was too short to inject reordering")

	// The trace is still being written while the connection winds down, so the
	// adapted window is awaited instead of being read once.
	var losses quicxTestLossCounts
	require.Eventually(t, func() bool {
		losses = quicxTestCountLosses(t, traces)
		return losses.adapted > 0
	}, 20*time.Second, 500*time.Millisecond,
		"the service never reported a reordering window: the injected reordering did not reach loss detection")

	t.Logf("%d datagrams were held back; reordering_threshold: declared lost %d, of which spurious %d; time_threshold spurious %d; window adaptations %d (largest threshold %d)",
		held, losses.reorderingLost, losses.reorderingSpurious, losses.timeSpurious, losses.adapted, losses.largestThreshold)
	require.LessOrEqual(t, losses.reorderingLost, 50,
		"the packet threshold declared packets lost although the path only reordered them")
	require.LessOrEqual(t, losses.reorderingSpurious, 10,
		"the packet threshold kept declaring late packets lost after it measured the reordering")
}

// quicxTestReorderingPacketConn delays every holdEvery-th datagram it sends
// until holdFor further datagrams have been written, which is the reordering
// shape of a mobile path: a packet is overtaken by a handful of later ones.
type quicxTestReorderingPacketConn struct {
	net.PacketConn

	access    sync.Mutex
	sent      int
	heldTotal int
	holdEvery int
	holdFor   int
	held      []*quicxTestHeldDatagram
}

// heldDatagrams reports how many datagrams were held back, so a test can tell
// an adapted threshold apart from a transfer which never reordered anything.
func (c *quicxTestReorderingPacketConn) heldDatagrams() int {
	c.access.Lock()
	defer c.access.Unlock()
	return c.heldTotal
}

type quicxTestHeldDatagram struct {
	payload   []byte
	addr      net.Addr
	remaining int
}

func (c *quicxTestReorderingPacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	c.access.Lock()
	c.sent++
	if c.holdEvery > 0 && c.sent%c.holdEvery == 0 {
		// quic-go reuses its send buffers, so the payload has to be copied.
		c.heldTotal++
		c.held = append(c.held, &quicxTestHeldDatagram{
			payload:   append([]byte(nil), payload...),
			addr:      addr,
			remaining: c.holdFor,
		})
		c.access.Unlock()
		return len(payload), nil
	}
	var due []*quicxTestHeldDatagram
	kept := c.held[:0]
	for _, held := range c.held {
		held.remaining--
		if held.remaining <= 0 {
			due = append(due, held)
			continue
		}
		kept = append(kept, held)
	}
	c.held = kept
	c.access.Unlock()

	written, err := c.PacketConn.WriteTo(payload, addr)
	for _, held := range due {
		if _, writeErr := c.PacketConn.WriteTo(held.payload, held.addr); writeErr != nil && err == nil {
			err = writeErr
		}
	}
	return written, err
}

// quicxTestLossCounts is what a qlog trace says about loss detection: how many
// packets each detector declared lost, how many of those were only late, and
// what the adaptive packet threshold did.
type quicxTestLossCounts struct {
	reorderingLost     int
	reorderingSpurious int
	timeSpurious       int
	adapted            int
	largestThreshold   int
}

type quicxTestLossEvent struct {
	Name string `json:"name"`
	Data struct {
		Trigger            string `json:"trigger"`
		PacketThreshold    int    `json:"packet_threshold"`
		ObservedReordering int    `json:"observed_reordering"`
	} `json:"data"`
}

func quicxTestCountLosses(t *testing.T, paths []string) quicxTestLossCounts {
	t.Helper()
	var counts quicxTestLossCounts
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range bytes.Split(content, []byte{'\n'}) {
			line = bytes.Trim(line, "\x1e\r")
			if len(line) == 0 || line[0] != '{' {
				continue
			}
			var event quicxTestLossEvent
			if err = json.Unmarshal(line, &event); err != nil {
				continue
			}
			switch event.Name {
			case "recovery:packet_lost":
				if event.Data.Trigger == "reordering_threshold" {
					counts.reorderingLost++
				}
			case "recovery:spurious_loss":
				switch event.Data.Trigger {
				case "reordering_threshold":
					counts.reorderingSpurious++
				case "time_threshold":
					counts.timeSpurious++
				}
			case "recovery:reordering_window_updated":
				if event.Data.ObservedReordering > 0 {
					counts.adapted++
				}
				if event.Data.PacketThreshold > counts.largestThreshold {
					counts.largestThreshold = event.Data.PacketThreshold
				}
			}
		}
	}
	return counts
}
