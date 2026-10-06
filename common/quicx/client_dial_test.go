//go:build with_quic

package quicx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ N.Dialer = (*failingDialer)(nil)

// failingDialer stands in for sing's dialer, which resolves the configured
// server address itself: a failure here is either a resolution or a UDP
// connectivity failure, exactly the case the client has to report.
type failingDialer struct {
	err error
}

func (d *failingDialer) DialContext(_ context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return nil, d.err
}

func (d *failingDialer) ListenPacket(_ context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return nil, d.err
}

// recordingLogger keeps the diagnostics a test asserted on. The embedded
// interface covers the rest of sing's logger interface, which is never called.
type recordingLogger struct {
	logger.Logger
	access sync.Mutex
	lines  []string
}

func (l *recordingLogger) Debug(args ...any) {
	l.append("debug", args)
}

func (l *recordingLogger) Error(args ...any) {
	l.append("error", args)
}

func (l *recordingLogger) append(level string, args []any) {
	l.access.Lock()
	defer l.access.Unlock()
	l.lines = append(l.lines, level+" "+fmt.Sprint(args...))
}

func (l *recordingLogger) entries() []string {
	l.access.Lock()
	defer l.access.Unlock()
	return append([]string(nil), l.lines...)
}

// TestDialFailureReportsStageAndServer covers the client side of the lost
// dials: a request which cannot reach the server has to leave a log line which
// says which stage failed and to which address, so an unreachable path can be
// told apart from a server refusing the connection.
func TestDialFailureReportsStageAndServer(t *testing.T) {
	const serverAddress = "165.99.42.79:30010"
	dialErr := errors.New("dial udp: no route to internet")
	testLogger := &recordingLogger{}
	client := &Client{
		dialer:     &failingDialer{err: dialErr},
		serverAddr: M.ParseSocksaddr(serverAddress),
		logger:     testLogger,
	}
	_, err := client.offerNew(context.Background())
	if !errors.Is(err, dialErr) {
		t.Fatalf("offerNew returned %v, want the dialer error", err)
	}
	entries := testLogger.entries()
	if len(entries) != 1 {
		t.Fatalf("got %d log lines, want 1: %v", len(entries), entries)
	}
	line := entries[0]
	for _, expected := range []string{
		"error",
		"stage=dial",
		"transport=udp",
		"server=" + serverAddress,
		"error=" + dialErr.Error(),
	} {
		if !strings.Contains(line, expected) {
			t.Errorf("log line %q does not contain %q", line, expected)
		}
	}
}

// TestDialFailureOfDomainReportsDomain covers the other half of the same
// question: when the server is configured as a name, the failing address has to
// be logged as the name, since that is what a resolution failure has to be
// explained with.
func TestDialFailureOfDomainReportsDomain(t *testing.T) {
	const serverAddress = "example.com:30010"
	testLogger := &recordingLogger{}
	client := &Client{
		dialer:     &failingDialer{err: errors.New("dns: exchange failed for example.com")},
		serverAddr: M.ParseSocksaddr(serverAddress),
		logger:     testLogger,
	}
	_, err := client.offerNew(context.Background())
	if err == nil {
		t.Fatal("offerNew succeeded, want a dial failure")
	}
	entries := testLogger.entries()
	if len(entries) != 1 {
		t.Fatalf("got %d log lines, want 1: %v", len(entries), entries)
	}
	if !strings.Contains(entries[0], "server="+serverAddress) {
		t.Errorf("log line %q does not report the configured domain", entries[0])
	}
	if !strings.Contains(entries[0], "stage=dial") {
		t.Errorf("log line %q does not report the dial stage", entries[0])
	}
}
