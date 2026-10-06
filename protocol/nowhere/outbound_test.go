package nowhere

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/bundle"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestOutboundImplementsInterfaceUpdateListener(t *testing.T) {
	t.Parallel()
	var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)
}

func TestNewOutboundConstructsTCPOnly(t *testing.T) {
	t.Parallel()
	pool := 2
	logger := log.NewNOPFactory().Logger()
	out, err := NewOutbound(context.Background(), nil, logger, "nw", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2077},
		Password:      "secret",
		Up:            "tcp",
		Down:          "tcp",
		Pool:          &pool,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:  true,
				Insecure: true,
				ALPN:     badoption.Listable[string]{"nw2"},
			},
		},
	})
	require.NoError(t, err)
	nw := out.(*Outbound)
	require.Equal(t, "tcp", nw.matrix.Up)
	require.Equal(t, 2, nw.matrix.Pool)
	require.False(t, nw.matrix.NeedsQUIC)
}

func TestNewOutboundRejectsMissingTLS(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, err := NewOutbound(context.Background(), nil, logger, "nw", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2077},
		Password:      "secret",
		Up:            "tcp",
		Down:          "tcp",
	})
	require.Error(t, err)
}

func TestNewOutboundRejectsUnknownQUICCongestionControlForTCPOnly(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, err := NewOutbound(context.Background(), nil, logger, "nw", option.NowhereOutboundOptions{
		ServerOptions:         option.ServerOptions{Server: "127.0.0.1", ServerPort: 2077},
		Password:              "secret",
		Up:                    "tcp",
		Down:                  "tcp",
		QUICCongestionControl: "BBR",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true},
		},
	})
	require.ErrorContains(t, err, "unknown quic congestion control")
}

func TestNewOutboundAcceptsPoolWithinRustLimit(t *testing.T) {
	t.Parallel()
	pool := 99
	logger := newWarningLogger()
	out, err := NewOutbound(context.Background(), nil, logger, "nw", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2077},
		Password:      "secret",
		Up:            "tcp",
		Down:          "tcp",
		Pool:          &pool,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 99, out.(*Outbound).matrix.Pool)
	require.Empty(t, logger.Warnings())
	require.NoError(t, out.(*Outbound).Close())
}

func TestNewOutboundWarnsWhenPoolIsIgnoredForUDP(t *testing.T) {
	t.Parallel()
	if !quicIncluded {
		t.Skip("requires with_quic")
	}
	pool := 5
	logger := newWarningLogger()
	out, err := NewOutbound(context.Background(), nil, logger, "nw", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2077},
		Password:      "secret",
		Up:            "udp",
		Down:          "udp",
		Pool:          &pool,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true},
		},
	})
	require.NoError(t, err)
	require.Zero(t, out.(*Outbound).matrix.Pool)
	require.Len(t, logger.Warnings(), 1)
	require.NoError(t, out.(*Outbound).Close())
}

func TestOutboundDialContextUDPDoesNotReturnListenPacketHint(t *testing.T) {
	t.Parallel()
	nw := newTestTCPOutbound(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	conn, err := nw.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddrHostPort("127.0.0.1", 9))
	if err == nil {
		// OpenUDPAsync returns immediately; setup failures surface on I/O.
		require.NotNil(t, conn)
		_ = conn.Close()
		return
	}
	require.NotContains(t, err.Error(), "use ListenPacket for UDP")
}

func TestOutboundInterfaceUpdatedRebuildsBundleLazily(t *testing.T) {
	t.Parallel()
	nw := newTestTCPOutbound(t)
	var rebuilds atomic.Int32
	base := nw.newBundle
	nw.newBundle = func() (*bundle.CarrierBundle, error) {
		rebuilds.Add(1)
		return base()
	}

	require.NotNil(t, nw.bundleForTest())
	nw.InterfaceUpdated(context.Background())
	require.Nil(t, nw.bundleForTest())
	require.Equal(t, int32(0), rebuilds.Load())

	_, err := nw.getBundle()
	require.NoError(t, err)
	require.Equal(t, int32(1), rebuilds.Load())
	require.NotNil(t, nw.bundleForTest())
}

func TestOutboundClosePreventsBundleResurrection(t *testing.T) {
	t.Parallel()
	nw := newTestTCPOutbound(t)
	require.NoError(t, nw.Close())
	_, err := nw.getBundle()
	require.ErrorIs(t, err, net.ErrClosed)
}

func newTestTCPOutbound(t *testing.T) *Outbound {
	t.Helper()
	pool := 0
	logger := log.NewNOPFactory().Logger()
	out, err := NewOutbound(context.Background(), nil, logger, "nw", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2077},
		Password:      "secret",
		Up:            "tcp",
		Down:          "tcp",
		Pool:          &pool,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:  true,
				Insecure: true,
				ALPN:     badoption.Listable[string]{"nw2"},
			},
		},
	})
	require.NoError(t, err)
	return out.(*Outbound)
}

type warningLogger struct {
	log.ContextLogger
	mu       sync.Mutex
	warnings []string
}

func newWarningLogger() *warningLogger {
	return &warningLogger{ContextLogger: log.NewNOPFactory().Logger()}
}

func (l *warningLogger) Warn(args ...any) {
	l.mu.Lock()
	l.warnings = append(l.warnings, fmt.Sprint(args...))
	l.mu.Unlock()
}

func (l *warningLogger) Warnings() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.warnings...)
}

func TestNewOutboundConstructsMixAndMux(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	mux := 1
	out, err := NewOutbound(context.Background(), nil, logger, "nw", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2077},
		Password:      "secret",
		Up:            "tcp",
		Down:          "tcp",
		Mux:           &mux,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true, ALPN: badoption.Listable[string]{"nw2"}},
		},
	})
	require.NoError(t, err)
	nw := out.(*Outbound)
	require.Equal(t, 0, nw.matrix.Pool)
	require.True(t, nw.matrix.Mux == 1)
	require.NoError(t, nw.Close())

	if !quicIncluded {
		t.Skip("mix requires with_quic")
	}
	out, err = NewOutbound(context.Background(), nil, logger, "nw-mix", option.NowhereOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 2077},
		Password:      "secret",
		Up:            "mix",
		Down:          "mix",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true, ALPN: badoption.Listable[string]{"nw2"}},
		},
	})
	require.NoError(t, err)
	nw = out.(*Outbound)
	require.True(t, nw.matrix.MixEnabled())
	require.True(t, nw.matrix.NeedsTCP)
	require.True(t, nw.matrix.NeedsQUIC)
	require.NoError(t, nw.Close())
}
