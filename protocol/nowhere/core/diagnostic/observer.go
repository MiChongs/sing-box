// Package diagnostic defines structured, host-owned observability hooks.
package diagnostic

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// Level is the severity of an Event.
type Level uint8

const (
	// LevelDebug describes verbose lifecycle information.
	LevelDebug Level = iota
	// LevelInfo describes normal lifecycle information.
	LevelInfo
	// LevelWarn describes a recoverable or degraded condition.
	LevelWarn
	// LevelError describes a failed protocol operation.
	LevelError
)

// Well-known Result values.
const (
	ResultOK       = "ok"
	ResultCanceled = "canceled"
	ResultTimeout  = "timeout"
	ResultFailed   = "failed"
)

// Well-known ErrorClass values.
const (
	ErrorClassRemoteClose = "remote_close"
	ErrorClassLocalCancel = "local_cancel"
	ErrorClassNetwork     = "network"
	ErrorClassProtocol    = "protocol"
	ErrorClassProbeClose  = "probe_close"
)

// Well-known Carrier values.
const (
	CarrierTCPTLS = "tcp_tls"
	CarrierQUIC   = "quic"
)

// Event is a structured diagnostic emitted by the protocol core.
// Zero-valued fields are omitted by host adapters.
type Event struct {
	Level      Level
	Code       string // event name, e.g. flow_open / pair_timeout
	Component  string // server | tcptls | quic | ...
	Carrier    string // tcp_tls | quic
	Source     net.Addr
	Target     string
	SessionID  wire.SessionID
	FlowID     wire.FlowID
	CarrierID  uint64
	State      string
	Outcome    string
	Result     string // ok | canceled | timeout | failed
	ErrorClass string
	Count      int
	Bytes      uint64
	Duration   time.Duration
	Err        error

	// Half / pair correlation fields (asymmetric flows).
	HalfRole          string // open | attach (received role)
	MissingHalf       string
	Transport         string // received transport tcp|quic|udp
	ExpectedTransport string
	ReceivedHalf      string // alias clarity for pair diagnostics
	UplinkCarrierID   uint64
	DownlinkCarrierID uint64
	UplinkTransport   string
	DownlinkTransport string
	Stage             string
	ContextCause      string
	CloseReason       string
	Server            string // portal dial address (distinct from business Target)
	DialQueueMs       int64
	RawDialMs         int64
	TLSms             int64
	AuthMs            int64
	PairWaitMs        int64
	FirstByteMs       int64
	AcquireWaitMs     int64
	OpenTotalMs       int64
	PoolIdle          int
	PoolPreparing     int
	PoolTarget        int
	RxBytes           uint64
	TxBytes           uint64
}

// Observer receives diagnostic events. Implementations must return promptly.
type Observer interface {
	Observe(context.Context, Event)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(context.Context, Event)

// Observe invokes f with the supplied event.
func (f ObserverFunc) Observe(ctx context.Context, event Event) { f(ctx, event) }

// NopObserver discards events.
type NopObserver struct{}

// Observe discards the supplied event.
func (NopObserver) Observe(context.Context, Event) {}

// Emit invokes observer while isolating host observer panics from protocol goroutines.
func Emit(ctx context.Context, observer Observer, event Event) {
	if observer == nil {
		return
	}
	defer func() { _ = recover() }()
	observer.Observe(ctx, event)
}
