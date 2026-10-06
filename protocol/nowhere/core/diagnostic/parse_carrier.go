package diagnostic

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// ParseCarrierLog converts legacy "[Nowhere] [carrier] <event> k=v ..." printf
// lines into a structured Event skeleton (Code + common fields).
func ParseCarrierLog(msg string) Event {
	msg = strings.TrimSpace(msg)
	for _, prefix := range []string{"[Nowhere] [carrier] ", "[Nowhere] "} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	msg = strings.TrimSpace(msg)
	ev := Event{
		Level:     LevelDebug,
		Component: "tcptls",
		Carrier:   CarrierTCPTLS,
	}
	if msg == "" {
		ev.Code = "carrier_debug"
		return ev
	}
	fields := strings.Fields(msg)
	if len(fields) == 0 {
		ev.Code = "carrier_debug"
		return ev
	}
	ev.Code = fields[0]
	for _, field := range fields[1:] {
		key, val, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "flow_id":
			ev.FlowID = parseFlowID(val)
		case "carrier_id":
			ev.CarrierID = parseUint(val)
		case "target":
			// pool_acquire historically used target= for pool size; ignore numeric-only there.
			if ev.Code == "pool_acquire" && isAllDigits(val) {
				ev.PoolTarget = int(parseInt64(val))
			} else {
				ev.Target = val
			}
		case "server":
			ev.Server = val
		case "network":
			ev.Transport = val
		case "stage":
			ev.Stage = val
		case "outcome":
			ev.Outcome = val
			ev.Result = mapOutcomeResult(val)
		case "raw_dial_ms":
			ev.RawDialMs = parseInt64(val)
		case "tls_ms":
			ev.TLSms = parseInt64(val)
		case "auth_write_ms", "auth_ms":
			ev.AuthMs = parseInt64(val)
		case "rx_bytes":
			ev.RxBytes = parseUint(val)
		case "tx_bytes":
			ev.TxBytes = parseUint(val)
		case "first_byte_ms":
			ev.FirstByteMs = parseInt64(val)
		case "pool_idle", "idle":
			ev.PoolIdle = int(parseInt64(val))
		case "pool_preparing", "preparing":
			ev.PoolPreparing = int(parseInt64(val))
		case "pool_target":
			ev.PoolTarget = int(parseInt64(val))
		case "acquire_wait_ms", "elapsed_ms":
			if ev.AcquireWaitMs == 0 {
				ev.AcquireWaitMs = parseInt64(val)
			}
		case "open_total_ms":
			ev.OpenTotalMs = parseInt64(val)
		case "close_reason":
			ev.CloseReason = val
			switch val {
			case "ok":
				ev.Result = ResultOK
			case ErrorClassRemoteClose:
				ev.ErrorClass = val
				ev.Result = ResultOK
			case ErrorClassLocalCancel, ErrorClassProbeClose:
				ev.ErrorClass = val
				ev.Result = ResultCanceled
			case ErrorClassNetwork, ErrorClassProtocol:
				ev.ErrorClass = val
				ev.Result = ResultFailed
			default:
				ev.Result, ev.ErrorClass = ClassifyClose(errString(val))
			}
		case "role":
			ev.HalfRole = val
		case "delay_ms", "next_retry_ms", "pair_wait_ms":
			if key == "pair_wait_ms" && ev.PairWaitMs == 0 {
				ev.PairWaitMs = parseInt64(val)
			}
		}
	}
	if ev.Result == "" {
		if strings.Contains(ev.Code, "failed") || strings.HasSuffix(ev.Outcome, "_failed") {
			ev.Result = ResultFailed
		}
	}
	return ev
}

type errString string

func (e errString) Error() string { return string(e) }

func parseUint(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

func parseFlowID(s string) wire.FlowID {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return wire.FlowID(n)
}

func parseInt64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func mapOutcomeResult(outcome string) string {
	switch {
	case outcome == "" || outcome == "warm" || outcome == "fresh" || outcome == "warm_prepare":
		return ResultOK
	case strings.Contains(outcome, "failed"), strings.Contains(outcome, "throttled"):
		if strings.Contains(outcome, "cancel") {
			return ResultCanceled
		}
		return ResultFailed
	case strings.Contains(outcome, "cancel"):
		return ResultCanceled
	default:
		return ""
	}
}
