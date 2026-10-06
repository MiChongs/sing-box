package diagnostic

import (
	"fmt"
	"strings"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// FormatEvent renders a structured Event as a single log line of key=value fields.
// Zero-valued optional fields are omitted.
func FormatEvent(event Event) string {
	parts := []string{"nowhere"}
	if event.Component != "" {
		parts = append(parts, "component="+event.Component)
	}
	if event.Carrier != "" {
		parts = append(parts, "carrier="+event.Carrier)
	}
	if event.Code != "" {
		parts = append(parts, "event="+event.Code)
	}
	if event.Source != nil {
		parts = append(parts, fmt.Sprintf("source=%v", event.Source))
	}
	if event.Target != "" {
		parts = append(parts, fmt.Sprintf("target=%s", event.Target))
	}
	if event.Server != "" {
		parts = append(parts, fmt.Sprintf("server=%s", event.Server))
	}
	if event.SessionID != (wire.SessionID{}) {
		parts = append(parts, fmt.Sprintf("session_id=%x", event.SessionID))
	}
	if event.FlowID != 0 {
		parts = append(parts, fmt.Sprintf("flow_id=%d", event.FlowID))
	}
	if event.CarrierID != 0 {
		parts = append(parts, fmt.Sprintf("carrier_id=%d", event.CarrierID))
	}
	if event.UplinkCarrierID != 0 {
		parts = append(parts, fmt.Sprintf("uplink_carrier_id=%d", event.UplinkCarrierID))
	}
	if event.DownlinkCarrierID != 0 {
		parts = append(parts, fmt.Sprintf("downlink_carrier_id=%d", event.DownlinkCarrierID))
	}
	if event.UplinkTransport != "" {
		parts = append(parts, "uplink_transport="+event.UplinkTransport)
	}
	if event.DownlinkTransport != "" {
		parts = append(parts, "downlink_transport="+event.DownlinkTransport)
	}
	receivedHalf := event.ReceivedHalf
	if receivedHalf == "" {
		receivedHalf = event.HalfRole
	}
	if receivedHalf != "" {
		parts = append(parts, "received_half="+receivedHalf)
	}
	if event.MissingHalf != "" {
		parts = append(parts, "missing_half="+event.MissingHalf)
	}
	if event.Transport != "" {
		parts = append(parts, "received_transport="+event.Transport)
	}
	if event.ExpectedTransport != "" {
		parts = append(parts, "expected_transport="+event.ExpectedTransport)
	}
	if event.Stage != "" {
		parts = append(parts, "stage="+event.Stage)
	}
	if event.Result != "" {
		parts = append(parts, "result="+event.Result)
	}
	if event.ErrorClass != "" {
		parts = append(parts, "error_class="+event.ErrorClass)
	}
	if event.CloseReason != "" {
		parts = append(parts, "close_reason="+event.CloseReason)
	}
	if event.PoolIdle != 0 || event.PoolPreparing != 0 || event.PoolTarget != 0 || event.Code == "pool_acquire" {
		if event.Code == "pool_acquire" || event.PoolIdle != 0 {
			parts = append(parts, fmt.Sprintf("pool_idle=%d", event.PoolIdle))
		}
		if event.Code == "pool_acquire" || event.PoolPreparing != 0 {
			parts = append(parts, fmt.Sprintf("pool_preparing=%d", event.PoolPreparing))
		}
		if event.Code == "pool_acquire" || event.PoolTarget != 0 {
			parts = append(parts, fmt.Sprintf("pool_target=%d", event.PoolTarget))
		}
	}
	if event.DialQueueMs != 0 {
		parts = append(parts, fmt.Sprintf("dial_queue_ms=%d", event.DialQueueMs))
	}
	if event.RawDialMs != 0 {
		parts = append(parts, fmt.Sprintf("raw_dial_ms=%d", event.RawDialMs))
	}
	if event.TLSms != 0 {
		parts = append(parts, fmt.Sprintf("tls_ms=%d", event.TLSms))
	}
	if event.AuthMs != 0 {
		parts = append(parts, fmt.Sprintf("auth_ms=%d", event.AuthMs))
	}
	if event.PairWaitMs != 0 {
		parts = append(parts, fmt.Sprintf("pair_wait_ms=%d", event.PairWaitMs))
	}
	if event.FirstByteMs != 0 {
		parts = append(parts, fmt.Sprintf("first_byte_ms=%d", event.FirstByteMs))
	}
	if event.AcquireWaitMs != 0 {
		parts = append(parts, fmt.Sprintf("acquire_wait_ms=%d", event.AcquireWaitMs))
	}
	if event.OpenTotalMs != 0 {
		parts = append(parts, fmt.Sprintf("open_total_ms=%d", event.OpenTotalMs))
	}
	if event.RxBytes != 0 {
		parts = append(parts, fmt.Sprintf("rx_bytes=%d", event.RxBytes))
	}
	if event.TxBytes != 0 {
		parts = append(parts, fmt.Sprintf("tx_bytes=%d", event.TxBytes))
	}
	if event.Duration != 0 {
		parts = append(parts, fmt.Sprintf("duration_ms=%d", event.Duration.Milliseconds()))
	}
	if event.ContextCause != "" {
		parts = append(parts, fmt.Sprintf("context_cause=%q", event.ContextCause))
	}
	if event.Outcome != "" && !strings.Contains(event.Outcome, "[Nowhere]") {
		parts = append(parts, "outcome="+event.Outcome)
	}
	if event.State != "" {
		parts = append(parts, "state="+event.State)
	}
	if event.Count != 0 {
		parts = append(parts, fmt.Sprintf("count=%d", event.Count))
	}
	if event.Bytes != 0 && event.RxBytes == 0 && event.TxBytes == 0 {
		parts = append(parts, fmt.Sprintf("bytes=%d", event.Bytes))
	}
	if event.Err != nil {
		parts = append(parts, fmt.Sprintf("error=%q", event.Err.Error()))
	}
	return strings.Join(parts, " ")
}
