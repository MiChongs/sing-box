package observability

import (
	"io"
	"strconv"

	"github.com/sagernet/sing-box/common/dialer"
)

// writeTCPConcurrentMetrics exports dns.tcp_concurrent counters; the instance
// exists even while the switch is off, so enabling it at runtime keeps the
// series continuous.
func (m *Manager) writeTCPConcurrentMetrics(writer io.Writer) {
	tcpConcurrent := dialer.TCPConcurrentFromContext(m.ctx)
	if tcpConcurrent == nil {
		return
	}
	statistics := tcpConcurrent.Statistics()
	destinations, failures := tcpConcurrent.HistorySize()
	var enabled int64
	if tcpConcurrent.Enabled() {
		enabled = 1
	}
	writeHelpAndType(writer, "singbox_tcp_concurrent_enabled", "Whether dns.tcp_concurrent races resolved addresses by default.", "gauge")
	writeIntegerMetric(writer, "singbox_tcp_concurrent_enabled", enabled)
	writeHelpAndType(writer, "singbox_tcp_concurrent_races_total", "Dials that raced more than one resolved address.", "counter")
	writeIntegerMetric(writer, "singbox_tcp_concurrent_races_total", int64(statistics.Races))
	writeHelpAndType(writer, "singbox_tcp_concurrent_race_failures_total", "Races in which every attempt failed.", "counter")
	writeIntegerMetric(writer, "singbox_tcp_concurrent_race_failures_total", int64(statistics.RaceFailures))
	writeHelpAndType(writer, "singbox_tcp_concurrent_history_hits_total", "Races won by the remembered address alone during its head start.", "counter")
	writeIntegerMetric(writer, "singbox_tcp_concurrent_history_hits_total", int64(statistics.HistoryHits))
	writeHelpAndType(writer, "singbox_tcp_concurrent_attempts_total", "Connection attempts started by races.", "counter")
	writeIntegerMetric(writer, "singbox_tcp_concurrent_attempts_total", int64(statistics.Attempts))
	writeHelpAndType(writer, "singbox_tcp_concurrent_attempt_failures_total", "Connection attempts that failed on their own.", "counter")
	writeIntegerMetric(writer, "singbox_tcp_concurrent_attempt_failures_total", int64(statistics.Failures))
	writeHelpAndType(writer, "singbox_tcp_concurrent_attempts_canceled_total", "Connection attempts still pending when their race was decided.", "counter")
	writeIntegerMetric(writer, "singbox_tcp_concurrent_attempts_canceled_total", int64(statistics.Canceled))
	writeHelpAndType(writer, "singbox_tcp_concurrent_late_connections_closed_total", "Connections established after their race was decided and closed.", "counter")
	writeIntegerMetric(writer, "singbox_tcp_concurrent_late_connections_closed_total", int64(statistics.LateClosed))
	writeHelpAndType(writer, "singbox_tcp_concurrent_wins_total", "Won races grouped by the position of the winning attempt.", "counter")
	for i, wins := range statistics.Wins {
		position := strconv.Itoa(i + 1)
		if i == len(statistics.Wins)-1 {
			position += "+"
		}
		writeNamedLabeledIntegerMetric(writer, "singbox_tcp_concurrent_wins_total", "position", position, int64(wins))
	}
	writeHelpAndType(writer, "singbox_tcp_concurrent_connect_seconds_total", "Connect time of the winning attempts.", "counter")
	writeFloatMetric(writer, "singbox_tcp_concurrent_connect_seconds_total", statistics.ConnectTime.Seconds())
	writeHelpAndType(writer, "singbox_tcp_concurrent_remembered_destinations", "Destinations whose last winning address is remembered.", "gauge")
	writeIntegerMetric(writer, "singbox_tcp_concurrent_remembered_destinations", int64(destinations))
	writeHelpAndType(writer, "singbox_tcp_concurrent_failed_addresses", "Addresses tried last after a recent failure.", "gauge")
	writeIntegerMetric(writer, "singbox_tcp_concurrent_failed_addresses", int64(failures))
}
