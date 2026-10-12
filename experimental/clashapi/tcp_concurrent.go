package clashapi

import (
	"net/http"
	"time"

	"github.com/sagernet/sing-box/common/dialer"

	"github.com/go-chi/render"
)

type tcpConcurrentStatus struct {
	Enabled bool `json:"enabled"`
	// Adaptive is set when attempt_delay is empty; AttemptDelay is the fixed
	// delay in milliseconds otherwise.
	Adaptive      bool                        `json:"adaptive"`
	AttemptDelay  int64                       `json:"attemptDelay"`
	MaxConcurrent int                         `json:"maxConcurrent"`
	Statistics    tcpConcurrentStatistics     `json:"statistics"`
	Destinations  []tcpConcurrentDestination  `json:"destinations"`
	Failures      []tcpConcurrentFailedTarget `json:"failures"`
}

type tcpConcurrentStatistics struct {
	Races        uint64 `json:"races"`
	RaceFailures uint64 `json:"raceFailures"`
	HistoryHits  uint64 `json:"historyHits"`
	Attempts     uint64 `json:"attempts"`
	Failures     uint64 `json:"failures"`
	Canceled     uint64 `json:"canceled"`
	LateClosed   uint64 `json:"lateClosed"`
	// Wins counts won races by the position of the winning attempt, the last
	// element covering the positions after it.
	Wins               []uint64 `json:"wins"`
	AverageConnectTime float64  `json:"averageConnectTime"`
}

type tcpConcurrentDestination struct {
	Host        string    `json:"host"`
	Port        uint16    `json:"port"`
	Address     string    `json:"address"`
	ConnectTime float64   `json:"connectTime"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

type tcpConcurrentFailedTarget struct {
	Address   string    `json:"address"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}

func getTCPConcurrent(tcpConcurrent *dialer.TCPConcurrent) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if tcpConcurrent == nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError("tcp-concurrent is unavailable"))
			return
		}
		status := tcpConcurrent.Status()
		response := tcpConcurrentStatus{
			Enabled:       status.Enabled,
			Adaptive:      !status.FixedDelay,
			AttemptDelay:  status.AttemptDelay.Milliseconds(),
			MaxConcurrent: status.MaxConcurrent,
			Statistics: tcpConcurrentStatistics{
				Races:              status.Statistics.Races,
				RaceFailures:       status.Statistics.RaceFailures,
				HistoryHits:        status.Statistics.HistoryHits,
				Attempts:           status.Statistics.Attempts,
				Failures:           status.Statistics.Failures,
				Canceled:           status.Statistics.Canceled,
				LateClosed:         status.Statistics.LateClosed,
				Wins:               status.Statistics.Wins,
				AverageConnectTime: milliseconds(status.Statistics.AverageConnectTime),
			},
			Destinations: make([]tcpConcurrentDestination, 0, len(status.Destinations)),
			Failures:     make([]tcpConcurrentFailedTarget, 0, len(status.Failures)),
		}
		for _, destination := range status.Destinations {
			response.Destinations = append(response.Destinations, tcpConcurrentDestination{
				Host:        destination.Host,
				Port:        destination.Port,
				Address:     destination.Address.String(),
				ConnectTime: milliseconds(destination.ConnectTime),
				ExpiresAt:   destination.ExpiresAt,
			})
		}
		for _, failure := range status.Failures {
			response.Failures = append(response.Failures, tcpConcurrentFailedTarget{
				Address:   failure.Address.String(),
				ExpiresAt: failure.ExpiresAt,
			})
		}
		render.JSON(w, r, response)
	}
}

func resetTCPConcurrent(tcpConcurrent *dialer.TCPConcurrent) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if tcpConcurrent == nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError("tcp-concurrent is unavailable"))
			return
		}
		tcpConcurrent.ResetHistory()
		render.NoContent(w, r)
	}
}
