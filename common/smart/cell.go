package smart

import "time"

// Cell is the evidence one node has accumulated in one scope: the whole group
// (global), one target address family, one site (eTLD+1 or ASN) or one exact
// target. Cells are owned by a table shard and only touched under its lock.
type Cell struct {
	UpdatedAt Mono

	// Decayed business outcomes (evidence half-life). Setup failures weigh
	// double in the reliability bounds.
	SetupSuccess  float64
	SetupFailure  float64
	UsefulSuccess float64
	UsefulFailure float64

	// Fresh performance: setup and first-response latency in milliseconds,
	// upload and download goodput in bytes per second.
	Setup    Metric
	Response Metric
	Upload   Metric
	Download Metric
	// Long-lived connection quality (mihomo scene weight or LightGBM
	// prediction), and the TCP retransmission EMA of the node's carriers.
	Quality SlowMetric
	LossEMA float64
	LossAt  Mono

	// Failure state: consecutive hard failures, the earliest time the node
	// may be explored again, and when it last failed.
	FailStreak       uint32
	ExploreNotBefore Mono
	FailedAt         Mono
	// Business evidence older than this fence is void (failure, reload).
	InvalidatedAt Mono
	// An earned qualification kept alive by fresh business RX.
	QualifiedUntil Mono
	LastRXAt       Mono
	// Availability cohort: distinct reporters with fresh RX after the fence.
	AvailEpoch     uint32
	AvailReporters uint8
	AvailLatestRX  Mono
	AvailValidFrom Mono

	// A same-target response much slower than its history.
	DegradedAt Mono
	// Selection tick of the last admitted attempt on this node.
	SelectedAt uint64

	// Lifetime totals, kept for display, LightGBM inputs and persistence.
	Success       int64
	Failure       int64
	UploadTotal   float64 // MB
	DownloadTotal float64 // MB
	MaxUpRate     float64 // KB/s
	MaxDownRate   float64 // KB/s
	DurationAvg   float64 // minutes, EMA
	ConnectAvg    float64 // ms, EMA
	LatencyAvg    float64 // ms, EMA
	CumulSent     uint64
	CumulRetrans  uint64
	LastUsed      int64 // unix seconds
	// Probe baseline (configured health probes) and the age its producer's
	// cadence allows; only meaningful on the global cell.
	Probe       Metric
	ProbeMaxAge time.Duration

	// Name is the site key of a site cell, kept for persistence.
	Name string

	touched Mono // last read or write, for approximate LRU eviction
}

func (c *Cell) decayTo(now Mono) {
	if c.UpdatedAt != 0 {
		f := decay(now.Sub(c.UpdatedAt), evidenceHalfLife)
		c.SetupSuccess *= f
		c.SetupFailure *= f
		c.UsefulSuccess *= f
		c.UsefulFailure *= f
	}
	c.UpdatedAt = now
}

func (c *Cell) factor(now Mono) float64 {
	if c.UpdatedAt == 0 {
		return 1
	}
	return decay(now.Sub(c.UpdatedAt), evidenceHalfLife)
}

func (c *Cell) completed() float64       { return c.SetupSuccess + c.SetupFailure }
func (c *Cell) usefulCompleted() float64 { return c.UsefulSuccess + c.UsefulFailure }

func (c *Cell) invalidateBusiness(now Mono) {
	c.AvailEpoch++
	c.AvailReporters = 0
	c.AvailLatestRX = 0
	c.AvailValidFrom = maxMono(c.AvailValidFrom, now)
	c.QualifiedUntil = 0
	c.InvalidatedAt = maxMono(c.InvalidatedAt, now)
}

// recordAvailability counts one reporter's fresh business RX into the
// availability cohort. credited is the reporter's last credited epoch for
// this cell, so a reporter and its clones count once per cohort.
func (c *Cell) recordAvailability(rxAt, now Mono, credited *uint32) bool {
	if c.AvailLatestRX != 0 && now.Sub(c.AvailLatestRX) >= liveQualificationTTL {
		// A silent gap ends the cohort.
		c.AvailEpoch++
		c.AvailReporters = 0
		c.AvailValidFrom = maxMono(c.AvailValidFrom, c.AvailLatestRX.Add(liveQualificationTTL))
		c.AvailLatestRX = 0
	}
	latest := maxMono(c.AvailLatestRX, now)
	if rxAt > now || latest.Sub(rxAt) >= liveQualificationTTL || (c.AvailValidFrom != 0 && rxAt < c.AvailValidFrom) {
		return false
	}
	if *credited != c.AvailEpoch+1 {
		if c.AvailReporters < validationSamples {
			c.AvailReporters++
		}
		*credited = c.AvailEpoch + 1
	}
	c.AvailLatestRX = maxMono(c.AvailLatestRX, rxAt)
	return true
}

// observeRX records fresh business progress: it clears exploration delay,
// may recover a failed member once four distinct reporters were seen since
// the failure, and renews an earned qualification.
func (c *Cell) observeRX(rxAt, now Mono, credited *uint32) {
	if c.InvalidatedAt != 0 && rxAt <= c.InvalidatedAt {
		return
	}
	if !c.recordAvailability(rxAt, now, credited) {
		return
	}
	c.ExploreNotBefore = 0
	if c.FailedAt != 0 && c.AvailReporters >= validationSamples {
		c.FailStreak = 0
		c.QualifiedUntil = maxMono(c.QualifiedUntil, rxAt.Add(liveQualificationTTL))
	}
	c.LastRXAt = maxMono(c.LastRXAt, rxAt)
	c.retainQualification(rxAt, now)
}

func (c *Cell) retainQualification(rxAt, now Mono) {
	qualified := c.usefulCompleted()*c.factor(now) >= validationSamples
	if qualified && c.LastRXAt != 0 {
		rxAt = c.LastRXAt
	}
	if now.Sub(rxAt) >= liveQualificationTTL || (c.InvalidatedAt != 0 && rxAt <= c.InvalidatedAt) {
		return
	}
	if qualified || (c.QualifiedUntil != 0 && rxAt < c.QualifiedUntil) {
		until := rxAt.Add(liveQualificationTTL)
		latest := rxAt
		if c.LastRXAt != 0 && c.LastRXAt < until {
			latest = c.LastRXAt
		}
		c.QualifiedUntil = maxMono(c.QualifiedUntil, latest.Add(liveQualificationTTL))
	}
}

// observeLatency records a setup or first-response latency sample. exact
// cells compare it against the same target's history to detect degradation.
func (c *Cell) observeLatency(metric *Metric, latency time.Duration, now Mono, exact bool) {
	sample := float64(latency) / float64(time.Millisecond)
	if exact {
		previous := metric.Read(now)
		if previous.Mature() && sample > max(previous.Value, 1)*degradeFactor {
			c.DegradedAt = now
		}
	}
	metric.Record(sample, now)
}

// observeTransfer records one goodput window.
func (c *Cell) observeTransfer(tx, rx int64, elapsed time.Duration, now Mono) {
	if elapsed < minThroughputDuration || elapsed > maxThroughputDuration {
		return
	}
	seconds := elapsed.Seconds()
	if tx >= minThroughputBytes {
		c.Upload.Record(float64(tx)/seconds, now)
	}
	if rx >= minThroughputBytes {
		c.Download.Record(float64(rx)/seconds, now)
	}
}

// finish settles one business attempt into the cell.
func (c *Cell) finish(f *Finish, now Mono, hard bool) {
	c.decayTo(now)
	if f.Outcome == OutcomeCancelled {
		return
	}
	if hard && f.Outcome != OutcomeSuccess {
		c.FailStreak++
		c.ExploreNotBefore = now.Add(exploreBackoff(c.FailStreak))
		c.invalidateBusiness(now)
		c.FailedAt = maxMono(c.FailedAt, now)
	}
	if f.SetupOK {
		c.SetupSuccess++
	} else {
		c.SetupFailure++
	}
	if f.Outcome == OutcomeSuccess && f.TX > 0 && f.RX > 0 {
		c.UsefulSuccess++
		if f.RXAt != 0 {
			c.retainQualification(f.RXAt, now)
		}
	} else {
		c.UsefulFailure++
	}
	if f.Outcome == OutcomeSuccess {
		c.Success++
	} else {
		c.Failure++
	}
	if f.Quality > 0 {
		c.Quality.Record(f.Quality, now)
	}
	c.recordTotals(f, now)
}

func (c *Cell) recordTotals(f *Finish, now Mono) {
	const alpha = 0.2
	c.UploadTotal += float64(f.TX) / (1 << 20)
	c.DownloadTotal += float64(f.RX) / (1 << 20)
	c.MaxUpRate = max(c.MaxUpRate, f.MaxUpRate)
	c.MaxDownRate = max(c.MaxDownRate, f.MaxDownRate)
	minutes := f.Duration.Minutes()
	if c.DurationAvg == 0 {
		c.DurationAvg = minutes
	} else {
		c.DurationAvg += alpha * (minutes - c.DurationAvg)
	}
	if f.SetupOK && f.SetupLatency > 0 {
		ms := float64(f.SetupLatency) / float64(time.Millisecond)
		if c.ConnectAvg == 0 {
			c.ConnectAvg = ms
		} else {
			c.ConnectAvg += alpha * (ms - c.ConnectAvg)
		}
	}
	if f.ResponseLatency > 0 {
		ms := float64(f.ResponseLatency) / float64(time.Millisecond)
		if c.LatencyAvg == 0 {
			c.LatencyAvg = ms
		} else {
			c.LatencyAvg += alpha * (ms - c.LatencyAvg)
		}
	}
	if f.Sent > 0 {
		c.CumulSent += f.Sent
		c.CumulRetrans += f.Retrans
		rate := float64(f.Retrans) / float64(f.Sent)
		if c.LossAt == 0 {
			c.LossEMA = rate
		} else {
			c.LossEMA += lossAlpha * (rate - c.LossEMA)
		}
		c.LossAt = now
	}
	c.LastUsed = now.Wall().Unix()
}

// CumulLossRate is the node's retransmission share over every measured
// connection in this scope.
func (c *Cell) CumulLossRate() float64 {
	if c.CumulSent == 0 {
		return 0
	}
	return min(float64(c.CumulRetrans)/float64(c.CumulSent), 1)
}

const lossAlpha = 0.3
