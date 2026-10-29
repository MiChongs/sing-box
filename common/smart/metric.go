package smart

import (
	"math"
	"time"
)

// Metric is a bounded-inertia weighted mean of one performance measurement
// (setup latency, first-response latency, upload or download goodput). It
// remembers at most validationSamples observations' worth of weight, so ten
// thousand old samples never outvote the next few observations of a degraded
// path, and it loses confidence linearly after half of performanceMaxAge and
// expires entirely at performanceMaxAge.
type Metric struct {
	Sum    float64
	Weight float64
	At     Mono
}

// MetricValue is a Metric read at one instant. Valid is false when the metric
// has no fresh observation; Confidence is in [0, 1].
type MetricValue struct {
	Value      float64
	Confidence float64
	Valid      bool
}

func (m *Metric) Record(sample float64, now Mono) {
	m.RecordAge(sample, now, performanceMaxAge)
}

// RecordAge is Record for a metric whose producer reports at its own
// cadence: maxAge replaces performanceMaxAge.
func (m *Metric) RecordAge(sample float64, now Mono, maxAge time.Duration) {
	if m.At == 0 || now.Sub(m.At) >= maxAge {
		m.Sum, m.Weight = 0, 0
	}
	if m.Weight >= validationSamples {
		m.Sum *= (validationSamples - 1) / m.Weight
		m.Weight = validationSamples - 1
	}
	m.Sum += sample
	m.Weight++
	m.At = now
}

func (m *Metric) Read(now Mono) MetricValue {
	return m.ReadAge(now, performanceMaxAge)
}

// ReadAge is Read with a producer-specific maximum age.
func (m *Metric) ReadAge(now Mono, maxAge time.Duration) MetricValue {
	if m.At == 0 || m.Weight <= 0 {
		return MetricValue{}
	}
	age := now.Sub(m.At)
	if age >= maxAge {
		return MetricValue{}
	}
	freshness := math.Min(2*(1-float64(age)/float64(maxAge)), 1)
	return MetricValue{
		Value:      m.Sum / m.Weight,
		Confidence: math.Min(m.Weight/validationSamples, 1) * freshness,
		Valid:      true,
	}
}

// Mature reports whether the metric carries full confidence: at least
// validationSamples observations, the newest within half of performanceMaxAge.
func (v MetricValue) Mature() bool {
	return v.Valid && v.Confidence >= 0.999
}

// SlowMetric is a long-lived quality average that decays with the evidence
// half-life instead of expiring. It carries the per-connection quality weight
// (the scene-aware formula or the LightGBM prediction) so that it survives
// restarts and idle periods, unlike the fresh performance Metrics.
type SlowMetric struct {
	Sum    float64
	Weight float64
	At     Mono
}

func (m *SlowMetric) decayTo(now Mono) {
	if m.At != 0 {
		f := decay(now.Sub(m.At), evidenceHalfLife)
		m.Sum *= f
		m.Weight *= f
	}
	m.At = now
}

func (m *SlowMetric) Record(sample float64, now Mono) {
	m.decayTo(now)
	if m.Weight >= slowMetricCap {
		m.Sum *= (slowMetricCap - 1) / m.Weight
		m.Weight = slowMetricCap - 1
	}
	m.Sum += sample
	m.Weight++
}

func (m *SlowMetric) Read(now Mono) MetricValue {
	if m.At == 0 {
		return MetricValue{}
	}
	f := decay(now.Sub(m.At), evidenceHalfLife)
	w := m.Weight * f
	if w <= 0.05 {
		return MetricValue{}
	}
	return MetricValue{
		Value:      m.Sum / m.Weight,
		Confidence: math.Min(w/validationSamples, 1),
		Valid:      true,
	}
}

// betaBounds returns the lower and upper bounds of a Beta(successes+1,
// failures+1) posterior at reliabilityZ standard deviations.
func betaBounds(successes, failures float64) (lower, upper float64) {
	a := successes + 1
	b := failures + 1
	sum := a + b
	mean := a / sum
	deviation := math.Sqrt(a * b / (sum * sum * (sum + 1)))
	return clamp01(mean - reliabilityZ*deviation), clamp01(mean + reliabilityZ*deviation)
}

// exploreBackoff is the exponential exploration backoff after streak
// consecutive hard failures: 5 minutes doubling up to 6 hours.
func exploreBackoff(streak uint32) time.Duration {
	if streak == 0 {
		return 0
	}
	shift := min(streak-1, 7)
	return min(exploreBackoffBase<<shift, exploreBackoffMax)
}
