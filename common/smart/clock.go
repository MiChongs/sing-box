package smart

import (
	"math"
	"time"
)

// Mono is a monotonic timestamp in nanoseconds since the process started.
// The engine stores every event time as a Mono so that cells stay small and
// comparisons never touch the wall clock; 0 means "never".
type Mono int64

var monoBase = time.Now()

// Now returns the current monotonic time. It is never 0.
func Now() Mono {
	return Mono(time.Since(monoBase)) + 1
}

// MonoAt converts a wall-clock time recorded in this process to a Mono.
func MonoAt(t time.Time) Mono {
	return Mono(t.Sub(monoBase)) + 1
}

// Wall converts a Mono back to wall-clock time.
func (m Mono) Wall() time.Time {
	return monoBase.Add(time.Duration(m - 1))
}

// Add returns m advanced by d.
func (m Mono) Add(d time.Duration) Mono {
	return m + Mono(d)
}

// Sub returns the duration m-o, clamped at 0 when o is later than m.
func (m Mono) Sub(o Mono) time.Duration {
	if o >= m {
		return 0
	}
	return time.Duration(m - o)
}

// Since returns how long ago m was, measured at now; a zero m is infinitely old.
func (m Mono) Since(now Mono) time.Duration {
	if m == 0 {
		return math.MaxInt64
	}
	return now.Sub(m)
}

func maxMono(a, b Mono) Mono {
	if a > b {
		return a
	}
	return b
}

// decay is the exponential decay factor 2^(-elapsed/halfLife).
func decay(elapsed, halfLife time.Duration) float64 {
	if elapsed <= 0 {
		return 1
	}
	return math.Exp2(-float64(elapsed) / float64(halfLife))
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
