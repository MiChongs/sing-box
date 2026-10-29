package smart

import "math"

// Performance is a set of fresh metrics read at one instant.
type Performance struct {
	Setup    MetricValue
	Response MetricValue
	Upload   MetricValue
	Download MetricValue
}

func (p Performance) preferSpecific(specific Performance) Performance {
	pick := func(base, specific MetricValue) MetricValue {
		if specific.Valid {
			return specific
		}
		return base
	}
	return Performance{
		Setup:    pick(p.Setup, specific.Setup),
		Response: pick(p.Response, specific.Response),
		Upload:   pick(p.Upload, specific.Upload),
		Download: pick(p.Download, specific.Download),
	}
}

// Snapshot is one candidate's blended evidence for one selection context.
type Snapshot struct {
	Completed       float64
	UsefulCompleted float64
	Qualified       bool // four useful completions, or a live qualification lease
	Recovered       bool // recovered by four fresh reporters after a failure
	// Reliability is the Beta lower bound, ReliabilityUpper the upper bound
	// and Observed the plain success share (0.5 when unknown).
	Reliability      float64
	ReliabilityUpper float64
	Observed         float64

	Performance       Performance // global/family
	TargetPerformance Performance // site/exact
	Probe             MetricValue
	Quality           MetricValue
	Loss              float64 // retransmission EMA, 0 when unknown

	UnresolvedFailure bool
	ExploreBackedOff  bool
	FailStreak        uint32
	NodeFailStreak    uint32
	DegradedAt        Mono
	SelectedAt        uint64

	Priority float64 // policy_priority factor, 1 when unset
}

func snapshotOf(c *Cell, now Mono) Snapshot {
	if c == nil {
		return Snapshot{Observed: 0.5, Reliability: lowerPrior, ReliabilityUpper: upperPrior, Priority: 1}
	}
	f := c.factor(now)
	successes := c.UsefulSuccess * f
	failures := (c.UsefulFailure + c.SetupFailure*2) * f
	lower, upper := betaBounds(successes, failures)
	observed := 0.5
	if raw := c.UsefulSuccess + c.UsefulFailure + c.SetupFailure*2; raw > 0 {
		observed = c.UsefulSuccess / raw
	}
	qualifiedLive := c.QualifiedUntil != 0 && now < c.QualifiedUntil
	s := Snapshot{
		Completed:        c.completed() * f,
		UsefulCompleted:  c.usefulCompleted() * f,
		Reliability:      lower,
		ReliabilityUpper: upper,
		Observed:         observed,
		Performance: Performance{
			Setup:    c.Setup.Read(now),
			Response: c.Response.Read(now),
			Upload:   c.Upload.Read(now),
			Download: c.Download.Read(now),
		},
		Quality:           c.Quality.Read(now),
		UnresolvedFailure: c.FailStreak > 0,
		ExploreBackedOff:  c.ExploreNotBefore != 0 && c.ExploreNotBefore > now,
		FailStreak:        c.FailStreak,
		SelectedAt:        c.SelectedAt,
		Priority:          1,
	}
	s.Qualified = s.UsefulCompleted >= validationSamples || qualifiedLive
	s.Recovered = c.FailedAt != 0 && c.FailStreak == 0 && c.AvailReporters >= validationSamples && qualifiedLive
	if c.DegradedAt != 0 && now.Sub(c.DegradedAt) < performanceMaxAge {
		s.DegradedAt = c.DegradedAt
	}
	if c.LossAt != 0 && now.Sub(c.LossAt) < evidenceHalfLife {
		s.Loss = c.LossEMA
	}
	return s
}

var lowerPrior, upperPrior = betaBounds(0, 0)

func blend(base, specific, weight float64) float64 {
	return base*(1-weight) + specific*weight
}

// merge folds a more specific layer into s. node marks the parent (global)
// node invalidation fence: a child cell older than it lost its business
// performance and qualification with the node failure.
func (s *Snapshot) merge(child Snapshot, staleChild bool, targetLayer bool) {
	if staleChild {
		child.Performance = Performance{}
		child.Qualified = child.UsefulCompleted >= validationSamples
		child.Recovered = false
	}
	weight := clamp01(child.UsefulCompleted / switchFullEvidence)
	s.Reliability = blend(s.Reliability, child.Reliability, weight)
	s.ReliabilityUpper = blend(s.ReliabilityUpper, child.ReliabilityUpper, weight)
	s.Observed = blend(s.Observed, child.Observed, weight)
	s.Completed = max(s.Completed, child.Completed)
	s.UsefulCompleted = max(s.UsefulCompleted, child.UsefulCompleted)
	s.Qualified = s.Qualified || child.Qualified
	if targetLayer {
		s.Recovered = child.Recovered
		s.TargetPerformance = s.TargetPerformance.preferSpecific(child.Performance)
	} else {
		s.Recovered = s.Recovered || child.Recovered
		s.Performance = s.Performance.preferSpecific(child.Performance)
	}
	if child.Quality.Valid {
		s.Quality = child.Quality
	}
	if child.Loss > 0 {
		s.Loss = child.Loss
	}
	s.UnresolvedFailure = s.UnresolvedFailure || child.UnresolvedFailure
	s.FailStreak = max(s.FailStreak, child.FailStreak)
	s.ExploreBackedOff = s.ExploreBackedOff || child.ExploreBackedOff
	s.SelectedAt = max(s.SelectedAt, child.SelectedAt)
	s.DegradedAt = maxMono(s.DegradedAt, child.DegradedAt)
}

func (s *Snapshot) finalize() {
	s.Recovered = s.Recovered && !s.UnresolvedFailure
}

// Baseline holds the best values across eligible candidates, which every
// candidate's performance is measured relative to.
type Baseline struct {
	Performance       Performance
	TargetPerformance Performance
	Probe             MetricValue
	Quality           MetricValue
	BestReliability   float64
	BestObserved      float64
	AnyHealthy        bool
	AnyQualified      bool
}

// NewBaseline computes the baseline over snapshots, honoring member when it
// is not nil.
func NewBaseline(snapshots []Snapshot, member []bool) Baseline {
	in := func(i int) bool { return member == nil || member[i] }
	var b Baseline
	for i := range snapshots {
		if in(i) && snapshots[i].FailStreak < failStreakExclude {
			b.AnyHealthy = true
			break
		}
	}
	healthy := func(s *Snapshot) bool { return !b.AnyHealthy || s.FailStreak < failStreakExclude }
	for i := range snapshots {
		if s := &snapshots[i]; in(i) && healthy(s) && s.Qualified {
			b.AnyQualified = true
			break
		}
	}
	for i := range snapshots {
		s := &snapshots[i]
		if !in(i) || !healthy(s) || (b.AnyQualified && !s.Qualified) {
			continue
		}
		b.BestReliability = max(b.BestReliability, s.Reliability)
		b.BestObserved = max(b.BestObserved, s.Observed)
	}
	type acc struct {
		best  float64
		count int
	}
	var (
		perf  [4]acc
		tperf [4]acc
		probe acc
		qual  acc
	)
	add := func(a *acc, v MetricValue, larger bool) {
		if !v.Valid {
			return
		}
		if a.count == 0 || (larger && v.Value > a.best) || (!larger && v.Value < a.best) {
			a.best = v.Value
		}
		a.count++
	}
	for i := range snapshots {
		s := &snapshots[i]
		if !in(i) || !Eligible(s, b) {
			continue
		}
		add(&perf[0], s.Performance.Setup, false)
		add(&perf[1], s.Performance.Response, false)
		add(&perf[2], s.Performance.Upload, true)
		add(&perf[3], s.Performance.Download, true)
		add(&tperf[0], s.TargetPerformance.Setup, false)
		add(&tperf[1], s.TargetPerformance.Response, false)
		add(&tperf[2], s.TargetPerformance.Upload, true)
		add(&tperf[3], s.TargetPerformance.Download, true)
		add(&probe, s.Probe, false)
		add(&qual, s.Quality, true)
	}
	// A best value needs two candidates: one measured member has nothing to
	// be compared against.
	get := func(a acc) MetricValue {
		if a.count < 2 {
			return MetricValue{}
		}
		return MetricValue{Value: a.best, Confidence: 1, Valid: true}
	}
	b.Performance = Performance{get(perf[0]), get(perf[1]), get(perf[2]), get(perf[3])}
	b.TargetPerformance = Performance{get(tperf[0]), get(tperf[1]), get(tperf[2]), get(tperf[3])}
	b.Probe = get(probe)
	b.Quality = get(qual)
	return b
}

// Eligible reports whether a candidate may win ordinary selection: it is not
// excluded by a failure streak while others are healthy, and its reliability
// is close to the best.
func Eligible(s *Snapshot, b Baseline) bool {
	if b.AnyHealthy && s.FailStreak >= failStreakExclude {
		return false
	}
	if s.Recovered && !s.UnresolvedFailure {
		return true
	}
	if b.AnyQualified {
		return s.Qualified &&
			s.ReliabilityUpper+reliabilityClose >= b.BestReliability &&
			s.Observed+reliabilityClose >= b.BestObserved
	}
	return s.Reliability+reliabilityClose >= b.BestReliability
}

func relative(v, best MetricValue, larger bool) (float64, bool) {
	if !v.Valid || !best.Valid {
		return 0, false
	}
	if larger {
		return clamp01(v.Value / math.Max(best.Value, 1)), true
	}
	return clamp01(math.Max(best.Value, 1) / math.Max(v.Value, 1)), true
}

func correction(base float64, v, best MetricValue, larger bool) float64 {
	r, ok := relative(v, best, larger)
	if !ok {
		return base
	}
	return blend(base, r, v.Confidence)
}

func scopedCorrection(base float64, aggregate, aggregateBest, exact, exactBest MetricValue, larger bool) float64 {
	if _, ok := relative(exact, exactBest, larger); ok {
		return correction(base, exact, exactBest, larger)
	}
	return correction(base, aggregate, aggregateBest, larger)
}

// lossPenalty maps a retransmission rate to [0, 1).
func lossPenalty(rate float64) float64 {
	if rate <= 0 {
		return 0
	}
	return 1 - math.Exp(-rate*50)
}

// Utility is the comprehensive score of one candidate: observed reliability
// is the payoff; latency, goodput and long-lived quality only break
// near-ties, so sample volume is never a bonus by itself. The policy
// priority factor scales the whole score.
func Utility(s *Snapshot, b Baseline) float64 {
	var latency float64
	if b.Probe.Valid {
		latency = correction(0, s.Probe, b.Probe, false)
	} else {
		latency = scopedCorrection(latency, s.Performance.Setup, b.Performance.Setup, s.TargetPerformance.Setup, b.TargetPerformance.Setup, false)
	}
	latency = scopedCorrection(latency, s.Performance.Response, b.Performance.Response, s.TargetPerformance.Response, b.TargetPerformance.Response, false)
	upload := scopedCorrection(0, s.Performance.Upload, b.Performance.Upload, s.TargetPerformance.Upload, b.TargetPerformance.Upload, true)
	download := scopedCorrection(0, s.Performance.Download, b.Performance.Download, s.TargetPerformance.Download, b.TargetPerformance.Download, true)
	quality := correction(0, s.Quality, b.Quality, true)
	u := s.Observed +
		utilityLatency*latency +
		utilityGoodput*max(upload, download) +
		utilityQuality*quality -
		utilityLossCost*lossPenalty(s.Loss)
	if s.Priority > 0 {
		u *= s.Priority
	}
	return u
}

// switchMargin is the gain a challenger needs over a trained incumbent:
// ten percent of the performance range at full evidence.
func switchMargin(completed float64) float64 {
	return 0.05 * performanceSwitchMargin * clamp01(completed/switchFullEvidence)
}

// NewBaselineOf computes the baseline over snapshot pointers.
func NewBaselineOf(snapshots []*Snapshot) Baseline {
	values := make([]Snapshot, len(snapshots))
	for i, s := range snapshots {
		values[i] = *s
	}
	return NewBaseline(values, nil)
}
