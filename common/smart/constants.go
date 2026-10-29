package smart

import "time"

// Evidence and scoring constants. The reliability, performance, switching,
// exploration and pool values follow honk's Score policy; the quality,
// loss, block and persistence values follow vernesong/mihomo's Smart group.
const (
	// Business reliability decays with this half-life.
	evidenceHalfLife = 30 * time.Minute
	// Standard deviations used for the Beta reliability bounds.
	reliabilityZ = 1.64
	// Members within this reliability distance of the best are comparable.
	reliabilityClose = 0.05

	// Fresh performance metrics lose confidence after half of this age and
	// expire at it, whatever their sample count.
	performanceMaxAge = 120 * time.Second
	// Observations needed for full metric confidence, cold qualification,
	// recovery and availability.
	validationSamples = 4.0
	// Effective completions needed before a decision is trusted at all.
	minTrainedEvidence = 0.5
	// Completions at which switching protection reaches its full margin and
	// a more specific evidence layer fully overrides its parent.
	switchFullEvidence = 8.0
	// Relative gain that counts as a real performance difference.
	performanceSwitchMargin = 0.1

	// Hard failures in a row that exclude a member while others are healthy.
	failStreakExclude = 3
	// Exploration backoff after a hard failure: base, doubling, capped.
	exploreBackoffBase = 5 * time.Minute
	exploreBackoffMax  = 6 * time.Hour

	// Transfer windows: a measured direction needs this many bytes within a
	// window of this length range.
	minThroughputBytes    = 64 * 1024
	minThroughputDuration = time.Second
	maxThroughputDuration = 10 * time.Second

	// A business RX keeps an earned qualification alive this long, and four
	// distinct reporters inside it recover a failed member.
	liveQualificationTTL = 60 * time.Second
	// A response this much slower than the same target's mature mean marks
	// the path degraded and reopens comparison.
	degradeFactor = 1.5

	// Utility weights: reliability is the payoff, performance only breaks
	// near-ties. quality carries the scene weight / LightGBM prediction.
	utilityLatency  = 0.03
	utilityGoodput  = 0.02
	utilityQuality  = 0.02
	utilityLossCost = 0.02

	// Long-lived quality average inertia.
	slowMetricCap = 16.0

	// Selection history (incumbents per target) capacity.
	historyCapacity = 4096
	// A switch back to the previous winner within this many ordinary
	// choices counts as a flap.
	switchFlapWindow = 8
)

// Exploration budget (honk budget.rs).
const (
	explorationPeriod     = 16 // each original start earns 1/16 trial
	busyExplorationPeriod = 8  // ... or 1/8 when busy and trials pay off
	busyRate              = 2.0
	earnedCap             = 8
	inFlightTTL           = 60 * time.Second
	yieldHalfLife         = 10 * time.Minute
	productiveWeight      = 2.5
	productiveShare       = 0.8
	pauseWeight           = 1.5
	halfOpenWeight        = 0.5
	failingShare          = 0.2
)

// Serving pool (honk evaluation.rs).
const (
	poolRefresh        = 5 * time.Minute
	poolSubstituteGap  = 30 * time.Second
	poolRotationSlot   = 10 * time.Minute
	demandHalfLife     = 5 * time.Minute
	poolMinMembers     = 3
	poolMaxMembers     = 25
	qualificationShare = 0.5
	rankHysteresis     = 2
)

// Evidence tables.
const (
	exactCapacity     = 16384
	siteCapacity      = 8192
	aggregateCapacity = 4096
	tableShards       = 64
)
