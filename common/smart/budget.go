package smart

import (
	"math"
	"sync"
)

// TrialKind says how an optional exploration attempt was funded.
type TrialKind uint8

const (
	TrialNone     TrialKind = iota
	TrialCold               // from the initial allowance
	TrialPeriodic           // from credit earned by business starts
	TrialRecovery           // budget-neutral half-open retry of a failed member
)

func (k TrialKind) String() string {
	switch k {
	case TrialCold:
		return "cold"
	case TrialPeriodic:
		return "periodic"
	case TrialRecovery:
		return "recovery"
	default:
		return ""
	}
}

// explorationTarget is the number of members the budget can keep exploring:
// all of them up to four, otherwise ceil(sqrt(n))+1.
func explorationTarget(n int) int {
	if n <= 4 {
		return n
	}
	return min(int(math.Ceil(math.Sqrt(float64(n))))+1, n)
}

type decayedOutcomes struct {
	success float64
	weight  float64
	at      Mono
}

func (d *decayedOutcomes) read(now Mono) (float64, float64) {
	if d.at == 0 {
		return 0, 0
	}
	f := decay(now.Sub(d.at), yieldHalfLife)
	return d.success * f, d.weight * f
}

func (d *decayedOutcomes) record(success bool, now Mono) {
	d.success, d.weight = d.read(now)
	d.weight++
	if success {
		d.success++
	}
	d.at = now
}

type inFlight struct {
	expires Mono
	kind    TrialKind
}

// Budget funds optional exploration for one (group, network, family) scope.
// It starts with a cold allowance B covering about sqrt(n) members, and each
// original business start earns 1/16 trial (1/8 while the group is busy and
// its trials pay off). Spent trials plus reservations never exceed B plus
// the earned credit, unspent credit is capped, and trials that keep failing
// while the ordinary choice works pause exploration.
type Budget struct {
	access sync.Mutex

	members       int
	coldAllowance int
	coldAvailable int
	credit        int // in 1/explorationPeriod units
	earned        int
	outcomes      decayedOutcomes
	inFlight      map[uint32]inFlight

	// counters
	BusinessStarts uint64
	TrialStarts    uint64
	ColdStarts     uint64
	PeriodicStarts uint64
	RecoveryStarts uint64
	BudgetBlocked  uint64
	InFlightBlock  uint64
	Refunded       uint64
	TrialSuccess   uint64
	TrialFailure   uint64
}

func NewBudget(members int) *Budget {
	allowance := explorationTarget(members)
	return &Budget{
		members:       members,
		coldAllowance: allowance,
		coldAvailable: allowance,
		inFlight:      make(map[uint32]inFlight),
	}
}

func (b *Budget) paused(now Mono) bool {
	success, weight := b.outcomes.read(now)
	if weight <= halfOpenWeight || success >= failingShare*weight {
		return false
	}
	if weight > pauseWeight {
		return true
	}
	for _, f := range b.inFlight {
		if f.expires > now && f.kind != TrialRecovery {
			return true
		}
	}
	return false
}

func (b *Budget) period(busy bool, now Mono) int {
	success, weight := b.outcomes.read(now)
	if busy && weight > productiveWeight && success >= productiveShare*weight {
		return busyExplorationPeriod
	}
	return explorationPeriod
}

// Earn records one original business start.
func (b *Budget) Earn(busy bool, now Mono) {
	b.access.Lock()
	b.BusinessStarts++
	b.credit += explorationPeriod / b.period(busy, now)
	for b.credit >= explorationPeriod {
		b.credit -= explorationPeriod
		if b.earned < earnedCap {
			b.earned++
		}
	}
	b.access.Unlock()
}

func (b *Budget) expireLocked(now Mono) {
	for node, f := range b.inFlight {
		if f.expires <= now {
			delete(b.inFlight, node)
		}
	}
}

// Busy reports whether node has an unanswered trial.
func (b *Budget) Busy(node uint32, now Mono) bool {
	b.access.Lock()
	defer b.access.Unlock()
	f, ok := b.inFlight[node]
	return ok && f.expires > now
}

// Reserve tries to fund one trial on node. usable says whether the ordinary
// selection is observed to work, which allows low-yield pausing.
func (b *Budget) Reserve(node uint32, recovery, usable bool, now Mono) (TrialKind, bool) {
	b.access.Lock()
	defer b.access.Unlock()
	b.expireLocked(now)
	if _, busy := b.inFlight[node]; busy {
		b.InFlightBlock++
		return TrialNone, false
	}
	kind := TrialRecovery
	if !recovery {
		if usable && b.paused(now) {
			b.BudgetBlocked++
			return TrialNone, false
		}
		switch {
		case b.coldAvailable > 0:
			b.coldAvailable--
			kind = TrialCold
			b.ColdStarts++
		case b.earned > 0:
			b.earned--
			kind = TrialPeriodic
			b.PeriodicStarts++
		default:
			b.BudgetBlocked++
			return TrialNone, false
		}
	} else {
		b.RecoveryStarts++
	}
	b.TrialStarts++
	b.inFlight[node] = inFlight{expires: now.Add(inFlightTTL), kind: kind}
	return kind, true
}

// Refund returns an unstarted reservation.
func (b *Budget) Refund(node uint32, kind TrialKind) {
	b.access.Lock()
	defer b.access.Unlock()
	if _, ok := b.inFlight[node]; !ok {
		return
	}
	delete(b.inFlight, node)
	b.Refunded++
	switch kind {
	case TrialCold:
		b.coldAvailable = min(b.coldAvailable+1, b.coldAllowance)
	case TrialPeriodic:
		b.earned = min(b.earned+1, earnedCap)
	}
}

// Settle records a finished trial's outcome. Cancelled trials count nothing.
func (b *Budget) Settle(node uint32, kind TrialKind, outcome Outcome, now Mono) {
	b.access.Lock()
	defer b.access.Unlock()
	delete(b.inFlight, node)
	if outcome == OutcomeCancelled || kind == TrialRecovery {
		return
	}
	success := outcome == OutcomeSuccess
	if success {
		b.TrialSuccess++
	} else {
		b.TrialFailure++
	}
	b.outcomes.record(success, now)
}

// BudgetState is a read-only view for the API.
type BudgetState struct {
	ColdAllowance  int     `json:"coldAllowance"`
	ColdAvailable  int     `json:"coldAvailable"`
	Earned         int     `json:"earnedAvailable"`
	EarningPeriod  int     `json:"earningPeriod"`
	Paused         bool    `json:"paused"`
	InFlight       int     `json:"inFlight"`
	TrialYield     float64 `json:"trialYield"`
	BusinessStarts uint64  `json:"businessStarts"`
	TrialStarts    uint64  `json:"trialStarts"`
	ColdStarts     uint64  `json:"coldTrialStarts"`
	PeriodicStarts uint64  `json:"periodicTrialStarts"`
	RecoveryStarts uint64  `json:"recoveryStarts"`
	BudgetBlocked  uint64  `json:"budgetBlocked"`
	InFlightBlock  uint64  `json:"inFlightBlocked"`
	Refunded       uint64  `json:"refunded"`
	TrialSuccess   uint64  `json:"trialSuccess"`
	TrialFailure   uint64  `json:"trialFailure"`
}

func (b *Budget) State(busy bool, now Mono) BudgetState {
	b.access.Lock()
	defer b.access.Unlock()
	success, weight := b.outcomes.read(now)
	yield := 0.0
	if weight > 0 {
		yield = success / weight
	}
	inflight := 0
	for _, f := range b.inFlight {
		if f.expires > now {
			inflight++
		}
	}
	return BudgetState{
		ColdAllowance:  b.coldAllowance,
		ColdAvailable:  b.coldAvailable,
		Earned:         b.earned,
		EarningPeriod:  b.period(busy, now),
		Paused:         b.paused(now),
		InFlight:       inflight,
		TrialYield:     yield,
		BusinessStarts: b.BusinessStarts,
		TrialStarts:    b.TrialStarts,
		ColdStarts:     b.ColdStarts,
		PeriodicStarts: b.PeriodicStarts,
		RecoveryStarts: b.RecoveryStarts,
		BudgetBlocked:  b.BudgetBlocked,
		InFlightBlock:  b.InFlightBlock,
		Refunded:       b.Refunded,
		TrialSuccess:   b.TrialSuccess,
		TrialFailure:   b.TrialFailure,
	}
}

// Reload keeps the earned currency but forgets trial outcomes and pending
// trials, and freezes a new cold allowance for the new membership.
func (b *Budget) Reload(members int) {
	b.access.Lock()
	defer b.access.Unlock()
	b.members = members
	b.coldAllowance = explorationTarget(members)
	b.coldAvailable = min(b.coldAvailable, b.coldAllowance)
	b.outcomes = decayedOutcomes{}
	clear(b.inFlight)
}
