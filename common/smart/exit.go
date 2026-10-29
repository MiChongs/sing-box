package smart

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"sync/atomic"
)

const (
	ExitProbeBodyLimit = 2048

	ReasonRegionUnavailable = "region unavailable"

	// A suspicion needs independent nodes of the same key, one answer never condemns a whole
	// region or network.
	suspectThreshold          = 2
	suspectMaxControlExitKeys = 16
	suspectMaxTargets         = 4096
	targetLabelMaxEntries     = 4096

	// exit probes keep their own slots; a slow trace cannot hold back the status probes
	exitProbeMaxInflight = 2
)

// ExitHalfOpenLease is how long a member holding a suspicion's half-open
// lease may probe it before another member may.
const ExitHalfOpenLease = 8 * time.Second

// The intervals are variables so a test can shrink them instead of waiting them out.
var (
	suspectConfirmWindow = 10 * time.Minute
	exitRegionTTL        = 6 * time.Hour
	exitProbeRetryGap    = 15 * time.Minute
	backfillInterval     = 2 * time.Second
	traceWitnessNodes    = 2
	noTraceTTL           = 6 * time.Hour
)

var exitProbeInflight = make(chan struct{}, exitProbeMaxInflight)

// ExitTraceURLs are tried in order, so a blocked endpoint costs a fallback, not the answer.
var ExitTraceURLs = []string{
	"https://www.cloudflare.com/cdn-cgi/trace",
	"https://api.ip.sb/geoip",
	"https://ipwho.is/",
}

// TraceUnanswerableError marks a trace endpoint that answered without an exit answer,
// which is a property of the asked host rather than of the node that carried the probe.
type TraceUnanswerableError struct {
	Reason string
}

type ExitProbeResult struct {
	Region string
	ASN    string
	Key    string
}

// ExitProber reports where a node's traffic lands; the address behind the answer is
// consumed by the probe itself and never handed back.
type ExitProber interface {
	ExitProbe(ctx context.Context, wantASN bool) (*ExitProbeResult, error)
}

type TargetExitProber interface {
	TargetExitProbe(ctx context.Context, host string, wantASN bool) (*ExitProbeResult, error)
}

type ExitInfo struct {
	Region  string `json:"region,omitempty"`
	ASN     string `json:"asn,omitempty"`
	Key     string `json:"key,omitempty"`
	Updated int64  `json:"updated,omitempty"`
}

type exitRecord struct {
	info   ExitInfo
	failed int64
}

type targetNodeKey struct {
	target string
	node   string
}

type targetRecord struct {
	info   ExitInfo
	failed int64
}

type suspectHalfOpen struct {
	owner   string
	until   int64
	expires int64
}

type ExitState struct {
	mu        sync.RWMutex
	nodes     map[string]*exitRecord
	targets   map[targetNodeKey]*targetRecord
	refusals  exitHold
	controls  exitHold
	noTrace   map[string]int64
	witnesses map[string]map[string]bool
}

// exitHold keeps one target per node, dropped once the confirm window passes.
type exitHold map[string]map[string]int64

type SuspectTracker struct {
	mu         sync.RWMutex
	pending    map[string]map[string]map[string]int64
	successes  map[string]map[string]map[string]int64
	suspected  map[string]map[string]int64
	halfOpen   map[string]map[string]suspectHalfOpen
	lastPruned atomic.Int64
	active     atomic.Bool
}

type ExitWatcher struct {
	ExitState

	name           string
	config         string
	options        ExitWatcherOptions
	wantASN        func() bool
	inflight       sync.Map // string
	targetInflight sync.Map // targetNodeKey
	seeded         sync.Map // string
	regions        SuspectTracker
	asns           SuspectTracker

	hostMu sync.Mutex
	hosts  map[string]string

	backfillAt map[string]int64
}

// ExitWatcherOptions wires an ExitWatcher to its group: persistence of the
// node exits, the pin owner and logging.
type ExitWatcherOptions struct {
	Name    string
	Config  string
	WantASN func() bool
	// Load returns a node's persisted exit and last failure (unix seconds).
	Load func(node string) (info ExitInfo, failed int64, ok bool)
	// Save persists a node's exit (failed == 0) or its failed attempt.
	Save func(node string, info ExitInfo, failed int64)
	// DropPin forgets the pinned winner of a target after a suspicion rose.
	DropPin func(target string)
	// Debug logs one line.
	Debug func(message string)
}

// ExitCandidate is one member offered to Backfill.
type ExitCandidate struct {
	Node   string
	Prober TargetExitProber
}

func (e *TraceUnanswerableError) Error() string { return e.Reason }

func IsTraceUnanswerable(err error) bool {
	var target *TraceUnanswerableError
	return errors.As(err, &target)
}

func (h *exitHold) add(target, node string, at int64) {
	if *h == nil {
		*h = make(exitHold)
	}
	for heldNode, targets := range *h {
		for heldTarget, heldAt := range targets {
			if at-heldAt > int64(suspectConfirmWindow) {
				delete(targets, heldTarget)
			}
		}
		if len(targets) == 0 {
			delete(*h, heldNode)
		}
	}
	if (*h)[node] == nil {
		(*h)[node] = make(map[string]int64)
	}
	(*h)[node][target] = at
}

func (h exitHold) take(node string, at int64) []string {
	targets := h[node]
	delete(h, node)
	if len(targets) == 0 {
		return nil
	}
	released := make([]string, 0, len(targets))
	for target, heldAt := range targets {
		if at-heldAt >= 0 && at-heldAt <= int64(suspectConfirmWindow) {
			released = append(released, target)
		}
	}
	return released
}

func (s *ExitState) Due(node string, ttl, retry time.Duration, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.nodes[node]
	if !ok {
		return true
	}
	if rec.info.Updated != 0 && now.Unix()-rec.info.Updated < int64(ttl.Seconds()) {
		return false
	}
	return rec.failed == 0 || now.Unix()-rec.failed >= int64(retry.Seconds())
}

func (s *ExitState) NoteFailure(node string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.record(node)
	rec.failed = now.Unix()
}

func (s *ExitState) Store(node string, info ExitInfo, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info.Updated = now.Unix()
	rec := s.record(node)
	rec.info = info
	rec.failed = 0
}

// Seed restores an earlier answer; a fresher in-memory answer always wins.
func (s *ExitState) Seed(node string, info ExitInfo) {
	if info.Updated == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.nodes[node]; ok && rec.info.Updated >= info.Updated {
		return
	}
	s.record(node).info = info
}

func (s *ExitState) Info(node string) ExitInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if rec, ok := s.nodes[node]; ok {
		return rec.info
	}
	return ExitInfo{}
}

func (s *ExitState) targetDue(target, node string, ttl, retry time.Duration, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if until, marked := s.noTrace[target]; marked && now.Unix() < until {
		return false
	}
	rec, ok := s.targets[targetNodeKey{target, node}]
	if !ok {
		return true
	}
	if rec.info.Updated != 0 && now.Unix()-rec.info.Updated < int64(ttl.Seconds()) {
		return false
	}
	return rec.failed == 0 || now.Unix()-rec.failed >= int64(retry.Seconds())
}

func (s *ExitState) TargetInfo(target, node string) ExitInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if rec, ok := s.targets[targetNodeKey{target, node}]; ok {
		return rec.info
	}
	return ExitInfo{}
}

func (s *ExitState) StoreTarget(target, node string, info ExitInfo, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.noTrace, target)
	delete(s.witnesses, target)
	key := targetNodeKey{target, node}
	rec, ok := s.targets[key]
	if !ok {
		if len(s.targets) >= targetLabelMaxEntries {
			s.pruneTargetsLocked(now)
			if len(s.targets) >= targetLabelMaxEntries {
				return
			}
		}
		if s.targets == nil {
			s.targets = make(map[targetNodeKey]*targetRecord)
		}
		rec = &targetRecord{}
		s.targets[key] = rec
	}
	info.Updated = now.Unix()
	rec.info = info
	rec.failed = 0
}

func (s *ExitState) pruneTargetsLocked(now time.Time) {
	for key, rec := range s.targets {
		if rec.info.Updated != 0 {
			if now.Unix()-rec.info.Updated > int64(exitRegionTTL.Seconds()) {
				delete(s.targets, key)
			}
			continue
		}
		if rec.failed != 0 && now.Unix()-rec.failed > int64(exitProbeRetryGap.Seconds()) {
			delete(s.targets, key)
		}
	}
	for target, until := range s.noTrace {
		if now.Unix() >= until {
			delete(s.noTrace, target)
			delete(s.witnesses, target)
		}
	}
}

func (s *ExitState) NoteTargetFailure(target, node string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := targetNodeKey{target, node}
	rec, ok := s.targets[key]
	if !ok {
		if len(s.targets) >= targetLabelMaxEntries {
			s.pruneTargetsLocked(now)
			if len(s.targets) >= targetLabelMaxEntries {
				return
			}
		}
		if s.targets == nil {
			s.targets = make(map[targetNodeKey]*targetRecord)
		}
		rec = &targetRecord{}
		s.targets[key] = rec
	}
	rec.failed = now.Unix()
}

// NoteTargetUnanswerable: enough distinct witnesses drop the target from probing.
func (s *ExitState) NoteTargetUnanswerable(target, node string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.witnesses == nil {
		s.witnesses = make(map[string]map[string]bool)
	}
	nodes := s.witnesses[target]
	if nodes == nil {
		if len(s.witnesses) >= targetLabelMaxEntries {
			return
		}
		nodes = make(map[string]bool)
		s.witnesses[target] = nodes
	}
	nodes[node] = true
	if len(nodes) < traceWitnessNodes {
		return
	}
	if s.noTrace == nil {
		s.noTrace = make(map[string]int64)
	}
	s.noTrace[target] = now.Add(noTraceTTL).Unix()
}

// Withhold holds a refusal until its node's exit answer arrives; Release completes it.
func (s *ExitState) Withhold(target, node string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refusals.add(target, node, time.Now().UnixNano())
}

// WithholdSuccess holds a 2xx control until its node's exit answer arrives, so the answer can
// still corroborate the refusal of another key; ReleaseSuccess replays it.
func (s *ExitState) WithholdSuccess(target, node string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.controls.add(target, node, time.Now().UnixNano())
}

func (s *ExitState) Release(node string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refusals.take(node, time.Now().UnixNano())
}

func (s *ExitState) ReleaseSuccess(node string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.controls.take(node, time.Now().UnixNano())
}

func (s *ExitState) record(node string) *exitRecord {
	if s.nodes == nil {
		s.nodes = make(map[string]*exitRecord)
	}
	rec, ok := s.nodes[node]
	if !ok {
		rec = &exitRecord{}
		s.nodes[node] = rec
	}
	return rec
}

func (t *SuspectTracker) Note(target, key, identity string, now time.Time) (raised bool) {
	if target == "" || key == "" || identity == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneIfDueLocked(now)

	if until, ok := t.suspected[target][key]; ok && until > now.UnixNano() {
		// a fresh refusal is more evidence, it carries the suspicion forward
		t.suspected[target][key] = now.Add(probeRegionalBlockTTL).UnixNano()
		delete(t.halfOpen[target], key)
		return false
	}
	if _, pending := t.pending[target]; !pending {
		if _, suspected := t.suspected[target]; !suspected && len(t.pending)+len(t.suspected) >= suspectMaxTargets {
			return false
		}
	}

	if t.pending == nil {
		t.pending = make(map[string]map[string]map[string]int64)
	}
	keys := t.pending[target]
	if keys == nil {
		keys = make(map[string]map[string]int64)
		t.pending[target] = keys
	}
	seen := keys[key]
	if seen == nil {
		seen = make(map[string]int64)
		keys[key] = seen
	}
	seen[identity] = now.UnixNano()
	if len(seen) < suspectThreshold || !t.hasControlSuccess(target, key, seen) {
		return false
	}

	if t.suspected == nil {
		t.suspected = make(map[string]map[string]int64)
	}
	suspicions := t.suspected[target]
	if suspicions == nil {
		suspicions = make(map[string]int64)
		t.suspected[target] = suspicions
	}
	suspicions[key] = now.Add(probeRegionalBlockTTL).UnixNano()
	delete(t.halfOpen[target], key)
	delete(keys, key)
	if len(keys) == 0 {
		delete(t.pending, target)
	}
	t.active.Store(true)
	return true
}

func (t *SuspectTracker) NoteSuccess(target, key, identity string, now time.Time) []string {
	if target == "" || key == "" || identity == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneIfDueLocked(now)
	failures := t.pending[target]
	for failedKey, identities := range failures {
		for failedIdentity, at := range identities {
			if now.Sub(time.Unix(0, at)) > suspectConfirmWindow {
				delete(identities, failedIdentity)
			}
		}
		if len(identities) == 0 {
			delete(failures, failedKey)
		}
	}
	if len(failures) == 0 {
		delete(t.pending, target)
	}
	controlSuccesses := t.successes[target]
	for successKey, identities := range controlSuccesses {
		for successIdentity, at := range identities {
			if now.Sub(time.Unix(0, at)) > suspectConfirmWindow {
				delete(identities, successIdentity)
			}
		}
		if len(identities) == 0 {
			delete(controlSuccesses, successKey)
		}
	}
	if len(controlSuccesses) == 0 {
		delete(t.successes, target)
	}
	if t.successes == nil {
		t.successes = make(map[string]map[string]map[string]int64)
	}
	keys := t.successes[target]
	if keys == nil {
		if len(t.successes) >= probeMaxEntries {
			return nil
		}
		keys = make(map[string]map[string]int64)
		t.successes[target] = keys
	}
	seen := keys[key]
	if _, exists := seen[identity]; !exists {
		controlCount := 0
		for _, identities := range keys {
			controlCount += len(identities)
		}
		if controlCount >= suspectMaxControlExitKeys {
			return nil
		}
	}
	if seen == nil {
		seen = make(map[string]int64)
		keys[key] = seen
	}
	seen[identity] = now.UnixNano()

	var raised []string
	for failedKey, identities := range t.pending[target] {
		if len(identities) < suspectThreshold || !t.hasControlSuccess(target, failedKey, identities) {
			continue
		}
		if t.suspected == nil {
			t.suspected = make(map[string]map[string]int64)
		}
		suspicions := t.suspected[target]
		if suspicions == nil {
			suspicions = make(map[string]int64)
			t.suspected[target] = suspicions
		}
		suspicions[failedKey] = now.Add(probeRegionalBlockTTL).UnixNano()
		delete(t.halfOpen[target], failedKey)
		delete(failures, failedKey)
		raised = append(raised, failedKey)
	}
	if len(failures) == 0 {
		delete(t.pending, target)
	}
	if len(raised) > 0 {
		t.active.Store(true)
	}
	return raised
}

func (t *SuspectTracker) hasControlSuccess(target, failedKey string, failures map[string]int64) bool {
	for successKey, identities := range t.successes[target] {
		if successKey == failedKey {
			continue
		}
		for identity := range identities {
			if _, sameExit := failures[identity]; !sameExit {
				return true
			}
		}
	}
	return false
}

func (t *SuspectTracker) Suspected(target, key string, now time.Time) bool {
	if !t.active.Load() || target == "" || key == "" {
		return false
	}
	// the cleanup mutates the maps, the lookup itself only reads them
	t.pruneIfDue(now)
	t.mu.RLock()
	defer t.mu.RUnlock()
	if until, ok := t.suspected[target][key]; ok {
		if until > now.UnixNano() {
			return true
		}
	}
	state, ok := t.halfOpen[target][key]
	return ok && state.owner != "" && state.until > now.UnixNano()
}

func (t *SuspectTracker) Active() bool {
	return t.active.Load()
}

func (t *SuspectTracker) Defer(target, key, owner string, now time.Time, lease time.Duration) bool {
	if !t.active.Load() || target == "" || key == "" || owner == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	nowNano := now.UnixNano()
	t.pruneIfDueLocked(now)
	until, suspected := t.suspected[target][key]
	if suspected && until > nowNano {
		return true
	}
	state, leased := t.halfOpen[target][key]
	if !suspected && !leased {
		return false
	}
	if suspected {
		delete(t.suspected[target], key)
		if len(t.suspected[target]) == 0 {
			delete(t.suspected, target)
		}
	}
	if leased && state.expires <= nowNano {
		delete(t.halfOpen[target], key)
		leased = false
	}
	if leased && state.owner != "" && state.until > nowNano {
		return true
	}
	if t.halfOpen == nil {
		t.halfOpen = make(map[string]map[string]suspectHalfOpen)
	}
	keys := t.halfOpen[target]
	if keys == nil {
		keys = make(map[string]suspectHalfOpen)
		t.halfOpen[target] = keys
	}
	state.owner = owner
	state.until = now.Add(lease).UnixNano()
	if state.expires == 0 {
		state.expires = now.Add(exitRegionTTL).UnixNano()
	}
	keys[key] = state
	t.active.Store(true)
	return true
}

func (t *SuspectTracker) ReleaseHalfOpen(target, key, owner string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if state, ok := t.halfOpen[target][key]; ok && state.owner == owner {
		state.owner = ""
		state.until = 0
		t.halfOpen[target][key] = state
	}
}

func (t *SuspectTracker) TryHalfOpen(target, key, owner string, now time.Time, lease time.Duration) bool {
	if target == "" || key == "" || owner == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	nowNano := now.UnixNano()
	until := t.suspected[target][key]
	state, leased := t.halfOpen[target][key]
	if leased && state.owner != "" && state.until > nowNano {
		return state.owner == owner
	}
	if until <= nowNano && (!leased || state.expires <= nowNano) {
		return false
	}
	if t.halfOpen == nil {
		t.halfOpen = make(map[string]map[string]suspectHalfOpen)
	}
	keys := t.halfOpen[target]
	if keys == nil {
		keys = make(map[string]suspectHalfOpen)
		t.halfOpen[target] = keys
	}
	if until <= nowNano {
		until = state.expires
	}
	keys[key] = suspectHalfOpen{owner: owner, until: now.Add(lease).UnixNano(), expires: until}
	t.active.Store(true)
	return true
}

// Clear drops a suspicion that a later answer has disproved.
func (t *SuspectTracker) Clear(target, key string) {
	if target == "" || key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if keys := t.pending[target]; keys != nil {
		delete(keys, key)
		if len(keys) == 0 {
			delete(t.pending, target)
		}
	}
	if keys := t.suspected[target]; keys != nil {
		delete(keys, key)
		if len(keys) == 0 {
			delete(t.suspected, target)
		}
	}
	if keys := t.halfOpen[target]; keys != nil {
		delete(keys, key)
		if len(keys) == 0 {
			delete(t.halfOpen, target)
		}
	}
	t.active.Store(len(t.suspected) > 0 || len(t.halfOpen) > 0)
}

func (t *SuspectTracker) prune(now time.Time) {
	nowNano := now.UnixNano()
	for target, keys := range t.pending {
		for key, seen := range keys {
			for identity, at := range seen {
				if now.Sub(time.Unix(0, at)) > suspectConfirmWindow {
					delete(seen, identity)
				}
			}
			if len(seen) == 0 {
				delete(keys, key)
			}
		}
		if len(keys) == 0 {
			delete(t.pending, target)
		}
	}
	for target, keys := range t.suspected {
		for key, until := range keys {
			if until <= nowNano {
				if t.halfOpen == nil {
					t.halfOpen = make(map[string]map[string]suspectHalfOpen)
				}
				halfOpen := t.halfOpen[target]
				if halfOpen == nil {
					halfOpen = make(map[string]suspectHalfOpen)
					t.halfOpen[target] = halfOpen
				}
				if _, exists := halfOpen[key]; !exists {
					halfOpen[key] = suspectHalfOpen{expires: now.Add(exitRegionTTL).UnixNano()}
				}
				delete(keys, key)
			}
		}
		if len(keys) == 0 {
			delete(t.suspected, target)
		}
	}
	for target, keys := range t.halfOpen {
		for key, state := range keys {
			if state.owner != "" && state.until <= nowNano {
				state.owner = ""
				state.until = 0
				keys[key] = state
			}
			if state.expires <= nowNano {
				delete(keys, key)
			}
		}
		if len(keys) == 0 {
			delete(t.halfOpen, target)
		}
	}
	for target, keys := range t.successes {
		for key, seen := range keys {
			for identity, at := range seen {
				if now.Sub(time.Unix(0, at)) > suspectConfirmWindow {
					delete(seen, identity)
				}
			}
			if len(seen) == 0 {
				delete(keys, key)
			}
		}
		if len(keys) == 0 {
			delete(t.successes, target)
		}
	}
	t.lastPruned.Store(nowNano)
	t.active.Store(len(t.suspected) > 0 || len(t.halfOpen) > 0)
}

// pruneDue reports whether the periodic cleanup is due; the caller decides which lock to take.
func (t *SuspectTracker) pruneDue(now time.Time) bool {
	interval := suspectConfirmWindow
	if interval > time.Minute {
		interval = time.Minute
	}
	return now.UnixNano()-t.lastPruned.Load() >= int64(interval)
}

// pruneIfDue runs the cleanup for a read path, it takes the write lock itself.
func (t *SuspectTracker) pruneIfDue(now time.Time) {
	if !t.pruneDue(now) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// another reader may have pruned while this one waited for the lock
	if !t.pruneDue(now) {
		return
	}
	t.prune(now)
}

// pruneIfDueLocked runs the cleanup for a caller that already holds the write lock.
func (t *SuspectTracker) pruneIfDueLocked(now time.Time) {
	if !t.pruneDue(now) {
		return
	}
	t.prune(now)
}

func NewExitWatcher(options ExitWatcherOptions) *ExitWatcher {
	return &ExitWatcher{name: options.Name, config: options.Config, options: options, wantASN: options.WantASN}
}

func (w *ExitWatcher) debugf(format string, args ...any) {
	if w.options.Debug != nil {
		w.options.Debug(fmt.Sprintf(format, args...))
	}
}

// TryStartExitProbe takes one exit probe slot; the returned function releases it.
func TryStartExitProbe() (func(), bool) {
	select {
	case exitProbeInflight <- struct{}{}:
		return func() { <-exitProbeInflight }, true
	default:
		return nil, false
	}
}

// MaybeProbe learns where a node's traffic lands, at most once per exitRegionTTL.
func (w *ExitWatcher) MaybeProbe(parent context.Context, node string, prober ExitProber) {
	if prober == nil {
		return
	}
	now := time.Now()
	w.EnsureLoaded(node)
	if !w.Due(node, exitRegionTTL, exitProbeRetryGap, now) {
		return
	}
	if _, loaded := w.inflight.LoadOrStore(node, struct{}{}); loaded {
		return
	}
	w.startProbe(parent, prober, node)
}

func (w *ExitWatcher) startProbe(parent context.Context, prober ExitProber, node string) {
	go func() {
		defer w.inflight.Delete(node)

		done, ok := TryStartExitProbe()
		if !ok {
			return
		}
		defer done()

		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, ProbeTimeout)
		defer cancel()

		wantASN := w.wantASN != nil && w.wantASN()
		result, err := prober.ExitProbe(ctx, wantASN)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				return
			}
			failedAt := time.Now()
			w.NoteFailure(node, failedAt)
			w.storeExitFailure(node, failedAt)
			w.debugf("[Smart] Exit probe [%s] node [%s] failed: %s", w.name, node, err.Error())
			return
		}

		w.Store(node, ExitInfo{Region: result.Region, ASN: result.ASN, Key: result.Key}, time.Now())
		w.debugf("[Smart] Exit probe [%s] node [%s] -> [%s]", w.name, node, describeExit(result.Region, result.ASN))
		w.storeExitState(node, w.Info(node))
		for _, target := range w.Release(node) {
			w.debugf("[Smart] Exit refusal released [%s] target [%s] node [%s]", w.name, target, node)
			w.confirm(target, node)
		}
		for _, target := range w.ReleaseSuccess(node) {
			w.debugf("[Smart] Exit control released [%s] target [%s] node [%s]", w.name, target, node)
			w.NoteSuccess(target, node)
		}
	}()
}

func (w *ExitWatcher) MaybeProbeTarget(parent context.Context, prober TargetExitProber, target, node, host string) {
	if target == "" || node == "" || host == "" {
		return
	}
	w.rememberHost(target, host)
	now := time.Now()
	if !w.targetDue(target, node, exitRegionTTL, exitProbeRetryGap, now) {
		return
	}
	if prober == nil {
		return
	}
	w.startTargetProbe(parent, prober, target, node, host)
}

func (w *ExitWatcher) startTargetProbe(parent context.Context, prober TargetExitProber, target, node, host string) {
	key := targetNodeKey{target, node}
	if _, loaded := w.targetInflight.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	done, ok := TryStartExitProbe()
	if !ok {
		w.targetInflight.Delete(key)
		return
	}

	go func() {
		defer w.targetInflight.Delete(key)
		defer done()

		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, ProbeTimeout)
		defer cancel()

		wantASN := w.wantASN != nil && w.wantASN()
		result, err := prober.TargetExitProbe(ctx, host, wantASN)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				return
			}
			w.NoteTargetFailure(target, node, time.Now())
			if IsTraceUnanswerable(err) {
				w.NoteTargetUnanswerable(target, node, time.Now())
			}
			w.debugf("[Smart] Target exit probe [%s] target [%s] node [%s] failed: %s", w.name, target, node, err.Error())
		} else {
			w.StoreTarget(target, node, ExitInfo{Region: result.Region, ASN: result.ASN, Key: result.Key}, time.Now())
			w.debugf("[Smart] Target exit probe [%s] target [%s] node [%s] -> [%s]", w.name, target, node, describeExit(result.Region, result.ASN))
		}
		w.replayHeld(node)
	}()
}

func (w *ExitWatcher) replayHeld(node string) {
	for _, t := range w.Release(node) {
		if region, asn, _ := w.exitLabel(t, node); region == "" && asn == "" {
			w.Withhold(t, node)
			continue
		}
		w.debugf("[Smart] Exit refusal released [%s] target [%s] node [%s]", w.name, t, node)
		w.confirm(t, node)
	}
	for _, t := range w.ReleaseSuccess(node) {
		if region, asn, _ := w.exitLabel(t, node); region == "" && asn == "" {
			w.WithholdSuccess(t, node)
			continue
		}
		w.debugf("[Smart] Exit control released [%s] target [%s] node [%s]", w.name, t, node)
		w.NoteSuccess(t, node)
	}
}

func (w *ExitWatcher) Backfill(ctx context.Context, target string, proxies []ExitCandidate) {
	if target == "" || len(proxies) == 0 {
		return
	}
	if !w.regions.Active() && !w.asns.Active() {
		return
	}
	host, ok := w.backfillDue(target)
	if !ok {
		return
	}
	if HostBackedOff(w.config, w.name, host) {
		return
	}
	for _, p := range proxies {
		if p.Prober == nil {
			continue
		}
		w.MaybeProbeTarget(ctx, p.Prober, target, p.Node, host)
	}
}

func (w *ExitWatcher) backfillDue(target string) (string, bool) {
	now := time.Now().Unix()
	w.hostMu.Lock()
	defer w.hostMu.Unlock()

	host, ok := w.hosts[target]
	if !ok || host == "" {
		return "", false
	}
	if until, ok := w.backfillAt[target]; ok && until > now {
		return "", false
	}
	if w.backfillAt == nil {
		w.backfillAt = make(map[string]int64)
	}
	if _, seen := w.backfillAt[target]; !seen && len(w.backfillAt) >= suspectMaxTargets {
		return host, true
	}
	w.backfillAt[target] = now + int64(backfillInterval.Seconds())
	return host, true
}

func (w *ExitWatcher) rememberHost(target, host string) {
	w.hostMu.Lock()
	defer w.hostMu.Unlock()
	if w.hosts == nil {
		w.hosts = make(map[string]string)
	}
	if _, ok := w.hosts[target]; !ok && len(w.hosts) >= suspectMaxTargets {
		return
	}
	w.hosts[target] = host
}

func (w *ExitWatcher) exitLabel(target, node string) (region, asn, key string) {
	if info := w.TargetInfo(target, node); info.Region != "" || info.ASN != "" {
		return info.Region, info.ASN, info.Key
	}
	info := w.Info(node)
	return info.Region, info.ASN, info.Key
}

// Label is exitLabel for callers that only annotate a connection: a node re-forwards one
// target to a different landing than the rest of its traffic.
func (w *ExitWatcher) Label(target, node string) (region, asn string) {
	region, asn, _ = w.exitLabel(target, node)
	return
}

// EnsureLoaded reads a node's stored answer once per run, so a connection arriving before
// any probe still reports it; a failed probe keeps its retry gap.
func (w *ExitWatcher) EnsureLoaded(node string) {
	if _, loaded := w.seeded.LoadOrStore(node, struct{}{}); loaded {
		return
	}
	info, failed, ok := w.loadExitState(node)
	if !ok {
		return
	}
	if info.Updated != 0 {
		w.Seed(node, info)
	}
	if failed != 0 {
		w.NoteFailure(node, time.Unix(failed, 0))
	}
}

// storeExitState keeps the learned exit where later runs can read it.
func (w *ExitWatcher) storeExitState(node string, info ExitInfo) {
	if w.options.Save != nil {
		w.options.Save(node, info, 0)
	}
}

// storeExitFailure persists the failed attempt, so a restart waits the retry
// gap again; the stored answer is kept.
func (w *ExitWatcher) storeExitFailure(node string, at time.Time) {
	if w.options.Save != nil {
		w.options.Save(node, w.Info(node), at.Unix())
	}
}

// loadExitState lets a restart reuse an answer that is still fresh.
func (w *ExitWatcher) loadExitState(node string) (ExitInfo, int64, bool) {
	if w.options.Load == nil {
		return ExitInfo{}, 0, false
	}
	return w.options.Load(node)
}

// Note blames a refusal on the node's own answer; while that answer is unknown the
// suspicion waits for it instead of being dropped. It reports whether a suspicion was raised.
func (w *ExitWatcher) Note(target, node string) bool {
	now := time.Now()
	if info := w.TargetInfo(target, node); info.Region == "" && info.ASN == "" {
		if w.targetDue(target, node, exitRegionTTL, exitProbeRetryGap, now) {
			w.Withhold(target, node)
			w.debugf("[Smart] Exit refusal held [%s] target [%s] node [%s]", w.name, target, node)
			return false
		}
	}
	return w.confirm(target, node)
}

// NoteSuccess records a 2xx control answer and reports whether it raised a suspicion for
// another key; a control arriving before the node's exit is held and replayed later.
func (w *ExitWatcher) NoteSuccess(target, node string) bool {
	now := time.Now()
	if info := w.TargetInfo(target, node); info.Region == "" && info.ASN == "" {
		if w.targetDue(target, node, exitRegionTTL, exitProbeRetryGap, now) {
			w.WithholdSuccess(target, node)
			w.debugf("[Smart] Exit control held [%s] target [%s] node [%s]", w.name, target, node)
			return false
		}
	}
	region, asn, key := w.exitLabel(target, node)
	identity := w.identity(key, node)
	raised := false
	raise := func(kind string, failed []string) {
		for _, failedKey := range failed {
			raised = true
			w.debugf("[Smart] Exit suspect [%s] target [%s] %s [%s] raised by a control from node [%s]", w.name, target, kind, failedKey, node)
		}
	}
	if region != "" {
		raise("region", w.regions.NoteSuccess(target, region, identity, now))
	}
	if w.wantASN != nil && w.wantASN() && asn != "" {
		raise("asn", w.asns.NoteSuccess(target, asn, identity, now))
	}
	if raised {
		w.dropUnwrapResult(target)
	}
	return raised
}

func (w *ExitWatcher) confirm(target, node string) bool {
	now := time.Now()
	region, asn, key := w.exitLabel(target, node)
	identity := w.identity(key, node)
	raised := false
	raise := func(kind, hitKey string, hit bool) {
		if !hit {
			return
		}
		raised = true
		w.debugf("[Smart] Exit suspect [%s] target [%s] %s [%s] raised by node [%s]", w.name, target, kind, hitKey, node)
	}
	if region != "" {
		raise("region", region, w.regions.Note(target, region, identity, now))
	}
	if w.wantASN != nil && w.wantASN() && asn != "" {
		raise("asn", asn, w.asns.Note(target, asn, identity, now))
	}
	if raised {
		w.dropUnwrapResult(target)
	}
	return raised
}

// A target pinned to a node of the suspected key would keep dialing that node, so the pin is
// dropped and the next selection ranks the nodes again.
func (w *ExitWatcher) dropUnwrapResult(target string) {
	if w.options.DropPin == nil {
		return
	}
	w.options.DropPin(target)
	w.debugf("[Smart] Exit suspect [%s] target [%s] unwrap pin cleared", w.name, target)
}

// identity tells the exit machines of two nodes apart, falling back to the node name.
func (w *ExitWatcher) identity(key, node string) string {
	if key != "" {
		return key
	}
	return node
}

func describeExit(region, asn string) string {
	if asn == "" {
		return "GeoIP [" + region + "]"
	}
	return "GeoIP [" + region + "] -> ASN [" + asn + "]"
}

func (w *ExitWatcher) Suspected(target, node string) bool {
	if !w.regions.Active() && !w.asns.Active() {
		return false
	}
	now := time.Now()
	region, asn, _ := w.exitLabel(target, node)
	if region != "" && w.regions.Suspected(target, region, now) {
		return true
	}
	if w.wantASN != nil && w.wantASN() && asn != "" && w.asns.Suspected(target, asn, now) {
		return true
	}
	return false
}

func (w *ExitWatcher) Defer(target, node string, now time.Time, lease time.Duration) bool {
	if !w.regions.Active() && !w.asns.Active() {
		return false
	}
	region, asn, _ := w.exitLabel(target, node)
	if w.wantASN != nil && w.wantASN() && asn != "" && w.asns.Defer(target, asn, node, now, lease) {
		return true
	}
	if region == "" {
		return false
	}
	return w.regions.Defer(target, region, node, now, lease)
}

func (w *ExitWatcher) AllowFallback(target, node string, now time.Time, lease time.Duration) bool {
	region, asn, _ := w.exitLabel(target, node)
	regionSuspected := region != "" && w.regions.Suspected(target, region, now)
	asnSuspected := w.wantASN != nil && w.wantASN() && asn != "" && w.asns.Suspected(target, asn, now)
	if !regionSuspected && !asnSuspected {
		return true
	}
	claimedASN := false
	if asnSuspected {
		if !w.asns.TryHalfOpen(target, asn, node, now, lease) {
			return false
		}
		claimedASN = true
	}
	if regionSuspected && !w.regions.TryHalfOpen(target, region, node, now, lease) {
		if claimedASN {
			w.asns.ReleaseHalfOpen(target, asn, node)
		}
		return false
	}
	return true
}

func (w *ExitWatcher) Clear(target, node string) {
	info := w.TargetInfo(target, node)
	region, asn := info.Region, info.ASN
	if region == "" && asn == "" {
		if w.targetDue(target, node, exitRegionTTL, exitProbeRetryGap, time.Now()) {
			return
		}
		fallback := w.Info(node)
		region, asn = fallback.Region, fallback.ASN
	}
	if region != "" {
		w.regions.Clear(target, region)
	}
	if w.wantASN != nil && w.wantASN() && asn != "" {
		w.asns.Clear(target, asn)
	}
}

// ParseExitAnswer reads the region and address out of any of the exit endpoints; the
// address is only for the caller's own lookup and must not be stored.
func ParseExitAnswer(body []byte) (region string, ip netip.Addr) {
	if region, ip = ParseExitTrace(body); region != "" {
		return region, ip
	}
	var answer struct {
		CountryCode string `json:"country_code"`
		Country     string `json:"country"`
		IP          string `json:"ip"`
	}
	if json.Unmarshal(body, &answer) != nil {
		return "", netip.Addr{}
	}
	code := answer.CountryCode
	if code == "" && len(answer.Country) == 2 {
		code = answer.Country
	}
	if code = strings.ToLower(strings.TrimSpace(code)); len(code) != 2 {
		return "", netip.Addr{}
	}
	if parsed, err := netip.ParseAddr(strings.TrimSpace(answer.IP)); err == nil {
		ip = parsed
	}
	return code, ip
}

func ParseExitTrace(body []byte) (region string, ip netip.Addr) {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "loc":
			if v := strings.ToLower(strings.TrimSpace(value)); len(v) == 2 {
				region = v
			}
		case "ip":
			if v, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil {
				ip = v
			}
		}
	}
	return region, ip
}

// IsRegionUnavailableLocation tells a region refusal apart from an ordinary relocation.
func IsRegionUnavailableLocation(location string) bool {
	if location == "" {
		return false
	}
	location = strings.ToLower(location)
	for _, pattern := range []string{
		"app-unavailable-in-region",
		"/welcome/unavailable",
		"unavailable-in-region",
		"region-unavailable",
		"not-available-in-your-region",
		"unsupported-region",
	} {
		if strings.Contains(location, pattern) {
			return true
		}
	}
	region := false
	for _, word := range []string{"region", "country", "location", "geo-block", "geoblock", "geo-restrict", "georestrict"} {
		if strings.Contains(location, word) {
			region = true
			break
		}
	}
	if !region {
		return false
	}
	for _, word := range []string{"unavailable", "not-available", "notavailable", "unsupported", "blocked", "restricted", "denied"} {
		if strings.Contains(location, word) {
			return true
		}
	}
	return false
}

// IsRegionUnavailableText recognizes a refusal that is only stated in the page body.
func IsRegionUnavailableText(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	text := strings.ReplaceAll(strings.ToLower(string(body)), "_", " ")
	for _, phrase := range []string{
		"not available in your region",
		"not available in your country",
		"not available in your area",
		"not available in your location",
		"not available in your territory",
		"unavailable in your region",
		"unavailable in your country",
		"not available in this region",
		"not available in this country",
		"not available in the region",
		"unsupported country",
		"unsupported region",
		"region is not supported",
		"country is not supported",
		"not supported in your country",
		"not supported in your region",
		"blocked in your region",
		"blocked in your country",
		"geo-blocked",
		"geoblocked",
		"geo-restricted",
		"georestricted",
		"地区不可用",
		"所在地区不可用",
		"不支持您所在的",
		"您所在的地区",
		"お住まいの地域",
		"お住まいの国",
		"地域ではご利用",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

// ExitKey derives a pseudonymous identity of an exit address: nodes behind the same
// machine share it, and the address itself is never kept.
func ExitKey(ip netip.Addr) string {
	sum := sha256.Sum256(ip.AsSlice())
	return hex.EncodeToString(sum[:6])
}
