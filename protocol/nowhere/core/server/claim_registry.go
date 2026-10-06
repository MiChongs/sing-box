package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

type claimKey struct {
	sessionID wire.SessionID
	flowID    wire.FlowID
}

type claimMetadata struct {
	Kind     wire.FlowKind
	Uplink   wire.Carrier
	Downlink wire.Carrier
	Hops     uint8
}

func (m claimMetadata) equal(other claimMetadata) bool {
	return m.Kind == other.Kind && m.Uplink == other.Uplink && m.Downlink == other.Downlink && m.Hops == other.Hops
}

type flowClaim struct {
	SessionID       wire.SessionID
	FlowID          wire.FlowID
	Generation      uint64
	BoundGeneration bool
	Role            wire.FlowRole
	Carrier         wire.Carrier
	Metadata        claimMetadata
	Target          wire.Target
	Stream          net.Conn
	UDP             udpHalf
	Source          net.Addr
}

func (c flowClaim) selected() bool {
	return c.Carrier == c.Metadata.Downlink
}

func (c flowClaim) close(cause error) {
	if c.UDP.Uplink != nil || c.UDP.Downlink != nil {
		closeUDPHalfWithError(c.UDP, cause)
		return
	}
	closeConnWithError(c.Stream, cause)
}

func setupResultForClaim(claim flowClaim) *setupResult {
	if !claim.selected() || claim.Stream == nil {
		return nil
	}
	return newSetupResult(claim.Stream, claim.Metadata.Kind, claim.Metadata.Downlink)
}

type claimEntryState uint8

const (
	claimPending claimEntryState = iota
	claimActive
	claimTerminal
)

type claimEntry struct {
	key              claimKey
	generation       uint64
	metadata         claimMetadata
	target           wire.Target
	open             *flowClaim
	attach           *flowClaim
	duplex           *flowClaim
	selected         *setupResult
	state            claimEntryState
	done             chan struct{}
	err              error
	timer            *time.Timer
	permit           *udpPermit
	pendingTCP       bool
	terminalConsumed bool
	expiredAt        time.Time
	active           *claimedFlow
}

type claimedFlow struct {
	Metadata  claimMetadata
	Target    wire.Target
	Open      *flowClaim
	Attach    *flowClaim
	Duplex    *flowClaim
	Selected  flowClaim
	Readiness *flowReadiness
	Context   context.Context

	registry *claimRegistry
	entry    *claimEntry
	once     sync.Once
}

func (f *claimedFlow) Release() {
	if f == nil {
		return
	}
	f.once.Do(func() {
		if f.registry != nil {
			f.registry.releaseActive(f.entry)
		}
	})
}

type udpPermit struct {
	registry *claimRegistry
	key      sessionGeneration
	once     sync.Once
}

func (p *udpPermit) Release() {
	if p == nil || p.registry == nil {
		return
	}
	p.once.Do(func() {
		p.registry.mu.Lock()
		if count := p.registry.udpInUse[p.key]; count <= 1 {
			delete(p.registry.udpInUse, p.key)
		} else {
			p.registry.udpInUse[p.key] = count - 1
		}
		p.registry.maybeCleanupGenerationLocked(p.key.sessionID)
		p.registry.mu.Unlock()
	})
}

type sessionGeneration struct {
	sessionID  wire.SessionID
	generation uint64
}

type generationProvenance uint8

const (
	generationProvisional generationProvenance = iota + 1
	generationPhysical
)

type pendingClaimCleanup struct {
	claims   []flowClaim
	selected *setupResult
	permit   *udpPermit
}

type activeClaimCleanup struct {
	flow   *claimedFlow
	permit *udpPermit
}

type claimAbort struct {
	once  sync.Once
	close func(error)
}

func (a *claimAbort) Close(cause error) {
	if a == nil {
		return
	}
	a.once.Do(func() {
		if a.close != nil {
			a.close(cause)
		}
	})
}

type sessionReplacementCleanup struct {
	cause   error
	pending []pendingClaimCleanup
	active  []activeClaimCleanup
}

func (c *sessionReplacementCleanup) run() {
	if c == nil {
		return
	}
	for _, failure := range c.pending {
		if failure.selected != nil {
			_ = failure.selected.reject(wire.SetupResultSessionReplaced)
		}
		for _, claim := range failure.claims {
			claim.close(c.cause)
		}
		failure.permit.Release()
	}
	for _, failure := range c.active {
		if failure.flow != nil {
			_ = failure.flow.Readiness.Reject(c.cause)
			if cancel := contextCancel(failure.flow.Context); cancel != nil {
				cancel(c.cause)
			}
			closeClaimedFlow(failure.flow, c.cause)
		}
		failure.permit.Release()
	}
}

type claimRegistry struct {
	mu sync.Mutex

	pairTimeout    time.Duration
	limits         Limits
	terminalLimit  int
	observer       diagnostic.Observer
	entries        map[claimKey]*claimEntry
	closing        []*claimAbort
	terminalOrder  []*claimEntry
	generations    map[wire.SessionID]uint64
	registered     map[sessionGeneration]int
	provenance     map[sessionGeneration]generationProvenance
	pending        map[wire.SessionID]int
	udpInUse       map[sessionGeneration]int
	nextGeneration uint64
	idleTCP        int
	accepting      bool
	closed         bool
}

func newClaimRegistry(pairTimeout time.Duration, limits Limits) *claimRegistry {
	if pairTimeout <= 0 {
		pairTimeout = DefaultFlowPairTimeout
	}
	if limits.PendingFlowsPerSession <= 0 {
		limits.PendingFlowsPerSession = DefaultPendingFlowsPerSession
	}
	if limits.UDPFlowsPerSession <= 0 {
		limits.UDPFlowsPerSession = DefaultUDPFlowsPerSession
	}
	if limits.AuthenticatedTCPIdleConnections <= 0 {
		limits.AuthenticatedTCPIdleConnections = DefaultAuthenticatedTCPIdleConnections
	}
	return &claimRegistry{
		pairTimeout:   pairTimeout,
		limits:        limits,
		terminalLimit: limits.PendingFlowsPerSession,
		entries:       make(map[claimKey]*claimEntry),
		generations:   make(map[wire.SessionID]uint64),
		registered:    make(map[sessionGeneration]int),
		provenance:    make(map[sessionGeneration]generationProvenance),
		pending:       make(map[wire.SessionID]int),
		udpInUse:      make(map[sessionGeneration]int),
		accepting:     true,
	}
}

func (r *claimRegistry) CurrentGeneration(sessionID wire.SessionID) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.generations[sessionID]
}

func (r *claimRegistry) nextGenerationLocked() uint64 {
	r.nextGeneration++
	if r.nextGeneration == 0 {
		panic("nowhere: session generation exhausted")
	}
	return r.nextGeneration
}

func (r *claimRegistry) observeGenerationLocked(generation uint64) {
	if generation > r.nextGeneration {
		r.nextGeneration = generation
	}
}

func (r *claimRegistry) beginSessionRegistration(sessionID wire.SessionID, replacing bool, cause error) (uint64, *sessionReplacementCleanup) {
	cause = markForcedTermination(cause)
	r.mu.Lock()
	generation := uint64(0)
	current := r.generations[sessionID]
	currentKey := sessionGeneration{sessionID: sessionID, generation: current}
	if !replacing && current != 0 && r.provenance[currentKey] == generationProvisional &&
		!r.hasRegisteredSessionLocked(sessionID) && r.hasLiveProvisionalLocked(sessionID, current) {
		generation = current
	}
	if generation == 0 {
		generation = r.nextGenerationLocked()
	}
	key := sessionGeneration{sessionID: sessionID, generation: generation}
	r.generations[sessionID] = generation
	r.provenance[key] = generationPhysical
	r.registered[key]++
	cleanup := r.detachSessionLocked(sessionID, generation, cause)
	r.mu.Unlock()
	return generation, cleanup
}

func (r *claimRegistry) hasRegisteredSessionLocked(sessionID wire.SessionID) bool {
	for key, count := range r.registered {
		if key.sessionID == sessionID && count > 0 {
			return true
		}
	}
	return false
}

func (r *claimRegistry) hasLiveProvisionalLocked(sessionID wire.SessionID, generation uint64) bool {
	for key, entry := range r.entries {
		if key.sessionID == sessionID && entry.generation == generation && entry.state != claimTerminal {
			return true
		}
	}
	return r.udpInUse[sessionGeneration{sessionID: sessionID, generation: generation}] > 0
}

func (r *claimRegistry) unregisterSessionGeneration(sessionID wire.SessionID, generation uint64) {
	if r == nil || generation == 0 {
		return
	}
	r.mu.Lock()
	key := sessionGeneration{sessionID: sessionID, generation: generation}
	if count := r.registered[key]; count <= 1 {
		delete(r.registered, key)
	} else {
		r.registered[key] = count - 1
	}
	r.maybeCleanupGenerationLocked(sessionID)
	r.mu.Unlock()
}

func (r *claimRegistry) Submit(ctx context.Context, claim flowClaim) (*claimedFlow, error) {
	if claim.BoundGeneration && claim.Generation == 0 {
		err := fmt.Errorf("%w: zero bound generation", ErrCarrierMismatch)
		if result := setupResultForClaim(claim); result != nil {
			_ = result.reject(wire.SetupResultInvalidRequest)
		}
		claim.close(err)
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateClaim(claim); err != nil {
		if result := setupResultForClaim(claim); result != nil {
			_ = result.reject(setupFailureCode(err))
		}
		claim.close(err)
		return nil, err
	}

	key := claimKey{sessionID: claim.SessionID, flowID: claim.FlowID}
	r.mu.Lock()
	if !r.accepting {
		r.mu.Unlock()
		if result := setupResultForClaim(claim); result != nil {
			_ = result.reject(wire.SetupResultFlowLimit)
		}
		claim.close(ErrDraining)
		return nil, ErrDraining
	}
	r.expireTerminalsLocked(time.Now())
	sessionClaims := 0
	for existing, entry := range r.entries {
		if existing.sessionID == claim.SessionID && (entry.state == claimPending || entry.state == claimActive) {
			sessionClaims++
		}
	}
	if sessionClaims >= r.limits.PendingFlowsPerSession || len(r.entries) >= DefaultPortalClaims {
		r.mu.Unlock()
		err := fmt.Errorf("%w: claim admission", ErrPairLimit)
		if result := setupResultForClaim(claim); result != nil {
			_ = result.reject(wire.SetupResultFlowLimit)
		}
		claim.close(err)
		return nil, err
	}
	generation := r.generations[claim.SessionID]
	if generation == 0 && !claim.BoundGeneration {
		generation = claim.Generation
		if generation == 0 {
			generation = r.nextGenerationLocked()
		} else {
			r.observeGenerationLocked(generation)
		}
		r.generations[claim.SessionID] = generation
		r.provenance[sessionGeneration{sessionID: claim.SessionID, generation: generation}] = generationProvisional
	}
	if claim.Generation == 0 {
		claim.Generation = generation
	}
	registered := r.registered[sessionGeneration{sessionID: claim.SessionID, generation: claim.Generation}] > 0
	if generation == 0 || claim.Generation != generation || (claim.BoundGeneration && !registered) {
		r.mu.Unlock()
		err := fmt.Errorf("%w: stale generation %d, current %d", ErrClosed, claim.Generation, generation)
		if result := setupResultForClaim(claim); result != nil {
			_ = result.reject(wire.SetupResultSessionReplaced)
		}
		claim.close(err)
		return nil, err
	}

	if existing := r.entries[key]; existing != nil {
		return r.submitExistingLocked(ctx, existing, claim)
	}

	permit, err := r.acquireUDPPermitLocked(claim)
	if err != nil {
		r.mu.Unlock()
		if result := setupResultForClaim(claim); result != nil {
			_ = result.reject(wire.SetupResultFlowLimit)
		}
		claim.close(err)
		return nil, err
	}

	entry := &claimEntry{
		key: key, generation: claim.Generation, metadata: claim.Metadata,
		done: make(chan struct{}), permit: permit,
	}
	if claim.Role == wire.FlowRoleDuplex {
		entry.duplex = cloneFlowClaim(claim)
		entry.target = claim.Target
		entry.selected = setupResultForClaim(claim)
		entry.state = claimActive
		active := r.activateLocked(entry)
		r.entries[key] = entry
		r.mu.Unlock()
		return active, nil
	}

	if r.pending[claim.SessionID] >= r.limits.PendingFlowsPerSession ||
		(claim.Carrier == wire.CarrierTLSTCP && r.idleTCP >= r.limits.AuthenticatedTCPIdleConnections) {
		r.maybeCleanupGenerationLocked(claim.SessionID)
		r.mu.Unlock()
		permit.Release()
		err := fmt.Errorf("%w: pending flow budget", ErrPairLimit)
		if result := setupResultForClaim(claim); result != nil {
			_ = result.reject(wire.SetupResultFlowLimit)
		}
		claim.close(err)
		return nil, err
	}
	entry.state = claimPending
	entry.selected = setupResultForClaim(claim)
	entry.pendingTCP = claim.Carrier == wire.CarrierTLSTCP
	if claim.Role == wire.FlowRoleOpen {
		entry.open = cloneFlowClaim(claim)
		entry.target = claim.Target
	} else {
		entry.attach = cloneFlowClaim(claim)
	}
	r.pending[claim.SessionID]++
	if entry.pendingTCP {
		r.idleTCP++
	}
	r.entries[key] = entry
	entry.timer = time.AfterFunc(r.pairTimeout, func() { r.timeout(entry) })
	waitEvent := claimPairEvent("pair_wait", entry, &claim, nil)
	r.mu.Unlock()
	r.emitPair(ctx, waitEvent)
	return r.waitPending(ctx, entry)
}

func (r *claimRegistry) submitExistingLocked(ctx context.Context, entry *claimEntry, claim flowClaim) (*claimedFlow, error) {
	if entry.state == claimTerminal {
		err := entry.err
		result := setupResultForClaim(claim)
		write := result != nil && !entry.terminalConsumed
		if write {
			entry.terminalConsumed = true
		}
		r.mu.Unlock()
		if write {
			_ = result.reject(setupFailureCode(err))
		}
		claim.close(err)
		return nil, err
	}

	if entry.state == claimActive {
		err := fmt.Errorf("%w: conflicting active flow claim", ErrMetadataConflict)
		result := setupResultForClaim(claim)
		r.mu.Unlock()
		if result != nil {
			_ = result.reject(wire.SetupResultMetadataConflict)
		}
		claim.close(err)
		return nil, err
	}

	metadataConflict := entry.generation != claim.Generation || !entry.metadata.equal(claim.Metadata)
	duplicateHalf := (entry.open != nil && claim.Role == wire.FlowRoleOpen) ||
		(entry.attach != nil && claim.Role == wire.FlowRoleAttach) || claim.Role == wire.FlowRoleDuplex
	if metadataConflict || duplicateHalf {
		cause := ErrMetadataConflict
		if duplicateHalf && !metadataConflict {
			cause = ErrDuplicateHalf
		}
		err := fmt.Errorf("%w: conflicting flow claim", cause)
		claims, selected, permit := r.failPendingLocked(entry, err, true)
		currentResult := setupResultForClaim(claim)
		if currentResult != nil && selected == nil {
			selected = currentResult
			entry.terminalConsumed = true
		}
		r.mu.Unlock()
		if selected != nil {
			_ = selected.reject(wire.SetupResultMetadataConflict)
		}
		for _, existing := range claims {
			existing.close(err)
		}
		claim.close(err)
		permit.Release()
		return nil, err
	}

	if claim.Role == wire.FlowRoleOpen {
		entry.open = cloneFlowClaim(claim)
		entry.target = claim.Target
	} else {
		entry.attach = cloneFlowClaim(claim)
	}
	if result := setupResultForClaim(claim); result != nil {
		entry.selected = result
	}
	r.finishPendingLocked(entry)
	entry.state = claimActive
	active := r.activateLocked(entry)
	close(entry.done)
	successEvent := claimPairEvent("pair_success", entry, &claim, nil)
	r.mu.Unlock()
	r.emitPair(ctx, successEvent)
	return active, nil
}

func (r *claimRegistry) waitPending(ctx context.Context, entry *claimEntry) (*claimedFlow, error) {
	select {
	case <-entry.done:
		r.mu.Lock()
		state, err := entry.state, entry.err
		r.mu.Unlock()
		if state == claimActive {
			return nil, nil
		}
		return nil, err
	case <-ctx.Done():
		r.mu.Lock()
		if current := r.entries[entry.key]; current == entry && entry.state == claimPending {
			cause := context.Cause(ctx)
			if cause == nil {
				cause = ctx.Err()
			}
			claims, selected, permit := r.failPendingLocked(entry, cause, true)
			r.mu.Unlock()
			if selected != nil {
				_ = selected.reject(setupFailureCode(cause))
			}
			for _, claim := range claims {
				claim.close(cause)
			}
			permit.Release()
			return nil, cause
		}
		state, err := entry.state, entry.err
		r.mu.Unlock()
		if state == claimActive {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return nil, ctx.Err()
	}
}

func (r *claimRegistry) timeout(entry *claimEntry) {
	r.mu.Lock()
	if current := r.entries[entry.key]; current != entry || entry.state != claimPending {
		r.mu.Unlock()
		return
	}
	err := fmt.Errorf("%w: flow=%d", ErrPairTimeout, entry.key.flowID)
	received := entry.open
	if received == nil {
		received = entry.attach
	}
	timeoutEvent := claimPairEvent("pair_timeout", entry, received, err)
	claims, selected, permit := r.failPendingLocked(entry, err, true)
	r.mu.Unlock()
	r.emitPair(context.Background(), timeoutEvent)
	if selected != nil {
		_ = selected.reject(wire.SetupResultPairTimeout)
	}
	for _, claim := range claims {
		claim.close(err)
	}
	permit.Release()
}

func (r *claimRegistry) Reject(sessionID wire.SessionID, flowID wire.FlowID, generation uint64, cause error) {
	_, _ = r.reject(sessionID, flowID, generation, false, cause)
}

func (r *claimRegistry) reject(sessionID wire.SessionID, flowID wire.FlowID, generation uint64, boundGeneration bool, cause error) (bool, wire.SetupResult) {
	if boundGeneration && generation == 0 {
		return false, wire.SetupResultMetadataConflict
	}
	if cause == nil {
		cause = errors.New("nowhere: invalid request")
	}
	key := claimKey{sessionID: sessionID, flowID: flowID}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return false, wire.SetupResultSessionReplaced
	}
	current := r.generations[sessionID]
	if current == 0 && !boundGeneration {
		current = generation
		if current == 0 {
			current = r.nextGenerationLocked()
		} else {
			r.observeGenerationLocked(current)
		}
		r.generations[sessionID] = current
		r.provenance[sessionGeneration{sessionID: sessionID, generation: current}] = generationProvisional
	}
	if generation == 0 {
		generation = current
	}
	registered := r.registered[sessionGeneration{sessionID: sessionID, generation: generation}] > 0
	if current == 0 || generation != current || (boundGeneration && !registered) {
		r.mu.Unlock()
		return false, wire.SetupResultMetadataConflict
	}
	entry := r.entries[key]
	if entry == nil {
		entry = &claimEntry{
			key: key, generation: generation, state: claimTerminal,
			done: make(chan struct{}), err: cause,
		}
		close(entry.done)
		r.addTerminalLocked(entry)
		r.mu.Unlock()
		return true, 0
	}
	if entry.generation != generation {
		r.mu.Unlock()
		return false, wire.SetupResultMetadataConflict
	}
	if entry.state == claimTerminal {
		r.mu.Unlock()
		return true, 0
	}
	if entry.state == claimPending {
		claims, selected, permit := r.failPendingLocked(entry, cause, true)
		r.mu.Unlock()
		if selected != nil {
			_ = selected.reject(setupFailureCode(cause))
		}
		for _, claim := range claims {
			claim.close(cause)
		}
		permit.Release()
		return true, 0
	}
	active := entry.active
	permit := entry.permit
	entry.permit = nil
	delete(r.entries, key)
	r.maybeCleanupGenerationLocked(sessionID)
	r.mu.Unlock()
	if active != nil {
		_ = active.Readiness.Reject(cause)
		if cancel := contextCancel(active.Context); cancel != nil {
			cancel(cause)
		}
		closeClaimedFlow(active, cause)
	}
	permit.Release()
	return true, 0
}

func (r *claimRegistry) RejectClaim(claim flowClaim, cause error) {
	accepted, rejectionCode := r.reject(claim.SessionID, claim.FlowID, claim.Generation, claim.BoundGeneration, cause)
	result := setupResultForClaim(claim)
	if !accepted {
		if result != nil {
			_ = result.reject(rejectionCode)
		}
		claim.close(cause)
		return
	}
	if result == nil {
		claim.close(cause)
		return
	}
	key := claimKey{sessionID: claim.SessionID, flowID: claim.FlowID}
	r.mu.Lock()
	entry := r.entries[key]
	write := entry != nil && entry.state == claimTerminal && !entry.terminalConsumed
	if write {
		entry.terminalConsumed = true
	}
	r.mu.Unlock()
	if write {
		_ = result.reject(setupFailureCode(cause))
	}
	claim.close(cause)
}

func (r *claimRegistry) ReplaceSession(sessionID wire.SessionID, generation uint64, cause error) {
	cause = markForcedTermination(cause)
	r.mu.Lock()
	if generation == 0 {
		generation = r.nextGenerationLocked()
	} else {
		r.observeGenerationLocked(generation)
	}
	r.generations[sessionID] = generation
	r.provenance[sessionGeneration{sessionID: sessionID, generation: generation}] = generationPhysical
	cleanup := r.detachSessionLocked(sessionID, generation, cause)
	r.mu.Unlock()
	cleanup.run()
}

func (r *claimRegistry) detachSessionLocked(sessionID wire.SessionID, generation uint64, cause error) *sessionReplacementCleanup {
	cleanup := &sessionReplacementCleanup{cause: cause}
	for key, entry := range r.entries {
		if key.sessionID != sessionID || entry.generation == generation {
			continue
		}
		switch entry.state {
		case claimPending:
			claims, selected, permit := r.failPendingLocked(entry, cause, false)
			cleanup.pending = append(cleanup.pending, pendingClaimCleanup{claims: claims, selected: selected, permit: permit})
		case claimActive:
			delete(r.entries, key)
			permit := entry.permit
			entry.permit = nil
			cleanup.active = append(cleanup.active, activeClaimCleanup{flow: entry.active, permit: permit})
		case claimTerminal:
			delete(r.entries, key)
		}
	}
	r.maybeCleanupGenerationLocked(sessionID)
	return cleanup
}

func (r *claimRegistry) Close() {
	_ = r.CloseContextCause(context.Background(), markForcedTermination(ErrClosed))
}

// CloseAdmission is the synchronous OPEN/ATTACH activation barrier used by
// graceful shutdown. It does not close existing or pending claims by itself.
func (r *claimRegistry) CloseAdmission() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.accepting = false
	r.mu.Unlock()
}

// BeginDrainContext rejects every pending setup with FLOW_LIMIT while
// preserving active relays. CloseContextCause performs final forced cleanup.
func (r *claimRegistry) BeginDrainContext(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	type drainingEntry struct {
		claims   []flowClaim
		selected *setupResult
		permit   *udpPermit
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.accepting = false
	entries := make([]drainingEntry, 0, len(r.entries))
	for key, entry := range r.entries {
		switch entry.state {
		case claimPending:
			claims, selected, permit := r.failPendingLocked(entry, ErrDraining, false)
			entries = append(entries, drainingEntry{
				claims: claims, selected: selected, permit: permit,
			})
		case claimTerminal:
			delete(r.entries, key)
		}
	}
	r.terminalOrder = nil
	r.mu.Unlock()

	for _, entry := range entries {
		if entry.selected != nil {
			_ = entry.selected.rejectContext(ctx, wire.SetupResultFlowLimit)
		}
		for _, claim := range entry.claims {
			claim.close(ErrDraining)
		}
		entry.permit.Release()
	}
	if err := ctx.Err(); err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return err
	}
	return nil
}

func (r *claimRegistry) CloseContext(ctx context.Context) error {
	return r.CloseContextCause(ctx, markForcedTermination(ErrClosed))
}

func (r *claimRegistry) CloseContextCause(ctx context.Context, cause error) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cause = markForcedTermination(cause)
	type closingEntry struct {
		entry  *claimEntry
		permit *udpPermit
		abort  *claimAbort
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.accepting = false
	r.closed = true
	entries := make([]closingEntry, 0, len(r.entries))
	for key, entry := range r.entries {
		permit := entry.permit
		entry.permit = nil
		abort := newClaimAbort(entry)
		entries = append(entries, closingEntry{entry: entry, permit: permit, abort: abort})
		r.closing = append(r.closing, abort)
		delete(r.entries, key)
		if entry.state == claimPending {
			r.finishPendingLocked(entry)
			entry.state = claimTerminal
			entry.err = cause
			close(entry.done)
		}
	}
	r.entries = make(map[claimKey]*claimEntry)
	r.terminalOrder = nil
	r.generations = make(map[wire.SessionID]uint64)
	r.registered = make(map[sessionGeneration]int)
	r.provenance = make(map[sessionGeneration]generationProvenance)
	r.pending = make(map[wire.SessionID]int)
	r.udpInUse = make(map[sessionGeneration]int)
	r.nextGeneration = 0
	r.idleTCP = 0
	r.mu.Unlock()
	for _, closing := range entries {
		entry := closing.entry
		if entry.selected != nil {
			_ = entry.selected.rejectContext(ctx, wire.SetupResultSessionReplaced)
		}
		if entry.active != nil {
			_ = entry.active.Readiness.Reject(cause)
		}
		closing.abort.Close(cause)
		closing.permit.Release()
	}
	r.mu.Lock()
	r.closing = nil
	r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		if callerCause := context.Cause(ctx); callerCause != nil {
			return callerCause
		}
		return err
	}
	return nil
}

func (r *claimRegistry) AbortClosing(cause error) {
	if r == nil {
		return
	}
	r.mu.Lock()
	closing := append([]*claimAbort(nil), r.closing...)
	r.mu.Unlock()
	for _, abort := range closing {
		abort.Close(cause)
	}
}

func newClaimAbort(entry *claimEntry) *claimAbort {
	if entry == nil {
		return &claimAbort{}
	}
	flow := entry.active
	claims := entryClaims(entry)
	return &claimAbort{close: func(cause error) {
		if flow != nil {
			if cancel := contextCancel(flow.Context); cancel != nil {
				cancel(cause)
			}
			closeClaimedFlow(flow, cause)
			return
		}
		for _, claim := range claims {
			claim.close(cause)
		}
	}}
}

func (r *claimRegistry) activateLocked(entry *claimEntry) *claimedFlow {
	selectedClaim := selectedClaim(entry)
	ready := func() error { return nil }
	reject := func(wire.SetupResult) error { return nil }
	if entry.selected != nil {
		ready = entry.selected.ready
		reject = entry.selected.reject
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	ctx = context.WithValue(ctx, claimCancelKey{}, cancel)
	active := &claimedFlow{
		Metadata: entry.metadata, Target: entry.target,
		Open: entry.open, Attach: entry.attach, Duplex: entry.duplex,
		Selected: selectedClaim, Readiness: newFlowReadiness(ready, reject), Context: ctx,
		registry: r, entry: entry,
	}
	entry.active = active
	return active
}

type claimCancelKey struct{}

func contextCancel(ctx context.Context) context.CancelCauseFunc {
	if ctx == nil {
		return nil
	}
	cancel, _ := ctx.Value(claimCancelKey{}).(context.CancelCauseFunc)
	return cancel
}

func (r *claimRegistry) acquireUDPPermitLocked(claim flowClaim) (*udpPermit, error) {
	if claim.Metadata.Kind != wire.FlowKindUDP {
		return nil, nil
	}
	key := sessionGeneration{sessionID: claim.SessionID, generation: claim.Generation}
	if r.udpInUse[key] >= r.limits.UDPFlowsPerSession {
		return nil, fmt.Errorf("%w: UDP flow limit", ErrPairLimit)
	}
	r.udpInUse[key]++
	return &udpPermit{registry: r, key: key}, nil
}

func (r *claimRegistry) finishPendingLocked(entry *claimEntry) {
	if entry.timer != nil {
		entry.timer.Stop()
		entry.timer = nil
	}
	if count := r.pending[entry.key.sessionID]; count <= 1 {
		delete(r.pending, entry.key.sessionID)
	} else {
		r.pending[entry.key.sessionID] = count - 1
	}
	if entry.pendingTCP && r.idleTCP > 0 {
		r.idleTCP--
	}
	entry.pendingTCP = false
}

func (r *claimRegistry) failPendingLocked(entry *claimEntry, cause error, keepTerminal bool) ([]flowClaim, *setupResult, *udpPermit) {
	r.finishPendingLocked(entry)
	entry.state = claimTerminal
	entry.err = cause
	selected := entry.selected
	if selected != nil {
		entry.terminalConsumed = true
	}
	claims := entryClaims(entry)
	if keepTerminal {
		entry.open = nil
		entry.attach = nil
		entry.duplex = nil
		entry.selected = nil
		entry.expiredAt = time.Now().Add(r.pairTimeout)
		r.addTerminalLocked(entry)
	} else {
		delete(r.entries, entry.key)
		r.maybeCleanupGenerationLocked(entry.key.sessionID)
	}
	close(entry.done)
	permit := entry.permit
	entry.permit = nil
	return claims, selected, permit
}

func (r *claimRegistry) releaseActive(entry *claimEntry) {
	if r == nil || entry == nil {
		return
	}
	r.mu.Lock()
	if current := r.entries[entry.key]; current == entry {
		delete(r.entries, entry.key)
	}
	permit := entry.permit
	entry.permit = nil
	r.maybeCleanupGenerationLocked(entry.key.sessionID)
	r.mu.Unlock()
	if cancel := contextCancel(entry.active.Context); cancel != nil {
		cancel(net.ErrClosed)
	}
	permit.Release()
}

func validateClaim(claim flowClaim) error {
	if claim.FlowID == 0 {
		return fmt.Errorf("%w: zero flow ID", ErrCarrierMismatch)
	}
	if claim.Metadata.Kind != wire.FlowKindTCP && claim.Metadata.Kind != wire.FlowKindUDP {
		return fmt.Errorf("%w: invalid flow kind", ErrCarrierMismatch)
	}
	if claim.Metadata.Uplink != wire.CarrierTLSTCP && claim.Metadata.Uplink != wire.CarrierQUIC {
		return fmt.Errorf("%w: invalid uplink", ErrCarrierMismatch)
	}
	if claim.Metadata.Downlink != wire.CarrierTLSTCP && claim.Metadata.Downlink != wire.CarrierQUIC {
		return fmt.Errorf("%w: invalid downlink", ErrCarrierMismatch)
	}
	switch claim.Role {
	case wire.FlowRoleOpen:
		if claim.Metadata.Uplink == claim.Metadata.Downlink || claim.Carrier != claim.Metadata.Uplink {
			return fmt.Errorf("%w: invalid open carrier", ErrCarrierMismatch)
		}
	case wire.FlowRoleAttach:
		if claim.Metadata.Uplink == claim.Metadata.Downlink || claim.Carrier != claim.Metadata.Downlink {
			return fmt.Errorf("%w: invalid attach carrier", ErrCarrierMismatch)
		}
	case wire.FlowRoleDuplex:
		if claim.Metadata.Uplink != claim.Metadata.Downlink || claim.Carrier != claim.Metadata.Downlink {
			return fmt.Errorf("%w: invalid duplex carrier", ErrCarrierMismatch)
		}
	default:
		return fmt.Errorf("%w: invalid role", ErrCarrierMismatch)
	}
	return nil
}

func selectedClaim(entry *claimEntry) flowClaim {
	for _, claim := range []*flowClaim{entry.duplex, entry.open, entry.attach} {
		if claim != nil && claim.selected() {
			return *claim
		}
	}
	return flowClaim{}
}

func entryClaims(entry *claimEntry) []flowClaim {
	claims := make([]flowClaim, 0, 2)
	for _, claim := range []*flowClaim{entry.duplex, entry.open, entry.attach} {
		if claim != nil {
			claims = append(claims, *claim)
		}
	}
	return claims
}

func closeClaimedFlow(flow *claimedFlow, cause error) {
	if flow == nil {
		return
	}
	for _, claim := range []*flowClaim{flow.Duplex, flow.Open, flow.Attach} {
		if claim != nil {
			claim.close(cause)
		}
	}
}

func (r *claimRegistry) emitPair(ctx context.Context, event diagnostic.Event) {
	if ctx == nil {
		ctx = context.Background()
	}
	diagnostic.Emit(ctx, r.observer, event)
}

func claimPairEvent(code string, entry *claimEntry, received *flowClaim, cause error) diagnostic.Event {
	event := diagnostic.Event{
		Level:             diagnostic.LevelDebug,
		Code:              code,
		Component:         "server",
		Target:            targetAddress(entry.target),
		SessionID:         entry.key.sessionID,
		FlowID:            entry.key.flowID,
		UplinkTransport:   carrierTransportName(entry.metadata.Uplink),
		DownlinkTransport: carrierTransportName(entry.metadata.Downlink),
		Err:               cause,
	}
	switch code {
	case "pair_success":
		event.Result = diagnostic.ResultOK
	case "pair_timeout":
		event.Level = diagnostic.LevelWarn
		event.Result = diagnostic.ResultTimeout
	}
	if received == nil {
		return event
	}
	event.Source = received.Source
	event.HalfRole = flowRoleName(received.Role)
	event.ReceivedHalf = event.HalfRole
	event.Transport = carrierTransportName(received.Carrier)
	if code == "pair_success" {
		return event
	}
	switch received.Role {
	case wire.FlowRoleOpen:
		event.MissingHalf = "attach"
		event.ExpectedTransport = carrierTransportName(entry.metadata.Downlink)
	case wire.FlowRoleAttach:
		event.MissingHalf = "open"
		event.ExpectedTransport = carrierTransportName(entry.metadata.Uplink)
	}
	return event
}

func (r *claimRegistry) expireTerminalsLocked(now time.Time) {
	if len(r.terminalOrder) == 0 {
		return
	}
	compacted := r.terminalOrder[:0]
	for _, candidate := range r.terminalOrder {
		current := r.entries[candidate.key]
		if current != candidate || candidate.state != claimTerminal {
			continue
		}
		if !candidate.expiredAt.IsZero() && !candidate.expiredAt.After(now) {
			delete(r.entries, candidate.key)
			r.maybeCleanupGenerationLocked(candidate.key.sessionID)
			continue
		}
		compacted = append(compacted, candidate)
	}
	r.terminalOrder = compacted
}

func (r *claimRegistry) addTerminalLocked(entry *claimEntry) {
	compacted := r.terminalOrder[:0]
	for _, candidate := range r.terminalOrder {
		if current := r.entries[candidate.key]; current == candidate && candidate.state == claimTerminal {
			compacted = append(compacted, candidate)
		}
	}
	r.terminalOrder = append(compacted, entry)
	r.entries[entry.key] = entry
	limit := r.terminalLimit
	if limit <= 0 {
		limit = 1
	}
	for len(r.terminalOrder) > limit {
		oldest := r.terminalOrder[0]
		r.terminalOrder = r.terminalOrder[1:]
		if current := r.entries[oldest.key]; current == oldest && oldest.state == claimTerminal {
			delete(r.entries, oldest.key)
			r.maybeCleanupGenerationLocked(oldest.key.sessionID)
		}
	}
}

func (r *claimRegistry) maybeCleanupGenerationLocked(sessionID wire.SessionID) {
	for key := range r.provenance {
		if key.sessionID == sessionID && !r.hasGenerationStateLocked(key) {
			delete(r.provenance, key)
		}
	}
	current := sessionGeneration{sessionID: sessionID, generation: r.generations[sessionID]}
	if current.generation != 0 && !r.hasGenerationStateLocked(current) {
		delete(r.generations, sessionID)
	}
}

func (r *claimRegistry) hasGenerationStateLocked(generation sessionGeneration) bool {
	for key, entry := range r.entries {
		if key.sessionID == generation.sessionID && entry.generation == generation.generation {
			return true
		}
	}
	return r.registered[generation] > 0 || r.udpInUse[generation] > 0
}

func cloneFlowClaim(claim flowClaim) *flowClaim {
	copy := claim
	return &copy
}
