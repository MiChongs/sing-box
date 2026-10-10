package urltest

import (
	"context"
	"sync"
	"time"

	N "github.com/sagernet/sing/common/network"
)

// Prober deduplicates probes across everything measuring through one box
// instance. A probe of the same outbound, URL and status policy that is
// still running is joined, and one that finished at or after the caller's
// horizon is reused, instead of dialing the outbound again. Groups sharing
// members, nested groups and API tests thereby cost one connection per
// outbound, which matters for nodes billed per request.
type Prober struct {
	access    sync.Mutex
	calls     map[probeKey]*probeCall
	lastPrune time.Time
}

type ProbeRequest struct {
	// Tag identifies the measured outbound, usually its real tag.
	Tag    string
	Link   string
	Status *StatusMatcher
	Dialer N.Dialer
	// Timeout bounds the probe on top of ctx; zero leaves it to ctx.
	Timeout time.Duration
	// Since is the oldest finished result the caller accepts.
	Since time.Time
}

type ProbeResult struct {
	Delay uint16
	Err   error
	// Time is when the measurement finished.
	Time time.Time
}

type probeKey struct {
	tag     string
	link    string
	status  string
	unified bool
}

type probeCall struct {
	done     chan struct{}
	result   ProbeResult
	canceled bool
}

// proberRetention bounds how long finished results are kept for reuse;
// horizons never reach further back than one probe round.
const proberRetention = 10 * time.Minute

// Probe measures request.Link through request.Dialer, or shares a matching
// probe. Errors caused by ctx are never shared: a caller whose probe was
// cut short by its owner measures again.
func (p *Prober) Probe(ctx context.Context, request ProbeRequest) ProbeResult {
	link := request.Link
	if link == "" {
		link = DefaultLink
	}
	key := probeKey{
		tag:     request.Tag,
		link:    link,
		unified: UnifiedDelayFromContext(ctx),
	}
	if request.Status != nil {
		key.status = request.Status.String()
	}
	for {
		call, owner := p.acquire(key, request.Since)
		if owner {
			p.run(ctx, key, call, request)
			return call.result
		}
		select {
		case <-call.done:
		case <-ctx.Done():
			return ProbeResult{Err: ctx.Err(), Time: time.Now()}
		}
		if !call.canceled {
			return call.result
		}
		if ctx.Err() != nil {
			return ProbeResult{Err: ctx.Err(), Time: time.Now()}
		}
	}
}

func (p *Prober) acquire(key probeKey, since time.Time) (*probeCall, bool) {
	p.access.Lock()
	defer p.access.Unlock()
	if call, loaded := p.calls[key]; loaded {
		select {
		case <-call.done:
			if !call.canceled && !call.result.Time.Before(since) {
				return call, false
			}
		default:
			return call, false
		}
	}
	now := time.Now()
	if p.calls == nil {
		p.calls = make(map[probeKey]*probeCall)
	} else if now.Sub(p.lastPrune) > time.Minute {
		p.lastPrune = now
		for oldKey, oldCall := range p.calls {
			select {
			case <-oldCall.done:
				if now.Sub(oldCall.result.Time) > proberRetention {
					delete(p.calls, oldKey)
				}
			default:
			}
		}
	}
	call := &probeCall{done: make(chan struct{})}
	p.calls[key] = call
	return call, true
}

func (p *Prober) run(ctx context.Context, key probeKey, call *probeCall, request ProbeRequest) {
	probeCtx := ctx
	if request.Timeout > 0 {
		var cancel context.CancelFunc
		probeCtx, cancel = context.WithTimeout(ctx, request.Timeout)
		defer cancel()
	}
	// Return once probeCtx is done even if the outbound ignores
	// cancellation, so one unresponsive outbound cannot hold the caller.
	resultChan := make(chan ProbeResult, 1)
	go func() {
		delay, err := URLTestWithStatus(probeCtx, request.Link, request.Dialer, request.Status)
		resultChan <- ProbeResult{Delay: delay, Err: err}
	}()
	var result ProbeResult
	select {
	case result = <-resultChan:
	case <-probeCtx.Done():
		result.Err = probeCtx.Err()
	}
	result.Time = time.Now()
	call.result = result
	call.canceled = result.Err != nil && ctx.Err() != nil
	if call.canceled {
		p.access.Lock()
		if p.calls[key] == call {
			delete(p.calls, key)
		}
		p.access.Unlock()
	}
	close(call.done)
}
