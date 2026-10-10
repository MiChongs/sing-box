package group

import (
	"context"
	"maps"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	N "github.com/sagernet/sing/common/network"
)

type urlTestSessionContextKey struct{}

// contextWithURLTestSession marks the start of a recursive test: nested
// groups tested within it share every result measured since, so a leaf
// reachable through several groups is measured once per URL.
func contextWithURLTestSession(ctx context.Context) (context.Context, time.Time) {
	if session := urlTestSessionFromContext(ctx); !session.IsZero() {
		return ctx, session
	}
	session := time.Now()
	return context.WithValue(ctx, urlTestSessionContextKey{}, session), session
}

func urlTestSessionFromContext(ctx context.Context) time.Time {
	session, _ := ctx.Value(urlTestSessionContextKey{}).(time.Time)
	return session
}

type recursiveURLTestGroup interface {
	adapter.OutboundGroup
	urlTest(ctx context.Context, force bool) (map[string]uint16, error)
}

// fallbackProber serves history storages without a prober of their own.
var fallbackProber urltest.Prober

func proberFor(history adapter.URLTestHistoryStorage) *urltest.Prober {
	if storage, isStorage := history.(*urltest.HistoryStorage); isStorage && storage != nil {
		return storage.Prober()
	}
	return &fallbackProber
}

type urlTestBatch struct {
	ctx      context.Context
	outbound adapter.OutboundManager
	history  adapter.URLTestHistoryStorage
	prober   *urltest.Prober
	logger   log.Logger
	since    time.Time
	batch    *batch.Batch[any]
	checked  map[string]bool
	groups   []adapter.OutboundGroup
	access   sync.Mutex
	result   map[string]uint16
}

// URLTestOutbounds tests outbounds and the members of nested groups. Without
// force, leaves measured within interval are skipped.
func URLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history adapter.URLTestHistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool) map[string]uint16 {
	ctx, since := contextWithURLTestSession(ctx)
	if !force {
		since = since.Add(-interval / 2)
	}
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](probeConcurrency))
	testBatch := &urlTestBatch{
		ctx:      ctx,
		outbound: outboundManager,
		history:  history,
		prober:   proberFor(history),
		logger:   logger,
		since:    since,
		batch:    b,
		checked:  make(map[string]bool),
		result:   make(map[string]uint16),
	}
	testBatch.test(outbounds, link, interval, force)
	b.Wait()
	for _, outboundGroup := range testBatch.groups {
		groupHistory := history.LoadURLTestHistory(RealTag(outboundGroup, N.NetworkTCP))
		if groupHistory != nil {
			testBatch.result[outboundGroup.Tag()] = groupHistory.Delay
		}
	}
	return testBatch.result
}

func (b *urlTestBatch) test(outbounds []adapter.Outbound, link string, interval time.Duration, force bool) {
	for _, detour := range outbounds {
		tag := detour.Tag()
		if b.checked[tag] {
			continue
		}
		switch nested := detour.(type) {
		case recursiveURLTestGroup:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.batch.Go(tag, func() (any, error) {
				nestedResult, _ := nested.urlTest(b.ctx, force)
				b.access.Lock()
				maps.Copy(b.result, nestedResult)
				b.access.Unlock()
				return nil, nil
			})
		case adapter.OutboundGroup:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.test(common.FilterNotNil(common.Map(nested.All(), func(it string) adapter.Outbound {
				member, _ := b.outbound.Outbound(it)
				return member
			})), link, interval, force)
		default:
			history := b.history.LoadURLTestHistory(tag)
			if !force && history != nil && time.Since(history.Time) < interval {
				continue
			}
			b.checked[tag] = true
			b.batch.Go(tag, func() (any, error) {
				result := b.prober.Probe(b.ctx, urltest.ProbeRequest{
					Tag:     tag,
					Link:    link,
					Dialer:  detour,
					Timeout: C.TCPTimeout,
					Since:   b.since,
				})
				if result.Err != nil {
					if b.ctx.Err() != nil {
						return nil, nil
					}
					b.logger.Debug("outbound ", tag, " unavailable: ", result.Err)
					deleteURLTestHistory(b.history, tag, result.Time)
				} else {
					b.logger.Debug("outbound ", tag, " available: ", result.Delay, "ms")
					storeURLTestHistory(b.history, tag, result)
					b.access.Lock()
					b.result[tag] = result.Delay
					b.access.Unlock()
				}
				return nil, nil
			})
		}
	}
}
