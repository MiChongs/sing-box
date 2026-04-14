package clashapi

import (
	"context"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func cacheRouter(ctx context.Context) http.Handler {
	r := chi.NewRouter()
	r.Post("/fakeip/flush", flushFakeip(ctx))
	r.Post("/dns/flush", flushDNS(ctx))
	// Smart store maintenance (mihomo parity):
	//   POST /cache/smart/flush          — clear every Smart group's weights & prefetch
	//   POST /cache/smart/flush/{name}   — clear one Smart group by outbound tag
	// DELETE verbs are accepted too so "clear" buttons in Clash dashboards
	// (metacubexd, Yacd) that send DELETE instead of POST still work.
	r.Post("/smart/flush", flushSmartAll(ctx))
	r.Delete("/smart/flush", flushSmartAll(ctx))
	r.Post("/smart/flush/{name}", flushSmartGroup(ctx))
	r.Delete("/smart/flush/{name}", flushSmartGroup(ctx))
	return r
}

// flushSmartAll drops persisted data for every Smart group in the current
// config and triggers a recompute so /proxies/<tag>/weights reflects the
// fresh state immediately (instead of waiting ~1 min for the next ranking
// tick). The response body lists per-group deletion counts so operators
// hitting this endpoint can confirm the operation was effective — the
// previous `{"flushed_groups": N}` payload lacked enough signal to tell
// "actually cleared 2000 keys" from "silent no-op because nothing was there".
func flushSmartAll(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		outboundMgr := service.FromContext[adapter.OutboundManager](ctx)
		if outboundMgr == nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError("outbound manager unavailable"))
			return
		}

		type groupResult struct {
			Group   string           `json:"group"`
			Stats   smart.FlushStats `json:"deleted"`
			Recomp  bool             `json:"recomputed"`
			Error   string           `json:"error,omitempty"`
		}
		var (
			results      []groupResult
			total        smart.FlushStats
			flushedGroup int
			errorsFound  int
		)

		for _, ob := range outboundMgr.Outbounds() {
			sg, ok := ob.(*group.Smart)
			if !ok {
				continue
			}
			res := groupResult{Group: sg.Tag()}
			stats, err := sg.FlushStore()
			res.Stats = stats
			if err != nil {
				res.Error = err.Error()
				errorsFound++
			} else {
				flushedGroup++
				total.Stats += stats.Stats
				total.Nodes += stats.Nodes
				total.Ranking += stats.Ranking
				total.Prefetch += stats.Prefetch
				total.Failures += stats.Failures
				total.Queue += stats.Queue
			}
			// Trigger an async recompute so the API reflects the cleared
			// state immediately. RecomputeWeights is non-blocking.
			if err == nil {
				sg.RecomputeWeights()
				res.Recomp = true
			}
			results = append(results, res)
		}

		status := http.StatusOK
		if errorsFound > 0 && flushedGroup == 0 {
			status = http.StatusInternalServerError
		}
		render.Status(r, status)
		render.JSON(w, r, render.M{
			"flushed_groups": flushedGroup,
			"errors":         errorsFound,
			"total":          total,
			"groups":         results,
		})
	}
}

// flushSmartGroup drops persisted data for a single Smart group (by outbound
// tag) and schedules an immediate recompute. Returns detailed per-bucket
// deletion counts so the caller can confirm exactly what was purged.
func flushSmartGroup(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("group name required"))
			return
		}
		outboundMgr := service.FromContext[adapter.OutboundManager](ctx)
		if outboundMgr == nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError("outbound manager unavailable"))
			return
		}
		ob, loaded := outboundMgr.Outbound(name)
		if !loaded {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}
		sg, ok := ob.(*group.Smart)
		if !ok {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("not a Smart group"))
			return
		}
		stats, err := sg.FlushStore()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, render.M{
				"group":   name,
				"deleted": stats,
				"error":   err.Error(),
			})
			return
		}
		sg.RecomputeWeights()
		render.JSON(w, r, render.M{
			"group":      name,
			"deleted":    stats,
			"total":      stats.Total(),
			"recomputed": true,
		})
	}
}

func flushFakeip(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		if cacheFile != nil {
			err := cacheFile.FakeIPReset()
			if err != nil {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, newError(err.Error()))
				return
			}
		}
		render.NoContent(w, r)
	}
}

func flushDNS(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
		if dnsRouter != nil {
			dnsRouter.ClearCache()
		}
		render.NoContent(w, r)
	}
}
