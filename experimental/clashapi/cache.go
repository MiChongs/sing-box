package clashapi

import (
	"context"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
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
	r.Post("/smart/flush", flushSmartAll(ctx))
	r.Post("/smart/flush/{name}", flushSmartGroup(ctx))
	return r
}

// flushSmartAll drops all persisted data for every Smart group by invoking
// FlushByGroup on each instance. We intentionally don't call FlushAll on the
// underlying store (that would blow away LightGBM ranking records for groups
// outside the current config, which users don't expect from a Clash API call).
func flushSmartAll(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		outboundMgr := service.FromContext[adapter.OutboundManager](ctx)
		if outboundMgr == nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError("outbound manager unavailable"))
			return
		}
		count := 0
		for _, ob := range outboundMgr.Outbounds() {
			sg, ok := ob.(*group.Smart)
			if !ok {
				continue
			}
			if err := sg.FlushStore(); err != nil {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, newError(err.Error()))
				return
			}
			count++
		}
		render.JSON(w, r, render.M{"flushed_groups": count})
	}
}

// flushSmartGroup drops persisted data for a single Smart group (by outbound tag).
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
		if err := sg.FlushStore(); err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
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
