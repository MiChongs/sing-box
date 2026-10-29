package clashapi

import (
	"context"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func cacheRouter(ctx context.Context) http.Handler {
	r := chi.NewRouter()
	r.Post("/fakeip/flush", flushFakeip(ctx))
	r.Post("/dns/flush", flushDNS(ctx))
	// Smart learned state (mihomo parity), DELETE accepted for dashboards
	// that send it:
	//   POST /cache/smart/flush          — every Smart group
	//   POST /cache/smart/flush/{name}   — one Smart group by tag
	r.Post("/smart/flush", flushSmartAll(ctx))
	r.Delete("/smart/flush", flushSmartAll(ctx))
	r.Post("/smart/flush/{name}", flushSmartGroup(ctx))
	r.Delete("/smart/flush/{name}", flushSmartGroup(ctx))
	return r
}

// flushSmartAll drops the learned state of every Smart group (mihomo
// FlushAll): 204 on success.
func flushSmartAll(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		groups, err := smartGroups(ctx)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		for _, sg := range groups {
			if _, err = sg.FlushStore(); err != nil {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, newError(sg.Tag()+": "+err.Error()))
				return
			}
		}
		render.NoContent(w, r)
	}
}

// flushSmartGroup drops the learned state of one Smart group. mihomo keys
// this route by configuration name; a name that is no Smart group flushes
// every group, as the one configuration holds them all.
func flushSmartGroup(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("config name is required"))
			return
		}
		sg, err := resolveSmartGroup(ctx, name)
		if err != nil {
			flushSmartAll(ctx)(w, r)
			return
		}
		if _, err = sg.FlushStore(); err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	}
}

func flushFakeip(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Reset through the FakeIP store, so that both in-memory and cache file
		// storages are cleared and allocation restarts from the beginning.
		var fakeIPTransport adapter.FakeIPTransport
		if transportManager := service.FromContext[adapter.DNSTransportManager](ctx); transportManager != nil {
			fakeIPTransport = transportManager.FakeIP()
		}
		if fakeIPTransport != nil {
			err := fakeIPTransport.Store().Reset()
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
