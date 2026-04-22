package clashapi

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badjson"
	N "github.com/sagernet/sing/common/network"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func proxyRouter(server *Server, router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProxies(server))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName(server))
		r.Get("/", getProxy(server))
		r.Get("/delay", getProxyDelay(server))
		r.Put("/", updateProxy)
		// DELETE /proxies/{name} clears the manual pin on Selector / Smart
		// groups (mihomo parity — metacubexd / Yacd dashboards bind their
		// "取消固定 / release fixed" button to this verb). Equivalent to
		// PUT with {"name": ""} but idiomatic REST so UIs don't need to
		// fabricate a dummy JSON body.
		r.Delete("/", clearProxySelection)
		// PATCH is accepted as an alias for PUT — a small handful of
		// dashboards (zashboard fork variants) use PATCH for selection
		// updates, and returning 405 on them reads as "sing-box broke the
		// endpoint" even though the verb is just non-standard.
		r.Patch("/", updateProxy)
		// Smart-specific: per-group weight ranking (mihomo parity).
		// `?refresh=true` recomputes synchronously instead of returning cache.
		r.Get("/weights", getSmartGroupWeights)
		// DELETE drops the group's persisted Smart data (stats, node states,
		// rankings, prefetch, host-failure counters). Equivalent to
		// POST /cache/smart/flush/{name} but exposed on the proxy resource
		// so UI "clear weights" buttons can use the natural REST verb.
		r.Delete("/weights", deleteSmartGroupWeights)
	})
	return r
}

// clearProxySelection releases the manual pin on a Smart group and performs
// the full side-effect cascade (unwrap cache drop, active-connection
// interrupt, async ranking refresh). Mirrors mihomo's DELETE /proxies/{name}
// semantic — metacubexd / Yacd dashboards bind this to "取消固定 / clear
// fixed". Non-Smart groups can't meaningfully "clear" a selection (a
// Selector must always have some chosen node), so those respond 400 with
// JSON instead of 405 which reads like a broken endpoint.
//
// The response body mirrors mihomo's verbose unpinning reply:
//
//	{
//	  "group":            "🇸🇬 狮城智能",
//	  "previous_pin":     "HK-01",      // omitted when no pin was active
//	  "now":              "HK-07",      // best current guess for next dial
//	  "interrupted_mux":  true,
//	  "unwrap_cleared":   true
//	}
//
// so the UI can render a toast like "已解除对 HK-01 的固定，当前推荐 HK-07".
func clearProxySelection(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
	switch p := proxy.(type) {
	case *group.Smart:
		render.JSON(w, r, p.ClearSelection())
	case *group.URLTest:
		// URLTest's temporary manual pin — empty tag clears it. The pin
		// also auto-clears on the next user-triggered speed test, so
		// DELETE just mirrors that lifecycle for UIs that bind the
		// "release fixed" button to the REST verb.
		previous := p.Selected()
		p.SelectOutbound("")
		render.JSON(w, r, render.M{
			"group":        p.Tag(),
			"previous_pin": previous,
			"now":          p.Now(),
		})
	default:
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("only Smart and URLTest groups support clearing the manual pin; Selector requires PUT with a node name"))
	}
}

// getSmartGroupWeights returns the Smart group's weight ranking.
// Non-Smart groups get 400. Mirrors mihomo's GET /groups/{name}/weights.
//
// Query parameters:
//
//	?refresh=true  — force recompute from prefetch (bypass cache).
//	?full=1        — include the per-(target, node) raw weight table in
//	                 addition to the per-node aggregate. Use this to
//	                 audit API output against the internal selection
//	                 pipeline — the table matches exactly what
//	                 GetBestProxyForTarget sees at dial time.
func getSmartGroupWeights(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
	sg, ok := proxy.(*group.Smart)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, render.M{
			"weights": []any{},
			"error":   "not a Smart group",
		})
		return
	}
	refresh := r.URL.Query().Get("refresh") == "true"
	full := r.URL.Query().Get("full") == "1" || r.URL.Query().Get("full") == "true"

	weights, err := sg.WeightRanking(refresh)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, render.M{
			"weights": []any{},
			"error":   err.Error(),
		})
		return
	}
	payload := render.M{"weights": weights}
	if len(weights) == 0 {
		payload["message"] = "no weight data available for this group"
	}
	if full {
		if store := sg.SmartStore(); store != nil {
			payload["per_target"] = store.GetPerTargetWeights(sg.Tag(), sg.ConfigName())
		}
	}
	render.JSON(w, r, payload)
}

// deleteSmartGroupWeights clears the Smart group's persisted weight / ranking /
// prefetch / node-state data and kicks off an immediate async recompute. The
// response reports per-bucket deletion counts so UIs can surface "N keys
// cleared" instead of a bare 204 that leaves operators wondering whether
// anything happened.
func deleteSmartGroupWeights(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
	sg, ok := proxy.(*group.Smart)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, render.M{"error": "not a Smart group"})
		return
	}
	stats, err := sg.FlushStore()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, render.M{
			"group":   sg.Tag(),
			"deleted": stats,
			"error":   err.Error(),
		})
		return
	}
	sg.RecomputeWeights()
	render.JSON(w, r, render.M{
		"group":      sg.Tag(),
		"deleted":    stats,
		"total":      stats.Total(),
		"recomputed": true,
	})
}

func parseProxyName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProxyByName(server *Server) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProxyName).(string)
			proxy, exist := server.outbound.Outbound(name)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func proxyInfo(server *Server, detour adapter.Outbound) *badjson.JSONObject {
	var info badjson.JSONObject
	var clashType string
	switch detour.Type() {
	case C.TypeBlock:
		clashType = "Reject"
	default:
		clashType = C.ProxyDisplayName(detour.Type())
	}
	info.Put("type", clashType)
	info.Put("name", detour.Tag())
	info.Put("udp", common.Contains(detour.Network(), N.NetworkUDP))

	realTag := adapter.OutboundTag(detour)
	delayHistory := server.urlTestHistory.LoadURLTestHistory(realTag)
	if delayHistory != nil {
		info.Put("history", []*adapter.URLTestHistory{delayHistory})
		// Alive: history exists and is fresh (within 10 minutes)
		info.Put("alive", time.Since(delayHistory.Time) < 10*time.Minute)
		info.Put("delay", delayHistory.Delay)
	} else {
		info.Put("history", []*adapter.URLTestHistory{})
		info.Put("alive", false)
		info.Put("delay", 0)
	}

	if groupOutbound, isGroup := detour.(adapter.OutboundGroup); isGroup {
		info.Put("now", groupOutbound.Now())
		allTags := groupOutbound.All()
		info.Put("all", allTags)
		// mihomo-compatible dashboard hints. Always emitted (no
		// omitempty) so front-ends can rely on the field's presence —
		// `hidden=false`, `icon=""` are the documented "absent" sentinels.
		info.Put("hidden", groupOutbound.Hidden())
		info.Put("icon", groupOutbound.Icon())

		// URLTest's temporary manual pin surfaces like Smart's `fixed`
		// so metacubexd / zashboard can render a uniform "pinned" chip
		// across group types. `fixedActive` echoes `fixed` because
		// URLTest doesn't have a separate "pin suspended" state — if
		// the pin is still in the snapshot it remains in effect.
		if ut, ok := detour.(*group.URLTest); ok {
			selected := ut.Selected()
			info.Put("fixed", selected)
			info.Put("fixedSuspended", false)
			info.Put("fixedActive", selected)
		}

		if sg, ok := detour.(*group.Smart); ok {
			info.Put("testUrl", sg.TestURL())
			info.Put("useASN", sg.UseASN())
			info.Put("useLightGBM", sg.UseLightGBM())
			info.Put("collectData", sg.CollectData())
			info.Put("fixed", sg.Selected())
			// pin suspension state — true when Smart had to fall back
			// to an algorithm-selected node because the user's pin
			// just failed a dial (and the breaker hasn't tripped
			// yet). The pin tag stays in `fixed` so UIs can render
			// "pinned to A (currently unavailable, traffic on B)";
			// `fixedActive` exposes the node traffic is actually
			// flowing through during the suspension. When not
			// suspended, `fixedActive` echoes `fixed` for a uniform
			// client-side render.
			suspended := sg.PinSuspended()
			info.Put("fixedSuspended", suspended)
			if suspended {
				info.Put("fixedActive", groupOutbound.Now())
			} else {
				info.Put("fixedActive", sg.Selected())
			}
			// Live algorithm + anti-flap window so /proxies dashboards
			// can verify what's actually in effect (especially after a
			// runtime PUT /groups/{name}/algorithm swap). Always-output
			// even when hysteresis is 0 — matches the hidden/icon
			// contract so front-ends never have to handle "field missing
			// vs field present-and-zero".
			info.Put("algorithm", sg.CurrentAlgorithm())
			info.Put("hysteresis", sg.HysteresisDuration().String())
			// Parsed policy_priority rules (nil when nothing configured).
			// Surfacing the rule list — not the original raw string —
			// lets dashboards verify that prefixes like ! / = / ~ /
			// auto-glob were interpreted as intended.
			info.Put("policyPriority", sg.PolicyPriorityRules())
			info.Put("pinEndorsements", sg.PinEndorsementDebug())
			if age := sg.LGBMModelAge(); age > 0 {
				info.Put("lgbmModelAge", age.Truncate(time.Second).String())
			}
		}
	}
	return &info
}

func getProxies(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var proxyMap badjson.JSONObject
		outbounds := common.Filter(server.outbound.Outbounds(), func(detour adapter.Outbound) bool {
			return detour.Tag() != ""
		})
		outbounds = append(outbounds, common.Map(common.Filter(server.endpoint.Endpoints(), func(detour adapter.Endpoint) bool {
			return detour.Tag() != ""
		}), func(it adapter.Endpoint) adapter.Outbound {
			return it
		})...)

		allProxies := make([]string, 0, len(outbounds))

		for _, detour := range outbounds {
			switch detour.Type() {
			case C.TypeDirect, C.TypeBlock, C.TypeDNS:
				continue
			}
			allProxies = append(allProxies, detour.Tag())
		}

		defaultTag := server.outbound.Default().Tag()

		sort.SliceStable(allProxies, func(i, j int) bool {
			return allProxies[i] == defaultTag
		})

		// fix clash dashboard
		proxyMap.Put("GLOBAL", map[string]any{
			"type":    "Fallback",
			"name":    "GLOBAL",
			"udp":     true,
			"history": []*adapter.URLTestHistory{},
			"alive":   true,
			"delay":   0,
			"all":     allProxies,
			"now":     defaultTag,
		})

		for i, detour := range outbounds {
			var tag string
			if detour.Tag() == "" {
				tag = F.ToString(i)
			} else {
				tag = detour.Tag()
			}
			proxyMap.Put(tag, proxyInfo(server, detour))
		}
		var responseMap badjson.JSONObject
		responseMap.Put("proxies", &proxyMap)
		response, err := responseMap.MarshalJSON()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Write(response)
	}
}

func getProxy(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		response, err := proxyInfo(server, proxy).MarshalJSON()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Write(response)
	}
}

type UpdateProxyRequest struct {
	Name string `json:"name"`
}

func updateProxy(w http.ResponseWriter, r *http.Request) {
	req := UpdateProxyRequest{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
	switch p := proxy.(type) {
	case *group.Selector:
		if !p.SelectOutbound(req.Name) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("Selector update error: not found"))
			return
		}
	case *group.Smart:
		// Empty name clears manual pinning; non-empty pins a node (mihomo parity).
		if !p.SelectOutbound(req.Name) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("Smart update error: not found"))
			return
		}
	case *group.URLTest:
		// Temporary manual pin on URLTest — empty name clears. Auto-
		// released on the next user-triggered group speed test.
		if !p.SelectOutbound(req.Name) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("URLTest update error: not found"))
			return
		}
	default:
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Must be a Selector, Smart, or URLTest"))
		return
	}

	render.NoContent(w, r)
}

// getProxyDelay performs multi-sample delay testing for accuracy.
// Tests up to 3 times and returns the median for stable results.
func getProxyDelay(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		url := query.Get("url")
		if strings.HasPrefix(url, "http://") {
			url = ""
		}
		timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 32)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)

		// NOTE: previously this path auto-released a Smart group's manual
		// pin before running the delay test ("mihomo parity"). Dashboards
		// like zashboard / metacubexd poll per-group delay every few
		// seconds, which silently wiped the user's pin within moments of
		// setting it. Kept off: the delay test still dials through the
		// pinned node (correct behaviour — measures what traffic actually
		// uses), and explicit unpin is available via DELETE /proxies/<tag>
		// or PUT {"name":""} when the user really wants it.

		realTag := group.RealTag(proxy)
		timeoutDuration := time.Millisecond * time.Duration(timeout)

		// Multi-sample: test up to 3 times, collect valid results
		const maxSamples = 3
		var samples []uint16
		for i := 0; i < maxSamples; i++ {
			ctx, cancel := context.WithTimeout(r.Context(), timeoutDuration)
			t, testErr := urltest.URLTest(ctx, url, proxy)
			cancel()
			if testErr != nil || t == 0 {
				continue
			}
			samples = append(samples, t)
			// If first sample is very fast (<50ms), result is already reliable
			if i == 0 && t < 50 {
				break
			}
		}

		if len(samples) == 0 {
			// All attempts failed — check if it was a timeout
			ctx, cancel := context.WithTimeout(r.Context(), timeoutDuration)
			_, _ = urltest.URLTest(ctx, url, proxy)
			timedOut := ctx.Err() != nil
			cancel()

			if timedOut {
				render.Status(r, http.StatusGatewayTimeout)
				render.JSON(w, r, ErrRequestTimeout)
			} else {
				render.Status(r, http.StatusServiceUnavailable)
				render.JSON(w, r, newError("An error occurred in the delay test"))
			}
			return
		}

		// Take median for stability
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		delay := samples[len(samples)/2]

		server.urlTestHistory.StoreURLTestHistory(realTag, &adapter.URLTestHistory{
			Time:  time.Now(),
			Delay: delay,
		})

		render.JSON(w, r, render.M{
			"delay": delay,
		})
	}
}
