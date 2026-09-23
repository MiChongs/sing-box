package clashapi

import (
	"context"
	"net/http"
	"slices"
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
		// Some dashboards select with PATCH instead of PUT.
		r.Patch("/", updateProxy)
		// DELETE /proxies/{name} clears the manual pin on Smart groups
		// (mihomo parity — metacubexd / Yacd dashboards bind their
		// "取消固定 / release fixed" button to this verb). Equivalent to
		// PUT with {"name": ""} but idiomatic REST so UIs don't need to
		// fabricate a dummy JSON body.
		r.Delete("/", clearProxySelection)
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

// clearProxySelection releases the manual pin on a Smart or URLTest group.
// Mirrors mihomo's DELETE /proxies/{name} semantic — metacubexd / Yacd
// dashboards bind this to "取消固定 / clear fixed". A Selector must always
// have some chosen node, so it responds 400 with JSON instead of 405 which
// reads like a broken endpoint.
func clearProxySelection(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
	switch outboundGroup := proxy.(type) {
	case *group.Smart:
		render.JSON(w, r, outboundGroup.ClearSelection())
	case *group.URLTest:
		previous := outboundGroup.Selected()
		outboundGroup.SelectOutbound("")
		render.JSON(w, r, render.M{
			"group":        outboundGroup.Tag(),
			"previous_pin": previous,
			"now":          outboundGroup.Now(),
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
	delayHistory := server.urlTestHistory.LoadURLTestHistory(group.RealTag(server.outbound, detour))
	if delayHistory != nil {
		info.Put("history", []*adapter.URLTestHistory{delayHistory})
		info.Put("alive", time.Since(delayHistory.Time) < proxyAliveTimeout)
		info.Put("delay", delayHistory.Delay)
	} else {
		info.Put("history", []*adapter.URLTestHistory{})
		info.Put("alive", false)
		info.Put("delay", 0)
	}
	if outboundGroup, isGroup := detour.(adapter.OutboundGroup); isGroup {
		info.Put("now", outboundGroup.Now())
		info.Put("all", outboundGroup.All())
		// mihomo-compatible dashboard hints. Always emitted on groups so
		// front-ends can rely on the fields' presence: `hidden=false` and
		// `icon=""` are the documented "absent" sentinels.
		var (
			hidden bool
			icon   string
		)
		if hint, isHint := detour.(adapter.OutboundGroupHint); isHint {
			hidden = hint.Hidden()
			icon = hint.Icon()
		}
		info.Put("hidden", hidden)
		info.Put("icon", icon)
		// URLTest's manual selection is reported like Smart's pin, so
		// dashboards render both the same way.
		if urlTestGroup, isURLTest := detour.(*group.URLTest); isURLTest {
			selected := urlTestGroup.Selected()
			info.Put("fixed", selected)
			info.Put("fixedSuspended", false)
			info.Put("fixedActive", selected)
		}
		if smartGroup, isSmart := detour.(*group.Smart); isSmart {
			putSmartProxyInfo(&info, smartGroup)
		}
	}
	return &info
}

// putSmartProxyInfo adds the Smart group's runtime state to the /proxies
// entry so mihomo-compatible dashboards can render pin / algorithm state.
func putSmartProxyInfo(info *badjson.JSONObject, smartGroup *group.Smart) {
	info.Put("testUrl", smartGroup.TestURL())
	info.Put("useASN", smartGroup.UseASN())
	info.Put("useLightGBM", smartGroup.UseLightGBM())
	info.Put("collectData", smartGroup.CollectData())
	info.Put("fixed", smartGroup.Selected())
	// pin suspension state — true when Smart had to fall back to an
	// algorithm-selected node because the user's pin just failed a dial
	// (and the breaker hasn't tripped yet). The pin tag stays in `fixed`
	// so UIs can render "pinned to A (currently unavailable, traffic on
	// B)"; `fixedActive` exposes the node traffic is actually flowing
	// through during the suspension. When not suspended, `fixedActive`
	// echoes `fixed` for a uniform client-side render.
	suspended := smartGroup.PinSuspended()
	info.Put("fixedSuspended", suspended)
	if suspended {
		info.Put("fixedActive", smartGroup.Now())
	} else {
		info.Put("fixedActive", smartGroup.Selected())
	}
	// Live algorithm + anti-flap window so /proxies dashboards can verify
	// what's actually in effect (especially after a runtime
	// PUT /smart/groups/{name}/algorithm swap). Always emitted even when
	// hysteresis is 0, so front-ends never have to handle "field missing
	// vs field present-and-zero".
	info.Put("algorithm", smartGroup.CurrentAlgorithm())
	info.Put("hysteresis", smartGroup.HysteresisDuration().String())
	// Parsed policy_priority rules (nil when nothing configured). Surfacing
	// the rule list — not the original raw string — lets dashboards verify
	// that prefixes like ! / = / ~ / auto-glob were interpreted as intended.
	info.Put("policyPriority", smartGroup.PolicyPriorityRules())
	info.Put("pinEndorsements", smartGroup.PinEndorsementDebug())
	if age := smartGroup.LGBMModelAge(); age > 0 {
		info.Put("lgbmModelAge", age.Truncate(time.Second).String())
	}
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
			"hidden":  false,
			"icon":    "",
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
	switch outboundGroup := proxy.(type) {
	case *group.Selector:
		if !outboundGroup.SelectOutbound(req.Name) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("Selector update error: not found"))
			return
		}
	case *group.Smart:
		// Empty name clears manual pinning; non-empty pins a node (mihomo parity).
		if !outboundGroup.SelectOutbound(req.Name) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("Smart update error: not found"))
			return
		}
	case *group.URLTest:
		// Selection lasts until the next user-triggered group delay test;
		// an empty name clears it.
		if !outboundGroup.SelectOutbound(req.Name) {
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

func groupContains(outboundManager adapter.OutboundManager, outboundGroup adapter.OutboundGroup, tag string, visited map[string]bool) bool {
	for _, memberTag := range outboundGroup.All() {
		if memberTag == tag {
			return true
		}
		member, loaded := outboundManager.Outbound(memberTag)
		if !loaded {
			continue
		}
		if group.RealTag(outboundManager, member) == tag {
			return true
		}
		memberGroup, isGroup := member.(adapter.OutboundGroup)
		if !isGroup || visited[memberTag] {
			continue
		}
		visited[memberTag] = true
		if groupContains(outboundManager, memberGroup, tag, visited) {
			return true
		}
	}
	return false
}

const (
	proxyDelaySamples    = 3
	proxyDelayFastSample = 50
	// proxyAliveTimeout is how long a delay test result marks a proxy alive.
	proxyAliveTimeout = 10 * time.Minute
)

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
		ctx, cancel := context.WithTimeout(r.Context(), time.Millisecond*time.Duration(timeout))
		defer cancel()

		// Up to three samples within the timeout, answered with the median;
		// a fast first sample is already reliable.
		var samples []uint16
		for i := 0; i < proxyDelaySamples && ctx.Err() == nil; i++ {
			sample, sampleErr := urltest.URLTest(ctx, url, proxy)
			if sampleErr != nil || sample == 0 {
				continue
			}
			samples = append(samples, sample)
			if i == 0 && sample < proxyDelayFastSample {
				break
			}
		}
		var delay uint16
		if len(samples) > 0 {
			slices.Sort(samples)
			delay = samples[len(samples)/2]
		}
		defer func() {
			realTag := group.RealTag(server.outbound, proxy)
			// A failed test keeps the history; periodic checks decide
			// whether the outbound is down.
			if delay > 0 {
				server.urlTestHistory.StoreURLTestHistory(realTag, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: delay,
				})
			}
			for _, detour := range server.outbound.Outbounds() {
				urlTestGroup, isURLTestGroup := detour.(adapter.URLTestGroup)
				if !isURLTestGroup {
					continue
				}
				if !groupContains(server.outbound, urlTestGroup, realTag, map[string]bool{detour.Tag(): true}) {
					continue
				}
				urlTestGroup.PerformUpdateCheck()
			}
		}()

		if delay == 0 {
			if ctx.Err() != nil {
				render.Status(r, http.StatusGatewayTimeout)
				render.JSON(w, r, ErrRequestTimeout)
			} else {
				render.Status(r, http.StatusServiceUnavailable)
				render.JSON(w, r, newError("An error occurred in the delay test"))
			}
			return
		}

		render.JSON(w, r, render.M{
			"delay": delay,
		})
	}
}
