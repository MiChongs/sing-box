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
		// Smart-specific: per-group weight ranking (mihomo parity).
		// `?refresh=true` recomputes synchronously instead of returning cache.
		r.Get("/weights", getSmartGroupWeights)
	})
	return r
}

// getSmartGroupWeights returns the Smart group's weight ranking.
// Non-Smart groups get 400. Mirrors mihomo's GET /groups/{name}/weights.
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
	weights, err := sg.WeightRanking(refresh)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, render.M{
			"weights": []any{},
			"error":   err.Error(),
		})
		return
	}
	if len(weights) == 0 {
		render.JSON(w, r, render.M{
			"weights": []any{},
			"message": "no weight data available for this group",
		})
		return
	}
	render.JSON(w, r, render.M{"weights": weights})
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

		if sg, ok := detour.(*group.Smart); ok {
			info.Put("testUrl", sg.TestURL())
			info.Put("useASN", sg.UseASN())
			info.Put("useLightGBM", sg.UseLightGBM())
			info.Put("collectData", sg.CollectData())
			info.Put("fixed", sg.Selected())
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
	default:
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Must be a Selector or Smart"))
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

		// Mihomo parity: running a delay test against a pinned Smart group
		// should implicitly release the pin so the next dial re-enters
		// auto-selection and the freshly measured delay can take effect.
		if sg, ok := proxy.(*group.Smart); ok {
			if pinned := sg.Selected(); pinned != "" {
				sg.SelectOutbound("")
			}
		}

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
