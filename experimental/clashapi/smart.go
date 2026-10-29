// Smart Clash API endpoints. mihomo's own routes (GET /group/{name}/weights,
// GET /group/weights, POST /cache/smart/flush, DELETE
// /connections/smart/{id}) live with their routers; this file hosts the
// /smart extensions: group listing, diagnostics with the comprehensive
// score state, node blocks and the smart-loadbalance region controls.
package clashapi

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/protocol/group"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// smartRouter mounts at /smart.
func smartRouter(ctx context.Context) http.Handler {
	r := chi.NewRouter()
	r.Get("/weights", getAllSmartWeights(ctx))
	r.Get("/groups", listSmartGroups(ctx))
	r.Get("/groups/{name}/diag", smartGroupDiag(ctx))
	r.Post("/groups/{name}/block/{node}", blockSmartNode(ctx))
	r.Delete("/groups/{name}/block/{node}", unblockSmartNode(ctx))
	r.Post("/groups/{name}/recompute", recomputeSmartWeights(ctx))
	r.Post("/groups/{name}/clear-selection", clearSmartSelection(ctx))
	// smart-loadbalance: region table, region lock / mode, balance
	// strategy / affinity, member re-detection.
	r.Get("/groups/{name}/regions", getSmartRegions(ctx))
	r.Put("/groups/{name}/regions", updateSmartRegions(ctx))
	r.Delete("/groups/{name}/regions/lock", unlockSmartRegion(ctx))
	r.Post("/groups/{name}/regions/detect", redetectSmartRegions(ctx))
	r.Put("/groups/{name}/balance", updateSmartBalance(ctx))
	return r
}

func smartGroups(ctx context.Context) ([]*group.Smart, error) {
	outboundMgr := service.FromContext[adapter.OutboundManager](ctx)
	if outboundMgr == nil {
		return nil, E.New("outbound manager unavailable")
	}
	var groups []*group.Smart
	for _, ob := range outboundMgr.Outbounds() {
		if sg, ok := ob.(*group.Smart); ok {
			groups = append(groups, sg)
		}
	}
	return groups, nil
}

func resolveSmartGroup(ctx context.Context, name string) (*group.Smart, error) {
	outboundMgr := service.FromContext[adapter.OutboundManager](ctx)
	if outboundMgr == nil {
		return nil, E.New("outbound manager unavailable")
	}
	ob, loaded := outboundMgr.Outbound(name)
	if !loaded {
		return nil, E.New("group not found: " + name)
	}
	sg, ok := ob.(*group.Smart)
	if !ok {
		return nil, E.New("not a Smart group: " + name)
	}
	return sg, nil
}

// allSmartWeights ranks every Smart group concurrently (mihomo
// getAllGroupWeights): groups without data map to null.
func allSmartWeights(ctx context.Context, refresh bool) (map[string][]smart.NodeRank, map[string]string, error) {
	groups, err := smartGroups(ctx)
	if err != nil {
		return nil, nil, err
	}
	result := make(map[string][]smart.NodeRank, len(groups))
	errorsMap := make(map[string]string)
	var (
		access sync.Mutex
		wg     sync.WaitGroup
		sem    = make(chan struct{}, 5)
	)
	for _, sg := range groups {
		wg.Add(1)
		sem <- struct{}{}
		go func(sg *group.Smart) {
			defer wg.Done()
			defer func() { <-sem }()
			weights, err := sg.WeightRanking(refresh)
			access.Lock()
			defer access.Unlock()
			if err != nil {
				errorsMap[sg.Tag()] = err.Error()
				return
			}
			result[sg.Tag()] = weights
		}(sg)
	}
	wg.Wait()
	return result, errorsMap, nil
}

func getAllSmartWeights(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		result, errorsMap, err := allSmartWeights(ctx, r.URL.Query().Get("refresh") == "true")
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if len(result) == 0 && len(errorsMap) == 0 {
			render.JSON(w, r, render.M{"weights": map[string][]smart.NodeRank{}, "message": "No Smart groups or no weight data available"})
			return
		}
		render.JSON(w, r, render.M{"weights": result, "errors": errorsMap})
	}
}

// smartGroupInfo is the per-group summary of GET /smart/groups.
func smartGroupInfo(sg *group.Smart) map[string]any {
	info := map[string]any{
		"name":           sg.Tag(),
		"type":           sg.Type(),
		"testUrl":        sg.TestURL(),
		"expectedStatus": sg.ExpectedStatus(),
		"preferASN":      sg.PreferASN(),
		"useLightGBM":    sg.UseLightGBM(),
		"collectData":    sg.CollectData(),
		"sampleRate":     sg.SampleRate(),
		"tolerance":      sg.Tolerance(),
		"fixed":          sg.FixedSelection(),
		"now":            sg.Now(),
		"members":        len(sg.MemberTags()),
	}
	if rules := sg.PolicyPriority(); len(rules) > 0 {
		priority := make([]map[string]any, len(rules))
		for i, rule := range rules {
			priority[i] = map[string]any{"pattern": rule.Pattern, "factor": rule.Factor}
		}
		info["policyPriority"] = priority
	}
	if age := sg.LGBMModelAge(); age > 0 {
		info["lgbmModelAge"] = age.Round(time.Second).String()
	}
	if sg.IsLoadBalance() {
		info["loadBalance"] = sg.BalanceInfo()
	}
	return info
}

func listSmartGroups(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		groups, err := smartGroups(ctx)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		infos := make([]map[string]any, 0, len(groups))
		for _, sg := range groups {
			infos = append(infos, smartGroupInfo(sg))
		}
		render.JSON(w, r, render.M{"groups": infos})
	}
}

// smartGroupDiag returns the group's selection state: members with their
// health, stability and blocks; the per-network selection reasons, switch
// counts, serving pool and exploration budgets; host block records; and
// the evidence cache sizes.
func smartGroupDiag(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sg, err := resolveSmartGroup(ctx, chi.URLParam(r, "name"))
		if err != nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		diag := sg.Diagnostic()
		if ranking, err := sg.WeightRanking(false); err == nil {
			diag["ranking"] = ranking
		}
		render.JSON(w, r, diag)
	}
}

func recomputeSmartWeights(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sg, err := resolveSmartGroup(ctx, chi.URLParam(r, "name"))
		if err != nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		ranking, _ := sg.WeightRanking(true)
		render.JSON(w, r, render.M{"group": sg.Tag(), "ranking": ranking})
	}
}

func clearSmartSelection(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sg, err := resolveSmartGroup(ctx, chi.URLParam(r, "name"))
		if err != nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.JSON(w, r, sg.ClearSelection())
	}
}

// blockSmartNode blocks a member for the whole group, for ?duration= (Go
// duration, default 30m).
func blockSmartNode(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sg, err := resolveSmartGroup(ctx, chi.URLParam(r, "name"))
		if err != nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		node := chi.URLParam(r, "node")
		duration := group.DefaultBlockDuration
		if d := r.URL.Query().Get("duration"); d != "" {
			if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
				duration = parsed
			}
		}
		if err = sg.MarkBlocked(node, duration); err != nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.JSON(w, r, render.M{
			"group":         sg.Tag(),
			"node":          node,
			"blocked_until": time.Now().Add(duration).Format(time.RFC3339),
		})
	}
}

func unblockSmartNode(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sg, err := resolveSmartGroup(ctx, chi.URLParam(r, "name"))
		if err != nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		sg.UnblockNode(chi.URLParam(r, "node"))
		render.NoContent(w, r)
	}
}

// resolveLoadBalanceGroup resolves a smart-loadbalance group or answers the
// request with the error.
func resolveLoadBalanceGroup(ctx context.Context, w http.ResponseWriter, r *http.Request) (*group.Smart, bool) {
	name := chi.URLParam(r, "name")
	sg, err := resolveSmartGroup(ctx, name)
	if err != nil {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError(err.Error()))
		return nil, false
	}
	if !sg.IsLoadBalance() {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("not a smart-loadbalance group: "+name))
		return nil, false
	}
	return sg, true
}

// getSmartRegions returns the region table of a smart-loadbalance group:
// every region with its members, their detection source, health, load and
// quality, plus the live mode / lock / strategy settings.
func getSmartRegions(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sg, ok := resolveLoadBalanceGroup(ctx, w, r)
		if !ok {
			return
		}
		render.JSON(w, r, sg.RegionTable())
	}
}

// updateSmartRegions changes the region lock and / or the region mode.
// Body: {"lock": "JP"} (region code, built-in name or region outbound tag;
// "" unlocks) and / or {"mode": "destination"} ("" restores the configured
// mode). Fields left out are not touched.
func updateSmartRegions(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sg, ok := resolveLoadBalanceGroup(ctx, w, r)
		if !ok {
			return
		}
		var body struct {
			Lock *string `json:"lock"`
			Mode *string `json:"mode"`
		}
		if err := render.DecodeJSON(r.Body, &body); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("invalid JSON body: "+err.Error()))
			return
		}
		if body.Lock == nil && body.Mode == nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(`body must set "lock" and / or "mode"`))
			return
		}
		response := render.M{"group": sg.Tag()}
		if body.Mode != nil {
			mode, err := sg.SetRegionMode(*body.Mode)
			if err != nil {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, newError(err.Error()))
				return
			}
			response["mode"] = mode
		}
		if body.Lock != nil {
			lock, err := sg.SetRegionLock(*body.Lock)
			if err != nil {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, newError(err.Error()))
				return
			}
			response["lock"] = lock
		}
		response["now"] = sg.Now()
		render.JSON(w, r, response)
	}
}

func unlockSmartRegion(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sg, ok := resolveLoadBalanceGroup(ctx, w, r)
		if !ok {
			return
		}
		previous := sg.RegionLock()
		if _, err := sg.SetRegionLock(""); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.JSON(w, r, render.M{"group": sg.Tag(), "previous": previous, "now": sg.Now()})
	}
}

// redetectSmartRegions re-sorts the members into regions and starts exit
// probes; ?force=true probes every member, not just those that need it.
func redetectSmartRegions(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sg, ok := resolveLoadBalanceGroup(ctx, w, r)
		if !ok {
			return
		}
		force := r.URL.Query().Get("force") == "true" || r.URL.Query().Get("force") == "1"
		started := sg.RedetectRegions(force)
		render.JSON(w, r, render.M{"group": sg.Tag(), "exitProbes": started})
	}
}

// updateSmartBalance switches the balance strategy and / or affinity.
// Body: {"strategy": "least-connections", "affinity": "site"}; "default"
// restores the configured value, fields left out are not touched.
func updateSmartBalance(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sg, ok := resolveLoadBalanceGroup(ctx, w, r)
		if !ok {
			return
		}
		var body struct {
			Strategy string `json:"strategy"`
			Affinity string `json:"affinity"`
		}
		if err := render.DecodeJSON(r.Body, &body); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("invalid JSON body: "+err.Error()))
			return
		}
		strategy, affinity, err := sg.SetBalance(body.Strategy, body.Affinity)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.JSON(w, r, render.M{"group": sg.Tag(), "strategy": strategy, "affinity": affinity})
	}
}
