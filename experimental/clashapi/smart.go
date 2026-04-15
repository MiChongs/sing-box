// Smart-specific Clash API endpoints mirroring mihomo's /groups/weights
// and the connection-level Smart block action. Per-group weight endpoint
// lives under /proxies/{name}/weights; this file hosts cross-group routes.
package clashapi

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// smartRouter mounts at /smart.
//
//	GET  /smart/weights             — aggregate ranking across all Smart groups
//	GET  /smart/groups              — list Smart groups with capability flags
//	POST /smart/groups/{name}/block/{node}
//	                                 — block a single node by tag within a group
func smartRouter(ctx context.Context) http.Handler {
	r := chi.NewRouter()
	r.Get("/weights", getAllSmartWeights(ctx))
	r.Get("/groups", listSmartGroups(ctx))
	r.Get("/groups/{name}/diag", smartGroupDiag(ctx))
	r.Post("/groups/{name}/block/{node}", blockSmartNode(ctx))
	r.Put("/groups/{name}/algorithm", setSmartAlgorithm(ctx))
	return r
}

// smartGroupDiag returns deep internal state for one Smart group so
// operators can debug "TargetCount is wrong" / "ranking looks stale"
// without attaching a debugger. Surfaces:
//
//   - currently configured algorithm + hysteresis
//   - parsed policy_priority rules
//   - which fallback tier WeightRanking would currently serve
//     (snapshot / bbolt cache / live / delay)
//   - per-node TargetCount / SampleCount as observed RIGHT NOW from
//     the bbolt stats table — bypasses every cache so the user sees
//     the source of truth
//
// Read-only; safe to hammer.
func smartGroupDiag(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
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
		render.JSON(w, r, sg.DiagnosticSnapshot())
	}
}

// setSmartAlgorithm switches the per-group reorder algorithm at
// runtime. Body: {"algorithm":"<name>"}. Unknown names collapse to
// strict-best (mirrors NewSmart). Returns the canonical name actually
// applied, plus the prior value so clients can confirm the swap.
func setSmartAlgorithm(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("group name required"))
			return
		}
		var body struct {
			Algorithm string `json:"algorithm"`
		}
		if err := render.DecodeJSON(r.Body, &body); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("invalid JSON body: "+err.Error()))
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
		previous := sg.CurrentAlgorithm()
		applied := sg.SetAlgorithm(body.Algorithm)
		render.JSON(w, r, render.M{
			"group":     name,
			"requested": body.Algorithm,
			"applied":   applied,
			"previous":  previous,
		})
	}
}

// getAllSmartWeights returns a map of group-tag → weight-ranking list.
// Parallel fetch (5 workers cap) to match mihomo's implementation shape.
func getAllSmartWeights(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		outboundMgr := service.FromContext[adapter.OutboundManager](ctx)
		if outboundMgr == nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError("outbound manager unavailable"))
			return
		}

		refresh := r.URL.Query().Get("refresh") == "true"

		result := make(map[string][]smart.NodeRank)
		errorsMap := make(map[string]string)

		var (
			mu  sync.Mutex
			wg  sync.WaitGroup
			sem = make(chan struct{}, 5)
		)

		for _, ob := range outboundMgr.Outbounds() {
			sg, ok := ob.(*group.Smart)
			if !ok {
				continue
			}
			tag := sg.Tag()
			wg.Add(1)
			sem <- struct{}{}
			go func(tag string, sg *group.Smart) {
				defer wg.Done()
				defer func() { <-sem }()
				weights, err := sg.WeightRanking(refresh)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errorsMap[tag] = err.Error()
					return
				}
				result[tag] = weights
			}(tag, sg)
		}
		wg.Wait()

		if len(result) == 0 && len(errorsMap) == 0 {
			render.JSON(w, r, render.M{
				"weights": map[string][]smart.NodeRank{},
				"message": "no Smart groups configured",
			})
			return
		}
		render.JSON(w, r, render.M{
			"weights": result,
			"errors":  errorsMap,
		})
	}
}

// listSmartGroups returns capability info for every Smart group — what mihomo
// users rely on to decide which groups can receive weights / block calls.
func listSmartGroups(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		outboundMgr := service.FromContext[adapter.OutboundManager](ctx)
		if outboundMgr == nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError("outbound manager unavailable"))
			return
		}
		type groupInfo struct {
			Name           string           `json:"name"`
			TestURL        string           `json:"testUrl"`
			UseASN         bool             `json:"useASN"`
			UseLightGBM    bool             `json:"useLightGBM"`
			CollectData    bool             `json:"collectData"`
			Fixed          string           `json:"fixed"`
			Now            string           `json:"now"`
			LGBMModelAge   string           `json:"lgbmModelAge,omitempty"`
			Members        int              `json:"members"`
			PolicyPriority []map[string]any `json:"policyPriority,omitempty"`
			PinEndorsements []map[string]any `json:"pinEndorsements,omitempty"`
			Algorithm      string           `json:"algorithm"`
			Hysteresis     string           `json:"hysteresis,omitempty"`
		}
		out := []groupInfo{}
		for _, ob := range outboundMgr.Outbounds() {
			sg, ok := ob.(*group.Smart)
			if !ok {
				continue
			}
			gi := groupInfo{
				Name:        sg.Tag(),
				TestURL:     sg.TestURL(),
				UseASN:      sg.UseASN(),
				UseLightGBM: sg.UseLightGBM(),
				CollectData: sg.CollectData(),
				Fixed:       sg.Selected(),
				Now:         sg.Now(),
				Members:     len(sg.All()),
				// Surface the parsed rules so operators can verify the
				// policy_priority string was understood as intended.
				// Only present (omitempty) when rules exist.
				PolicyPriority: sg.PolicyPriorityRules(),
				PinEndorsements: sg.PinEndorsementDebug(),
				// Live algorithm setting — reflects any runtime
				// SetAlgorithm calls, not just the start-up config.
				Algorithm: sg.CurrentAlgorithm(),
			}
			if h := sg.HysteresisDuration(); h > 0 {
				gi.Hysteresis = h.String()
			}
			if age := sg.LGBMModelAge(); age > 0 {
				gi.LGBMModelAge = age.Truncate(time.Second).String()
			}
			out = append(out, gi)
		}
		render.JSON(w, r, render.M{"groups": out})
	}
}

// blockSmartNode marks a node inside a specific Smart group as blocked for
// the default cooldown period. `?duration=15m` (Go duration format) overrides.
// Responds 404 if the group or node doesn't exist.
func blockSmartNode(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		node := chi.URLParam(r, "node")
		if name == "" || node == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("group and node names required"))
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

		// Verify the node is actually in the group before blocking, otherwise
		// we'd write a NodeState for a non-existent node.
		inGroup := false
		for _, tag := range sg.All() {
			if tag == node {
				inGroup = true
				break
			}
		}
		if !inGroup {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError("node not a member of this group"))
			return
		}

		duration := group.DefaultBlockDuration
		if d := r.URL.Query().Get("duration"); d != "" {
			if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
				duration = parsed
			}
		}

		if err := sg.MarkBlocked(node, duration); err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.JSON(w, r, render.M{
			"group":         name,
			"node":          node,
			"blocked_until": time.Now().Add(duration).Format(time.RFC3339),
		})
	}
}
