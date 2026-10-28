package clashapi

import (
	"context"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	R "github.com/sagernet/sing-box/route/rule"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badjson"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func ruleProviderRouter(router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRuleProviders(router))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProviderName, findRuleProviderByName(router))
		r.Get("/", getRuleProvider)
		r.Put("/", updateRuleProvider)
	})
	return r
}

// ruleSetInfo 对齐 mihomo rule-provider 的 JSON：behavior 按内容推断，
// format 沿用 mihomo 的 xxxRule 命名，ruleCount 为完整展开后的条目数。
func ruleSetInfo(ruleSet adapter.RuleSet) *badjson.JSONObject {
	var info badjson.JSONObject
	info.Put("name", ruleSet.Name())
	info.Put("type", "Rule")
	info.Put("vehicleType", ruleSetVehicleType(ruleSet.Type()))
	info.Put("behavior", ruleSetBehavior(ruleSet))
	if ruleSet.Type() != C.RuleSetTypeInline {
		info.Put("format", ruleSetFormat(ruleSet.Format()))
	}
	info.Put("ruleCount", ruleSet.RuleCount())
	info.Put("updatedAt", ruleSet.UpdatedTime().Format("2006-01-02T15:04:05.999999999-07:00"))
	return &info
}

func ruleSetVehicleType(ruleSetType string) string {
	switch ruleSetType {
	case C.RuleSetTypeRemote:
		return "HTTP"
	case C.RuleSetTypeLocal:
		return "File"
	case C.RuleSetTypeInline:
		return "Inline"
	default:
		return "Unknown"
	}
}

func ruleSetFormat(format string) string {
	switch format {
	case C.RuleSetFormatSource:
		return "JsonRule"
	case C.RuleSetFormatBinary:
		return "SrsRule"
	default:
		return "Unknown"
	}
}

func ruleSetBehavior(ruleSet adapter.RuleSet) string {
	if behaviorRuleSet, isBehavior := ruleSet.(interface{ Behavior() string }); isBehavior {
		return behaviorRuleSet.Behavior()
	}
	return R.RuleSetBehaviorClassical
}

func getRuleProviders(router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		providerMap := render.M{}
		for i, ruleSet := range router.RuleSets() {
			var tag string
			if ruleSet.Name() == "" {
				tag = F.ToString(i)
			} else {
				tag = ruleSet.Name()
			}
			providerMap[tag] = ruleSetInfo(ruleSet)
		}
		render.JSON(w, r, render.M{
			"providers": providerMap,
		})
	}
}

func getRuleProvider(w http.ResponseWriter, r *http.Request) {
	ruleSet := r.Context().Value(CtxKeyProvider).(adapter.RuleSet)
	render.JSON(w, r, ruleSetInfo(ruleSet))
}

func updateRuleProvider(w http.ResponseWriter, r *http.Request) {
	ruleSet := r.Context().Value(CtxKeyProvider).(adapter.RuleSet)
	err := ruleSet.Update(r.Context())
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func findRuleProviderByName(router adapter.Router) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProviderName).(string)
			provider, exist := router.RuleSet(name)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyProvider, provider)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
