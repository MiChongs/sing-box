package clashapi

import (
	"context"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func ruleRouter(router adapter.Router, dnsRouter adapter.DNSRouter) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules(router, dnsRouter))
	r.Patch("/disable", disableRules(router, dnsRouter))
	r.Route("/{uuid}", func(r chi.Router) {
		r.Use(parseRuleUUID, findRuleByUUID(router, dnsRouter))
		r.Put("/", changeRuleStatus)
	})
	return r
}

type Rule struct {
	Index   int    `json:"index"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
	Size    int    `json:"size"`

	// Extra 与 mihomo RuleWrapper 的统计字段一致
	Extra *RuleExtra `json:"extra,omitempty"`

	Disabled bool   `json:"disabled,omitempty"`
	UUID     string `json:"uuid,omitempty"`
}

type RuleExtra struct {
	Disabled  bool      `json:"disabled"`
	HitCount  uint64    `json:"hitCount"`
	HitAt     time.Time `json:"hitAt"`
	MissCount uint64    `json:"missCount"`
	MissAt    time.Time `json:"missAt"`
}

// allRules 返回 /rules 列出的规则，下标即 Rule.Index：与 mihomo 一致先列出路由规则，
// DNS 规则接在其后。
func allRules(router adapter.Router, dnsRouter adapter.DNSRouter) []adapter.Rule {
	routeRules := router.Rules()
	dnsRules := dnsRouter.Rules()
	rules := make([]adapter.Rule, 0, len(routeRules)+len(dnsRules))
	rules = append(rules, routeRules...)
	for _, rule := range dnsRules {
		rules = append(rules, rule)
	}
	return rules
}

func getRules(router adapter.Router, dnsRouter adapter.DNSRouter) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		rawRules := allRules(router, dnsRouter)
		rules := make([]Rule, 0, len(rawRules))
		for index, rule := range rawRules {
			disabled := rule.Disabled()
			ruleType, payload := R.ClashRule(rule)
			rules = append(rules, Rule{
				Index:   index,
				Type:    ruleType,
				Payload: payload,
				Proxy:   R.ClashProxy(rule.Action()),
				Size:    -1,
				Extra: &RuleExtra{
					Disabled:  disabled,
					HitCount:  rule.HitCount(),
					HitAt:     rule.HitAt(),
					MissCount: rule.MissCount(),
					MissAt:    rule.MissAt(),
				},

				Disabled: disabled,
				UUID:     rule.UUID(),
			})
		}
		render.JSON(w, r, render.M{
			"rules": rules,
		})
	}
}

// disableRules 同 mihomo PATCH /rules/disable：按 /rules 返回的 index 设置禁用状态，
// 请求体 key 为规则下标，value 为是否禁用；越界下标忽略。
func disableRules(router adapter.Router, dnsRouter adapter.DNSRouter) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var payload map[int]bool
		if err := render.DecodeJSON(r.Body, &payload); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if len(payload) != 0 {
			rules := allRules(router, dnsRouter)
			for index, disabled := range payload {
				if index < 0 || index >= len(rules) {
					continue
				}
				rules[index].SetDisabled(disabled)
			}
		}
		render.NoContent(w, r)
	}
}

func parseRuleUUID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uuid := getEscapeParam(r, "uuid")
		ctx := context.WithValue(r.Context(), CtxKeyRuleUUID, uuid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findRuleByUUID(router adapter.Router, dnsRouter adapter.DNSRouter) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uuid := r.Context().Value(CtxKeyRuleUUID).(string)
			routeRule, exist := router.Rule(uuid)
			if exist {
				ctx := context.WithValue(r.Context(), CtxKeyRule, routeRule)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			dnsRule, dnsExist := dnsRouter.Rule(uuid)
			if dnsExist {
				ctx := context.WithValue(r.Context(), CtxKeyRule, adapter.Rule(dnsRule))
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
		})
	}
}

func changeRuleStatus(w http.ResponseWriter, r *http.Request) {
	rule := r.Context().Value(CtxKeyRule).(adapter.Rule)
	rule.ChangeStatus()
	render.NoContent(w, r)
}
