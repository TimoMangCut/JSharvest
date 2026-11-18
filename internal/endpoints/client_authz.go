package endpoints

import (
	"net/url"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

const maxAuthzItems = 500

// GuardedRoute is a client-side SPA route whose router metadata declares
// authentication, role, or permission requirements.
type GuardedRoute struct {
	Path         string   `json:"path"`
	AuthRequired *bool    `json:"auth_required,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
}

// ClientAuthz aggregates the client-side authorization surface across all
// non-tracker application scripts for intel.json and MCP get_intel.
type ClientAuthz struct {
	Roles         []string          `json:"roles,omitempty"`
	Permissions   []string          `json:"permissions,omitempty"`
	Rules         []jsapi.AuthzRule `json:"rules,omitempty"`
	PublicRoutes  []string          `json:"public_routes,omitempty"`
	GuardedRoutes []GuardedRoute    `json:"guarded_routes,omitempty"`
}

// ClientAuthzBuilder deduplicates and merges client-side authz signals across
// scripts and SPA router metadata.
type ClientAuthzBuilder struct {
	roles   map[string]bool
	perms   map[string]bool
	rules   map[jsapi.AuthzRule]bool
	pub     map[string]bool
	guarded map[string]*guardedRouteAcc
}

type guardedRouteAcc struct {
	authRequired *bool
	roles        map[string]bool
	perms        map[string]bool
}

func (b *ClientAuthzBuilder) init() {
	if b.roles != nil {
		return
	}
	b.roles = map[string]bool{}
	b.perms = map[string]bool{}
	b.rules = map[jsapi.AuthzRule]bool{}
	b.pub = map[string]bool{}
	b.guarded = map[string]*guardedRouteAcc{}
}

// AddJSAuthz merges a single script's AST-extracted ClientAuthz.
func (b *ClientAuthzBuilder) AddJSAuthz(ca *jsapi.ClientAuthz) {
	if ca == nil {
		return
	}
	b.init()
	for _, r := range ca.Roles {
		if r != "" {
			b.roles[r] = true
		}
	}
	for _, p := range ca.Permissions {
		if p != "" {
			b.perms[p] = true
		}
	}
	for _, rl := range ca.Rules {
		if rl.Action != "" {
			b.rules[rl] = true
		}
	}
}

// AddRoute merges a single SPA route's metadata into PublicRoutes / GuardedRoutes
// and propagates route-level roles and permissions into the global sets.
func (b *ClientAuthzBuilder) AddRoute(path string, authRequired *bool, roles, perms []string) {
	if path == "" {
		return
	}
	b.init()
	for _, r := range roles {
		if r != "" {
			b.roles[r] = true
		}
	}
	for _, p := range perms {
		if p != "" {
			b.perms[p] = true
		}
	}
	if authRequired != nil && !*authRequired && len(roles) == 0 && len(perms) == 0 {
		b.pub[path] = true
		return
	}
	if len(roles) == 0 && len(perms) == 0 && (authRequired == nil || !*authRequired) {
		return
	}
	acc := b.guarded[path]
	if acc == nil {
		acc = &guardedRouteAcc{roles: map[string]bool{}, perms: map[string]bool{}}
		b.guarded[path] = acc
	}
	if authRequired != nil {
		v := *authRequired || (acc.authRequired != nil && *acc.authRequired)
		acc.authRequired = &v
	}
	for _, r := range roles {
		if r != "" {
			acc.roles[r] = true
		}
	}
	for _, p := range perms {
		if p != "" {
			acc.perms[p] = true
		}
	}
}

// Build finalizes deduplicated, deterministically sorted, and capped slices,
// returning nil when no authorization surface was found.
func (b *ClientAuthzBuilder) Build() *ClientAuthz {
	if b == nil || b.roles == nil {
		return nil
	}
	out := &ClientAuthz{
		Roles:       sortedCappedStrings(b.roles, maxAuthzItems),
		Permissions: sortedCappedStrings(b.perms, maxAuthzItems),
	}
	if len(b.rules) > 0 {
		rules := make([]jsapi.AuthzRule, 0, len(b.rules))
		for r := range b.rules {
			rules = append(rules, r)
		}
		sort.Slice(rules, func(i, j int) bool {
			if rules[i].Action != rules[j].Action {
				return rules[i].Action < rules[j].Action
			}
			return rules[i].Subject < rules[j].Subject
		})
		if len(rules) > maxAuthzItems {
			rules = rules[:maxAuthzItems]
		}
		out.Rules = rules
	}
	for p := range b.guarded {
		delete(b.pub, p)
	}
	out.PublicRoutes = sortedCappedStrings(b.pub, maxAuthzItems)
	if len(b.guarded) > 0 {
		paths := sortedCappedStringsFromKeys(b.guarded, maxAuthzItems)
		out.GuardedRoutes = make([]GuardedRoute, 0, len(paths))
		for _, p := range paths {
			acc := b.guarded[p]
			out.GuardedRoutes = append(out.GuardedRoutes, GuardedRoute{
				Path:         p,
				AuthRequired: acc.authRequired,
				Roles:        sortedCappedStrings(acc.roles, maxAuthzItems),
				Permissions:  sortedCappedStrings(acc.perms, maxAuthzItems),
			})
		}
	}
	if len(out.Roles) == 0 && len(out.Permissions) == 0 && len(out.Rules) == 0 &&
		len(out.PublicRoutes) == 0 && len(out.GuardedRoutes) == 0 {
		return nil
	}
	return out
}

// MergeClientAuthz aggregates ClientAuthz across all non-tracker scripts.
func MergeClientAuthz(scripts []Script) *ClientAuthz {
	var b ClientAuthzBuilder
	linked := resolveScriptAuthzConsts(scripts)
	for idx, s := range scripts {
		if isAuthzTrackerScript(s) {
			continue
		}
		b.AddJSAuthz(s.ClientAuthz)
		extra := linked[idx]
		if extra != nil && (len(extra.roles) > 0 || len(extra.perms) > 0 || len(extra.rules) > 0) {
			b.AddJSAuthz(&jsapi.ClientAuthz{
				Roles:       extra.roles,
				Permissions: extra.perms,
				Rules:       extra.rules,
			})
		}
		mergeScriptRoutesWithExtra(&b, s, extra)
	}
	return b.Build()
}

// mergeScriptRoutes connects SPA router metadata (Section 2.2 RouteEntries)
// into ClientAuthzBuilder.
func mergeScriptRoutes(b *ClientAuthzBuilder, s Script) {
	mergeScriptRoutesWithExtra(b, s, nil)
}

func mergeScriptRoutesWithExtra(b *ClientAuthzBuilder, s Script, extra *resolvedScriptAuthz) {
	for _, re := range s.RouteEntries {
		roles := re.Roles
		perms := re.Permissions
		if extra != nil {
			if xr := extra.routeRoles[re.Path]; len(xr) > 0 {
				roles = append(append([]string(nil), roles...), xr...)
			}
			if xp := extra.routePerms[re.Path]; len(xp) > 0 {
				perms = append(append([]string(nil), perms...), xp...)
			}
		}
		b.AddRoute(re.Path, re.AuthRequired, roles, perms)
	}
}

func sortedCappedStrings(m map[string]bool, limit int) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sortedCappedStringsFromKeys[V any](m map[string]V, limit int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

var authzTrackerSuffixes = []string{
	"google-analytics.com",
	"googletagmanager.com",
	"googlesyndication.com",
	"googleadservices.com",
	"doubleclick.net",
	"facebook.net",
	"facebook.com",
	"hotjar.com",
	"clarity.ms",
	"segment.com",
	"segment.io",
	"mixpanel.com",
	"amplitude.com",
	"fullstory.com",
	"heapanalytics.com",
	"heap-analytics.com",
	"intercom.io",
	"intercomcdn.com",
	"hubspot.com",
	"hs-scripts.com",
	"hs-analytics.net",
	"tiktok.com",
	"licdn.com",
	"ads-twitter.com",
	"bing.com",
	"yandex.ru",
	"newrelic.com",
	"nr-data.net",
	"datadoghq.com",
	"browser-intake-datadoghq.com",
	"sentry.io",
	"sentry-cdn.com",
	"bugsnag.com",
	"rollbar.com",
	"logrocket.io",
	"lr-ingest.io",
	"cookielaw.org",
	"onetrust.com",
	"cookiebot.com",
	"usercentrics.eu",
	"criteo.com",
	"criteo.net",
	"taboola.com",
	"outbrain.com",
	"optimizely.com",
	"launchdarkly.com",
	"pendo.io",
	"walkme.com",
	"drift.com",
	"zdassets.com",
	"zendesk.com",
	"crisp.chat",
	"tawk.to",
	"livechatinc.com",
	"posthog.com",
	"plausible.io",
	"rudderlabs.com",
	"cdnjs.cloudflare.com",
	"unpkg.com",
	"cdn.jsdelivr.net",
	"code.jquery.com",
	"ajax.googleapis.com",
	"stackpath.bootstrapcdn.com",
	"maxcdn.bootstrapcdn.com",
}

func isAuthzTrackerScript(s Script) bool {
	if len(s.URLs) == 0 {
		return s.ThirdParty
	}
	for _, raw := range s.URLs {
		if !isAuthzTrackerURL(raw, s.ThirdParty) {
			return false
		}
	}
	return true
}

func isAuthzTrackerURL(raw string, thirdParty bool) bool {
	if detect.ChallengeURL(raw) || detect.InfraURL(raw) {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return thirdParty
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	for _, suf := range authzTrackerSuffixes {
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return true
		}
	}
	if thirdParty {
		for _, pre := range []string{"analytics.", "telemetry.", "tracker.", "tracking.", "metrics.", "pixel.", "ads."} {
			if strings.HasPrefix(h, pre) {
				return true
			}
		}
	}
	return false
}
