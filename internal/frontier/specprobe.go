package frontier

import (
	"cmp"
	"maps"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

const (
	// MaxSpecBases bounds the API gateway / sub-path bases probed in Phase 2 (0: unlimited).
	MaxSpecBases = 0
	// MaxServiceDocPrefixes bounds the microservice prefixes probed for
	// /v3/api-docs and /v2/api-docs in Phase 2 (0: unlimited).
	MaxServiceDocPrefixes = 0
	// MaxPhase2SpecProbes caps total Phase-2 GET requests across a crawl (0: unlimited).
	MaxPhase2SpecProbes = 0
	// MaxOutOfScopeSpecBasesPerOrigin bounds the bases of one host outside
	// -scope that Phase 2 asks SpecPaths of (round 40, B1): only bases the
	// app's code names itself (an API Gateway stage, /prod; a worker's /v1),
	// never derived gateways nor microservice prefixes.
	MaxOutOfScopeSpecBasesPerOrigin = 2
)

// ServiceDocPaths are the canonical microservice OpenAPI paths probed on
// top service sub-prefixes in Phase 2 (D3).
var ServiceDocPaths = []string{"/v3/api-docs", "/v2/api-docs"}

var (
	versionSegRe = regexp.MustCompile(`(?i)^v\d+(?:\.\d+)*$`)
	serviceSegRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,47}$`)
	headerNameRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]{1,128}$`)
)

var genericServiceSegs = map[string]bool{
	"api": true, "apis": true, "rest": true, "graphql": true, "gql": true,
	"rpc": true, "grpc": true, "ajax": true, "odata": true, "_api": true,
	"oauth": true, "oauth2": true, "oidc": true, ".well-known": true, "well-known": true,
	"static": true, "assets": true, "public": true, "js": true, "css": true,
	"img": true, "images": true, "fonts": true, "media": true, "files": true,
	"uploads": true, "download": true, "swagger": true, "openapi": true,
	"api-docs": true, "swagger-resources": true, "docs": true,
}

var unsafeClientHeaders = map[string]bool{
	"host":                true,
	"cookie":              true,
	"cookie2":             true,
	"set-cookie":          true,
	"authorization":       true,
	"proxy-authorization": true,
	"content-length":      true,
	"transfer-encoding":   true,
	"connection":          true,
	"keep-alive":          true,
	"te":                  true,
	"trailer":             true,
	"upgrade":             true,
	"proxy-connection":    true,
	"origin":              true,
	"referer":             true,
	"user-agent":          true,
	"accept-encoding":     true,
}

// ServiceDocTarget is one microservice root to ask ServiceDocPaths of.
type ServiceDocTarget struct {
	GatewayBase string // e.g. "https://host/api-gateway" or "https://host"
	PrefixURL   string // e.g. "https://host/api-gateway/auth"
}

// SpecProbePlan is the deterministic Phase-2 probe schedule derived from
// harvested scripts.
type SpecProbePlan struct {
	Bases    []string
	Services []ServiceDocTarget
}

type scopedHeader struct {
	origin string
	name   string
	value  string
}

type rawBase struct {
	raw      string
	origin   string
	explicit bool
}

type rawEndpoint struct {
	url       string
	origin    string
	client    bool
	noInherit bool
}

var propNameSepCutter = strings.NewReplacer("_", "", "-", "")

// isAPIBasePropName reports whether a PropBases property name identifies a
// server/API/gateway base rather than a UI menu link, template URL, or XML namespace.
func isAPIBasePropName(name string) bool {
	name = strings.TrimSpace(name)
	if len(name) < 2 || len(name) > 64 {
		return false
	}
	n := strings.ToLower(propNameSepCutter.Replace(name))
	for _, bad := range []string{
		"cdn", "asset", "static", "image", "img", "icon", "avatar", "thumb", "logo", "media",
		"login", "logout", "home", "page", "web", "site", "redirect", "callback", "return",
		"template", "chart", "schema", "xml", "draw", "worksheet", "doc", "help", "support",
		"socket", "menu", "nav", "route", "sidebar", "breadcrumb", "download", "link", "href", "src",
	} {
		if strings.Contains(n, bad) {
			return false
		}
	}
	switch n {
	case "base", "host", "origin", "server", "gateway", "gw", "backend", "proxy", "endpoint":
		return true
	}
	for _, tok := range []string{"base", "gateway", "server", "backend", "proxy", "endpoint", "rest", "graphql"} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	if strings.HasSuffix(n, "gw") || strings.HasSuffix(n, "host") || strings.HasSuffix(n, "origin") {
		return true
	}
	return strings.Contains(n, "api") && (strings.Contains(n, "url") || strings.Contains(n, "uri") || strings.Contains(n, "root") || strings.Contains(n, "prefix") || strings.HasSuffix(n, "api"))
}

func normalizeRoutePath(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	s, _, _ = strings.Cut(s, "?")
	s, _, _ = strings.Cut(s, "#")
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return ""
		}
		s = u.Path
	}
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return ""
	}
	cleanP := path.Clean("/" + strings.Trim(s, "/"))
	if cleanP == "/" || cleanP == "." {
		return ""
	}
	return cleanP
}

// SpecCollector gathers Bases, microservice endpoint prefixes and static
// ClientHeaders from harvested non-tracker scripts during a crawl.
type SpecCollector struct {
	mu        sync.Mutex
	headers   []scopedHeader
	bases     []rawBase
	endpoints []rawEndpoint
	routes    map[string]bool
}

// AddScript records the bases, endpoints and static client_headers of r.
// Vendor, CDN-infra and third-party tracker scripts are ignored.
func (sc *SpecCollector) AddScript(r jsapi.Result, pageURL, scriptURL string) {
	if Vendor(scriptURL) || IsTrackerURL(scriptURL) || detect.InfraURL(scriptURL) {
		return
	}
	srcURL := pageURL
	if srcURL == "" {
		srcURL = scriptURL
	}
	origin := cleanOrigin(srcURL)
	if origin == "" {
		return
	}

	var hs []scopedHeader
	for _, h := range r.ClientHeaders {
		name := strings.TrimSpace(h.Name)
		val := strings.TrimSpace(h.Value)
		if !validStaticClientHeader(name, val) {
			continue
		}
		hs = append(hs, scopedHeader{origin: origin, name: name, value: val})
	}

	var bs []rawBase
	for _, b := range r.Bases {
		bs = append(bs, rawBase{raw: b, origin: origin, explicit: true})
	}
	for _, b := range r.PropBases {
		if isAPIBasePropName(b.Name) {
			bs = append(bs, rawBase{raw: b.Value, origin: origin, explicit: false})
		}
	}
	for _, s := range r.Settings {
		bs = append(bs, rawBase{raw: s.Value, origin: origin, explicit: false})
	}

	var eps []rawEndpoint
	for _, e := range r.Endpoints {
		if e.Kind == "navigation" || e.Kind == "openapi" || e.Collector || e.URL == "" {
			continue
		}
		eps = append(eps, rawEndpoint{
			url:       e.URL,
			origin:    origin,
			client:    e.Client,
			noInherit: e.NoInheritBase,
		})
	}

	var routes []string
	for _, rt := range r.Routes {
		if p := normalizeRoutePath(rt); p != "" {
			routes = append(routes, p)
		}
	}
	for _, re := range r.RouteEntries {
		if p := normalizeRoutePath(re.Path); p != "" {
			routes = append(routes, p)
		}
	}

	sc.mu.Lock()
	sc.headers = append(sc.headers, hs...)
	sc.bases = append(sc.bases, bs...)
	sc.endpoints = append(sc.endpoints, eps...)
	if len(routes) > 0 {
		if sc.routes == nil {
			sc.routes = map[string]bool{}
		}
		for _, p := range routes {
			sc.routes[p] = true
		}
	}
	sc.mu.Unlock()
}

func validStaticClientHeader(name, val string) bool {
	if name == "" || val == "" || len(val) > 4096 {
		return false
	}
	if strings.Contains(name, "{}") || strings.Contains(val, "{}") ||
		strings.ContainsAny(name, "\r\n\x00") || strings.ContainsAny(val, "\r\n\x00") {
		return false
	}
	if !headerNameRe.MatchString(name) {
		return false
	}
	low := strings.ToLower(name)
	if unsafeClientHeaders[low] || strings.HasPrefix(low, "sec-fetch-") || strings.HasPrefix(low, "sec-ch-ua") {
		return false
	}
	return true
}

// SameHeaderScope reports whether static client_headers declared on
// declaringOrigin may be attached to a probe request for targetURL.
func SameHeaderScope(declaringOrigin, targetURL string, inScope func(string) bool) bool {
	pu, err1 := url.Parse(declaringOrigin)
	tu, err2 := url.Parse(targetURL)
	if err1 != nil || err2 != nil || pu.Host == "" || tu.Host == "" {
		return false
	}
	th := strings.ToLower(tu.Hostname())
	if inScope != nil && !inScope(th) {
		return false
	}
	if strings.EqualFold(pu.Scheme, tu.Scheme) && strings.EqualFold(pu.Host, tu.Host) {
		return true
	}
	ph := strings.ToLower(pu.Hostname())
	if net.ParseIP(ph) != nil || net.ParseIP(th) != nil || !strings.Contains(ph, ".") || !strings.Contains(th, ".") {
		return false
	}
	rdnP, errP := publicsuffix.EffectiveTLDPlusOne(ph)
	rdnT, errT := publicsuffix.EffectiveTLDPlusOne(th)
	return errP == nil && errT == nil && rdnP != "" && strings.EqualFold(rdnP, rdnT)
}

// HeadersFor returns the static client_headers eligible for targetURL,
// scoped strictly to the declaring page/script's origin or RDN.
func (sc *SpecCollector) HeadersFor(targetURL string, inScope func(string) bool) []jsapi.Header {
	sc.mu.Lock()
	snapshot := slices.Clone(sc.headers)
	sc.mu.Unlock()

	var candidates []jsapi.Header
	for _, h := range snapshot {
		if SameHeaderScope(h.origin, targetURL, inScope) {
			candidates = append(candidates, jsapi.Header{Name: h.name, Value: h.value})
		}
	}
	slices.SortStableFunc(candidates, func(a, b jsapi.Header) int {
		if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		return strings.Compare(a.Value, b.Value)
	})
	var out []jsapi.Header
	seen := map[string]bool{}
	for _, h := range candidates {
		k := strings.ToLower(h.Name)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, h)
		if len(out) >= 16 {
			break
		}
	}
	return out
}

// JoinSpecBase joins a root or gateway base ("https://host" or
// "https://host/api-gateway") with a relative spec path ("/v2/api-docs" or
// "/orders/v2/api-docs") without duplicating the gateway prefix when rel
// already carries it.
func JoinSpecBase(base, rel string) string {
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	u, err := url.Parse(base)
	if err == nil && u.Path != "" && u.Path != "/" {
		bp := strings.TrimRight(u.Path, "/")
		if rel == bp || strings.HasPrefix(rel, bp+"/") || strings.HasPrefix(rel, bp+"?") {
			return strings.ToLower(u.Scheme+"://"+u.Host) + rel
		}
	}
	return base + rel
}

// Plan computes up to MaxSpecBases gateway bases and up to
// MaxServiceDocPrefixes microservice prefixes ordered by endpoint frequency
// then lexicographically.
func (sc *SpecCollector) Plan(seedOrigin string, inScope func(string) bool) SpecProbePlan {
	sc.mu.Lock()
	rawBases := slices.Clone(sc.bases)
	rawEps := slices.Clone(sc.endpoints)
	routes := maps.Clone(sc.routes)
	sc.mu.Unlock()

	type baseStat struct {
		url      string
		origin   string
		path     string
		explicit bool
		inScope  bool
		freq     int
	}
	urlInScope := func(raw string) bool {
		if inScope == nil {
			return true
		}
		u, err := url.Parse(raw)
		return err == nil && u != nil && u.Hostname() != "" && inScope(u.Hostname())
	}

	// A host outside -scope gets no sub-path multiplication (round 40, B1):
	// only a base the code names itself (Result.Bases, explicit) is asked
	// of, at most MaxOutOfScopeSpecBasesPerOrigin of a host, and never a
	// microservice prefix under it (addSvc). Third-party SDK/IdP/map hosts
	// are dropped earlier by normalizeSpecBase (isStaticOrNonAPIHost).
	baseMap := map[string]*baseStat{}
	noteBase := func(raw, defOrigin string, explicit bool) {
		norm, orig, bp, ok := normalizeSpecBase(raw, defOrigin)
		if !ok || bp == "" {
			return
		}
		inS := urlInScope(norm)
		st := baseMap[norm]
		if st == nil {
			if !inS && !explicit {
				return
			}
			st = &baseStat{url: norm, origin: orig, path: bp, explicit: explicit, inScope: inS}
			baseMap[norm] = st
		}
		if explicit {
			st.explicit = true
		}
		st.freq++
	}

	for _, b := range rawBases {
		def := b.origin
		if def == "" {
			def = seedOrigin
		}
		noteBase(b.raw, def, b.explicit)
	}

	// Detect implicit gateway prefixes from full paths like "/api-gateway/auth/v1.0/login"
	// when scripts inline the gateway prefix directly into endpoint URLs.
	type gwKey struct{ origin, seg0 string }
	gwServices := map[gwKey]map[string]int{}
	for _, ep := range rawEps {
		orig, cleanPath, ok := resolveEndpointPath(ep.url, ep.origin, seedOrigin)
		if !ok {
			continue
		}
		segs := splitCleanSegs(cleanPath)
		if len(segs) >= 3 && validGatewaySeg(segs[0]) && validServiceSeg(segs[1]) && versionSegRe.MatchString(segs[2]) {
			k := gwKey{origin: orig, seg0: segs[0]}
			if gwServices[k] == nil {
				gwServices[k] = map[string]int{}
			}
			gwServices[k][segs[1]]++
		}
	}
	for k, svcs := range gwServices {
		gwLower := strings.ToLower(k.seg0)
		looksLikeGateway := strings.Contains(gwLower, "gateway") || strings.Contains(gwLower, "gw") ||
			strings.Contains(gwLower, "api") || strings.Contains(gwLower, "proxy")
		if looksLikeGateway || len(svcs) >= 2 {
			noteBase(k.origin+"/"+k.seg0, k.origin, false)
		}
	}

	allBases := make([]*baseStat, 0, len(baseMap))
	for _, st := range baseMap {
		if !st.explicit && routes[st.path] {
			continue
		}
		allBases = append(allBases, st)
	}
	slices.SortFunc(allBases, func(a, b *baseStat) int {
		if a.inScope != b.inScope {
			if a.inScope {
				return -1
			}
			return 1
		}
		if a.explicit != b.explicit {
			if a.explicit {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(b.freq, a.freq); c != 0 {
			return c
		}
		return strings.Compare(a.url, b.url)
	})

	var plan SpecProbePlan
	var keptBases []*baseStat
	outOfScope := map[string]int{}
	for _, st := range allBases {
		if MaxSpecBases > 0 && len(plan.Bases) >= MaxSpecBases {
			break
		}
		if !st.inScope {
			if !st.explicit || outOfScope[st.origin] >= MaxOutOfScopeSpecBasesPerOrigin {
				continue
			}
			outOfScope[st.origin]++
		}
		plan.Bases = append(plan.Bases, st.url)
		keptBases = append(keptBases, st)
	}

	// Derive 1-segment microservice roots under gateway bases or origins.
	type svcStat struct {
		gateway string
		prefix  string
		freq    int
	}
	svcMap := map[string]*svcStat{}
	addSvc := func(gateway, svc string) {
		if !urlInScope(gateway) {
			return
		}
		prefix := strings.TrimRight(gateway, "/") + "/" + svc
		if st := svcMap[prefix]; st != nil {
			st.freq++
			return
		}
		svcMap[prefix] = &svcStat{gateway: strings.TrimRight(gateway, "/"), prefix: prefix, freq: 1}
	}

	for _, ep := range rawEps {
		isAbs := strings.Contains(ep.url, "://")
		orig, cleanPath, ok := resolveEndpointPath(ep.url, ep.origin, seedOrigin)
		if !ok {
			continue
		}

		// 1. Match full path already carrying a discovered gateway base (e.g. "/api-gateway/auth/v1/login").
		matchedBase := false
		for _, b := range keptBases {
			if b.origin == orig && strings.HasPrefix(cleanPath, b.path+"/") {
				rest := strings.TrimPrefix(cleanPath, b.path+"/")
				segs := splitCleanSegs(rest)
				if len(segs) >= 2 && validServiceSeg(segs[0]) {
					addSvc(b.url, segs[0])
				}
				matchedBase = true
			}
		}
		if matchedBase {
			continue
		}

		// 2. Relative endpoint path combined with discovered gateway bases on the same origin/RDN.
		segs := splitCleanSegs(cleanPath)
		if len(segs) < 2 || !validServiceSeg(segs[0]) {
			continue
		}
		if !isAbs && !ep.noInherit {
			hasExplicit := false
			for _, b := range keptBases {
				if b.explicit && (b.origin == orig || SameHeaderScope(ep.origin, b.url, inScope)) {
					hasExplicit = true
					break
				}
			}
			attached := false
			for _, b := range keptBases {
				if hasExplicit && !b.explicit {
					continue
				}
				if b.origin == orig || SameHeaderScope(ep.origin, b.url, inScope) {
					addSvc(b.url, segs[0])
					attached = true
				}
			}
			if attached {
				continue
			}
		}

		// 3. Origin-level versioned microservice path (e.g. "/auth/v1/login" or "https://api.host/auth/v1/login").
		if versionSegRe.MatchString(segs[1]) {
			addSvc(orig, segs[0])
		}
	}

	allSvcs := make([]*svcStat, 0, len(svcMap))
	for _, st := range svcMap {
		allSvcs = append(allSvcs, st)
	}
	slices.SortFunc(allSvcs, func(a, b *svcStat) int {
		if c := cmp.Compare(b.freq, a.freq); c != 0 {
			return c
		}
		return strings.Compare(a.prefix, b.prefix)
	})
	for _, st := range allSvcs {
		if MaxServiceDocPrefixes > 0 && len(plan.Services) >= MaxServiceDocPrefixes {
			break
		}
		plan.Services = append(plan.Services, ServiceDocTarget{
			GatewayBase: st.gateway,
			PrefixURL:   st.prefix,
		})
	}
	return plan
}

func cleanOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

func normalizeSpecBase(raw, defOrigin string) (normURL, orig, basePath string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.ContainsAny(s, "{}*?#! \t\r\n\\") || strings.HasPrefix(s, "//") {
		return "", "", "", false
	}
	var u *url.URL
	var err error
	if strings.Contains(s, "://") {
		u, err = url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return "", "", "", false
		}
		if isStaticOrNonAPIHost(strings.ToLower(u.Hostname())) {
			return "", "", "", false
		}
	} else {
		if !strings.HasPrefix(s, "/") || defOrigin == "" {
			return "", "", "", false
		}
		u, err = url.Parse(defOrigin + s)
		if err != nil || u.Host == "" {
			return "", "", "", false
		}
	}
	cleanP := path.Clean("/" + strings.Trim(u.Path, "/"))
	if cleanP == "/" || cleanP == "." {
		cleanP = ""
	}
	if cleanP != "" {
		if ext := strings.ToLower(path.Ext(cleanP)); ext != "" && (assetExt[ext] || ext == ".html" || ext == ".htm" || ext == ".json" || ext == ".yaml" || ext == ".yml" || ext == ".xml") {
			return "", "", "", false
		}
		if detect.InfraPath(cleanP) || internalPath(cleanP) || templatePath(cleanP) {
			return "", "", "", false
		}
	}
	orig = strings.ToLower(u.Scheme + "://" + u.Host)
	return orig + cleanP, orig, cleanP, true
}

func resolveEndpointPath(raw, epOrigin, seedOrigin string) (orig, cleanPath string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "//") {
		return "", "", false
	}
	s, _, _ = strings.Cut(s, "?")
	s, _, _ = strings.Cut(s, "#")
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.Contains(u.Host, "{") {
			return "", "", false
		}
		if isStaticOrNonAPIHost(strings.ToLower(u.Hostname())) {
			return "", "", false
		}
		orig = strings.ToLower(u.Scheme + "://" + u.Host)
		cleanPath = "/" + strings.TrimLeft(u.Path, "/")
		return orig, cleanPath, true
	}
	orig = epOrigin
	if orig == "" {
		orig = seedOrigin
	}
	if orig == "" {
		return "", "", false
	}
	cleanPath = "/" + strings.TrimLeft(s, "/")
	return orig, cleanPath, true
}

func splitCleanSegs(p string) []string {
	var out []string
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

func validServiceSeg(seg string) bool {
	if !serviceSegRe.MatchString(seg) {
		return false
	}
	low := strings.ToLower(seg)
	return !versionSegRe.MatchString(low) && !genericServiceSegs[low]
}

func validGatewaySeg(seg string) bool {
	if !serviceSegRe.MatchString(seg) {
		return false
	}
	low := strings.ToLower(seg)
	if versionSegRe.MatchString(low) {
		return false
	}
	for _, bad := range []string{"static", "assets", "public", "js", "css", "img", "images", "fonts", "media"} {
		if low == bad {
			return false
		}
	}
	return true
}
