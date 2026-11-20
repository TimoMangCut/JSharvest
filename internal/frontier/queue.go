package frontier

import (
	"container/heap"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

// Why a URL is not visited.
const (
	NotHTTP     = "scheme"
	OutOfScope  = "scope"
	NotGET      = "post"        // a form or call with another method: named, never sent
	OnlyNamed   = "listed"      // a resource or a text URL
	Asset       = "asset"       // a static file: no page
	API         = "api"         // an API call the scripts make; in endpoints.jsonl
	Destructive = "destructive" // logout, delete…: the guard's rules
	CDNInfra    = "cdn-infra"   // the CDN's own /cdn-cgi/ paths: never the site's pages
	Template          = "template"           // a path a script builds, its {placeholders} unfilled
	SPARoute          = "spa-route"          // a client route of an app whose server answers every path with its shell
	TemplateSaturated = "template-saturated" // an SSR/MPA path template that yielded 0 new info across repeated samples
	TooDeep           = "depth"
	Limit             = "limit"
	seenAlready       = "seen"
)

var (
	assetExt = map[string]bool{}
	// A versioned path (/scooter/v1.0/…, /v2/…) is an API's as much as /api/ is.
	apiRe = regexp.MustCompile(`(?i)(^|/)(api|apis|graphql|gql|rest|rpc|ajax|_api|odata)(/|$)|(^|/)v\d+(\.\d+)*(/|$)|\.(json|xml)$`)
)

func init() {
	for _, e := range strings.Fields(`js mjs cjs css map png jpg jpeg gif svg ico webp avif bmp tif tiff woff woff2 ttf otf eot
		mp4 webm mp3 ogg oga ogv wav flac m4a m4v avi mov wasm zip gz tgz bz2 xz rar 7z tar pdf doc docx xls xlsx ppt pptx
		odt exe msi dmg apk iso bin swf jar class vtt srt txt csv`) {
		assetExt["."+e] = true
	}
}

// Normalize gives the form of a URL that two links to one page share: no
// fragment unless it is a client-side route, sorted query, no default
// port, a path at least "/".
func Normalize(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if p := u.Port(); (u.Scheme == "http" && p == "80") || (u.Scheme == "https" && p == "443") {
		u.Host = u.Hostname()
	}
	if u.Path == "" {
		u.Path = "/"
	}
	if !hashRoute(u.Fragment) {
		u.Fragment, u.RawFragment = "", ""
	}
	if u.RawQuery != "" {
		u.RawQuery = u.Query().Encode()
	}
	u.User = nil
	return u.String(), true
}

// asset reports whether a URL is a static file rather than a page.
func asset(u *url.URL) bool {
	return assetExt[strings.ToLower(path.Ext(u.Path))]
}

// Item is a page to visit.
type Item struct {
	URL   string `json:"url"`
	Depth int    `json:"depth"`
	From  string `json:"from,omitempty"`
	How   string `json:"how"`
	vtime int64
	seq   int
}

type bandKey struct {
	depth int
	r     int
}

// Listed is a URL found and not visited, with why.
type Listed struct {
	URL    string `json:"url"`
	How    string `json:"how"`
	Method string `json:"method,omitempty"`
	From   string `json:"from,omitempty"`
	Reason string `json:"reason"`
}

type Options struct {
	InScope  func(host string) bool
	MaxDepth int
	MaxPages int // pages taken from the queue, the seed included
	// Destructive reports whether a GET of the URL is one the guard holds
	// back (logout, delete…): such a page is never visited.
	Destructive func(rawURL string) bool
}

const (
	maxListedEntries     = 50000
	maxListedKeys        = 200000
	maxQueuedOrSeenPages = 500000
)

// Queue is the frontier: the pages to visit, breadth first with fair-share
// Weighted DRR across hosts at the same (depth, how) tier, and the ones
// that will not be, with why.
type Queue struct {
	o           Options
	h           items
	seen        map[string]bool // normalised URLs queued or visited
	listed      map[string]bool
	Listed      []Listed
	ExtraListed map[string]int // counts beyond maxListedEntries
	taken       int
	seq         int
	dropped     int // pages over the limit
	bandFloor   map[bandKey]int64
	bandHostVT  map[bandKey]map[string]int64
	hostWeight  map[string]int
	emptyStreak map[string]int
}

func NewQueue(o Options) *Queue {
	if o.Destructive == nil {
		o.Destructive = func(string) bool { return false }
	}
	return &Queue{
		o:           o,
		seen:        map[string]bool{},
		listed:      map[string]bool{},
		ExtraListed: map[string]int{},
		bandFloor:   map[bandKey]int64{},
		bandHostVT:  map[bandKey]map[string]int64{},
		hostWeight:  map[string]int{},
		emptyStreak: map[string]int{},
	}
}

// Feedback updates a host's fair-share weight (1..4) from whether visiting
// rawURL yielded marginal information (new scripts, endpoints, OpenAPI, forms).
// Three consecutive zero-gain visits decay a boosted weight back toward 1.
func (q *Queue) Feedback(rawURL string, gained bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	h := strings.ToLower(u.Hostname())
	w := q.hostWeight[h]
	if w < 1 {
		w = 1
	}
	if gained {
		q.emptyStreak[h] = 0
		if w < 4 {
			q.hostWeight[h] = w + 1
		}
		return
	}
	q.emptyStreak[h]++
	if q.emptyStreak[h] >= 3 && w > 1 {
		q.hostWeight[h] = w - 1
		q.emptyStreak[h] = 0
	}
}

func (q *Queue) nextVTime(rawURL string, depth int, how string) int64 {
	h := ""
	if u, err := url.Parse(rawURL); err == nil {
		h = strings.ToLower(u.Hostname())
	}
	bk := bandKey{depth: depth, r: rank[how]}
	if q.bandHostVT[bk] == nil {
		q.bandHostVT[bk] = map[string]int64{}
	}
	vt := q.bandHostVT[bk][h]
	if floor := q.bandFloor[bk]; vt < floor {
		vt = floor
	}
	w := max(1, min(4, q.hostWeight[h]))
	q.bandHostVT[bk][h] = vt + int64(12/w)
	return vt
}

func (q *Queue) recordListed(f Found, from, reason string) {
	key := f.URL + " " + f.Method + " " + reason
	if len(q.Listed) < maxListedEntries {
		if !q.listed[key] {
			q.listed[key] = true
			q.Listed = append(q.Listed, Listed{URL: f.URL, How: f.How, Method: f.Method, From: from, Reason: reason})
		}
		return
	}
	if len(q.listed) < maxListedKeys {
		if q.listed[key] {
			return
		}
		q.listed[key] = true
	}
	q.ExtraListed[reason]++
}

// Add queues a found URL, depth links away from the seed, or records why
// not. It returns the reason, "" when queued.
func (q *Queue) Add(f Found, depth int, from string) string {
	reason := q.why(f, depth)
	switch reason {
	case "":
		n, _ := Normalize(f.URL)
		q.seen[n] = true
		q.seq++
		vt := q.nextVTime(f.URL, depth, f.How)
		heap.Push(&q.h, Item{URL: f.URL, Depth: depth, From: from, How: f.How, vtime: vt, seq: q.seq})
	case seenAlready:
	default:
		q.recordListed(f, from, reason)
	}
	return reason
}

// Precheck reports the non-budget reason f would not be visited at depth, or
// "" when f is an unseen, in-scope, visitable GET page within MaxDepth.
func (q *Queue) Precheck(f Found, depth int) string {
	u, err := url.Parse(f.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return NotHTTP
	}
	n, _ := Normalize(f.URL)
	switch {
	case q.seen[n]:
		return seenAlready
	case !q.o.InScope(u.Hostname()):
		return OutOfScope
	case f.Method != "" && f.Method != "GET":
		return NotGET
	case !f.Visit:
		return OnlyNamed
	case detect.InfraPath(u.Path):
		return CDNInfra
	case asset(u):
		return Asset
	case (f.How == JS || f.How == Route) && templatePath(u.Path):
		// /scooters/{scooter_id}/status, /apps/$slug/$, /posts/:id/edit:
		// a template, not a page.
		return Template
	case (f.How == JS || f.How == Route) && apiRe.MatchString(u.Path) && !SpecFile(u.Path):
		return API
	case q.o.Destructive(f.URL):
		return Destructive
	case depth > q.o.MaxDepth:
		return TooDeep
	}
	return ""
}

func (q *Queue) why(f Found, depth int) string {
	if r := q.Precheck(f, depth); r != "" {
		return r
	}
	if (q.o.MaxPages > 0 && q.taken+q.h.Len() >= q.o.MaxPages) || len(q.seen) >= maxQueuedOrSeenPages {
		q.dropped++
		return Limit
	}
	return ""
}

// specRe is the name of an API's description: openapi.yaml, swagger.json,
// api-docs, asyncapi.yml.
var specRe = regexp.MustCompile(`(?i)(^|/)(openapi|swagger|api-?docs?|asyncapi)([._-][\w.-]*)?(\.(ya?ml|json))?$`)

// SpecFile reports whether a path is an API's description, which a crawl
// fetches (and reads its endpoints from) though it is no page.
func SpecFile(p string) bool {
	low := strings.ToLower(p)
	return specRe.MatchString(p) && (strings.HasSuffix(low, "yaml") || strings.HasSuffix(low, "yml") ||
		strings.HasSuffix(low, "json") || strings.HasSuffix(low, "api-docs") || strings.HasSuffix(low, "swagger-resources"))
}

// ListAs names a URL with a reason of the caller's (an SPA's route), never
// to visit it.
func (q *Queue) ListAs(f Found, from, reason string) {
	n, _ := Normalize(f.URL)
	if q.seen[n] {
		return
	}
	q.recordListed(f, from, reason)
}

// Next takes the next page: the shallowest, then by how it was found,
// interleaved fairly across hosts by Weighted DRR.
func (q *Queue) Next() (Item, bool) {
	if q.h.Len() == 0 {
		return Item{}, false
	}
	q.taken++
	it := heap.Pop(&q.h).(Item)
	bk := bandKey{depth: it.Depth, r: rank[it.How]}
	if it.vtime > q.bandFloor[bk] {
		q.bandFloor[bk] = it.vtime
	}
	return it, true
}

// Peek is the page Next would take, without taking it.
func (q *Queue) Peek() (Item, bool) {
	if q.h.Len() == 0 {
		return Item{}, false
	}
	return q.h[0], true
}

// Retry queues a page taken already, to visit it again (once the session
// that it found lost is back).
func (q *Queue) Retry(it Item) {
	q.taken--
	q.seq++
	it.seq = q.seq
	it.vtime = q.nextVTime(it.URL, it.Depth, it.How)
	heap.Push(&q.h, it)
}

// Visited marks a URL loaded without being queued (the page went there
// itself), so that it is not visited again.
func (q *Queue) Visited(raw string) {
	if n, ok := Normalize(raw); ok {
		q.seen[n] = true
	}
}

// Refund returns a taken page slot to the -max-pages budget when the caller
// prunes a popped item (e.g. template-saturated) without visiting it over HTTP.
func (q *Queue) Refund() {
	if q.taken > 0 {
		q.taken--
	}
}

func (q *Queue) Len() int     { return q.h.Len() }
func (q *Queue) Dropped() int { return q.dropped }

// SortListed orders the listed URLs, for a stable output.
func (q *Queue) SortListed() {
	sort.SliceStable(q.Listed, func(i, j int) bool { return q.Listed[i].URL < q.Listed[j].URL })
}

type items []Item

func (h items) Len() int { return len(h) }
func (h items) Less(i, j int) bool {
	a, b := h[i], h[j]
	if a.Depth != b.Depth {
		return a.Depth < b.Depth
	}
	if rank[a.How] != rank[b.How] {
		return rank[a.How] < rank[b.How]
	}
	if a.vtime != b.vtime {
		return a.vtime < b.vtime
	}
	return a.seq < b.seq
}
func (h items) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *items) Push(x any)   { *h = append(*h, x.(Item)) }
func (h *items) Pop() any {
	old := *h
	it := old[len(old)-1]
	*h = old[:len(old)-1]
	return it
}

// templatePath reports a path a script names that is a router's pattern or
// a module's id, not a page: {placeholders}; a segment that is a
// parameter (:id, TanStack's $slug and $ splat, Next's [id]), a glob (*,
// **), a route group ((auth)), an ellipsis; a module under node_modules;
// TanStack's root route id.
func templatePath(p string) bool {
	if strings.ContainsAny(p, "{}*") || strings.Contains(p, "/node_modules/") {
		return true
	}
	for _, s := range strings.Split(p, "/") {
		switch {
		case s == "":
		case s[0] == ':' || s[0] == '$' || s[0] == '[':
			return true
		case s == "..." || s == "__root__":
			return true
		case s[0] == '(' && s[len(s)-1] == ')':
			return true
		}
	}
	return false
}

// SpecPaths are where an API's server keeps its description, asked of the
// target's origin and its API hosts (PIP-03): OpenAPI (FastAPI), NestJS's
// @nestjs/swagger (/api-json, /docs-json), Springdoc (/v3/api-docs),
// Springfox (/v2/api-docs, /swagger-resources), swaggo, and an OpenID
// Provider's configuration.
var SpecPaths = []string{"/openapi.json", "/openapi.yaml", "/api-json", "/docs-json", "/v3/api-docs", "/v2/api-docs",
	"/swagger-resources", "/swagger/doc.json", "/swagger/v1/swagger.json", "/.well-known/openid-configuration"}

// OriginSpecPaths are additional OpenAPI and Swagger UI paths probed once on
// origin roots only (never multiplied across sub-path gateway bases).
var OriginSpecPaths = []string{"/swagger.json", "/swagger.yaml", "/docs/api-docs.json", "/storage/api-docs/api-docs.json", "/api/documentation"}

// MaxAPIOrigins bounds the API hosts a crawl asks SpecPaths of (0: unlimited).
const MaxAPIOrigins = 0

var trackerDomains = []string{
	"google-analytics.com",
	"googletagmanager.com",
	"analytics.google.com",
	"doubleclick.net",
	"googlesyndication.com",
	"googleadservices.com",
	"facebook.net",
	"facebook.com",
	"sentry.io",
	"sentry-cdn.com",
	"hotjar.com",
	"clarity.ms",
	"segment.io",
	"segment.com",
	"mixpanel.com",
	"amplitude.com",
	"fullstory.com",
	"intercom.io",
	"intercomcdn.com",
	"hubspot.com",
	"hs-scripts.com",
	"hs-analytics.net",
	"newrelic.com",
	"nr-data.net",
	"datadoghq.com",
	"datadoghq-browser-agent.com",
	"bugsnag.com",
	"logrocket.com",
	"logrocket.io",
	"pendo.io",
	"optimizely.com",
	"criteo.com",
	"taboola.com",
	"outbrain.com",
	"snowplowanalytics.com",
}

var nonAPIInfraDomains = []string{
	"fonts.googleapis.com",
	"fonts.gstatic.com",
	"maps.googleapis.com",
	"gstatic.com",
	"cdnjs.cloudflare.com",
	"challenges.cloudflare.com",
	"unpkg.com",
	"jsdelivr.net",
	"npmjs.org",
	"w3.org",
	"schemas.openxmlformats.org",
	"schemas.microsoft.com",
	"storage.googleapis.com",
	"s3.amazonaws.com",
	"blob.core.windows.net",
	"r2.cloudflarestorage.com",
	"digitaloceanspaces.com",
	"stripe.com",
	"paypal.com",
	"braintreegateway.com",
	"adyen.com",
	"mapbox.com",
	"recaptcha.net",
	"hcaptcha.com",
	"github.com",
	"githubusercontent.com",
	"gitlab.com",
	"gravatar.com",
	"vimeo.com",
	"youtube.com",
	"ytimg.com",
	"onetrust.com",
	"cookielaw.org",
	"cookiebot.com",
	"trustarc.com",
	"usercentrics.eu",
	// Public IdP / Cloud SDK hosts (R40-B1 secondary filter for D2 root probes)
	"microsoftonline.com",
	"microsoftonline.us",
	"microsoftonline.cn",
	"chinacloudapi.cn",
	"graph.microsoft.com",
	"live.com",
	"accounts.google.com",
	"appleid.apple.com",
	"login.salesforce.com",
	// Map / Tile / Geocoding / Google APIs
	"openstreetmap.org",
	"maplibre.org",
	"tileserver.org",
	"mt0.google.com",
	"mt1.google.com",
	"mt2.google.com",
	"mt3.google.com",
	"googleapis.com",
	// Library docs & XML/schema namespaces
	"reactrouter.com",
	"reactjs.org",
	"react.dev",
	"vuejs.org",
	"angular.io",
	"mozilla.org",
	"adobe.com",
	"xfa.org",
	"xmlsoap.org",
	"json-schema.org",
	"ietf.org",
	"purl.org",
}

// IsTrackerHost reports whether host belongs to a third-party analytics,
// advertising or telemetry service rather than an application backend.
func IsTrackerHost(host string) bool {
	h := strings.ToLower(strings.Trim(host, "."))
	if h == "" {
		return false
	}
	for _, d := range trackerDomains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// IsTrackerURL reports whether any of rawURLs is hosted on a tracker domain.
func IsTrackerURL(rawURLs ...string) bool {
	for _, raw := range rawURLs {
		u, err := url.Parse(raw)
		if err == nil && IsTrackerHost(u.Hostname()) {
			return true
		}
	}
	return false
}

func isStaticOrNonAPIHost(h string) bool {
	if strings.HasPrefix(h, "cdn.") || strings.HasPrefix(h, "static.") ||
		strings.HasPrefix(h, "assets.") || strings.HasPrefix(h, "fonts.") {
		return true
	}
	if IsTrackerHost(h) {
		return true
	}
	for _, d := range nonAPIInfraDomains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	// Virtual-hosted or regional AWS S3 buckets (leaving execute-api.*.amazonaws.com intact).
	if strings.HasSuffix(h, ".amazonaws.com") && (strings.HasPrefix(h, "s3.") || strings.HasPrefix(h, "s3-") ||
		strings.Contains(h, ".s3.") || strings.Contains(h, ".s3-")) {
		return true
	}
	return false
}

// APIOrigins are the origins of the absolute bases, settings and endpoint
// URLs a non-tracker app script names (D2): in-scope origins first, followed
// by other app-referenced API origins, excluding static/CDN hosts and known
// analytics/ads trackers.
func APIOrigins(r jsapi.Result, inScope func(string) bool) []string {
	var inOut, extOut []string
	add := func(raw string) {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || strings.Contains(u.Host, "{") {
			return
		}
		h := strings.ToLower(u.Hostname())
		if isStaticOrNonAPIHost(h) {
			return
		}
		o := strings.ToLower(u.Scheme + "://" + u.Host)
		if slices.Contains(inOut, o) || slices.Contains(extOut, o) {
			return
		}
		if inScope != nil && inScope(h) {
			inOut = append(inOut, o)
		} else {
			extOut = append(extOut, o)
		}
	}
	for _, b := range r.Bases {
		add(b)
	}
	for _, b := range r.PropBases {
		if isAPIBasePropName(b.Name) && strings.Contains(b.Value, "://") {
			add(b.Value)
		}
	}
	for _, s := range r.Settings {
		if strings.Contains(s.Value, "://") {
			add(s.Value)
		}
	}
	for _, e := range r.Endpoints {
		if e.Kind != "navigation" && !e.Collector && strings.Contains(e.URL, "://") {
			add(e.URL)
		}
	}
	return append(inOut, extOut...)
}

// AppAPIOrigins returns all non-tracker, non-static API origins referenced in r.
func AppAPIOrigins(r jsapi.Result) []string {
	return APIOrigins(r, nil)
}
