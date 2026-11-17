// Package httpcrawl is the crawl without a browser (CF-03): the pages and
// manifests of a target over plain HTTP/2 with a browser's headers, their
// scripts, and every chunk those name, read statically (resolve.Static), to
// the end of the graph. It is the pre-auth engine: fast, quiet, and nothing
// in it says HeadlessChrome. What needs a runtime (events, workers, eval,
// a session) is the CDP engine's.
package httpcrawl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/htmlscan"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/resolve"
	"github.com/TimoMangCut/JSharvest/internal/sourcemap"
	"github.com/TimoMangCut/JSharvest/internal/tlsutil"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Options configure a crawl.
type Options struct {
	Target    *url.URL
	InScope   func(host string) bool
	PageScope func(host string) bool // narrows visited pages; nil uses InScope
	Depth     int                    // links away from Target (0: the one page)
	MaxPages  int
	Rate      float64 // requests a second, of every kind
	// MaxFiles bounds the script, manifest and source map requests
	// (-resolve-max): the graph of a large app is big.
	MaxFiles  int
	MaxBody   int
	Timeout   time.Duration
	UserAgent string
	Proxy     *url.URL
	HostRules string // "MAP *.example.test 127.0.0.1", as Chrome takes it
	NoDNS     bool   // a proxy or host rules: no DNS of our own for the scope policy
	// AllowPrivate lets the client reach private addresses: set when the
	// target itself is internal (Crawl also sets it from the policy: a
	// target that is not public). A public target's hosts never are.
	AllowPrivate bool
	// Resolver looks names up (nil: the system's); tests.
	Resolver netsafe.Resolver
	// Insecure accepts any TLS certificate (-insecure: a self-signed lab).
	Insecure bool
	// AIA completes the chains of servers that send their leaf alone; nil
	// makes one for the crawl.
	AIA *tlsutil.AIA
	// Probe reads the well-known files: robots.txt and its sitemaps, and the
	// manifests of the bundlers (asset-manifest.json, ngsw.json, the Vite
	// manifest, a service worker's precache list).
	Probe bool
	// NoSpecProbe skips OpenAPI/Swagger and OIDC discovery probes while
	// keeping robots.txt, sitemaps and bundler manifests when Probe is on.
	NoSpecProbe bool
	// SourceMaps fetches the .map a script names (SourceMap header or
	// sourceMappingURL), or <script>.map, and hands it on (CF-05).
	SourceMaps bool
	GuessMaps  bool // also ask <script>.map when no header or comment names a map
	// Destructive reports a GET the guard would hold back: never visited.
	Destructive func(raw string) bool
	Workers     int
	// RecordBody keeps up to this many bytes of a JSON answer in the
	// request log (0: none).
	RecordBody int

	Script    func(Script)        // each script, file or inline
	SourceMap func(SourceMap)     // each source map
	Request   func(traffic.Entry) // each request sent
	Page      func(Page)          // each page visited, or listed
	Log       func(format string, args ...any)
	// Extract optionally parses a script once and caches its jsapi.Result
	// (e.g. endpoints.ExtractCached); nil uses an in-memory SHA256 cache.
	Extract func(body []byte, urlHint string) jsapi.Result
}

// Script is a script the crawl fetched, or inline code of a page.
type Script struct {
	Body    []byte
	Kind    string // file or inline
	URL     string // a file's URL; a page's for inline code
	Page    string
	Status  int
	MIME    string
	Headers map[string]string // lowercase keys
	Tags    []string
	// Found is how it was found: src, module, modulepreload, preload,
	// importmap, next-build-id, asset-manifest, ngsw, vite-manifest, probe,
	// or the resolver's method (import, webpack-runtime, …).
	Found string
	From  string // the page or script that named it
}

// SourceMap is a script's source map, read.
type SourceMap struct {
	URL       string
	ScriptURL string
	Body      []byte
}

// Page is one page the crawl visited, or found and did not.
type Page struct {
	URL        string    `json:"url"`
	Visited    bool      `json:"visited"`
	FinalURL   string    `json:"final_url,omitempty"`
	Status     int       `json:"status,omitempty"`
	Depth      int       `json:"depth"`
	From       string    `json:"from,omitempty"`
	How        string    `json:"how"`
	Method     string    `json:"method,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Discovered int       `json:"discovered,omitempty"`
	Started    time.Time `json:"started,omitzero"`
	TookMS     int64     `json:"took_ms,omitempty"`
	Error      string    `json:"error,omitempty"`
	Blocked    bool      `json:"blocked,omitempty"`
	// Shell: the page answered with the first page's shell (an SPA's
	// fallback); its links are not followed again.
	Shell bool `json:"shell,omitempty"`
}

// Stats go into run.json.
type Stats struct {
	// UserAgent is the one the crawl presented (round 25L): what an
	// escalation to Chrome presents too.
	UserAgent  string         `json:"user_agent,omitempty"`
	Requests   int            `json:"requests"`
	Pages      int            `json:"pages"`
	Scripts    int            `json:"scripts"`
	Inline     int            `json:"inline"`
	Found      map[string]int `json:"found"`  // scripts by how they were found
	Probes     map[string]int `json:"probes"` // well-known file -> status
	SourceMaps int            `json:"source_maps,omitempty"`
	// MapGuessesHeld: <script>.map guesses not made, their origin having
	// missed sourcemap.GuessMisses with no map found.
	MapGuessesHeld int            `json:"map_guesses_held,omitempty"`
	NotFound       int            `json:"not_found"`  // a script URL that answered 404/410
	NotScript      int            `json:"not_script"` // answered with a page (an SPA's fallback)
	Failed         int            `json:"failed"`
	Challenge      int            `json:"challenge_scripts,omitempty"`
	SPA            bool           `json:"spa,omitempty"` // every path answers with the app's shell
	SPAOrigins     []string       `json:"spa_origins,omitempty"`
	Shells         int            `json:"shells,omitempty"`  // pages that were the shell again
	OpenAPI        int            `json:"openapi,omitempty"` // API descriptions fetched and kept
	Policy         map[string]int `json:"policy,omitempty"`  // script URLs not fetched, by the policy's verdict
	Stopped        string         `json:"stopped,omitempty"`
	// Capped: the script budget (-resolve-max) was spent; the pages went on.
	Capped string `json:"capped,omitempty"`
}

// Result is what a crawl found out, past the scripts it handed on.
type Result struct {
	Stats   Stats
	Seed    detect.Doc // the first page's document
	Blocked detect.Result
	// Challenged are the pages that answered with a challenge or deny page,
	// and those of a host that did so hostGiveUp times with no page passing,
	// which were not asked (Asked false): a browser may get past what plain
	// HTTP cannot (crawl -engine auto hands them to Chrome).
	Challenged []Challenged
	Fronted    string
	FrontedBy  []string
	Visited    int
	Queued     int
	Listed     map[string]int
	// SeedError is why the first page could not be fetched at all (no
	// answer: TLS, DNS, a refused connection).
	SeedError string
	// IncompleteChains are the hosts whose servers sent an incomplete
	// certificate chain the AIA completed.
	IncompleteChains []string
	// Cookies are the application's cookies the target set, in scope, as
	// they stand at the end: an escalation to Chrome takes them on.
	Cookies []Cookie
}

// Challenged is a page HTTP could not get past a challenge.
type Challenged struct {
	URL   string `json:"url"`
	Depth int    `json:"depth"`
	Asked bool   `json:"asked"`
	// Kind is the block's (detect.BlockKind) on a page asked: a challenge
	// a browser may pass, or a rule or ban it would meet alike (round 25J).
	Kind string `json:"kind,omitempty"`
}

// hostGiveUp is how many challenged pages of a host, with none of its
// pages passing, leave its other pages unasked: the host challenges the
// crawl, not one path (MAX-02 keeps the one path's case going).
const hostGiveUp = 2

// ChallengedHost is the reason of a page not asked for that.
const ChallengedHost = "challenged-host"

type hostState struct{ ok, challenged int }

// ErrStopped: the target asked the crawl to slow down or challenged it;
// what came before is kept.
var ErrStopped = errors.New("stopped to stay polite")

const (
	MaxSpecBases          = frontier.MaxSpecBases
	MaxServiceDocPrefixes = frontier.MaxServiceDocPrefixes
)

type crawler struct {
	o          Options
	c          *client
	policy     *resolve.Policy
	specPolicy *resolve.Policy
	q          *frontier.Queue
	cancel     context.CancelFunc // ends what is in flight at a stop

	mu      sync.Mutex
	res     *Result
	seen    map[string]bool // script and manifest URLs, normalised
	files   int             // script, manifest and map requests made
	stopped string
	// capped: -resolve-max is spent; scripts are no longer fetched, pages
	// still are (MAX-02).
	capped     string
	challenged int // later pages that were challenges, in a row
	hosts      map[string]*hostState
	guesses    sourcemap.Guesses
	// prints is each origin's first page's shell (its title and scripts);
	// spa is set for an origin when a path that cannot exist there answers
	// with that same shell: the app routes on the client, and the routes
	// its scripts name on that origin are listed, not fetched (each would
	// be the shell again). Another origin (developer.example.com next to
	// example.com) is another app: its pages are visited until it shows
	// the same (round 18). Only the crawl's loop touches them.
	prints  map[string]string
	spa     map[string]bool
	toCheck string // the first page of an origin, for spaCheck
	// apiOrigins are the target's API hosts the scripts name, asked for
	// their API's description once the pages are done (PIP-03).
	specBlocked  map[string]string
	apiOrigins   []string
	seedOrigin   string
	seedFinalURL string
	seedActive   *atomic.Bool
	onSeedLand   func(string)
	webpack      resolve.WebpackLinker
	specCtx      frontier.SpecCollector
	skel         *skeletonController
	extractMu    sync.Mutex
	extracted    map[[32]byte]jsapi.Result
}

// originOf is a URL's scheme and host, lowercased.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

type found struct {
	f     frontier.Found
	from  string
	depth int
}

type job struct {
	url, page, how, from string
	depth                int
	tags                 []string
	b                    *bucket // the page the script is fetched for (nil: none)
	admitted             bool    // claimed already (admit), when its page was taken
}

// bucket is what one page's scripts name (round 25K, step 2.3): its routes
// and API hosts, kept apart while its scripts are fetched beside the next
// pages', and given to the queue at the end of the level, in the order the
// pages were taken: what the queue gets is a crawl of one page at a time's.
// spa is the SPA check's word on each origin once the page was done, as
// the routes are listed (cr.add) by it.
type bucket struct {
	found      []found
	origins    []found // f.URL: the API host; from: the script naming it
	spa        map[string]bool
	inlineSigs [][32]byte
	pageStatus int
}

// sorted is the bucket's findings in an order of their own: by the script
// that named them, each script's in its own order. The page's scripts end
// in whatever order their fetches do (o.Workers at once): queued as they
// came, the same crawl twice could take its next pages in two orders.
func (b *bucket) sorted() (fs []found, origins []string) {
	fs = slices.Clone(b.found)
	slices.SortStableFunc(fs, func(x, y found) int { return strings.Compare(x.from, y.from) })
	os := slices.Clone(b.origins)
	slices.SortStableFunc(os, func(x, y found) int { return strings.Compare(x.from, y.from) })
	for _, o := range os {
		if !slices.Contains(origins, o.f.URL) {
			origins = append(origins, o.f.URL)
		}
	}
	return fs, origins
}

func (o *Options) defaults() {
	if o.Rate <= 0 {
		o.Rate = 5
	}
	if o.MaxFiles < 0 {
		o.MaxFiles = 0
	}
	if o.MaxBody <= 0 {
		o.MaxBody = 50 << 20
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.UserAgent == "" {
		o.UserAgent = DefaultUserAgent
	}
	if o.Workers <= 0 {
		o.Workers = 4
	}
	if o.MaxPages < 0 {
		o.MaxPages = 0
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	for _, f := range []*func(Script){&o.Script} {
		if *f == nil {
			*f = func(Script) {}
		}
	}
	if o.SourceMap == nil {
		o.SourceMap = func(SourceMap) {}
	}
	if o.Request == nil {
		o.Request = func(traffic.Entry) {}
	}
	if o.Page == nil {
		o.Page = func(Page) {}
	}
}

// internalTarget: the crawl's target is internal (netsafe.InternalTargetVia):
// its client may reach private addresses.
func internalTarget(ctx context.Context, o Options) bool {
	rules, _ := netsafe.ParseHostRules(o.HostRules) // a bad rule is newClient's error
	return netsafe.InternalTargetVia(ctx, o.Target.Hostname(), rules, o.Resolver, o.Proxy != nil)
}

// Crawl harvests a target over HTTP. It returns ErrStopped (with the
// result) when the target rate-limited or challenged a request past the
// first page; a challenge on the first page is Result.Blocked.
func Crawl(ctx context.Context, o Options) (*Result, error) {
	o.defaults()
	// A stop (429, a challenge) ends what is in flight too: a page's
	// scripts waiting out a Retry-After beside the next pages' (round 25L
	// review). The caller's own context says whether it was interrupted.
	outer := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	base, _ := cookiejar.New(nil)
	jar := &recJar{CookieJar: base}
	policy := resolve.NewPolicy(o.Target.Hostname(), o.InScope, o.NoDNS)
	specPolicy := resolve.NewPolicy(o.Target.Hostname(), func(h string) bool { return !frontier.IsTrackerHost(h) }, o.NoDNS)
	// Whether the target is internal is not the policy's answer (it takes a
	// target with any private address for internal): every address private,
	// a private literal, or a host rule to one; no lookup behind a proxy.
	o.AllowPrivate = o.AllowPrivate || internalTarget(ctx, o)
	var seedActive atomic.Bool
	var seedMu sync.RWMutex
	var seedLandingHost string
	basePageScope := o.InScope
	if o.PageScope != nil {
		basePageScope = func(h string) bool { return o.InScope(h) && o.PageScope(h) }
	}
	pageScope := func(h string) bool {
		if basePageScope(h) {
			return true
		}
		seedMu.RLock()
		lh := seedLandingHost
		seedMu.RUnlock()
		hl := strings.ToLower(h)
		return lh != "" && o.InScope(h) && (hl == lh || strings.HasSuffix(hl, "."+lh))
	}
	c, err := newClient(o, jar, func(u, first *url.URL, doc bool) bool {
		if doc && !seedActive.Load() && !pageScope(u.Hostname()) {
			return false
		}
		if u.User != nil || (o.Destructive != nil && o.Destructive(u.String())) {
			return false
		}
		if policy.Check(u.String()) == resolve.Allow {
			return true
		}
		return !doc && first != nil && strings.EqualFold(u.Hostname(), first.Hostname()) && specPolicy.Check(u.String()) == resolve.Allow
	})
	if err != nil {
		return nil, err
	}
	cr := &crawler{o: o, c: c, policy: policy, specPolicy: specPolicy, seedActive: &seedActive,
		onSeedLand: func(raw string) {
			if u, err := url.Parse(raw); err == nil && u.Hostname() != "" && o.InScope(u.Hostname()) {
				seedMu.Lock()
				seedLandingHost = strings.ToLower(u.Hostname())
				seedMu.Unlock()
			}
		},
		res:         &Result{Stats: Stats{Found: map[string]int{}, Probes: map[string]int{}, Policy: map[string]int{}}, Listed: map[string]int{}},
		seen:        map[string]bool{},
		hosts:       map[string]*hostState{},
		specBlocked: map[string]string{},
		prints:      map[string]string{},
		spa:         map[string]bool{},
		skel:        newSkeletonController()}
	cr.cancel = cancel
	cr.q = frontier.NewQueue(frontier.Options{InScope: pageScope, MaxDepth: o.Depth, MaxPages: o.MaxPages, Destructive: o.Destructive})
	cr.q.Add(frontier.Found{URL: o.Target.String(), How: frontier.Seed, Visit: true}, 0, "")
	cr.seedOrigin = originOf(o.Target.String())

	cr.pages(ctx)
	if o.Probe && !o.NoSpecProbe && ctx.Err() == nil {
		// The API hosts the scripts named: their description, if their
		// server keeps it where servers do.
		cr.mu.Lock()
		origins := slices.Clone(cr.apiOrigins)
		probeRef := cr.seedFinalURL
		cr.mu.Unlock()
		if probeRef == "" {
			probeRef = o.Target.String()
		}
		if len(origins) > 0 {
			specWorkers := min(max(cr.o.Workers, 4), 8)
			if specWorkers > len(origins) {
				specWorkers = len(origins)
			}
			ch := make(chan string, len(origins))
			for _, origin := range origins {
				ch <- origin
			}
			close(ch)
			var wg sync.WaitGroup
			for range specWorkers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for origin := range ch {
						if cr.stop() != "" || ctx.Err() != nil {
							return
						}
						cr.specProbeWithScope(ctx, origin, probeRef, cr.specCtx.HeadersFor(origin, o.InScope), nil, true)
					}
				}()
			}
			wg.Wait()
		}
		if cr.stop() == "" && ctx.Err() == nil {
			cr.specProbePhase2(ctx, probeRef)
		}
	}
	res := cr.res
	res.Queued = cr.q.Len()
	for _, l := range cr.q.Listed {
		res.Listed[l.Reason]++
		o.Page(Page{URL: l.URL, How: l.How, Method: l.Method, From: l.From, Reason: l.Reason})
	}
	if d := cr.q.Dropped(); d > 0 {
		res.Listed[frontier.Limit] += d
	}
	res.Stats.Stopped = cr.stop()
	res.Stats.UserAgent = o.UserAgent
	res.Cookies = jar.cookies(o.InScope)
	if cr.c.aia != nil {
		res.IncompleteChains = cr.c.aia.Hosts()
	}
	cr.mu.Lock()
	res.Stats.Capped = cr.capped
	cr.mu.Unlock()
	if err := outer.Err(); err != nil {
		return res, err
	}
	if res.Stats.Stopped != "" && !res.Blocked.Blocked {
		return res, ErrStopped
	}
	return res, nil
}

// spaCheck asks for a path that cannot exist on a page's origin. When it
// answers 200 with that origin's own shell, the server sends the app for
// every path, and fetching the routes would only fetch the shell again.
func (cr *crawler) spaCheck(ctx context.Context, seed string, depth int) {
	origin := originOf(seed)
	if cr.prints[origin] == "" {
		return
	}
	u, err := url.Parse(seed)
	if err != nil {
		return
	}
	probe := u.Scheme + "://" + u.Host + "/" + marker.Slug()
	a := cr.fetch(ctx, probe, seed, document, "Other")
	cr.politeAt(a, seed, depth)
	if a.Err != nil || a.Status != 200 {
		return
	}
	if shellPrint(htmlscan.Scan(a.Body, a.URL)) == cr.prints[origin] {
		cr.spa[origin] = true
		cr.count(func(st *Stats) { st.SPA = true; st.SPAOrigins = append(st.SPAOrigins, origin) })
		cr.o.Log("%s answers every path with the app's shell (an SPA): the routes and paths its scripts name there are listed (spa-route), not fetched", origin)
	}
}

// shellPrint is what makes a page the same app shell: its title and its
// scripts, in order (an inline one by its code). A challenge vendor's
// inline code is left out: Cloudflare's bot script carries each response's
// ray id, which would make every answer of the shell a new page.
func shellPrint(p htmlscan.Page) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00", p.Title)
	for _, s := range p.Scripts {
		switch {
		case s.URL != "":
			if !detect.ChallengeURL(s.URL) {
				fmt.Fprintf(h, "src %s\x00", s.URL)
			}
		case detect.IsChallengeScript("", "", "inline", []byte(s.Inline), false):
		default:
			fmt.Fprintf(h, "inline %s\x00", s.Inline)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fetch gets a URL and logs it, each try: a 429, or a 503 with a short
// Retry-After, is waited out and asked again, twice at most (MAX-02). What
// still asks to stop after that stops the crawl (polite).
func (cr *crawler) fetch(ctx context.Context, raw, referer string, k kind, rtype string) answer {
	return cr.fetchWithHeaders(ctx, raw, referer, k, rtype, nil)
}

func (cr *crawler) fetchWithHeaders(ctx context.Context, raw, referer string, k kind, rtype string, extra []jsapi.Header) answer {
	for try := 0; ; try++ {
		a := cr.c.getWithHeaders(ctx, raw, referer, k, extra)
		rt := rtype
		if rtype == "Document" && apiAnswer(a) {
			// A page the crawl asked for that is an API's answer (JSON):
			// what the site's code would fetch, logged so (PIP-02), for the
			// catalog to see it observed.
			rt = "Fetch"
		}
		cr.log(a, rt, referer)
		wait, ok := retryAfter(a)
		if !ok || try >= 2 {
			return a
		}
		cr.o.Log("%s answered %d: asking again in %s", raw, a.Status, wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return a
		}
	}
}

// retryAfter is how long to wait before asking again: a 429's Retry-After
// (2 s without one), a 503's when it has one; never more than 15 s, a
// longer wait being the target's way to say stop.
func retryAfter(a answer) (time.Duration, bool) {
	if a.Err != nil || (a.Status != http.StatusTooManyRequests && a.Status != http.StatusServiceUnavailable) {
		return 0, false
	}
	if strings.EqualFold(a.Header.Get("Cf-Mitigated"), "challenge") {
		return 0, false
	}
	ra := strings.TrimSpace(a.Header.Get("Retry-After"))
	if ra == "" {
		return 2 * time.Second, a.Status == http.StatusTooManyRequests
	}
	n, err := strconv.Atoi(ra)
	if err != nil {
		t, err := http.ParseTime(ra)
		if err != nil {
			return 0, false
		}
		n = int(time.Until(t).Seconds()) + 1
	}
	if n < 0 || n > 15 {
		return 0, false
	}
	return max(time.Duration(n)*time.Second, 500*time.Millisecond), true
}

func (cr *crawler) stop() string {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return cr.stopped
}

func (cr *crawler) setStop(why string) {
	cr.mu.Lock()
	if cr.stopped == "" {
		cr.stopped = why
		cr.o.Log("stopped: %s", why)
		if cr.cancel != nil {
			cr.cancel()
		}
	}
	cr.mu.Unlock()
}

// noteChallenged names page (the seed when "") among the challenged
// pages, once, when it and the asset met are in scope.
func (cr *crawler) noteChallenged(asset, page string, depth int, kind detect.BlockKind) {
	if page == "" {
		page, depth = cr.o.Target.String(), 0
	}
	pu, err1 := url.Parse(page)
	au, err2 := url.Parse(asset)
	if err1 != nil || err2 != nil || !cr.o.InScope(pu.Hostname()) || !cr.o.InScope(au.Hostname()) {
		return
	}
	cr.mu.Lock()
	defer cr.mu.Unlock()
	for _, c := range cr.res.Challenged {
		if c.URL == page {
			return
		}
	}
	cr.res.Challenged = append(cr.res.Challenged, Challenged{URL: page, Depth: depth, Asked: true, Kind: string(kind)})
}

// politeAt stops the crawl on an answer that asks it to: a 429, a
// challenge, a vendor's ban (detect.Classify on its status, headers and the
// head of its body), a 503 with Retry-After. A WAF rule on that one URL (a
// 1020, a "Sorry, you have been blocked" for a probe or a script) leaves
// that URL only: the rest of the site may still be reached (round 25J
// review). The answer was fetched for page (its depth; "" is the seed): a
// challenge a browser may pass, met on a script, a well-known file or the
// SPA check, names that page among the challenged, so that the crawl goes
// on in Chrome (-escalate) as for a challenged page (round 25L review);
// the page, never the asset, which Chrome would open as a page.
func (cr *crawler) politeAt(a answer, page string, depth int) {
	if a.Err == nil && a.Status != 0 {
		h := lower(a.Header)
		var title string
		if strings.Contains(h["content-type"], "html") {
			title = htmlscan.Scan(a.Body[:min(len(a.Body), 64<<10)], a.URL).Title
		}
		if b := detect.Classify(detect.Doc{URL: a.URL, Status: int64(a.Status), Headers: h, Title: title, Body: head(a.Body, 64<<10)}); b != nil {
			if b.Kind == detect.BlockRequest {
				return
			}
			if b.Kind != detect.BlockRate {
				if b.Kind.BrowserMayPass() {
					cr.noteChallenged(a.URL, page, depth, b.Kind)
				}
				cr.setStop(fmt.Sprintf("target answered with a %s", b))
				return
			}
		}
	}
	switch {
	case a.Status == http.StatusTooManyRequests:
		cr.setStop("target answered 429")
	case strings.EqualFold(a.Header.Get("Cf-Mitigated"), "challenge"):
		cr.setStop("target answered with a challenge (cf-mitigated)")
	case a.Status == http.StatusServiceUnavailable && a.Header.Get("Retry-After") != "":
		cr.setStop("target answered 503 with Retry-After")
	}
}

// --- pages ---

// host keeps a host's tally of challenged and passing pages.
func (cr *crawler) host(raw string) *hostState {
	h := ""
	if u, err := url.Parse(raw); err == nil {
		h = strings.ToLower(u.Hostname())
	}
	cr.mu.Lock()
	defer cr.mu.Unlock()
	st := cr.hosts[h]
	if st == nil {
		st = &hostState{}
		cr.hosts[h] = st
	}
	return st
}

func (cr *crawler) page(ctx context.Context, it frontier.Item, first bool, b *bucket) ([]job, []frontier.Found, bool) {
	start := time.Now().UTC()
	hs := cr.host(it.URL)
	cr.mu.Lock()
	givenUp := hs.ok == 0 && hs.challenged >= hostGiveUp
	if givenUp {
		cr.res.Challenged = append(cr.res.Challenged, Challenged{URL: it.URL, Depth: it.Depth})
		cr.res.Listed[ChallengedHost]++
	}
	cr.mu.Unlock()
	if givenUp {
		cr.o.Page(Page{URL: it.URL, How: it.How, From: it.From, Depth: it.Depth, Reason: ChallengedHost})
		return nil, nil, true
	}
	if first && cr.seedActive != nil {
		cr.seedActive.Store(true)
	}
	a := cr.fetch(ctx, it.URL, it.From, document, "Document")
	if first && cr.seedActive != nil {
		cr.seedActive.Store(false)
	}
	cr.q.Visited(a.URL)
	pg := Page{URL: it.URL, Visited: true, FinalURL: a.URL, Status: a.Status, Depth: it.Depth, From: it.From, How: it.How,
		Started: start, TookMS: a.Took.Milliseconds()}
	cr.mu.Lock()
	cr.res.Visited++
	cr.res.Stats.Pages++
	cr.mu.Unlock()
	if a.Err != nil {
		pg.Error = a.Err.Error()
		if first && a.Status == 0 {
			cr.mu.Lock()
			cr.res.SeedError = a.Err.Error()
			cr.mu.Unlock()
		}
		cr.o.Page(pg)
		return nil, nil, false
	}
	if first && a.Status >= 300 && a.Status < 400 {
		loc := a.Header.Get("Location")
		why := fmt.Sprintf("seed redirect (%d) out of scope", a.Status)
		if loc != "" {
			why = fmt.Sprintf("seed redirect (%d) out of scope: %s", a.Status, loc)
		}
		pg.Error = why
		cr.mu.Lock()
		cr.res.SeedError = why
		cr.mu.Unlock()
		cr.o.Page(pg)
		return nil, nil, false
	}
	if first && a.URL != "" {
		cr.seedFinalURL = a.URL
		if o := originOf(a.URL); o != "" {
			cr.mu.Lock()
			cr.seedOrigin = o
			cr.mu.Unlock()
		}
		if cr.onSeedLand != nil {
			cr.onSeedLand(a.URL)
		}
	}
	if pg.FinalURL == pg.URL {
		pg.FinalURL = ""
	}
	isHTML := strings.Contains(strings.ToLower(a.Header.Get("Content-Type")), "html") || htmlLike(a.Body)
	var p htmlscan.Page
	if isHTML {
		p = htmlscan.Scan(a.Body, a.URL)
	}
	doc := detect.Doc{URL: a.URL, Status: int64(a.Status), Headers: lower(a.Header), Title: p.Title, Body: head(a.Body, 64<<10)}
	// One classifier for every caller (round 25J review): a 403 with a
	// WAF's page that names no vendor (wafRe) is a block here too, not a
	// page that passed.
	verdict := detect.Check(doc)
	if !verdict.Blocked {
		if b := detect.Classify(doc); b != nil && b.Kind != detect.BlockRate {
			verdict = detect.Result{Blocked: true, Vendor: b.Vendor, Evidence: b.Evidence}
		}
	}
	if first {
		cr.mu.Lock()
		cr.res.Seed, cr.res.Blocked = doc, verdict
		cr.res.Fronted, cr.res.FrontedBy = detect.Vendor(doc)
		cr.mu.Unlock()
	}
	cr.mu.Lock()
	if verdict.Blocked {
		hs.challenged++
		ch := Challenged{URL: it.URL, Depth: it.Depth, Asked: true}
		if b := detect.Classify(doc); b != nil {
			ch.Kind = string(b.Kind)
		}
		cr.res.Challenged = append(cr.res.Challenged, ch)
	} else {
		hs.ok++ // answered, if only with a 404: the host lets the crawl in
	}
	cr.mu.Unlock()
	if verdict.Blocked {
		pg.Blocked, pg.Error = true, "bot challenge"
		cr.o.Page(pg)
		if !first {
			// A challenge past the first page may be one path's (a WAF rule
			// on /admin): the page is left, the others are visited. Three
			// in a row say the whole site now challenges the crawl: it
			// stops (MAX-02). The first page's does not stop it either: the
			// well-known files and the scripts the archives name are often
			// served all the same (CF-03).
			cr.mu.Lock()
			cr.challenged++
			n := cr.challenged
			cr.mu.Unlock()
			if n >= 3 {
				cr.setStop(fmt.Sprintf("%d pages in a row are %s challenges", n, verdict.Vendor))
			}
		}
		return nil, nil, true
	}
	if !first {
		cr.mu.Lock()
		cr.challenged = 0
		cr.mu.Unlock()
	}
	if !first {
		cr.politeAt(a, it.URL, it.Depth)
	}
	if b != nil {
		b.pageStatus = a.Status
	}
	if !isHTML && a.Status == 200 && jsapi.IsOpenAPI(a.Body) {
		// Its operations are the API's endpoints: kept beside the scripts,
		// for the catalog to read.
		cr.o.Script(Script{Body: a.Body, Kind: "file", URL: a.URL, Page: it.From, Status: a.Status, MIME: a.Header.Get("Content-Type"),
			Tags: []string{"openapi"}, Found: "openapi", From: it.From})
		cr.count(func(st *Stats) { st.OpenAPI++ })
		if b != nil {
			b.inlineSigs = append(b.inlineSigs, sha256.Sum256(a.Body))
		}
	}
	if !isHTML || a.Status >= 400 {
		cr.o.Page(pg)
		return nil, nil, false
	}
	if print, origin := shellPrint(p), originOf(a.URL); cr.prints[origin] == "" {
		cr.prints[origin] = print
		cr.toCheck = a.URL
	} else if print == cr.prints[origin] {
		// The shell again: its scripts are held and its links queued.
		pg.Shell = true
		cr.count(func(st *Stats) { st.Shells++ })
		cr.o.Page(pg)
		return nil, nil, false
	}
	var jobs []job
	for _, s := range p.Scripts {
		if s.URL != "" {
			jobs = append(jobs, job{url: s.URL, page: a.URL, how: s.How, from: a.URL, depth: it.Depth, b: b})
			continue
		}
		code := []byte(s.Inline)
		if detect.IsChallengeScript("", "", "inline", code, false) {
			cr.count(func(st *Stats) { st.Challenge++ })
			continue
		}
		cr.count(func(st *Stats) { st.Inline++ })
		cr.o.Script(Script{Body: code, Kind: "inline", URL: a.URL, Page: a.URL, Found: "inline", From: a.URL})
		if b != nil {
			if sig, ok := inlineSemanticSig(cr, cr.skel, code, a.URL); ok {
				b.inlineSigs = append(b.inlineSigs, sig)
			}
		}
		for _, cand := range resolve.Static(code, a.URL, a.URL) {
			jobs = append(jobs, job{url: cand.URL, page: a.URL, how: cand.Method, from: a.URL, depth: it.Depth, tags: resolvedTags(cand.Method), b: b})
		}
		for _, cand := range cr.webpack.Add(code, a.URL, a.URL, true, false) {
			jobs = append(jobs, job{url: cand.URL, page: a.URL, how: cand.Method, from: cand.From, depth: it.Depth, tags: resolvedTags(cand.Method), b: b})
		}
		if cr.o.Depth > 0 || (cr.o.Probe && !cr.o.NoSpecProbe) {
			cr.routes(code, a.URL, a.URL, it.Depth, b)
		}
	}
	for _, m := range p.NextManifests() {
		jobs = append(jobs, job{url: m, page: a.URL, how: "next-build-id", from: a.URL, depth: it.Depth, tags: resolvedTags("build-manifest"), b: b})
	}
	links := frontier.FromHTML(string(a.Body), a.URL)
	pg.Discovered = len(links)
	cr.o.Page(pg)
	return jobs, links, false
}

func (cr *crawler) extractScript(body []byte, hint string) jsapi.Result {
	key := sha256.Sum256(body)
	cr.extractMu.Lock()
	if res, ok := cr.extracted[key]; ok {
		cr.extractMu.Unlock()
		return res
	}
	cr.extractMu.Unlock()

	var res jsapi.Result
	if cr.o.Extract != nil {
		res = cr.o.Extract(body, hint)
	} else {
		res = jsapi.ExtractSource(body, hint)
		if strings.HasPrefix(res.Error, "parse") {
			parseErr := res.Error
			res = jsapi.ExtractLoose(body)
			res.LooseFallback = true
			res.ParseError = parseErr
		}
	}

	cr.extractMu.Lock()
	if cr.extracted == nil {
		cr.extracted = map[[32]byte]jsapi.Result{}
	}
	cr.extracted[key] = res
	cr.extractMu.Unlock()
	return res
}

// routes queues the pages a script names (its navigations and routes), and
// gathers API origins and gateway context for two-phase spec probing.
// A path in a script is the page's: its URL resolves against the page the
// script runs on, not against the script's own URL.
func (cr *crawler) routes(body []byte, scriptURL, page string, depth int, b *bucket) {
	if page == "" {
		page = scriptURL
	}
	isNonApp := frontier.Vendor(scriptURL) || frontier.IsTrackerURL(scriptURL) || detect.InfraURL(scriptURL)
	if cr.o.Depth == 0 && isNonApp {
		return
	}
	base, err := url.Parse(page)
	if err != nil || len(body) > 8<<20 {
		return
	}
	r := cr.extractScript(body, scriptURL)
	var fs []frontier.Found
	if cr.o.Depth > 0 {
		fs = frontier.FromScript(r, base, frontier.Vendor(scriptURL))
	}
	var origins []string
	if cr.o.Probe && !cr.o.NoSpecProbe && !isNonApp {
		cr.specCtx.AddScript(r, page, scriptURL)
		origins = frontier.APIOrigins(r, cr.o.InScope)
	}
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if b == nil {
		// Scripts no page is taken for (the API hosts' descriptions after
		// the pages): nothing of theirs is queued any more.
		return
	}
	for _, f := range fs {
		b.found = append(b.found, found{f: f, from: scriptURL, depth: depth + 1})
	}
	for _, o := range origins {
		b.origins = append(b.origins, found{f: frontier.Found{URL: o}, from: scriptURL})
	}
}

// noteOriginsLocked keeps the API hosts scripts named, at most
// frontier.MaxAPIOrigins, the first named first. cr.mu is held.
func (cr *crawler) noteOriginsLocked(origins []string) {
	for _, o := range origins {
		if o != cr.seedOrigin && (frontier.MaxAPIOrigins <= 0 || len(cr.apiOrigins) < frontier.MaxAPIOrigins) && !slices.Contains(cr.apiOrigins, o) {
			cr.apiOrigins = append(cr.apiOrigins, o)
		}
	}
}

// --- scripts ---

// drain fetches the scripts and what they name, with o.Workers at once, to
// the end of the graph or of the budget.
func (cr *crawler) drain(ctx context.Context, jobs []job) {
	var mu sync.Mutex
	cond := sync.NewCond(&mu)
	pending := slices.Clone(jobs)
	active := 0
	var wg sync.WaitGroup
	for range cr.o.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				for len(pending) == 0 && active > 0 {
					cond.Wait()
				}
				if len(pending) == 0 || ctx.Err() != nil {
					cond.Broadcast()
					mu.Unlock()
					return
				}
				j := pending[0]
				pending = pending[1:]
				active++
				mu.Unlock()
				more := cr.script(ctx, j)
				mu.Lock()
				pending = append(pending, more...)
				active--
				cond.Broadcast()
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

func resolvedTags(method string) []string { return []string{"resolved", "resolved:" + method} }

// admit says whether a script is fetched: not a challenge's, no
// credential in its URL, past the policy, and claimed (once, within the
// budget).
func (cr *crawler) admit(j job) bool {
	if detect.ChallengeURL(j.url) {
		cr.count(func(st *Stats) { st.Challenge++ })
		return false
	}
	if u, err := url.Parse(j.url); err != nil || u.User != nil {
		cr.count(func(st *Stats) { st.Policy["credential_in_url"]++ })
		return false // never sent: Go would send the userinfo as Basic auth
	}
	if v := cr.policy.Check(j.url); v != resolve.Allow {
		cr.count(func(st *Stats) { st.Policy[string(v)]++ })
		return false
	}
	ok, _ := cr.claim(j.url)
	return ok
}

// claim takes a URL for fetching once, within the budget.
func (cr *crawler) claim(raw string) (ok bool, why string) {
	n, _ := frontier.Normalize(raw)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if cr.seen[n] {
		return false, ""
	}
	cr.seen[n] = true
	if cr.stopped != "" || cr.capped != "" {
		return false, ""
	}
	if cr.o.MaxFiles > 0 && cr.files >= cr.o.MaxFiles {
		cr.capped = fmt.Sprintf("-resolve-max (%d) reached", cr.o.MaxFiles)
		cr.o.Log("%s: no more scripts fetched; the pages go on", cr.capped)
		return false, ""
	}
	cr.files++
	return true, ""
}

func (cr *crawler) script(ctx context.Context, j job) []job {
	if !j.admitted && !cr.admit(j) {
		return nil
	}
	a := cr.fetch(ctx, j.url, j.page, scriptReq, "Script")
	cr.politeAt(a, j.page, j.depth)
	switch {
	case a.Err != nil:
		cr.count(func(st *Stats) { st.Failed++ })
		cr.o.Log("script %s: %v", j.url, a.Err)
		return nil
	case a.Status == 404 || a.Status == 410:
		cr.count(func(st *Stats) { st.NotFound++ })
		return nil
	case a.Status != 200:
		cr.count(func(st *Stats) { st.Failed++ })
		return nil
	case notScriptBody(a.Header.Get("Content-Type"), a.Body):
		cr.count(func(st *Stats) { st.NotScript++ })
		return nil
	case len(a.Body) == 0:
		return nil
	}
	h := lower(a.Header)
	tags := slices.Clone(j.tags)
	if j.how == "probe" {
		tags = append(tags, "probe")
	}
	cr.count(func(st *Stats) { st.Scripts++; st.Found[j.how]++ })
	cr.o.Script(Script{Body: a.Body, Kind: "file", URL: j.url, Page: j.page, Status: a.Status, MIME: h["content-type"],
		Headers: h, Tags: tags, Found: j.how, From: j.from})
	var more []job
	for _, cand := range resolve.Static(a.Body, a.URL, j.page) {
		more = append(more, job{url: cand.URL, page: j.page, how: cand.Method, from: a.URL, depth: j.depth, tags: resolvedTags(cand.Method), b: j.b})
	}
	if !detect.InfraURL(a.URL) {
		for _, cand := range cr.webpack.Add(a.Body, a.URL, j.page, false, false) {
			more = append(more, job{url: cand.URL, page: j.page, how: cand.Method, from: cand.From, depth: j.depth, tags: resolvedTags(cand.Method), b: j.b})
		}
	}
	if cr.o.SourceMaps {
		cr.sourceMap(ctx, a, j, h)
	}
	if cr.o.Depth > 0 || (cr.o.Probe && !cr.o.NoSpecProbe) {
		cr.routes(a.Body, a.URL, j.page, j.depth, j.b)
	}
	return more
}

func (cr *crawler) count(f func(*Stats)) {
	cr.mu.Lock()
	f(&cr.res.Stats)
	cr.mu.Unlock()
}

// log hands a request on for requests.jsonl.
func (cr *crawler) log(a answer, rtype, page string) {
	cr.count(func(st *Stats) { st.Requests++ })
	tags := []string{"http"}
	if rtype == "Other" {
		// A well-known file or a source map: the crawl's own asking, as the
		// resolver's are; no endpoint of the site's.
		tags = append(tags, "jsharvest")
	}
	e := traffic.Entry{Time: time.Now().UTC().Add(-a.Took), DurationMS: float64(a.Took.Microseconds()) / 1000, Target: "http",
		Page: page, ResourceType: rtype, Method: http.MethodGet, URL: a.URL, Source: "http", Tags: tags}
	if a.Err != nil && a.Status == 0 {
		e.Outcome = "failed: " + a.Err.Error()
	} else {
		e.Outcome = "ok"
		e.Response = &traffic.Response{Status: int64(a.Status), Headers: lower(a.Header), MIME: a.Header.Get("Content-Type"),
			Source: "network", Protocol: a.Proto, RemoteIP: a.RemoteIP, TLSIncompleteChain: a.IncompleteChain}
	}
	if e.Response != nil && cr.o.RecordBody > 0 && rtype != "Script" && len(a.Body) > 0 &&
		strings.Contains(strings.ToLower(a.Header.Get("Content-Type")), "json") {
		// An API's answer, or an error's: what the server says it runs.
		e.Response.Body = traffic.MakeBody(a.Body, cr.o.RecordBody)
	}
	cr.o.Request(e)
}

// staticJSONRe is a JSON file that is no API's answer: a manifest, a
// configuration, a package description, an API's description.
var staticJSONRe = regexp.MustCompile(`(?i)(?:^|/)[\w.-]*(?:manifest|package|config|settings|env|ngsw|openapi|swagger|api-docs)[\w.-]*\.json$|(?:^|/)(?:swagger-resources|api-docs)$|\.map$`)

// apiAnswer reports a page's answer that is an API's: JSON, not an error
// of the server, no API description, no static file.
func apiAnswer(a answer) bool {
	if a.Err != nil || a.Status < 200 || a.Status >= 500 {
		return false
	}
	ct := strings.ToLower(a.Header.Get("Content-Type"))
	if !strings.Contains(ct, "application/json") && !(strings.HasPrefix(ct, "application/") && strings.Contains(ct, "+json")) {
		return false
	}
	u, err := url.Parse(a.URL)
	if err != nil || staticJSONRe.MatchString(u.Path) || htmlLike(a.Body) {
		return false
	}
	return !jsapi.IsOpenAPI(a.Body)
}

// --- the well-known files ---

// probe reads the well-known files of the seed's origin: the pages
// robots.txt and the sitemaps list, and the script lists of the bundlers'
// manifests. A file that is not there costs one 404.
func (cr *crawler) probe(ctx context.Context, seed string) ([]job, []frontier.Found) {
	u, err := url.Parse(seed)
	if err != nil {
		return nil, nil
	}
	root := u.Scheme + "://" + u.Host
	var jobs []job
	var links []frontier.Found
	get := func(p string) (answer, bool) {
		if cr.stop() != "" {
			return answer{}, false
		}
		if ok, _ := cr.claim(root + p); !ok {
			return answer{}, false
		}
		a := cr.fetch(ctx, root+p, seed, dataReq, "Other")
		cr.politeAt(a, seed, 0)
		cr.count(func(st *Stats) { st.Probes[p] = a.Status })
		return a, a.Err == nil && a.Status == 200 && !htmlLike(a.Body) && len(a.Body) > 0
	}
	sitemaps := []string{root + "/sitemap.xml"}
	if a, ok := get("/robots.txt"); ok {
		pages, maps := frontier.FromRobots(string(a.Body), root+"/robots.txt")
		links = append(links, pages...)
		for _, m := range maps {
			if strings.HasPrefix(m, root+"/") && !slices.Contains(sitemaps, m) {
				sitemaps = append(sitemaps, m)
			}
		}
	}
	for i, m := range sitemaps {
		if i == 5 {
			break
		}
		if a, ok := get(strings.TrimPrefix(m, root)); ok && bytes.Contains(a.Body, []byte("<loc>")) {
			links = append(links, frontier.FromSitemap(string(a.Body), m)...)
		}
	}
	add := func(urls []string, how string) {
		for _, s := range urls {
			jobs = append(jobs, job{url: s, page: seed, how: how, from: seed, tags: resolvedTags(how)})
		}
	}
	if a, ok := get("/asset-manifest.json"); ok {
		add(resolve.AssetManifest(a.Body, root+"/asset-manifest.json"), "asset-manifest")
	}
	if a, ok := get("/ngsw.json"); ok {
		for _, c := range resolve.NgswURLs(a.Body, root+"/ngsw.json") {
			jobs = append(jobs, job{url: c.URL, page: seed, how: "ngsw", from: root + "/ngsw.json", tags: resolvedTags("ngsw")})
		}
	}
	if a, ok := get("/.vite/manifest.json"); ok {
		add(resolve.ViteManifest(a.Body, root+"/"), "vite-manifest")
	}
	// Service workers: a Workbox precache list names the whole app.
	for _, p := range []string{"/service-worker.js", "/sw.js"} {
		jobs = append(jobs, job{url: root + p, page: seed, how: "probe", from: seed})
	}
	if !cr.o.NoSpecProbe {
		cr.specProbe(ctx, root, seed, nil, nil)
	}
	return jobs, links
}

// specProbe asks an origin or gateway base for its API's description where
// servers keep it (frontier.SpecPaths): an OpenAPI document or an OpenID
// Provider's configuration is kept beside the scripts (tag openapi), for the
// catalog. If /swagger-resources lists Springfox document paths, up to
// jsapi.MaxSwaggerResources are fetched under the same base.
func (cr *crawler) specHostBlocked(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return cr.specBlocked[h] != ""
}

// politeSpecAt isolates WAF/challenge/429 responses per host during post-page
// OpenAPI/OIDC spec probing so that a block on a third-party or secondary host
// stops only that host without halting specProbePhase2 on in-scope targets.
func (cr *crawler) politeSpecAt(a answer, base, referer string, postPages bool) {
	if !postPages && originOf(base) == cr.seedOrigin {
		cr.politeAt(a, referer, 0)
		return
	}
	u, err := url.Parse(a.URL)
	if err != nil {
		u, _ = url.Parse(base)
	}
	host := ""
	if u != nil {
		host = strings.ToLower(u.Hostname())
	}
	if host == "" {
		return
	}
	why := ""
	if a.Err == nil && a.Status != 0 {
		h := lower(a.Header)
		var title string
		if strings.Contains(h["content-type"], "html") {
			title = htmlscan.Scan(a.Body[:min(len(a.Body), 64<<10)], a.URL).Title
		}
		if b := detect.Classify(detect.Doc{URL: a.URL, Status: int64(a.Status), Headers: h, Title: title, Body: head(a.Body, 64<<10)}); b != nil {
			if b.Kind == detect.BlockRequest {
				return
			}
			if b.Kind != detect.BlockRate {
				if b.Kind.BrowserMayPass() && cr.o.InScope != nil && cr.o.InScope(host) {
					cr.noteChallenged(a.URL, referer, 0, b.Kind)
				}
				why = fmt.Sprintf("%s answered with a %s", host, b)
			}
		}
	}
	if why == "" {
		switch {
		case a.Status == http.StatusTooManyRequests:
			why = host + " answered 429"
		case strings.EqualFold(a.Header.Get("Cf-Mitigated"), "challenge"):
			why = host + " answered with a challenge (cf-mitigated)"
		case a.Status == http.StatusServiceUnavailable && a.Header.Get("Retry-After") != "":
			why = host + " answered 503 with Retry-After"
		}
	}
	if why != "" {
		cr.mu.Lock()
		if cr.specBlocked[host] == "" {
			cr.specBlocked[host] = why
		}
		cr.mu.Unlock()
		cr.o.Log("spec-probe host stopped (%s)", why)
	}
}

func tryTakeSpecBudget(budget *atomic.Int64) bool {
	if budget == nil {
		return true
	}
	for {
		cur := budget.Load()
		if cur <= 0 {
			return false
		}
		if budget.CompareAndSwap(cur, cur-1) {
			return true
		}
	}
}

func specBudgetExhausted(budget *atomic.Int64) bool {
	return budget != nil && budget.Load() <= 0
}

func (cr *crawler) specProbe(ctx context.Context, base, referer string, hdrs []jsapi.Header, budget *atomic.Int64) {
	cr.specProbeWithScope(ctx, base, referer, hdrs, budget, false)
}

func (cr *crawler) specProbeWithScope(ctx context.Context, base, referer string, hdrs []jsapi.Header, budget *atomic.Int64, postPages bool) {
	base = strings.TrimRight(base, "/")
	if _, err := url.Parse(base); err != nil || cr.specPolicy.Check(base+"/") != resolve.Allow || cr.specHostBlocked(base) {
		return
	}
	fetchSpec := func(targetURL, pathHint string) (answer, bool) {
		if cr.stop() != "" || cr.specHostBlocked(targetURL) || ctx.Err() != nil {
			return answer{}, false
		}
		if specBudgetExhausted(budget) {
			return answer{}, false
		}
		if ok, _ := cr.claim(targetURL); !ok {
			return answer{}, false
		}
		if !tryTakeSpecBudget(budget) {
			return answer{}, false
		}
		a := cr.fetchWithHeaders(ctx, targetURL, referer, dataReq, "Other", hdrs)
		cr.politeSpecAt(a, base, referer, postPages)
		key := strings.TrimPrefix(targetURL, cr.seedOrigin)
		if key == targetURL || key == "" {
			key = targetURL
		}
		cr.count(func(st *Stats) { st.Probes[key] = a.Status })
		if a.Err != nil || a.Status != 200 || htmlLike(a.Body) || len(a.Body) == 0 {
			return a, false
		}
		tags := []string{"openapi"}
		switch {
		case jsapi.IsOpenAPI(a.Body):
		case pathHint == "/.well-known/openid-configuration" && jsapi.IsOIDC(a.Body):
			tags = append(tags, "oidc")
		default:
			return a, false
		}
		cr.o.Script(Script{Body: a.Body, Kind: "file", URL: a.URL, Page: referer, Status: a.Status, MIME: a.Header.Get("Content-Type"),
			Tags: tags, Found: "spec-probe", From: referer})
		cr.count(func(st *Stats) { st.OpenAPI++ })
		cr.o.Log("%s: an API description (%s)", a.URL, strings.Join(tags, ", "))
		return a, true
	}

	for _, p := range frontier.SpecPaths {
		if cr.stop() != "" || cr.specHostBlocked(base) || ctx.Err() != nil || specBudgetExhausted(budget) {
			return
		}
		targetURL := frontier.JoinSpecBase(base, p)
		a, stored := fetchSpec(targetURL, p)
		if !stored && p == "/swagger-resources" && a.Err == nil && a.Status == 200 && !htmlLike(a.Body) {
			for _, rel := range jsapi.SwaggerResources(a.Body) {
				if cr.stop() != "" || cr.specHostBlocked(base) || ctx.Err() != nil || specBudgetExhausted(budget) {
					break
				}
				docURL := frontier.JoinSpecBase(base, rel)
				fetchSpec(docURL, rel)
			}
		}
	}
}

// specProbePhase2 runs post-JS context-aware spec probing (3.1 + D3):
// (a) discovered gateway/API bases with scoped static client_headers;
// (b) top microservice sub-prefixes (/v3/api-docs, /v2/api-docs) with D3
// uniform gate auto-brake.
func (cr *crawler) specProbePhase2(ctx context.Context, referer string) {
	cr.mu.Lock()
	seedOrig := cr.seedOrigin
	cr.mu.Unlock()

	plan := cr.specCtx.Plan(seedOrig, cr.o.InScope)
	var budgetPtr *atomic.Int64
	if frontier.MaxPhase2SpecProbes > 0 {
		var b atomic.Int64
		b.Store(int64(frontier.MaxPhase2SpecProbes))
		budgetPtr = &b
	}

	// (a) Gateway / Base Spec Probe (concurrent across discovered bases).
	if len(plan.Bases) > 0 {
		baseWorkers := min(max(cr.o.Workers, 4), 8)
		if baseWorkers > len(plan.Bases) {
			baseWorkers = len(plan.Bases)
		}
		bch := make(chan string, len(plan.Bases))
		for _, base := range plan.Bases {
			bch <- base
		}
		close(bch)
		var bwg sync.WaitGroup
		for range baseWorkers {
			bwg.Add(1)
			go func() {
				defer bwg.Done()
				for base := range bch {
					if cr.stop() != "" || ctx.Err() != nil || specBudgetExhausted(budgetPtr) {
						return
					}
					if cr.specHostBlocked(base) {
						continue
					}
					hdrs := cr.specCtx.HeadersFor(base, cr.o.InScope)
					cr.specProbeWithScope(ctx, base, referer, hdrs, budgetPtr, true)
				}
			}()
		}
		bwg.Wait()
	}

	// (b) Service Sub-Prefix Doc Probe + D3 Auto-Brake.
	type gateState struct {
		lastSig    string
		consec     int
		hadOpenAPI bool
		braked     bool
	}
	gates := map[string]*gateState{}

	for _, svc := range plan.Services {
		if cr.stop() != "" || ctx.Err() != nil || specBudgetExhausted(budgetPtr) {
			return
		}
		if cr.specPolicy.Check(svc.PrefixURL+"/") != resolve.Allow || cr.specHostBlocked(svc.PrefixURL) {
			continue
		}
		gs := gates[svc.GatewayBase]
		if gs == nil {
			gs = &gateState{}
			gates[svc.GatewayBase] = gs
		}
		if gs.braked {
			continue
		}
		hdrs := cr.specCtx.HeadersFor(svc.PrefixURL, cr.o.InScope)
		for _, p := range frontier.ServiceDocPaths {
			if cr.stop() != "" || cr.specHostBlocked(svc.PrefixURL) || ctx.Err() != nil || specBudgetExhausted(budgetPtr) || gs.braked {
				break
			}
			targetURL := frontier.JoinSpecBase(svc.PrefixURL, p)
			if ok, _ := cr.claim(targetURL); !ok {
				continue
			}
			if !tryTakeSpecBudget(budgetPtr) {
				break
			}
			a := cr.fetchWithHeaders(ctx, targetURL, referer, dataReq, "Other", hdrs)
			cr.politeSpecAt(a, svc.PrefixURL, referer, true)
			key := strings.TrimPrefix(targetURL, seedOrig)
			if key == targetURL || key == "" {
				key = targetURL
			}
			cr.count(func(st *Stats) { st.Probes[key] = a.Status })

			if a.Err == nil && a.Status == 200 && !htmlLike(a.Body) && len(a.Body) > 0 && jsapi.IsOpenAPI(a.Body) {
				cr.o.Script(Script{Body: a.Body, Kind: "file", URL: a.URL, Page: referer, Status: a.Status,
					MIME: a.Header.Get("Content-Type"), Tags: []string{"openapi"}, Found: "spec-probe", From: referer})
				cr.count(func(st *Stats) { st.OpenAPI++ })
				cr.o.Log("%s: an API description (openapi)", a.URL)
				gs.hadOpenAPI = true
				gs.lastSig = ""
				gs.consec = 0
				continue
			}

			sig, isGate := cr.gateSignature(a)
			if !isGate {
				gs.lastSig = ""
				gs.consec = 0
				continue
			}
			if sig == gs.lastSig {
				gs.consec++
			} else {
				gs.lastSig = sig
				gs.consec = 1
			}
			if gs.consec >= 2 && (!gs.hadOpenAPI || a.Status != http.StatusNotFound) {
				gs.braked = true
				cr.o.Log("spec-probe auto-brake on %s after uniform gate (%s)", svc.GatewayBase, sig)
				break
			}
		}
	}
}

// gateSignature classifies a non-OpenAPI probe response for D3 uniform gate
// detection: an SPA HTML fallback shell, a 400/401/403/404 auth/gateway wall,
// or repeated transport failures ("neterr") on an unreachable gateway.
func (cr *crawler) gateSignature(a answer) (string, bool) {
	if a.Err != nil || a.Status == 0 {
		return "neterr", true
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(a.Header.Get("Content-Type"), ";")[0]))
	if strings.Contains(ct, "html") || htmlLike(a.Body) {
		switch a.Status {
		case http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			sp := shellPrint(htmlscan.Scan(a.Body[:min(len(a.Body), 64<<10)], a.URL))
			return fmt.Sprintf("html:%d:%s", a.Status, sp), true
		}
		return "", false
	}
	switch a.Status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
	default:
		return "", false
	}
	trimmed := bytes.TrimSpace(a.Body[:min(len(a.Body), 8192)])
	if (strings.Contains(ct, "json") || bytes.HasPrefix(trimmed, []byte("{"))) && len(trimmed) > 0 {
		var obj map[string]any
		if json.Unmarshal(trimmed, &obj) == nil && len(obj) > 0 {
			keys := make([]string, 0, len(obj))
			for k := range obj {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			return fmt.Sprintf("json:%d:%s:%s|%v|%v", a.Status, ct, strings.Join(keys, ","), obj["code"], obj["error"]), true
		}
	}
	return fmt.Sprintf("wall:%d:%s:%d", a.Status, ct, len(trimmed)/64), true
}

// --- helpers ---

func lower(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		k = strings.ToLower(k)
		if k == "set-cookie" {
			out[k] = strings.Join(v, "\n")
		} else {
			out[k] = strings.Join(v, ", ")
		}
	}
	return out
}

func head(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

// htmlLike reports whether a body is a page, not a script: an SPA's
// fallback, a soft 404 (including XHTML with <?xml preamble).
func htmlLike(b []byte) bool {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	t := strings.ToLower(strings.TrimSpace(string(b[:min(len(b), 4096)])))
	if strings.HasPrefix(t, "<!doctype ") || strings.HasPrefix(t, "<html") || strings.HasPrefix(t, "<head") ||
		strings.HasPrefix(t, "<body") || strings.HasPrefix(t, "<?xml") || strings.HasPrefix(t, "<svg") ||
		strings.HasPrefix(t, "<rss") || strings.HasPrefix(t, "<feed") {
		return true
	}
	return strings.HasPrefix(t, "<") && (strings.Contains(t, "<html") || strings.Contains(t, "<head") || strings.Contains(t, "<body") || strings.Contains(t, "<!doctype html"))
}

func notScriptBody(contentType string, b []byte) bool {
	if htmlLike(b) {
		return true
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	switch {
	case ct == "text/html" || ct == "application/xhtml+xml" || ct == "application/xml" || ct == "text/xml" || ct == "application/pdf":
		trimmed := bytes.TrimSpace(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")))
		return len(trimmed) > 0 && (trimmed[0] == '<' || bytes.HasPrefix(trimmed, []byte("%PDF-")))
	case strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "audio/") || strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "font/"):
		return true
	}
	return false
}

// specURL reports whether a URL is an API's description (openapi.yaml).
func specURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && frontier.SpecFile(u.Path)
}

// maxPagesInFlight is how many pages' scripts are fetched at once: their
// requests share the one -http-rate limiter all the same.
var maxPagesInFlight = 4 // a var for the tests

// inflight is a page taken whose scripts are being fetched.
type inflight struct {
	it      frontier.Item
	links   []frontier.Found
	from    string
	blocked bool
	b       *bucket
	done    chan struct{}
}

// pages visits the queue, a level (depth) at a time (round 25K, step 2.3).
// Within a level the pages are fetched one after another, as before, but a
// page's scripts are fetched beside the next pages' (up to
// maxPagesInFlight pages): a slow script no longer holds the next page
// back, which made the crawl's pace its slowest scripts' once -http-rate
// was raised past ~7/s. Whatever a page finds (its links, its scripts'
// routes and API hosts) is queued at the end of the level, in the order
// the pages were taken: everything found is a level deeper, so the queue
// gives the pages in the order a crawl of one page at a time gives them.
// The first page (the seed, its well-known files) is done alone.
func (cr *crawler) pages(ctx context.Context) {
	o := cr.o
	first := true
	var level []*inflight
	sem := make(chan struct{}, maxPagesInFlight)
	commit := func() {
		for _, f := range level {
			<-f.done
		}
		for _, f := range level {
			if f.blocked {
				continue // a challenge's links are the vendor's
			}
			for _, l := range f.links {
				cr.q.Add(l, f.it.Depth+1, f.from)
			}
			fs, origins := f.b.sorted()
			for _, x := range fs {
				cr.addWith(x.f, x.depth, x.from, f.b.spa)
			}
			cr.mu.Lock()
			cr.noteOriginsLocked(origins)
			cr.mu.Unlock()
		}
		level = nil
	}
	defer commit()
	for ctx.Err() == nil && cr.stop() == "" {
		nx, ok := cr.q.Peek()
		if len(level) > 0 && (!ok || nx.Depth != level[0].it.Depth) {
			commit()
			continue
		}
		it, ok := cr.q.Next()
		if !ok {
			break
		}
		if !first && cr.skel != nil && cr.skel.shouldSkip(it.URL) {
			cr.q.Refund()
			cr.mu.Lock()
			cr.res.Listed[frontier.TemplateSaturated]++
			cr.mu.Unlock()
			o.Page(Page{URL: it.URL, How: it.How, From: it.From, Depth: it.Depth, Reason: frontier.TemplateSaturated})
			continue
		}
		b := &bucket{}
		jobs, links, blocked := cr.page(ctx, it, first, b)
		if cr.toCheck != "" && o.Depth > 0 && !blocked && cr.stop() == "" {
			cr.spaCheck(ctx, cr.toCheck, it.Depth)
		}
		cr.toCheck = ""
		fromURL := it.URL
		if first {
			if o.Probe && cr.stop() == "" && cr.res.SeedError == "" {
				probeURL := it.URL
				if cr.seedFinalURL != "" {
					probeURL = cr.seedFinalURL
				}
				pj, pl := cr.probe(ctx, probeURL)
				for i := range pj {
					pj[i].b = b
				}
				jobs, links = append(jobs, pj...), append(links, pl...)
			}
			if cr.seedFinalURL != "" {
				fromURL = cr.seedFinalURL
			}
		}
		cr.mu.Lock()
		b.spa = maps.Clone(cr.spa)
		cr.mu.Unlock()
		// The page's scripts are claimed now, in the order the pages are
		// taken (round 25L review): a bundle two pages of the level share
		// is the first page's, its routes queued with that page's, as a
		// one-page-at-a-time crawl has it, whichever page's scripts are
		// fetched first. (A chunk a script names is claimed when that
		// script is read: one a later page names in its HTML may go with
		// that page.)
		admitted := jobs[:0]
		for _, j := range jobs {
			if cr.admit(j) {
				j.admitted = true
				admitted = append(admitted, j)
			}
		}
		jobs = admitted
		if !blocked && cr.skel != nil && b.pageStatus > 0 {
			gained := cr.skel.observe(cr, fromURL, b.pageStatus, jobs, b.inlineSigs, links, b)
			cr.q.Feedback(fromURL, gained)
		}
		f := &inflight{it: it, links: links, from: fromURL, blocked: blocked, b: b, done: make(chan struct{})}
		level = append(level, f)
		if first {
			// The seed alone: its well-known files and scripts before any
			// other page, its findings queued at once.
			first = false
			cr.drain(ctx, jobs)
			close(f.done)
			commit()
			continue
		}
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; close(f.done) }()
			cr.drain(ctx, jobs)
		}()
	}
}

// addWith is add as the SPA check had it when the page was done.
func (cr *crawler) addWith(f frontier.Found, depth int, from string, spa map[string]bool) {
	if spa[originOf(f.URL)] && !specURL(f.URL) {
		cr.q.ListAs(f, from, frontier.SPARoute)
		return
	}
	cr.q.Add(f, depth, from)
}
