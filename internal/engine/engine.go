// Package engine runs one harvest of a target: it opens the store and the
// browser, captures while the page loads and settles, and writes the run
// report. The CLI only turns flags into a Config.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
	"github.com/TimoMangCut/JSharvest/internal/browser"
	"github.com/TimoMangCut/JSharvest/internal/capture"
	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/htmlscan"
	"github.com/TimoMangCut/JSharvest/internal/httpcrawl"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/resolve"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/sourcemap"
	"github.com/TimoMangCut/JSharvest/internal/store"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

type Config struct {
	Target  *url.URL
	OutRoot string
	Role    string
	// InScope decides the target's scope. When nil, it is built from
	// ScopeMode and the target's host, as a URL list needs for each URL.
	InScope   scope.Func
	ScopeMode string
	Browser   browser.Options

	MaxBody    int
	NavTimeout time.Duration
	Idle       time.Duration // network quiet time that counts as idle
	IdleMax    time.Duration
	SWWait     time.Duration
	NoDebugger bool

	// Guard holds back writes, logouts and destructive calls (see package
	// guard). AllowWebSocket keeps page WebSockets, which the guard cannot
	// inspect and otherwise stubs out.
	Guard          bool
	GuardRules     guard.Rules
	AllowWebSocket bool
	// GuardScope is what the guard protects of the workers already running
	// when it starts: a URL list's union of scopes. When nil, InScope, or
	// the scope of Target.
	GuardScope scope.Func

	// Record logs the requests to requests.jsonl, keeping at most RecordBody
	// bytes of each body. Redact hides credentials there and in blocked.*.
	Record     traffic.Mode
	RecordBody int
	Redact     bool

	// Actions records what the user or a driver does, and traces each
	// request to the action that caused it (flows.jsonl). NoTagger leaves
	// the page's event handlers alone, which leaves only timing to go by.
	Actions  bool
	NoTagger bool

	// Depth > 0 crawls: the pages the target links to, Depth links away
	// at most, MaxPages in all, PageRate a second, each given PageDwell at
	// least (see package frontier). Depth 0 harvests the one page.
	Depth    int
	MaxPages int
	PageRate float64
	// Tabs is how many URLs of a list are harvested at once (-tabs), each
	// in a browser context of its own. 1: one after the other, in the
	// browser's own context.
	Tabs      int
	PageDwell time.Duration

	// Login, when set, is the saved login the crawl runs with: put back at
	// the start, watched, and restored when lost.
	Login *Login
	// Logins, for a URL list, are the saved logins by host: each URL runs
	// with its host's (Login is then unused).
	Logins map[string]*Login
	// sharedKeeper is the keeper of the host a batch page belongs to, when
	// the batch runs the pages of one host and role in one browser context
	// (RunURLs, C4): runPage joins it instead of making its own.
	sharedKeeper *keeper

	// Explore does on each page what a person could (click, type, choose,
	// hover, scroll), at most ExploreActions actions and ExploreTime a
	// page, ExploreTotal in all, waiting ExploreWait at least after each.
	// It needs the guard and the recorder (see docs/gd4-explore-design.md).
	Explore        bool
	ExploreActions int
	ExploreTime    time.Duration
	ExploreTotal   time.Duration
	ExploreWait    time.Duration

	// Resolve fetches the chunks the app names but has not loaded, through
	// the page, under the scope policy, at most ResolveRate per second and
	// ResolveMax in all.
	Resolve     bool
	ResolveRate float64
	ResolveMax  int
	// SourceMaps reads the captured scripts' source maps through the page,
	// with the resolver; GuessMaps asks <script>.map of the app's scripts
	// that name none (MAX-07).
	SourceMaps bool
	GuessMaps  bool

	// ChallengeWait is how long a page that is a challenge is given to pass
	// on its own and reload before it counts as blocked (0: not at all).
	ChallengeWait time.Duration

	// OutHost is the output directory's host when it is not the target's:
	// the pages the HTTP engine hands to Chrome are filed with its seed's.
	OutHost string
	// PageScope narrows the pages the frontier visits to these hosts;
	// InScope still says which scripts and requests are the target's.
	// When nil, PageScopeMode ("auto", "fqdn" or "rdn") builds it.
	PageScope     func(host string) bool
	PageScopeMode string
	// Seeds are more pages the frontier starts from, with the target.
	Seeds []string
	// Cookies go into the browser context before the first page: an
	// escalation's, the application's cookies the HTTP engine's crawl of
	// the same run got (round 25L). In memory only: never a profile's.
	Cookies []*network.CookieParam
	// SpecProbe asks the target's origin and the API hosts its scripts
	// name for their API's description (frontier.SpecPaths), with the
	// frontier (crawl -probe). NoSpecProbe disables spec probing while
	// keeping other well-known probes.
	SpecProbe   bool
	NoSpecProbe bool
}

// outDir is where the run's output goes.
func (c Config) outDir() string {
	h := c.OutHost
	if h == "" {
		h = scope.TargetDir(c.Target)
	}
	return filepath.Join(c.OutRoot, h, c.Role)
}

// RunConfig is what a run was asked to cover, so that runs of two roles
// can be told comparable or not (jsharvest diff).
type RunConfig struct {
	Depth    int  `json:"depth"`
	MaxPages int  `json:"max_pages,omitempty"`
	Explore  bool `json:"explore"`
	Resolve  bool `json:"resolve"`
	Guard    bool `json:"guard"`
	Debugger bool `json:"debugger"`
	Session  bool `json:"session"` // a saved login
	// What else decides what a run can see, for monitor's comparing.
	Record       string `json:"record,omitempty"`
	PageDwellMS  int64  `json:"page_dwell_ms,omitempty"`
	ExploreActs  int    `json:"explore_actions,omitempty"`
	ExploreTime  int64  `json:"explore_time_s,omitempty"`
	ExploreTotal int64  `json:"explore_total_s,omitempty"`
	ResolveMax   int    `json:"resolve_max,omitempty"`
	AllowWrite   bool   `json:"allow_write,omitempty"`
	GuardAllow   string `json:"guard_allow,omitempty"`
	// Engine is "http" for a crawl without a browser; a browser's leaves it
	// out, as runs before the field did.
	Engine string `json:"engine,omitempty"`
}

func reString(re *regexp.Regexp) string {
	if re == nil {
		return ""
	}
	return re.String()
}

// scopeMode is -scope as the scope package reads it: rdn unless fqdn.
func scopeMode(m string) string {
	if m == "fqdn" {
		return m
	}
	return "rdn"
}

// ErrSessionLost is returned when the saved login was lost during a crawl
// and could not be restored; what came before is kept.
var ErrSessionLost = errors.New("the session was lost and could not be restored; the crawl stopped there")

// ErrBlocked is returned when the site answered with a bot challenge, so
// that a run never reports success while it was blocked.
// ErrPrivateAddress is returned when a page of a public origin got a
// response from a private address (layer 3 of the defence against a
// public page touching the internal network); run.json private_address_hit
// has them. It exits 1, with the reason in the message.
var ErrPrivateAddress = errors.New("a response to a public page came from a private address (run.json private_address_hit): the target may reach the internal network")

var ErrBlocked = errors.New("blocked by a bot challenge; its scripts were dropped, none is the site's")

// Record is written to run.json (the last run) and appended to runs.jsonl
// (every run) in the output directory.
type Record struct {
	Version int        `json:"version"`
	RunID   string     `json:"run_id"` // the "run" of this run's lines in requests.jsonl
	Target  string     `json:"target"`
	Role    string     `json:"role"`
	Mode    string     `json:"mode"`
	Scope   string     `json:"scope"` // -scope: rdn or fqdn
	Config  *RunConfig `json:"config,omitempty"`
	// Tabs: the run was one of that many at once (crawl -tabs). Not in
	// Config: it does not change what a run finds (jsharvest monitor).
	Tabs       int       `json:"tabs,omitempty"`
	Started    time.Time `json:"started"`
	Ended      time.Time `json:"ended"`
	DurationMS int64     `json:"duration_ms"`
	Requests   int       `json:"requests"` // lines written to requests.jsonl
	// PageRequests are the requests the pages sent; InternalRequests the
	// tool's own (tag jsharvest: resolver, well-known files, source maps),
	// in requests.jsonl too.
	PageRequests     int                     `json:"page_requests"`
	InternalRequests int                     `json:"internal_requests,omitempty"`
	Flows            *FlowStats              `json:"flows,omitempty"`
	Endpoints        map[string]int          `json:"endpoints,omitempty"` // endpoints.jsonl, by status
	StaticAnalysis   *endpoints.AnalyzeStats `json:"static_analysis,omitempty"`
	Frontier         *FrontierStats          `json:"frontier,omitempty"`
	Session          *SessionStats           `json:"session,omitempty"`
	Explore          *ExploreStats           `json:"explore,omitempty"`
	UniqueScripts    int                     `json:"unique_scripts"`
	// Scripts are the SHA-256 of the scripts this run saw: the run's own,
	// which the cumulative index cannot tell (jsharvest monitor).
	Scripts     []string           `json:"scripts,omitempty"`
	NewScripts  int                `json:"new_scripts"`
	Stats       capture.Stats      `json:"stats"`
	StoreErrors map[string]int     `json:"store_errors"`
	Idle        capture.IdleResult `json:"idle"`
	Resolver    ResolverStats      `json:"resolver"`
	// HTTP is the HTTP engine's counts (crawl -engine http): no browser.
	HTTP *httpcrawl.Stats `json:"http,omitempty"`
	// Fallback is what the archives gave when the first page was a
	// challenge (crawl -engine http -archive-fallback): see <host>/archive.
	Fallback any `json:"fallback,omitempty"`
	// Archive is what crawl -archive gave after the crawl (the HTTP engine).
	Archive any `json:"archive,omitempty"`
	// Escalated is what Chrome made of the pages the HTTP engine met a
	// challenge on (crawl -engine auto): their runs are in runs.jsonl.
	Escalated *Escalation `json:"escalated,omitempty"`
	// SPABoot: the SPA origins Chrome booted when the crawl saw no API
	// call (crawl -spa-boot).
	SPABoot []EscalatedRun `json:"spa_boot,omitempty"`
	// Totals aggregates this HTTP run's counts with any follow-up Chrome runs
	// (Escalated / SPABoot) while keeping the HTTP run's own counters intact.
	Totals  *RunTotals     `json:"totals,omitempty"`
	Guard   *guard.Stats   `json:"guard,omitempty"`
	Blocked detect.Result  `json:"blocked"`
	// Fronted names the bot/WAF vendor sitting in front of the target, blocked
	// or not; it tells an authorized operator which product to whitelist.
	Fronted   string   `json:"fronted,omitempty"`
	FrontedBy []string `json:"fronted_by,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	ExitCode  int      `json:"exit_code"`
}

// RunTotals aggregates an HTTP run's counters with its follow-up Chrome runs
// (Escalated and SPABoot), leaving the HTTP run's own per-run counters intact.
type RunTotals struct {
	Requests         int      `json:"requests"`
	PageRequests     int      `json:"page_requests"`
	InternalRequests int      `json:"internal_requests"`
	NewScripts       int      `json:"new_scripts"`
	Runs             []string `json:"runs"`
}

// runState is what the tabs of one run share: its record, its output,
// its request log and flows, the guard and the saved login, and the
// resolver's state. A run has one tab, or, with crawl -tabs N on the
// frontier, N; each tab is an engine over the same runState.
type runState struct {
	cfg Config
	run Record
	// recMu guards what the tabs add to the run record as they go:
	// Warnings and StoreErrors.
	recMu sync.Mutex
	// Layer 3: hosts given up, the user's host rules (exempt), and whether
	// the check is off because the target itself is internal.
	banMu     sync.Mutex
	banned    map[string]bool
	privRules netsafe.Rules
	privOff   bool
	st        *store.Store
	dir       *outDir // st's directory, which other runs of the process may share

	scripts    map[string]bool // SHA-256 of the scripts this run saw
	newScripts int             // of them, those new to the store
	// shared: other runs work at once in the browser (crawl -urls -tabs),
	// with one guard: its records are claimed by the capture, its counts
	// are not this run's.
	shared bool

	mu       sync.Mutex
	seen     map[string]bool              // normalized URLs captured so far
	parsed   map[string]bool              // script URLs already read by the resolver
	pending  []ref                        // captured bodies for the next resolver round
	resolved map[string]resolve.Candidate // URLs the resolver fetched, for their labels
	webpack  resolve.WebpackLinker        // cross-script Webpack runtimeChunk linker
	mapsSeen map[string]bool              // source map URLs asked for
	// mapGuesses: the <script>.map guesses each origin missed and found.
	mapGuesses sourcemap.Guesses
	rscDeduper htmlscan.RSCDeduper
	// resolveMu: one resolver round at a time, so that -resolve-rate is the
	// run's, and its counts in the run record are kept by one.
	resolveMu sync.Mutex
	guard     *guard.Guard
	guardAt   guard.Stats // the guard's counts when this run started; a batch shares one guard

	traffic  *traffic.Writer   // nil unless recording
	redactor *traffic.Redactor // nil unless redacting
	held     map[string]int    // held-back requests the log has, by network id and by "method url"
	// incomplete are requests with no answer when the capture stopped,
	// kept back until the guard's records are read: one the guard held
	// back is then logged once, as held back.
	incomplete []traffic.Entry

	keeper *keeper // the saved login, when the crawl has one
	// noSharedWorkers: a batch page that joined a host's keeper after
	// another page: that one captures the context's service workers.
	noSharedWorkers bool
	analyzing       atomic.Bool // a watch's background analysis of new scripts
	analyzed        int         // scripts in the store when it last started

	events      []flow.Event   // actions reported by the pages
	heard       time.Time      // when the last trusted one came
	summary     []flow.Request // what grouping needs of each logged request
	rootTab     context.Context
	extraCloses []context.CancelFunc // recycled tabs' context cancels
}

// engine is one tab of a run.
type engine struct {
	*runState
	tabMu        sync.RWMutex
	tab          context.Context
	closeTab     context.CancelFunc
	listenCtx    context.Context
	stopListen   context.CancelFunc
	lane         int // the tab's number in the run: 0 for a run of one tab, 1..N for crawl -tabs N
	harvest      *capture.Capture
	pastHarvests []*capture.Capture
	pastStats    capture.Stats
	timedOut     bool
	world        runtime.ExecutionContextID // isolated world the resolver fetches from
	mainID       string                     // the tab's main frame

	csdSeen atomic.Int32 // Clear-Site-Data responses this tab's capture saw
	// keeperCSD: those since the keeper last checked the tab (NEW-C4-04).
	keeperCSD atomic.Int32
	// keeperLogin: the tab's requests sent back to the login page since the
	// keeper last checked it (a page's script, a fetch, a frame): the
	// session ended on the server while the page loaded, though its
	// document came while logged in (round 25N review).
	keeperLogin atomic.Int32
	sockSeen    atomic.Int32       // WebSockets this tab's capture saw open
	passedAt    int                // the guard's count of this tab's login writes when the run began
	idle        capture.IdleResult // the tab's last wait for quiet
	// pageScripts are the scripts the tab's capture stored since the
	// frontier last read them (takePageScripts); kept only on a frontier.
	pageMu      sync.Mutex
	pageScripts []string
	frontier    bool
	blocked     detect.Result // what the tab's last document was, at the end
	// fronted names the bot/WAF vendor in front of the tab's last document,
	// blocked or not, so a run can report it even on a healthy page.
	fronted   string
	frontedEv []string
}

// newRun makes the state of a run whose first tab is tab.
func newRun(cfg Config, tab context.Context, g *guard.Guard) *engine {
	r := &runState{cfg: cfg, guard: g, rootTab: tab, seen: map[string]bool{}, parsed: map[string]bool{}, resolved: map[string]resolve.Candidate{},
		mapsSeen: map[string]bool{}}
	r.privRules, _ = netsafe.ParseHostRules(cfg.Browser.HostRules)
	if cfg.Target != nil {
		r.privOff = netsafe.InternalTargetVia(context.Background(), cfg.Target.Host, r.privRules, nil, cfg.Browser.Proxy != "")
	}
	if w := browser.AttachProxyWarning(cfg.Browser); w != "" {
		slog.Warn(w)
		r.warn(w)
	}
	e := r.newTab(tab, 0)
	// Layer 2 off (no permission name accepted) is said in the run, not
	// only in the log.
	if w := browser.LNAWarning(tab); w != "" {
		slog.Warn(w)
		r.warn(w)
	}
	return e
}

// currentHarvest returns the tab's active capture safely across goroutines.
func (e *engine) currentHarvest() *capture.Capture {
	e.pageMu.Lock()
	defer e.pageMu.Unlock()
	return e.harvest
}

func (e *engine) tabCtx() context.Context {
	e.tabMu.RLock()
	defer e.tabMu.RUnlock()
	return e.tab
}

func (e *engine) mainFrameID() string {
	e.tabMu.RLock()
	defer e.tabMu.RUnlock()
	return e.mainID
}

func (e *engine) resetListenCtx(parent context.Context) context.Context {
	e.tabMu.Lock()
	oldStop := e.stopListen
	lctx, stop := context.WithCancel(e.tab)
	e.listenCtx, e.stopListen = lctx, stop
	e.tabMu.Unlock()
	if oldStop != nil {
		oldStop()
	}
	context.AfterFunc(parent, stop)
	return lctx
}

func (e *engine) tabListenCtx() context.Context {
	e.tabMu.RLock()
	defer e.tabMu.RUnlock()
	return e.listenCtx
}

func (e *engine) stopTabListeners() {
	e.tabMu.Lock()
	stop := e.stopListen
	e.stopListen = nil
	e.tabMu.Unlock()
	if stop != nil {
		stop()
	}
}

// privateHit is the penalty of layer 3: the host is failed by the guard
// from now on (when there is a guard) and not visited again; when JS can
// read the response the tab is also sent to about:blank at once.
func (r *runState) privateHit(tab context.Context, h capture.PrivateHit) {
	slog.Error("private address hit", "host", h.Host, "ip", h.IP, "url", h.URL, "origin", h.Origin, "same_origin", h.SameOrigin, "penalty", h.Penalty)
	r.banMu.Lock()
	if r.banned == nil {
		r.banned = map[string]bool{}
	}
	r.banned[h.Host] = true
	r.banMu.Unlock()
	if r.guard != nil {
		r.guard.BlockHost(h.Host)
	}
	if h.Penalty == capture.HitCloseTab {
		go func() {
			ctx, cancel := context.WithTimeout(tab, 5*time.Second)
			defer cancel()
			if _, err := chromedp.Call(ctx, page.Navigate, page.NavigateParams{URL: "about:blank"}); err != nil {
				slog.Debug("private address hit: leaving the page", "err", err)
			}
		}()
	}
}

// hostBanned: a host layer 3 gave up; its pages are not visited.
func (r *runState) hostBanned(host string) bool {
	r.banMu.Lock()
	defer r.banMu.Unlock()
	return r.banned[strings.ToLower(host)]
}

// newTab adds a tab to the run.
func (r *runState) newTab(tab context.Context, lane int) *engine {
	return &engine{runState: r, tab: tab, lane: lane}
}

// warn adds a warning to the run record.
func (r *runState) warn(msg string) {
	r.recMu.Lock()
	r.run.Warnings = append(r.run.Warnings, msg)
	r.recMu.Unlock()
}

// storeError counts a script the store did not keep, by why.
func (r *runState) storeError(reason string) {
	r.recMu.Lock()
	r.run.StoreErrors[reason]++
	r.recMu.Unlock()
}

// FlowStats goes into run.json: how the run's requests were traced to
// actions. A low causal share on a page that has actions means its tags
// were lost (a busy page drops old async stacks) or never set.
type FlowStats struct {
	Actions  int            `json:"actions"`
	Requests map[string]int `json:"requests"` // by how they were traced: causal, handler, window, background
}

// Run harvests cfg.Target. It returns ctx's error when interrupted (partial
// results are saved) and ErrBlocked when a bot challenge answered.
func Run(ctx context.Context, cfg Config) error {
	_, err := RunRecord(ctx, cfg)
	return err
}

// RunRecord is Run, with the run's record.
func RunRecord(ctx context.Context, cfg Config) (Record, error) {
	sess, g, err := openBrowser(ctx, cfg)
	if err != nil {
		return Record{}, err
	}
	defer closeBrowser(sess, g)
	if len(cfg.Cookies) > 0 {
		cctx, cancel := context.WithTimeout(sess.Tab, 15*time.Second)
		_, err := chromedp.CallBrowser(cctx, storage.SetCookies, storage.SetCookiesParams{Cookies: cfg.Cookies, BrowserContextID: browserContext(sess.Tab)})
		cancel()
		if err != nil {
			slog.Warn("the HTTP crawl's cookies were not put into Chrome", "err", err)
		}
	}
	if cfg.Depth > 0 || cfg.Explore || len(cfg.Seeds) > 0 {
		return runFrontier(ctx, cfg, sess.Tab, g)
	}
	return runPage(ctx, cfg, sess.Tab, g)
}

// openBrowser starts the browser and, when asked, the guard, before any tab
// navigates.
func openBrowser(ctx context.Context, cfg Config) (*browser.Session, *guard.Guard, error) {
	bo := cfg.Browser
	bo.NoPrediction = cfg.Guard
	sess, err := browser.New(ctx, bo)
	if err != nil {
		return nil, nil, err
	}
	// Layer 2 against a public page reaching the internal network: Chrome's
	// own Local Network Access, denied for every origin. It does not depend
	// on the guard (-guard off keeps it).
	var lnaCtx cdp.BrowserContextID
	if bo.Attach != "" && bo.TabID != "" {
		lnaCtx = browser.ContextOf(sess.Tab, bo.TabID)
	}
	sess.Tab = browser.DenyLocalNetwork(sess.Tab, lnaCtx)
	if bo.Attach != "" {
		// The user's Chrome keeps no permission of ours. With no origin
		// named, the denial held for the other tabs of the context too, in
		// the meantime.
		base := context.WithoutCancel(sess.Tab)
		var once sync.Once
		sess.LNAReset = func() {
			once.Do(func() {
				if err := browser.ResetLocalNetwork(base, lnaCtx); err != nil {
					slog.Debug("local network access: reset", "err", err)
				}
			})
		}
		// Every way out of the run resets: an error below closes the
		// session through Close, which resets first.
		closeSess := sess.Close
		sess.Close = func() {
			sess.LNAReset()
			closeSess()
		}
	}
	if !cfg.Guard {
		return sess, nil, nil
	}
	if bo.Attach != "" {
		slog.Warn("guard: speculative prefetch cannot be turned off in an attached browser; turn off \"Preload pages\" in its settings")
	}
	in := cfg.GuardScope
	if in == nil {
		in = cfg.InScope
	}
	if in == nil && cfg.Target != nil {
		if in, err = scope.New(cfg.Target.Hostname(), cfg.ScopeMode); err != nil {
			sess.Close()
			return nil, nil, err
		}
	}
	hostRules, err := netsafe.ParseHostRules(bo.HostRules)
	if err != nil {
		sess.Close()
		return nil, nil, err
	}
	g, err := guard.Start(sess.Tab, guard.Options{Rules: cfg.GuardRules, Attach: bo.Attach != "", InScope: in, HostRules: hostRules})
	if err != nil {
		sess.Close()
		return nil, nil, err
	}
	return sess, g, nil
}

// closeBrowser shuts down in the order that keeps held-back requests held:
// close our tab so nothing new starts, let the guard answer what is still
// paused, and only then drop the browser or the connection. Dropping the
// connection first would send every paused request on.
func closeBrowser(sess *browser.Session, g *guard.Guard) {
	sess.CloseTab()
	if g != nil {
		g.Stop()
	}
	if sess.LNAReset != nil {
		sess.LNAReset()
	}
	sess.Close()
}

// runPage harvests cfg.Target in the given tab and returns its run record.
func runPage(ctx context.Context, cfg Config, tab context.Context, g *guard.Guard) (Record, error) {
	if cfg.InScope == nil {
		in, err := scope.New(cfg.Target.Hostname(), cfg.ScopeMode)
		if err != nil {
			return Record{}, err
		}
		cfg.InScope = in
	}
	// The store's background flush lives as long as this page.
	pageCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	e := newRun(cfg, tab, g)
	e.shared = cfg.Tabs > 1
	if err := e.open(); err != nil {
		return Record{}, err
	}
	defer e.close()
	if k := cfg.sharedKeeper; k != nil && cfg.Login != nil {
		// A page of a host's batch: one keeper for the host, joined by each
		// page (C4). The run record gets a copy of its stats at the end.
		e.keeper = k
		e.noSharedWorkers = !k.join(e)
		defer k.leave(e)
		e.run.Session = k.statsCopy()
	} else if cfg.Login != nil {
		e.keeper = newKeeper([]*engine{e}, cfg.Login)
		e.run.Session = e.keeper.stats
	}
	if err := e.start(); err != nil {
		return e.run, err
	}
	e.handleDialogs(e.resetListenCtx(pageCtx), nil)
	if g != nil {
		e.guardAt = g.Stats()
		e.passedAt = g.PassedLogin(e.mainFrameID())
		if !e.shared {
			g.SetPage(e.harvest.Page)
		}
		if !cfg.AllowWebSocket {
			if _, err := guard.StubSockets(tab); err != nil {
				return e.run, fmt.Errorf("guard: %w", err)
			}
		}
	}
	if k := e.keeper; k != nil {
		if err := k.installFor(e); err != nil {
			return e.run, err
		}
		k.wait() // another page's tab is putting the session back
	}
	var ep int64
	if k := e.keeper; k != nil {
		ep = k.Epoch()
	}
	e.navigate()
	e.settle(ctx)
	if k := e.keeper; k != nil {
		if cause := k.check(e, e.harvest.MainDocument(), e.cfg.Target.String()); cause != "" {
			if !k.recover(ctx, e, ep, cause, e.cfg.Target.String()) {
				err := e.finish(ctx)
				if err == nil {
					err = ErrSessionLost
				}
				return e.run, err
			}
			e.navigate()
			e.settle(ctx)
		}
	}
	if cfg.Resolve {
		e.resolve(ctx)
	}
	err := e.finish(ctx)
	return e.run, err
}

func (e *engine) open() error {
	d, err := openOutDir(e.cfg.outDir(), store.Options{MaxBody: e.cfg.MaxBody})
	if err != nil {
		return err
	}
	st := d.st
	e.dir, e.st, e.scripts = d, st, map[string]bool{}
	started := time.Now().UTC()
	e.run = Record{
		Version: 2, RunID: newRunID(started), Tabs: e.cfg.Tabs, Target: e.cfg.Target.String(), Role: e.cfg.Role, Mode: "launch", Scope: scopeMode(e.cfg.ScopeMode),
		Config: &RunConfig{Depth: e.cfg.Depth, MaxPages: e.cfg.MaxPages, Explore: e.cfg.Explore, Resolve: e.cfg.Resolve,
			Guard: e.cfg.Guard, Debugger: !e.cfg.NoDebugger, Session: e.cfg.Login != nil,
			Record: string(e.cfg.Record), PageDwellMS: e.cfg.PageDwell.Milliseconds(), ExploreActs: e.cfg.ExploreActions,
			ExploreTime: int64(e.cfg.ExploreTime.Seconds()), ExploreTotal: int64(e.cfg.ExploreTotal.Seconds()), ResolveMax: e.cfg.ResolveMax,
			AllowWrite: e.cfg.GuardRules.AllowWrite, GuardAllow: reString(e.cfg.GuardRules.Allow)},
		Started: started, StoreErrors: map[string]int{},
	}
	if e.cfg.Browser.Attach != "" {
		e.run.Mode = "attach"
	}
	if e.cfg.Redact {
		e.redactor = traffic.NewRedactor()
	}
	if e.cfg.Record != "" && e.cfg.Record != traffic.Off {
		w, err := traffic.Create(st.Dir(), e.run.RunID, e.redactor)
		if err != nil {
			return fmt.Errorf("request log: %w", err)
		}
		e.traffic = w
		e.held = map[string]int{}
	}
	return nil
}

// record writes one request to the log, noting the held-back ones so that
// the guard's records are not written twice.
func (e *engine) record(en traffic.Entry) {
	en.Tab = e.lane // before it may be kept back as incomplete: it stays this tab's
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.traffic == nil {
		return // closed: the run failed before the capture stopped
	}
	if e.run.Mode == "watch" && !e.inScope(en.Page) && !e.inScope(en.URL) {
		return // the watched tab is on another site: none of ours to keep
	}
	// A request the guard failed (its made-up answer could not be given)
	// is on record here as failed; the guard's record of it is not written
	// again.
	if strings.HasPrefix(en.Outcome, "held_back:") || (e.guard != nil && strings.Contains(en.Outcome, "ERR_BLOCKED_BY_CLIENT")) {
		e.held["id "+en.CDPID]++
		e.held[en.Method+" "+en.URL]++
	}
	if en.Outcome == "incomplete" && e.guard != nil && en.CDPID != "" {
		e.incomplete = append(e.incomplete, en)
		return
	}
	e.traffic.Write(en)
	e.summary = append(e.summary, e.summarize(en))
}

// inScope reports whether a page or request URL belongs to the target.
// A page that is not http(s) yet (about:blank before -open's first load)
// counts as the target's.
func (e *engine) inScope(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return true
	}
	return e.cfg.InScope(u.Hostname())
}

// summarize keeps what grouping needs of a logged request, without its
// bodies: the values it carries and gives, bounded.
func (e *engine) summarize(en traffic.Entry) flow.Request {
	r := flow.Request{
		ID: e.traffic.Count(), Time: en.Time, End: en.Time.Add(time.Duration(en.DurationMS * float64(time.Millisecond))),
		Target: en.Target, Page: en.Page, Method: en.Method, URL: en.URL, ResourceType: en.ResourceType, Outcome: en.Outcome,
		// A navigation the guard answered left the page where it was.
		MainDocument: en.Target == "page" && en.ResourceType == "Document" && en.Frame == e.mainFrameID() && en.Outcome != "redirect" &&
			!strings.HasPrefix(en.Outcome, "held_back"),
		// A challenge's requests are the vendor's: no action of the site's.
		Internal: slices.Contains(en.Tags, "jsharvest") || slices.Contains(en.Tags, detect.TagChallenge), Lane: en.Tab,
		Uses: flow.RequestValues(en), Provides: flow.ResponseValues(en),
	}
	if in := en.Initiator; in != nil {
		r.Chain = in.Chain
		for _, f := range in.Stack {
			r.Stack = append(r.Stack, flow.Frame{URL: f.URL, Func: f.Func, Line: f.Line, Col: f.Col})
		}
	}
	return r
}

// buildFlows groups the run's requests by action.
func (e *engine) buildFlows() []flow.Flow {
	e.mu.Lock()
	events := slices.Clone(e.events)
	reqs := slices.Clone(e.summary)
	e.mu.Unlock()
	inScope := e.cfg.InScope
	fs := flow.Build(events, reqs, flow.Options{Run: e.run.RunID, ThirdParty: func(raw string) bool {
		u, err := url.Parse(raw)
		return err == nil && (u.Scheme == "http" || u.Scheme == "https") && !inScope(u.Hostname())
	}, DropEmpty: e.run.Mode != "watch"})
	stats := &FlowStats{Requests: map[string]int{}}
	for _, f := range fs {
		if f.Kind != "background" {
			stats.Actions++
		}
		for _, r := range f.Requests {
			how := r.How
			if how == "" {
				how = "background"
			}
			stats.Requests[how]++
		}
	}
	e.run.Flows = stats
	return fs
}

// writeFlows appends the run's flows to flows.jsonl, hiding credentials in
// what they quote of URLs and pages when redacting. It holds no values,
// only where they are.
func (e *engine) writeFlows(fs []flow.Flow, name string, appendTo bool) error {
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if appendTo {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	path := filepath.Join(e.st.Dir(), name)
	tmp := path
	if !appendTo {
		tmp = path + ".tmp"
	}
	f, err := os.OpenFile(tmp, flags, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, fl := range fs {
		if r := e.redactor; r != nil {
			fl.Label, fl.Page = r.Text(fl.Label), r.URL(fl.Page)
			if fl.Element != nil {
				el := *fl.Element
				el.Label, el.Href, el.Action = r.Text(el.Label), r.URL(el.Href), r.URL(el.Action)
				fl.Element = &el
			}
			eps := slices.Clone(fl.Endpoints)
			for i := range eps {
				eps[i].Samples = slices.Clone(eps[i].Samples)
				for j, p := range eps[i].Samples {
					eps[i].Samples[j] = r.URL(p)
				}
			}
			fl.Endpoints = eps
		}
		if err := enc.Encode(fl); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if !appendTo {
		return os.Rename(tmp, path)
	}
	return nil
}

// onEvent keeps an action the page reported.
func (e *engine) onEvent(ev flow.Event) {
	ev.Lane = e.lane
	e.mu.Lock()
	e.events = append(e.events, ev)
	if ev.Trusted {
		e.heard = time.Now().UTC()
	}
	e.mu.Unlock()
	if ev.Trusted && (ev.Type == "click" || ev.Type == "submit") {
		slog.Info("action", "type", ev.Type, "element", describeElement(ev.Element), "page", ev.URL)
	}
}

func describeElement(el *flow.Element) string {
	if el == nil {
		return ""
	}
	switch {
	case el.Label != "":
		return el.Tag + " " + strconv.Quote(el.Label)
	case el.ID != "":
		return el.Tag + "#" + el.ID
	}
	return el.Selector
}

// closeTraffic closes the request log, once; runPage calls it again on
// the way out of a failed run.
func (e *engine) closeTraffic() {
	e.mu.Lock()
	e.flushIncomplete()
	w := e.traffic
	e.traffic = nil
	e.mu.Unlock()
	if w == nil {
		return
	}
	e.run.Requests = w.Count()
	e.run.InternalRequests = w.Internal()
	e.run.PageRequests = e.run.Requests - e.run.InternalRequests
	if err := w.Close(); err != nil {
		slog.Error("write requests.jsonl", "err", err)
		e.warn("request log: " + err.Error())
	}
}

// close ends the run's use of its directory.
func (e *engine) close() {
	e.closeTraffic()
	if d := e.dir; d != nil {
		e.dir = nil
		d.release()
	}
}

// recordHeld writes the held-back requests that no session logged, such as
// those of a target the capture did not attach to.
func (e *engine) recordHeld(records []guard.Record, tabs []*engine) {
	if e.traffic == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.flushIncomplete()
	for _, r := range records {
		if i := slices.IndexFunc(e.incomplete, func(en traffic.Entry) bool { return r.NetworkID != "" && en.CDPID == r.NetworkID }); i >= 0 {
			// The capture stopped before its answer: the guard's.
			en := e.incomplete[i]
			e.incomplete = slices.Delete(e.incomplete, i, i+1)
			en.Outcome = "held_back:" + r.Reason
			if en.Body.Body == "" && r.Body != "" {
				en.Body = traffic.MakeBody([]byte(r.Body), e.cfg.RecordBody)
			}
			e.traffic.Write(en)
			e.summary = append(e.summary, e.summarize(en))
			continue
		}
		if r.NetworkID != "" && e.held["id "+r.NetworkID] > 0 {
			e.held["id "+r.NetworkID]--
			e.held[r.Method+" "+r.URL]--
			continue
		}
		if e.held[r.Method+" "+r.URL] > 0 {
			e.held[r.Method+" "+r.URL]--
			continue
		}
		en := traffic.Entry{
			Tab:  heldTab(r, tabs),
			Time: r.Time, Source: "guard", Page: r.Page, Frame: r.FrameID, CDPID: r.NetworkID,
			ResourceType: r.ResourceType, Method: r.Method, URL: r.URL, Headers: r.Headers,
			Body: traffic.MakeBody([]byte(r.Body), e.cfg.RecordBody), Outcome: "held_back:" + r.Reason,
		}
		e.traffic.Write(en)
		e.summary = append(e.summary, e.summarize(en))
	}
}

// heldTab is the lane of the tab a held request came from: the one whose
// capture saw it, or its frame, or the popup's opener; else the first tab,
// whose capture has the browser context's service and shared workers.
func heldTab(r guard.Record, tabs []*engine) int {
	for _, t := range tabs {
		if t.currentHarvest().Owns(r.NetworkID, r.FrameID, r.Opener) {
			return t.lane
		}
		for _, ph := range t.pastHarvests {
			if ph.Owns(r.NetworkID, r.FrameID, r.Opener) {
				return t.lane
			}
		}
	}
	return tabs[0].lane
}

// flushIncomplete logs the requests kept back as incomplete. Call it with
// e.mu held.
func (e *engine) flushIncomplete() {
	if e.traffic != nil {
		for _, en := range e.incomplete {
			e.traffic.Write(en)
			e.summary = append(e.summary, e.summarize(en))
		}
	}
	e.incomplete = nil
}

// start begins capturing on the tab, before the navigation, so that the
// first requests of the page are not missed.
func (e *engine) start() error {
	h, mainID, err := e.startOn(e.tabCtx())
	if err != nil {
		return err
	}
	e.tabMu.Lock()
	e.mainID = mainID
	e.tabMu.Unlock()
	e.pageMu.Lock()
	e.harvest = h
	e.pageMu.Unlock()
	return nil
}

func (e *engine) startOn(tab context.Context) (*capture.Capture, string, error) {
	opts := capture.Options{
		InScope:    e.cfg.InScope,
		NoDebugger: e.cfg.NoDebugger,
		SWWait:     e.cfg.SWWait,
		// The tabs of a crawl share one browser context: its service and
		// shared workers are the first tab's to capture.
		NoSharedWorkers: e.lane > 1 || e.noSharedWorkers,
	}
	opts.PrivateRules = e.privRules
	// remoteIPAddress is the proxy's when there is one; an internal target
	// has private answers by nature.
	opts.NoPrivateCheck = e.cfg.Browser.Proxy != "" || e.privOff
	opts.OnPrivateHit = func(h capture.PrivateHit) { e.privateHit(tab, h) }
	if e.traffic != nil {
		opts.Record = capture.RecordOptions{Mode: e.cfg.Record, MaxBody: e.cfg.RecordBody, Sink: e.record}
	}
	if g := e.guard; g != nil {
		opts.OnClearSiteData = func(id string) {
			e.csdSeen.Add(1)
			g.NoteClearSiteData(id)
		}
		opts.OnWebSocket = func(u string) {
			e.sockSeen.Add(1)
			g.NoteWebSocket(u)
		}
	}
	if k := e.keeper; k != nil {
		note := opts.OnClearSiteData
		opts.OnClearSiteData = func(id string) {
			if note != nil {
				note(id)
			}
			e.keeperCSD.Add(1)
		}
		opts.OnRedirect = func(from, to string) {
			if k.loginRedirect(from, to) {
				e.keeperLogin.Add(1)
			}
		}
		opts.OnAPIStatus = func(u string, status int, fromGuard bool) { k.apiStatus(e, u, status, fromGuard) }
	}
	if e.cfg.Actions && e.traffic != nil {
		opts.Actions, opts.NoTagger, opts.OnEvent = true, e.cfg.NoTagger, e.onEvent
	}
	var mainID string
	if t := chromedp.FromContext(tab).Target; t != nil {
		mainID = string(t.TargetID)
	}
	h, err := capture.Start(tab, opts, e.sink)
	if err != nil {
		return nil, "", err
	}
	h.SetPage(e.cfg.Target.String())
	if e.lane > 0 {
		// Only the tab opened last has the focus: a page without it may
		// not take explore's keys (internal/browser's TestTabsAtOnce).
		fctx, cancel := context.WithTimeout(tab, 10*time.Second)
		_, err := chromedp.Call(fctx, emulation.SetFocusEmulationEnabled, emulation.SetFocusEmulationEnabledParams{Enabled: true})
		cancel()
		if err != nil {
			h.Stop()
			return nil, "", fmt.Errorf("focus emulation: %w", err)
		}
	}
	return h, mainID, nil
}

// sink stores one captured script. Capture calls it from one goroutine at a
// time, so the run record needs no lock here.
func (e *engine) sink(s capture.Script) {
	if s.Kind == "inline" && len(s.Body) > 0 {
		refURL := s.Page
		if refURL == "" {
			refURL = s.URL
		}
		if u, err := url.Parse(refURL); err == nil && u.Scheme != "" && u.Host != "" {
			orig := strings.ToLower(u.Scheme + "://" + u.Host)
			var keep bool
			s.Body, keep = e.rscDeduper.Compact(orig, s.Body)
			if !keep {
				return
			}
		}
	}
	e.noteCaptured(&s)
	key, isNew, err := e.st.Put(toRecord(s))
	if err != nil {
		if errors.Is(err, store.ErrTooLarge) {
			e.storeError("too_large")
			slog.Warn("script over -max-body, not kept", "url", s.URL, "size", len(s.Body))
		} else {
			e.storeError("write")
			slog.Error("store script", "url", s.URL, "err", err)
		}
		return
	}
	e.noteScript(key, isNew)
	if s.SHA256 != "" {
		return
	}
	if isNew {
		slog.Info("script", "target", s.Target, "kind", s.Kind, "size", len(s.Body), "url", s.URL)
	} else {
		slog.Debug("script seen again", "target", s.Target, "url", s.URL)
	}
}

// noteScript counts a script toward this run's own: the store may be
// shared, so its size and what it touched are not this run's.
func (e *engine) noteScript(key string, isNew bool) {
	if key == "" {
		return
	}
	e.mu.Lock()
	e.scripts[key] = true
	if isNew {
		e.newScripts++
	}
	e.mu.Unlock()
	if e.frontier {
		e.pageMu.Lock()
		e.pageScripts = append(e.pageScripts, key)
		e.pageMu.Unlock()
	}
}

// takePageScripts returns the scripts the tab stored since the last call.
func (e *engine) takePageScripts() []string {
	e.pageMu.Lock()
	defer e.pageMu.Unlock()
	out := e.pageScripts
	e.pageScripts = nil
	return out
}

func (e *engine) navigate() {
	ctx, cancel := context.WithTimeout(e.tab, e.cfg.NavTimeout)
	err := chromedp.Do(ctx, chromedp.Navigate(e.cfg.Target.String()))
	cancel()
	if err != nil {
		// A slow load event is not fatal: the scripts that did load still count.
		slog.Warn("navigate", "err", err)
		e.warn("navigate: " + err.Error())
	}
}

// settle waits for the network to go quiet. Targets are still accepted
// while waiting, so that workers and frames that start late are not lost.
func (e *engine) settle(ctx context.Context) {
	e.idle = e.quiet(ctx)
	e.challengeGrace(ctx)
}

// challengeGrace gives a challenge page the time to pass on its own (CF-06):
// a JS challenge runs, posts its answer (the guard lets /cdn-cgi/ through)
// and reloads the page, which is then the site's. Only when the last main
// document is still a challenge after cfg.ChallengeWait is the page blocked.
func (e *engine) challengeGrace(ctx context.Context) {
	if e.harvest == nil {
		return
	}
	// Read with its title once the page is quiet, so that a block page
	// that only its title tells is judged before the resolver reads the
	// scripts (capture holds a suspect page's).
	doc := e.harvest.MainDocument()
	if e.cfg.ChallengeWait <= 0 || !detect.Check(doc).Blocked {
		return
	}
	slog.Info("the page is a challenge; waiting for it to pass on its own", "for", e.cfg.ChallengeWait, "url", doc.URL)
	deadline := time.Now().Add(e.cfg.ChallengeWait)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
		if d := e.harvest.MainDocument(); !detect.Check(d).Blocked {
			slog.Info("the challenge passed; the page is the site's", "url", d.URL)
			e.idle = e.quiet(ctx)
			return
		}
	}
}

// quiet waits for the tab's network to go quiet, as settle does, without
// taking it for the page's (the resolver's fetches).
func (e *engine) quiet(ctx context.Context) capture.IdleResult {
	res := e.harvest.WaitIdle(ctx, e.cfg.Idle, e.cfg.IdleMax, 2)
	if res.Reason == "max" {
		if len(res.Inflight) > 0 {
			slog.Warn("network never went quiet; stopped at -idle-max", "open", res.Inflight)
		} else {
			slog.Warn("requests kept starting; stopped at -idle-max")
		}
		e.warn("stopped at -idle-max")
	}
	return res
}

// finish ends a run of one tab: its tab's part, then the run's.
func (e *engine) finish(ctx context.Context) error {
	if k := e.keeper; k != nil {
		k.finalize(e)
		if k == e.cfg.sharedKeeper {
			e.run.Session = k.statsCopy()
		}
	}
	e.finishTab(ctx)
	return e.finishRun(ctx, []*engine{e})
}

// finishTab ends a tab's capture: what is left in CacheStorage, the bodies
// still being read, what its last document was.
func (e *engine) finishTab(ctx context.Context) {
	e.stopTabListeners()
	h := e.harvest
	// What service workers precached on their own schedule, or on an earlier
	// run with the same profile, is still in CacheStorage.
	if n := h.SweepCaches(ctx, h.Origins()); n > 0 {
		slog.Debug("read scripts from CacheStorage", "count", n)
	}
	// After CacheStorage, which a frozen page does not answer.
	e.freeze()
	drainCtx, drainCancel := context.WithTimeout(ctx, 10*time.Second)
	h.Drain(drainCtx)
	drainCancel()

	doc := h.MainDocument()
	e.blocked = detect.Check(doc)
	e.fronted, e.frontedEv = detect.Vendor(doc)
	if w := detect.Warning(doc); w != "" && !e.blocked.Blocked {
		slog.Warn(w)
		e.warn(w)
	}
	h.Stop()
}

// finishRun ends the run once its tabs are done (finishTab): the guard's
// records, the flows, the request log, the index and the catalog, and
// run.json.
func (r *runState) finishRun(ctx context.Context, tabs []*engine) error {
	stopped := time.Now()
	defer func() { slog.Debug("after the capture stopped", "took", time.Since(stopped)) }()
	e := tabs[0]              // the tab whose engine does the run's writing
	r.run.Blocked = e.blocked // a challenge in any tab blocks the run
	r.run.Fronted, r.run.FrontedBy = e.fronted, e.frontedEv
	for _, t := range tabs {
		if t.fronted != "" && r.run.Fronted == "" {
			r.run.Fronted, r.run.FrontedBy = t.fronted, t.frontedEv
		}
		if t.blocked.Blocked {
			r.run.Blocked = t.blocked
			break
		}
	}
	r.run.Idle = e.idle

	if r.guard != nil {
		var claim func(guard.Record) bool
		if r.shared {
			h := e.harvest
			claim = func(rec guard.Record) bool { return h.Owns(rec.NetworkID, rec.FrameID, rec.Opener) }
		}
		records := r.guard.TakeFor(claim, func(id string) any {
			for _, t := range tabs {
				if in := t.harvest.InitiatorOf(id); in != nil {
					return in
				}
				for _, ph := range t.pastHarvests {
					if in := ph.InitiatorOf(id); in != nil {
						return in
					}
				}
			}
			return nil
		})
		if r.shared {
			page := e.harvest.Page()
			for i := range records {
				if records[i].Page == "" {
					records[i].Page = page
				}
			}
		}
		e.recordHeld(records, tabs)
		e.writeHeld(records)
		gs := r.guard.Stats().Sub(r.guardAt)
		if r.shared {
			gs = e.ownGuardStats(gs, records)
		}
		r.run.Guard = &gs
		if gs.ClearSiteDataSeen > 0 {
			r.warn(fmt.Sprintf("guard: %d response(s) carried Clear-Site-Data, which interception cannot stop; the session may have been wiped", gs.ClearSiteDataSeen))
		}
		if gs.WebSocketsSeen > 0 {
			r.warn(fmt.Sprintf("guard: %d WebSocket(s) opened that it could not hold back", gs.WebSocketsSeen))
		}
	}

	if r.traffic != nil {
		fs := e.buildFlows()
		r.dir.mu.Lock()
		err := e.writeFlows(fs, "flows.jsonl", true)
		r.dir.mu.Unlock()
		if err != nil {
			// The last checkpoint, if any, is kept: it is all there is.
			slog.Error("write flows.jsonl", "err", err)
			r.warn("flows: " + err.Error())
		} else {
			os.Remove(filepath.Join(r.st.Dir(), results.PartialFlows))
		}
	}
	e.closeTraffic()
	if err := r.st.Flush(); err != nil {
		return fmt.Errorf("write index: %w", err)
	}
	e.writeEndpoints()
	var stats capture.Stats
	for _, t := range tabs {
		stats = addStats(stats, addStats(t.pastStats, t.harvest.Stats()))
	}
	run := &r.run
	run.Stats = stats
	r.mu.Lock()
	run.UniqueScripts, run.NewScripts = r.st.Len(), r.newScripts
	run.Scripts = slices.Sorted(maps.Keys(r.scripts))
	r.mu.Unlock()
	// If every script this run saw was a vendor challenge's (dropped by the
	// capture), the run in truth reached nothing but the challenge, even if
	// the last document's status looked healthy. This is a warning, not a
	// block on its own: a Turnstile widget on an ordinary login form can be
	// the only script on a page that is otherwise fine.
	if detect.AllChallenge(len(run.Scripts)+stats.Challenge, stats.Challenge) && !run.Blocked.Blocked {
		r.warn(fmt.Sprintf("every script seen (%d) was a bot-challenge script; the run may have seen only the challenge", stats.Challenge))
	}
	for reason, n := range run.StoreErrors {
		r.warn(fmt.Sprintf("%d scripts not stored: %s", n, reason))
	}
	run.Ended = time.Now().UTC()
	run.DurationMS = run.Ended.Sub(run.Started).Milliseconds()

	err := ctx.Err()
	switch {
	case err != nil:
		run.ExitCode = 130
	case stats.PrivateHitCount > 0 && !run.Blocked.Blocked:
		run.ExitCode = 1
		err = ErrPrivateAddress
		r.warn(fmt.Sprintf("private_address_hit: %d response(s) of public pages came from private addresses, first %s from %s", stats.PrivateHitCount,
			stats.PrivateAddressHit[0].URL, stats.PrivateAddressHit[0].IP))
		slog.Error(err.Error())
	case run.Blocked.Blocked:
		run.ExitCode = 3
		err = ErrBlocked
		slog.Warn("bot challenge detected", "vendor", run.Blocked.Vendor, "evidence", run.Blocked.Evidence,
			"remedy", "before a login, crawl -engine http (no browser; it falls back to the archives); after one, jsharvest login -role R in a visible browser (its User-Agent is reused) or -attach to your own Chrome; on an authorized engagement, the owner can whitelist your source IP")
	default:
		if run.Fronted != "" {
			slog.Info("fronted by a bot/WAF vendor", "vendor", run.Fronted, "evidence", run.FrontedBy)
		}
	}
	r.dir.mu.Lock()
	werr := writeRun(r.st.Dir(), *run)
	r.dir.mu.Unlock()
	if werr != nil {
		slog.Error("write run.json", "err", werr)
	}
	slog.Info("done", "unique_scripts", run.UniqueScripts, "new_this_run", run.NewScripts, "requests", run.Requests, "page_requests", run.PageRequests, "internal_requests", run.InternalRequests,
		"targets", stats.Targets, "attach_failed", stats.AttachFailed, "bodies_lost", stats.BodiesLost,
		"cdp_internal", stats.CDPInternal, "challenge_dropped", stats.Challenge)
	return err
}

// addStats sums two tabs' capture counts.
func addStats(a, b capture.Stats) capture.Stats {
	sum := func(x, y map[string]int) map[string]int {
		out := maps.Clone(x)
		if out == nil {
			out = map[string]int{}
		}
		for k, n := range y {
			out[k] += n
		}
		return out
	}
	return capture.Stats{Targets: sum(a.Targets, b.Targets), AttachFailed: sum(a.AttachFailed, b.AttachFailed),
		Scripts: a.Scripts + b.Scripts, BodiesLost: sum(a.BodiesLost, b.BodiesLost), CDPInternal: a.CDPInternal + b.CDPInternal,
		Challenge: a.Challenge + b.Challenge, LNADenied: a.LNADenied + b.LNADenied, LNAInsecure: a.LNAInsecure + b.LNAInsecure,
		LNASamples:        firstSamples(a.LNASamples, b.LNASamples),
		PrivateHitCount:   a.PrivateHitCount + b.PrivateHitCount,
		PrivateAddressHit: capHead(append(slices.Clone(a.PrivateAddressHit), b.PrivateAddressHit...), 20)}
}

// firstSamples joins two lists of sample URLs, the first few, once each.
func firstSamples(a, b []string) []string {
	out := slices.Clone(a)
	for _, u := range b {
		if len(out) >= 5 {
			break
		}
		if !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

func capHead[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// writeHeld adds the held-back records to blocked.jsonl and writes them as
// blocked.har.
func (e *engine) writeHeld(records []guard.Record) {
	if e.redactor != nil {
		records = guard.Redact(records, e.redactor)
	}
	e.dir.mu.Lock()
	defer e.dir.mu.Unlock()
	if err := guard.Append(e.st.Dir(), records); err != nil {
		slog.Error("write blocked.jsonl", "err", err)
	}
	if err := guard.WriteHAR(filepath.Join(e.st.Dir(), "blocked.har"), records); err != nil {
		slog.Error("write blocked.har", "err", err)
	}
}

// ownGuardStats is the guard's count for one of several tabs at once: what
// it held back of this tab's, and what this tab's capture saw. The other
// counts are the browser's, since the run began, and are left out
// (answer errors; held navigations, which explore's are, not a list's).
func (e *engine) ownGuardStats(all guard.Stats, records []guard.Record) guard.Stats {
	gs := guard.Stats{ByReason: map[string]int{}, TargetsGuarded: all.TargetsGuarded,
		ClearSiteDataSeen: int(e.csdSeen.Load()), WebSocketsSeen: int(e.sockSeen.Load()),
		PassedLogin: e.guard.PassedLogin(e.mainFrameID()) - e.passedAt}
	for _, r := range records {
		gs.Blocked++
		gs.ByReason[r.Reason]++
	}
	return gs
}

// writeEndpoints analyses the scripts not analysed yet and writes the
// catalog: what the code calls, merged with every run's requests.
func (e *engine) writeEndpoints() {
	started := time.Now()
	e.dir.mu.Lock()
	defer e.dir.mu.Unlock()
	eps, scripts, st, err := endpoints.CatalogScriptsWithStats(e.st.Dir(), e.cfg.InScope, true)
	if err == nil {
		if r := e.redactor; r != nil {
			for i := range eps {
				if o := eps[i].Observed; o != nil {
					for j, p := range o.Samples {
						o.Samples[j] = r.URL(p)
					}
				}
			}
		}
		err = endpoints.Write(e.st.Dir(), eps)
	}
	if err != nil {
		slog.Error("write endpoints.jsonl", "err", err)
		e.warn("endpoints: " + err.Error())
		return
	}
	e.run.StaticAnalysis = &st
	e.run.Endpoints = map[string]int{}
	for _, ep := range eps {
		if !ep.ThirdParty {
			e.run.Endpoints[ep.Status]++
		}
	}
	slog.Info("endpoints", "in_code_only", e.run.Endpoints[endpoints.Static], "both", e.run.Endpoints[endpoints.Both],
		"in_traffic_only", e.run.Endpoints[endpoints.ObservedOnly], "bundle_parse_errors", st.BundleParseErrors,
		"bundle_ast_lowered", st.BundleASTLowered, "took", time.Since(started).Round(time.Millisecond))
	if st.BundleParseErrors > 0 {
		slog.Warn("bundle parse fallback to loose extraction", "count", st.BundleParseErrors, "bundles", strings.Join(st.FailedBundles, ","))
		wmsg := fmt.Sprintf("endpoints: %d bundle(s) failed AST parse and fell back to loose extraction", st.BundleParseErrors)
		if !slices.Contains(e.run.Warnings, wmsg) {
			e.warn(wmsg)
		}
	}
	var redact func(name, value string) string
	if r := e.redactor; r != nil {
		redact = func(name, value string) string { return r.Headers(map[string]string{name: value})[name] }
	}
	in, err := endpoints.SaveIntelFromScripts(e.st.Dir(), scripts, e.cfg.InScope, redact)
	scripts = nil
	if err != nil {
		e.warn("intel: " + err.Error())
	} else if len(in.Headers) > 0 || len(in.Cloud) > 0 {
		// The names only: the values (a client_secret) stay in the file.
		slog.Info("the code also names", "client_headers", strings.Join(in.Names(), ","), "bases", strings.Join(in.Bases, ","),
			"cloud_urls", len(in.Cloud), "file", filepath.Join(e.st.Dir(), endpoints.IntelFile))
	}
	if err == nil && len(in.SecurityNotes) > 0 {
		var kinds []string
		for _, n := range in.SecurityNotes {
			kinds = append(kinds, n.Kind)
		}
		slog.Info("the answers show configuration worth a look", "security_notes", strings.Join(kinds, ","), "file", filepath.Join(e.st.Dir(), endpoints.IntelFile))
	}
}

// analyzeNew analyses, in the background, the scripts a watch stored since
// the last time, so that jsharvest mcp can tell what the code calls while
// the watch goes on. One at a time.
func (e *engine) analyzeNew() {
	n := e.st.Len()
	if n == e.analyzed || !e.analyzing.CompareAndSwap(false, true) {
		return
	}
	e.analyzed = n
	go func() {
		defer e.analyzing.Store(false)
		if err := e.st.Flush(); err != nil {
			slog.Debug("flush index", "err", err)
			return
		}
		if _, err := endpoints.Analyze(e.st.Dir(), 1); err != nil {
			slog.Debug("analyze scripts", "err", err)
		}
	}()
}

// freeze stops the page's timers before the capture stops, so that it
// starts no request the log would miss while the browser closes; those
// under way still end and are logged. Only a tab of the tool's own: a
// watched or attached tab is the user's, and goes on.
func (e *engine) freeze() {
	if e.cfg.Browser.Attach != "" || e.run.Mode == "watch" {
		return
	}
	ctx, cancel := context.WithTimeout(e.tab, 5*time.Second)
	defer cancel()
	if _, err := chromedp.Call(ctx, page.SetWebLifecycleState, page.SetWebLifecycleStateParams{State: page.SetWebLifecycleStateStateFrozen}); err != nil {
		slog.Debug("freeze the page", "err", err)
		return
	}
	slog.Debug("page frozen")
}

func writeRun(dir string, run Record) error {
	b, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "run.json"), append(b, '\n')); err != nil {
		return err
	}
	line, err := json.Marshal(run)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "runs.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func toRecord(s capture.Script) store.Record {
	r := store.Record{
		Body: s.Body, SHA256: s.SHA256, URL: s.URL, Kind: s.Kind, Via: s.Via, Target: s.Target,
		Page: s.Page, MIME: s.MIME, Headers: s.Headers, SourceMapURL: s.SourceMapURL,
		IsModule: s.IsModule, Tags: s.Tags, Source: "live",
	}
	if r.SourceMapURL == "" && s.Headers != nil {
		r.SourceMapURL = s.Headers["sourcemap"]
		if r.SourceMapURL == "" {
			r.SourceMapURL = s.Headers["x-sourcemap"]
		}
	}
	if s.Initiator != nil {
		r.Initiator = &store.Initiator{Type: s.Initiator.Type, URL: s.Initiator.URL, Line: s.Initiator.Line, Col: s.Initiator.Col}
	}
	return r
}
