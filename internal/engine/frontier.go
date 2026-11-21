package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/htmlscan"
	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/resolve"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/store"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Page is one line of pages.jsonl: a page the crawl visited, or a URL it
// found and did not visit, with why.
type Page struct {
	Run        string    `json:"run"`
	URL        string    `json:"url"`
	Visited    bool      `json:"visited"`
	FinalURL   string    `json:"final_url,omitempty"` // where the page ended, after redirects and its own navigation
	Status     int64     `json:"status,omitempty"`
	Depth      int       `json:"depth"`
	From       string    `json:"from,omitempty"`
	How        string    `json:"how"`
	Method     string    `json:"method,omitempty"`
	Reason     string    `json:"reason,omitempty"` // why not visited
	Discovered int       `json:"discovered,omitempty"`
	Started    time.Time `json:"started,omitzero"` // when the crawl began to load it
	TookMS     int64     `json:"took_ms,omitempty"`
	Error      string    `json:"error,omitempty"`
	Explored   int       `json:"explored,omitempty"` // actions explore took on it
	Tab        int       `json:"tab,omitempty"`      // the tab that visited it (crawl -tabs)
	// DuplicateOf: the page landed where another tab's page had (crawl
	// -tabs), and was not read again.
	DuplicateOf string `json:"duplicate_of,omitempty"`
}

// FrontierStats goes into run.json.
type FrontierStats struct {
	Visited int            `json:"visited"`
	Queued  int            `json:"queued"` // left in the queue when the crawl stopped
	Listed  map[string]int `json:"listed"` // found and not visited, by reason
	Stopped string         `json:"stopped"`
}

// runFrontier crawls from cfg.Target: it visits a page, takes the URLs it
// finds, and visits those, breadth first, to cfg.Depth links away. One tab,
// or cfg.Tabs tabs of one browser context at once, each with its capture,
// in one run. Every page load is an action of the flows.
func runFrontier(ctx context.Context, cfg Config, tab context.Context, g *guard.Guard) (Record, error) {
	if cfg.InScope == nil {
		in, err := scope.New(cfg.Target.Hostname(), cfg.ScopeMode)
		if err != nil {
			return Record{}, err
		}
		cfg.InScope = in
	}
	if cfg.PageScope == nil {
		ps, err := scope.PageScope(cfg.Target.Hostname(), cfg.ScopeMode, cfg.PageScopeMode)
		if err != nil {
			return Record{}, err
		}
		cfg.PageScope = ps
	}
	n := max(1, cfg.Tabs)
	pageCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	e := newRun(cfg, tab, g)
	if err := e.open(); err != nil {
		return Record{}, err
	}
	defer e.close()
	defer func() {
		e.mu.Lock()
		closes := e.extraCloses
		e.mu.Unlock()
		for _, fn := range closes {
			fn()
		}
	}()
	tabs := []*engine{e}
	if n > 1 {
		e.lane = 1
		for lane := 2; lane <= n; lane++ {
			// A tab of the same browser context: one session, as a person's
			// tabs are.
			tctx, closeTab := chromedp.NewContext(tab)
			defer closeTab()
			if err := chromedp.Do(tctx); err != nil {
				return e.run, fmt.Errorf("tab %d: %w", lane, err)
			}
			if g != nil {
				// In attach mode the guard passes the tabs it does not
				// know for the user's; layer 1 judges the tool's own.
				id := tabTarget(tctx)
				g.AddTab(id)
				defer g.RemoveTab(id)
			}
			nt := e.newTab(tctx, lane)
			nt.closeTab = closeTab
			tabs = append(tabs, nt)
		}
	}
	if cfg.Login != nil {
		e.keeper = newKeeper(tabs, cfg.Login)
		e.run.Session = e.keeper.stats
	}
	for _, t := range tabs {
		t.frontier = true
		if err := t.start(); err != nil {
			return e.run, err
		}
		t.resetListenCtx(pageCtx)
	}
	if g != nil {
		e.guardAt = g.Stats()
		if n == 1 {
			g.SetPage(func() string { return e.currentHarvest().Page() })
		} else {
			g.SetPageOf(func(frame, networkID string) string {
				for _, t := range tabs {
					h := t.currentHarvest()
					if h.Owns(networkID, frame, "") {
						return h.Page()
					}
				}
				return tabs[0].currentHarvest().Page() // a service worker's: the first tab captures it
			})
		}
		if cfg.Guard && !cfg.AllowWebSocket {
			for _, t := range tabs {
				if _, err := guard.StubSockets(t.tab); err != nil {
					return e.run, fmt.Errorf("guard: %w", err)
				}
			}
		}
	}
	if k := e.keeper; k != nil {
		if err := k.install(); err != nil {
			return e.run, err
		}
	}
	// An explorer for each tab, sharing the controls used and the run's
	// budget; its counts are its own, summed at the end (NEW-C5-03).
	xs := make([]*explorer, len(tabs))
	if cfg.Explore {
		if !cfg.Guard || g == nil || e.traffic == nil || !cfg.Actions {
			return e.run, fmt.Errorf("explore needs the guard, the recorder and actions")
		}
		sh, err := newExploreShared()
		if err != nil {
			return e.run, fmt.Errorf("explore: %w", err)
		}
		defer sh.close()
		for i, t := range tabs {
			lctx := t.tabListenCtx()
			x, err := newExplorer(lctx, t, sh)
			if err != nil {
				return e.run, fmt.Errorf("explore: %w", err)
			}
			xs[i] = x
			t.handleDialogs(lctx, func() { x.dialogs.Add(1); x.stats.Dialogs++ })
		}
		e.run.Explore = xs[0].stats
	} else {
		for _, t := range tabs {
			t.handleDialogs(t.tabListenCtx(), nil)
		}
	}
	rules := cfg.GuardRules
	pageScope := cfg.InScope
	if cfg.PageScope != nil {
		pageScope = func(h string) bool { return cfg.InScope(h) && cfg.PageScope(h) }
	}
	q := frontier.NewQueue(frontier.Options{InScope: pageScope, MaxDepth: cfg.Depth, MaxPages: cfg.MaxPages,
		Destructive: func(u string) bool {
			return rules.Classify(guard.Request{Method: "GET", URL: u}).Action == guard.Fake
		}})
	q.Add(frontier.Found{URL: cfg.Target.String(), How: frontier.Seed, Visit: true}, 0, "")
	for _, s := range cfg.Seeds {
		q.Add(frontier.Found{URL: s, How: frontier.Seed, Visit: true}, 0, "")
	}

	pages, err := traffic.AppendOpen(filepath.Join(e.st.Dir(), "pages.jsonl"))
	if err != nil {
		return e.run, err
	}
	defer pages.Close()
	c := &crawl{
		runID:          e.run.RunID,
		specProbe:      cfg.SpecProbe && !cfg.NoSpecProbe,
		probeOffscope:  cfg.ProbeOffscope,
		hasProxy:       cfg.Browser.Proxy != "",
		seedOrigin:     strings.ToLower(cfg.Target.Scheme + "://" + cfg.Target.Host),
		inScope:        cfg.InScope,
		pageScope:      pageScope,
		q:              q,
		st:             e.st,
		enc:            json.NewEncoder(pages),
		stats:          &FrontierStats{Listed: map[string]int{}},
		limit:          newLimiter(cfg.PageRate),
		visited:        map[string]string{},
		blamed:         map[string]bool{},
		scripts:        map[string]bool{},
		thirdPartyDone: map[string]bool{},
		skel:           frontier.NewSkeleton(),
		seenScriptSHA:  map[string]bool{},
		queuedBySkel:   map[string]int{},
		deferredBySkel: map[string][]deferredFound{},
		deferredSeen:   map[string]bool{},
		dedupe:         n > 1,
		rscDeduper:     &e.rscDeduper,
	}
	c.cond = sync.NewCond(&c.mu)
	var wg sync.WaitGroup
	for i, t := range tabs {
		popups := t.watchPopups(t.tabListenCtx())
		tx := xs[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.crawlPages(ctx, pageCtx, c, tx, popups)
		}()
	}
	wg.Wait()
	if cfg.Explore && n > 1 {
		var all []*ExploreStats
		for _, x := range xs {
			all = append(all, x.stats)
		}
		e.run.Explore = addExploreStats(all)
	}
	c.mu.Lock()
	c.commit()
	extraQueued := c.finalizeDeferredLocked()
	if c.stopped == "" && (q.Len() > 0 || extraQueued > 0) {
		c.stopped = "tab-failed"
	}
	stats := c.stats
	stats.Stopped = c.stopped
	c.mu.Unlock()

	if c.specProbe && stats.Stopped == "" && ctx.Err() == nil && len(tabs) > 0 {
		refPage := tabs[0].harvest.Page()
		if refPage == "" {
			refPage = cfg.Target.String()
		}
		for _, o := range c.takeAPIOrigins() {
			if ctx.Err() != nil {
				break
			}
			tabs[0].specFiles(ctx, c, o, refPage)
		}
		if ctx.Err() == nil {
			tabs[0].specFilesPhase2(ctx, c, refPage)
		}
	}
	c.closeSpecClient()

	stats.Queued = q.Len() + extraQueued
	q.SortListed()
	for _, l := range q.Listed {
		stats.Listed[l.Reason]++
		c.enc.Encode(Page{Run: e.run.RunID, URL: l.URL, How: l.How, Method: l.Method, From: l.From, Reason: l.Reason})
	}
	for reason, cnt := range q.ExtraListed {
		stats.Listed[reason] += cnt
	}
	if n := q.Dropped(); n > 0 {
		e.warn(fmt.Sprintf("frontier: %d pages over -max-pages not visited", n))
	}
	e.run.Frontier = stats
	slog.Info("frontier", "visited", stats.Visited, "stopped", stats.Stopped, "left", stats.Queued, "listed", stats.Listed)
	if k := e.keeper; k != nil {
		k.finalize(e) // the tabs still hold their pages
	}
	var fwg sync.WaitGroup
	for _, t := range tabs {
		fwg.Add(1)
		go func() {
			defer fwg.Done()
			t.finishTab(ctx)
		}()
	}
	fwg.Wait()
	err = e.finishRun(ctx, tabs)
	switch {
	case err != nil:
	case stats.Stopped == "blocked":
		err = ErrBlocked
	case stats.Stopped == "session-lost":
		err = ErrSessionLost
	}
	return e.run, err
}

// crawl is what the tabs of a frontier crawl share. The queue is walked a
// level (a depth) at a time: no tab takes a page of the next level while
// one of this level is being visited. What a page found, and the URLs it
// loaded, are kept until its level is done, then given to the queue in the
// order the pages were taken: the queue sees what it sees with one tab, so
// the pages visited and those listed are the same with N
// (docs/gd5-parallel-design.md 8.3, 8.14).
const (
	cdpDynamicWindow = 12
	maxCDPDeferred   = 50000
)

type deferredFound struct {
	f     frontier.Found
	depth int
	from  string
}

type crawl struct {
	mu      sync.Mutex
	cond    *sync.Cond
	runID   string
	q       *frontier.Queue
	level   int
	busy    int // pages taken and not done
	taken   int
	done    []donePage
	stopped string
	stats   *FrontierStats
	enc     *json.Encoder // pages.jsonl
	limit   *limiter
	recent  []bool // the last pages' documents: answered 429 or 503
	// ruled: pages in a row whose document was a vendor's block that is
	// not a challenge (a WAF rule on one path, by its title): three stop
	// the crawl, as the HTTP engine's (MAX-02; round 25J).
	ruled  int
	blamed map[string]bool // pages after which the session was lost once: visited again, alone
	// solo: a page visited again after a lost session is visited alone,
	// no other tab at work: with others at once, which page ended the
	// session cannot be told (NEW-C4-02).
	solo      bool
	soloOrder int
	known     bool // robots.txt and the sitemaps read
	// specProbe: the target's origin and API hosts are asked for their
	// API's description (crawl -probe).
	specProbe     bool
	probeOffscope string
	hasProxy      bool
	seedOrigin    string
	inScope    func(string) bool
	pageScope  func(string) bool
	// apiOrigins: the target's API hosts the scripts name, each asked for
	// its API's description once, by the next page of any tab (PIP-03).
	apiSeen    map[string]bool
	apiPending []string
	specCtx    frontier.SpecCollector
	specMu     sync.Mutex
	specPol    *resolve.Policy
	specTr     *http.Transport
	specHTTP   *http.Client
	// dedupe: with several tabs, two pages that land on one URL are one
	// page; the later is named its duplicate (visited: page -> first page).
	dedupe  bool
	visited map[string]string

	st             *store.Store
	scripts        map[string]bool // read for URLs already
	thirdPartyDone map[string]bool // third-party scripts already scanned by noteAPIOrigins
	readAnyYet     bool            // the first page to read scripts reads every one in the store

	skel           *frontier.Skeleton
	seenScriptSHA  map[string]bool
	queuedBySkel   map[string]int
	deferredBySkel map[string][]deferredFound
	deferredKeys   []string
	deferredSeen   map[string]bool
	totalDeferred  int
	rscDeduper     *htmlscan.RSCDeduper
}

func isFrontierSpecURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && frontier.SpecFile(u.Path)
}

func (c *crawl) decSkelQueuedLocked(rawURL string) {
	if c.skel == nil || isFrontierSpecURL(rawURL) {
		return
	}
	if k, dyn := c.skel.Key(rawURL, false); dyn && k != "" && c.queuedBySkel[k] > 0 {
		c.queuedBySkel[k]--
	}
}

func (c *crawl) incSkelQueuedLocked(rawURL string) {
	if c.skel == nil || isFrontierSpecURL(rawURL) {
		return
	}
	if k, dyn := c.skel.Key(rawURL, false); dyn && k != "" {
		c.queuedBySkel[k]++
	}
}

// donePage is a page visited, waiting for its level to be done.
type donePage struct {
	order int
	it    frontier.Item
	p     Page
	skip  bool     // taken, not visited (interrupted): nothing to write
	marks []string // URLs it loaded without them being queued
	found []frontier.Found
	// The URLs of the scripts its tab stored since the tab's page before
	// are read at the level's end, in the pages' order, as one tab reads
	// them after each page (another tab's scripts are not this page's).
	readScripts bool
	scripts     []string
	after       []frontier.Found // what it found after its scripts: popups
}

// next takes a page to visit, waiting while the level's pages are being
// visited by other tabs. It reports false when the crawl is over.
func (c *crawl) next(ctx context.Context) (frontier.Item, int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if c.stopped == "" && ctx.Err() != nil {
			c.stopped = "interrupted"
		}
		if c.stopped != "" {
			c.cond.Broadcast()
			return frontier.Item{}, 0, false
		}
		if c.solo {
			c.cond.Wait()
			continue
		}
		if it, ok := c.q.Peek(); ok && it.Depth <= c.level {
			if it.How != frontier.Seed && c.skel != nil && c.skel.ShouldSkip(it.URL) {
				c.q.Next()
				c.q.Refund()
				c.decSkelQueuedLocked(it.URL)
				c.stats.Listed[frontier.TemplateSaturated]++
				c.enc.Encode(Page{Run: c.runID, URL: it.URL, Depth: it.Depth, From: it.From, How: it.How, Reason: frontier.TemplateSaturated})
				continue
			}
			if c.blamed[it.URL] {
				if c.busy > 0 {
					c.cond.Wait()
					continue
				}
				c.solo, c.soloOrder = true, c.taken+1
			}
			c.q.Next()
			c.decSkelQueuedLocked(it.URL)
			c.busy++
			c.taken++
			if n, ok := frontier.Normalize(it.URL); ok {
				if _, seen := c.visited[n]; !seen {
					c.visited[n] = it.URL
				}
			}
			return it, c.taken, true
		}
		if c.busy > 0 {
			c.cond.Wait()
			continue
		}
		c.commit()
		it, ok := c.q.Peek()
		if !ok {
			c.stopped = "done"
			c.cond.Broadcast()
			return frontier.Item{}, 0, false
		}
		c.level = it.Depth
	}
}

// finish hands back a page taken: done, to visit again (retry), or the
// crawl to stop.
func (c *crawl) finish(d donePage, stop string, retry bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if retry {
		c.q.Retry(d.it)
		c.incSkelQueuedLocked(d.it.URL)
	}
	c.done = append(c.done, d)
	if c.solo && d.order == c.soloOrder {
		c.solo = false
	}
	if stop != "" && c.stopped == "" {
		c.stopped = stop
	}
	c.busy--
	c.cond.Broadcast()
}

func (c *crawl) admitFoundLocked(f frontier.Found, depth int, from string) bool {
	if pre := c.q.Precheck(f, depth); pre != "" {
		c.q.Add(f, depth, from)
		return false
	}
	if c.skel != nil && !isFrontierSpecURL(f.URL) {
		if skelKey, dynamic := c.skel.Key(f.URL, true); dynamic && skelKey != "" {
			if c.skel.IsSaturated(skelKey) {
				c.q.ListAs(f, from, frontier.TemplateSaturated)
				return false
			}
			if c.queuedBySkel[skelKey] >= cdpDynamicWindow {
				if norm, ok := frontier.Normalize(f.URL); ok && !c.deferredSeen[norm] {
					if c.totalDeferred >= maxCDPDeferred {
						c.q.ListAs(f, from, frontier.Limit)
						return false
					}
					c.deferredSeen[norm] = true
					if len(c.deferredBySkel[skelKey]) == 0 {
						c.deferredKeys = append(c.deferredKeys, skelKey)
					}
					c.deferredBySkel[skelKey] = append(c.deferredBySkel[skelKey], deferredFound{f: f, depth: depth, from: from})
					c.totalDeferred++
				}
				return false
			}
			if c.q.Add(f, depth, from) == "" {
				c.queuedBySkel[skelKey]++
				return true
			}
			return false
		}
	}
	return c.q.Add(f, depth, from) == ""
}

func (c *crawl) flushDeferredLocked() {
	if len(c.deferredKeys) == 0 {
		return
	}
	keptKeys := c.deferredKeys[:0]
	for _, k := range c.deferredKeys {
		list := c.deferredBySkel[k]
		if len(list) == 0 {
			delete(c.deferredBySkel, k)
			continue
		}
		if c.skel != nil && c.skel.IsSaturated(k) {
			for _, df := range list {
				if norm, ok := frontier.Normalize(df.f.URL); ok {
					delete(c.deferredSeen, norm)
				}
				if c.totalDeferred > 0 {
					c.totalDeferred--
				}
				c.q.ListAs(df.f, df.from, frontier.TemplateSaturated)
			}
			delete(c.deferredBySkel, k)
			continue
		}
		for len(list) > 0 && c.queuedBySkel[k] < cdpDynamicWindow {
			df := list[0]
			list = list[1:]
			if norm, ok := frontier.Normalize(df.f.URL); ok {
				delete(c.deferredSeen, norm)
			}
			if c.totalDeferred > 0 {
				c.totalDeferred--
			}
			if c.q.Add(df.f, df.depth, df.from) == "" {
				c.queuedBySkel[k]++
			}
		}
		if len(list) > 0 {
			c.deferredBySkel[k] = list
			keptKeys = append(keptKeys, k)
		} else {
			delete(c.deferredBySkel, k)
		}
	}
	c.deferredKeys = keptKeys
}

func (c *crawl) finalizeDeferredLocked() int {
	if len(c.deferredKeys) == 0 {
		return 0
	}
	extraQueued := 0
	hitLimit := c.q.Dropped() > 0
	for _, k := range c.deferredKeys {
		list := c.deferredBySkel[k]
		if len(list) == 0 {
			continue
		}
		if c.skel != nil && c.skel.IsSaturated(k) {
			for _, df := range list {
				c.q.ListAs(df.f, df.from, frontier.TemplateSaturated)
			}
			continue
		}
		if hitLimit {
			for _, df := range list {
				c.q.Add(df.f, df.depth, df.from)
			}
			continue
		}
		extraQueued += len(list)
	}
	c.deferredBySkel = map[string][]deferredFound{}
	c.deferredKeys = nil
	c.deferredSeen = map[string]bool{}
	c.totalDeferred = 0
	return extraQueued
}

// commit gives the queue what the level's pages found, in the order they
// were taken, and writes their lines. Call it with c.mu held.
func (c *crawl) commit() {
	sort.Slice(c.done, func(i, j int) bool { return c.done[i].order < c.done[j].order })
	var ss []endpoints.Script
	if slices.ContainsFunc(c.done, func(d donePage) bool { return d.readScripts }) {
		if err := c.st.Flush(); err != nil {
			slog.Debug("flush index", "err", err)
		}
		var skip map[string]bool
		if c.readAnyYet {
			skip = map[string]bool{}
			for sha := range c.seenScriptSHA {
				if c.scripts[sha] || c.thirdPartyDone[sha] {
					skip[sha] = true
				}
			}
		}
		var err error
		if ss, err = endpoints.AnalyzeExcept(c.st.Dir(), 0, skip); err != nil {
			slog.Debug("analyze scripts", "err", err)
		}
	}
	for _, d := range c.done {
		if d.skip {
			continue
		}
		for _, u := range d.marks {
			c.q.Visited(u)
		}
		found := d.found
		var jsFound []frontier.Found
		var pageOrigins []string
		var newScripts []string
		var inlineSigs [][32]byte
		if d.readScripts {
			var mine map[string]bool
			wasReadAny := c.readAnyYet
			if c.readAnyYet {
				mine = map[string]bool{}
				for _, sha := range d.scripts {
					mine[sha] = true
				}
			}
			c.readAnyYet = true
			if !wasReadAny && c.dedupe && c.rscDeduper != nil {
				c.rscDeduper.Freeze()
			}
			for _, s := range ss {
				if (mine != nil && !mine[s.SHA256]) || c.seenScriptSHA[s.SHA256] {
					continue
				}
				c.seenScriptSHA[s.SHA256] = true
				if s.Inline {
					if sig, ok := endpoints.SemanticAPISig(s.Result); ok {
						inlineSigs = append(inlineSigs, sig)
					}
				} else if !s.ThirdParty || !frontier.IsTrackerURL(s.URLs...) {
					newScripts = append(newScripts, s.SHA256)
				}
			}
			pageOrigins = c.noteAPIOrigins(ss, mine)
			jsFound = scriptURLs(ss, d.p.FinalURL, c.scripts, mine)
			found = append(found, jsFound...)
		}
		if c.skel != nil && d.p.Error == "" && d.p.DuplicateOf == "" && d.p.Status > 0 {
			obsURL := d.p.FinalURL
			if obsURL == "" {
				obsURL = d.it.URL
			}
			jsURLs := make([]string, 0, len(jsFound))
			for _, jf := range jsFound {
				jsURLs = append(jsURLs, jf.URL)
			}
			gained := c.skel.Observe(frontier.Observation{
				PageURL:      obsURL,
				Status:       int(d.p.Status),
				NewScripts:   newScripts,
				InlineSigs:   inlineSigs,
				JSFoundURLs:  jsURLs,
				JSAPIOrigins: pageOrigins,
				Links:        d.found,
				InScope:      c.pageScope,
				ExtraGain:    d.p.Explored > 0,
			})
			c.q.Feedback(obsURL, gained)
		}
		found = append(found, d.after...)
		for _, f := range found {
			if c.admitFoundLocked(f, d.it.Depth+1, d.p.FinalURL) {
				d.p.Discovered++
			}
		}
		c.enc.Encode(d.p)
		c.stats.Visited++
		if len(d.found) > 0 || d.p.Error == "" {
			slog.Info("page", "url", logURL(d.it.URL), "status", d.p.Status, "depth", d.it.Depth, "new", d.p.Discovered, "queued", c.q.Len(), "tab", d.p.Tab)
		}
	}
	c.done = nil
	c.flushDeferredLocked()
}

// ruledPage counts the pages in a row, in any tab, whose document a WAF
// rule blocked (true), or ends the run (false); it returns the count.
func (c *crawl) ruledPage(blocked bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !blocked {
		c.ruled = 0
		return 0
	}
	c.ruled++
	return c.ruled
}

// rateLimited notes a page's status: true when the last three pages, in
// any tab, were answered 429 or 503.
func (c *crawl) rateLimited(status int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if status != 429 && status != 503 {
		c.recent = c.recent[:0]
		return false
	}
	c.recent = append(c.recent, true)
	return len(c.recent) >= 3
}

// blame reports whether a page lost the session before (and notes it).
func (c *crawl) blame(u string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	was := c.blamed[u]
	c.blamed[u] = true
	return was
}

// takeKnown reports whether this page reads robots.txt and the sitemaps:
// the first one that gets that far.
// noteAPIOrigins keeps the API hosts the scripts not read yet name.
// Under c.mu (commit).
func (c *crawl) noteAPIOrigins(ss []endpoints.Script, mine map[string]bool) []string {
	var added []string
	if c.apiSeen == nil {
		c.apiSeen = map[string]bool{c.seedOrigin: true}
	}
	for _, s := range ss {
		if c.scripts[s.SHA256] || c.thirdPartyDone[s.SHA256] || (mine != nil && !mine[s.SHA256]) {
			continue
		}
		if s.ThirdParty {
			c.thirdPartyDone[s.SHA256] = true
		}
		if frontier.Vendor(s.URLs...) || frontier.IsTrackerURL(s.URLs...) {
			continue
		}
		scriptURL := ""
		if len(s.URLs) > 0 {
			scriptURL = s.URLs[0]
		}
		if c.specProbe && !s.ThirdParty {
			c.specCtx.AddScript(s.Result, c.seedOrigin, scriptURL)
		}
		allowOffscope, _ := frontier.EffectiveProbeOffscope(c.probeOffscope, c.hasProxy)
		for _, o := range frontier.APIOrigins(s.Result, c.inScope) {
			if !c.apiSeen[o] && (frontier.MaxAPIOrigins <= 0 || len(c.apiSeen) <= frontier.MaxAPIOrigins) {
				c.apiSeen[o] = true
				added = append(added, o)
				if c.specProbe && (allowOffscope || frontier.OriginInScope(o, c.inScope)) {
					c.apiPending = append(c.apiPending, o)
				}
			}
		}
	}
	return added
}

// takeAPIOrigins hands the API hosts not asked yet to a page.
func (c *crawl) takeAPIOrigins() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.apiPending
	c.apiPending = nil
	return out
}

func (c *crawl) takeKnown() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	was := c.known
	c.known = true
	return !was
}

// duplicate names the page that loaded final first, when a page taken for
// requested ended there (a redirect) and another tab's page got there
// before; "" otherwise, and final is then this page's.
func (c *crawl) duplicate(requested, final string) string {
	if !c.dedupe {
		return ""
	}
	nf, ok := frontier.Normalize(final)
	nr, _ := frontier.Normalize(requested)
	if !ok || nf == nr {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if first, seen := c.visited[nf]; seen && first != requested {
		return first
	}
	c.visited[nf] = requested
	return ""
}

// crawlPages is a tab's part: it takes pages until the crawl is over.
func (e *engine) crawlPages(ctx, pageCtx context.Context, c *crawl, x *explorer, popups *popupWatch) {
	defer func() {
		if popups != nil && popups.stop != nil {
			popups.stop()
		}
		e.stopTabListeners()
	}()
	for {
		it, order, ok := c.next(ctx)
		if !ok {
			return
		}
		if err := c.limit.wait(ctx); err != nil {
			c.finish(donePage{order: order, it: it, skip: true}, "interrupted", false)
			return
		}
		e.timedOut = false
		d := donePage{order: order, it: it}
		stop, retry := e.frontierPage(ctx, c, &d, x, popups)
		c.finish(d, stop, retry)
		if stop == "" && e.timedOut && ctx.Err() == nil && e.cfg.Browser.Attach == "" && !e.tabResponsive() {
			var replaced bool
			popups, replaced = e.recycleTab(pageCtx, x, popups)
			if !replaced {
				return
			}
		}
	}
}

// tabResponsive checks whether the tab's renderer main thread still answers.
func (e *engine) tabResponsive() bool {
	ctx, cancel := context.WithTimeout(e.tabCtx(), 2*time.Second)
	defer cancel()
	_, err := chromedp.Call(ctx, runtime.Evaluate, runtime.EvaluateParams{Expression: "1"})
	return err == nil
}

// recycleTab replaces a wedged tab with a fresh one in the same browser
// context so subsequent frontier pages do not stack timeouts (ENH-04c).
// It reports false when the replacement tab or its capture could not start,
// leaving the old harvest intact for finishTab and halting this lane.
func (e *engine) recycleTab(pageCtx context.Context, x *explorer, popups *popupWatch) (*popupWatch, bool) {
	if e.rootTab == nil {
		return popups, false
	}
	tctx, closeTab := chromedp.NewContext(e.rootTab)
	if err := chromedp.Do(tctx); err != nil {
		closeTab()
		slog.Warn("frontier: could not open replacement tab", "lane", e.lane, "err", err)
		e.warn("frontier: could not open replacement tab: " + err.Error())
		return popups, false
	}
	if e.guard != nil {
		e.guard.AddTab(tabTarget(tctx))
	}
	newHarvest, newMainID, err := e.startOn(tctx)
	if err != nil {
		if e.guard != nil {
			e.guard.RemoveTab(tabTarget(tctx))
		}
		closeTab()
		slog.Warn("frontier: could not start capture on replacement tab", "lane", e.lane, "err", err)
		e.warn("frontier: could not start capture on replacement tab: " + err.Error())
		return popups, false
	}
	e.mu.Lock()
	e.extraCloses = append(e.extraCloses, closeTab)
	e.mu.Unlock()

	if popups != nil && popups.stop != nil {
		popups.stop()
	}
	e.stopTabListeners()

	oldID := target.ID(e.mainFrameID())
	oldClose := e.closeTab
	oldHarvest := e.harvest
	e.pastStats = addStats(e.pastStats, oldHarvest.Stats())
	e.pastHarvests = append(e.pastHarvests, oldHarvest)
	oldHarvest.Stop()
	if oldID != "" {
		cctx, cancel := context.WithTimeout(tctx, 5*time.Second)
		chromedp.CallBrowser(cctx, target.CloseTarget, target.CloseTargetParams{TargetID: oldID})
		cancel()
		if e.guard != nil {
			e.guard.RemoveTab(oldID)
		}
	}
	if oldClose != nil {
		oldClose()
	}

	e.tabMu.Lock()
	e.tab = tctx
	e.closeTab = closeTab
	e.mainID = newMainID
	e.tabMu.Unlock()
	e.pageMu.Lock()
	e.harvest = newHarvest
	e.pageMu.Unlock()
	e.world = 0
	e.timedOut = false

	lctx := e.resetListenCtx(pageCtx)
	if e.cfg.Guard && e.guard != nil && !e.cfg.AllowWebSocket {
		guard.StubSockets(tctx)
	}
	if e.keeper != nil {
		e.keeper.setTabScript(e)
	}
	if x != nil {
		x.bindTab(lctx)
		e.handleDialogs(lctx, func() { x.dialogs.Add(1); x.stats.Dialogs++ })
	} else {
		e.handleDialogs(lctx, nil)
	}
	slog.Warn("frontier: tab became unresponsive; opened a fresh tab", "lane", e.lane)
	return e.watchPopups(lctx), true
}

// frontierPage visits one page and gathers what it found. It returns why
// the crawl must stop (or ""), and whether the page is to be visited again.
func (e *engine) frontierPage(ctx context.Context, c *crawl, d *donePage, x *explorer, popups *popupWatch) (string, bool) {
	it := d.it
	started := time.Now()
	k := e.keeper
	var ep int64
	if k != nil {
		k.wait() // another tab is putting the session back
		ep = k.Epoch()
	}
	if u, err := url.Parse(it.URL); err == nil && e.hostBanned(u.Hostname()) {
		d.p = Page{URL: it.URL, Depth: it.Depth, From: it.From, How: it.How, Run: e.run.RunID, Tab: e.lane,
			Error: "host given up: a response of it came from a private address (private_address_hit)"}
		return "", false
	}
	p := e.visit(ctx, it)
	doc := e.harvest.MainDocument()
	p.Run, p.Status, p.FinalURL, p.Tab = e.run.RunID, doc.Status, e.harvest.Page(), e.lane
	d.marks = append(d.marks, p.FinalURL)
	defer func() { d.p = p }()
	if detect.Check(doc).Blocked {
		// A rule on this page's path (Cloudflare's "Sorry, you have been
		// blocked", a 1020) leaves the page, not the crawl: a WAF rule on
		// /admin must not end the visit of the rest. A challenge still
		// stops it, and so do three such pages in a row. The title is all
		// a tab tells of its document, so a ban and a rule read alike
		// here: the third in a row stops either.
		if b := detect.Classify(doc); b != nil && b.Kind == detect.BlockRequest && c.ruledPage(true) < 3 {
			p.Error = "blocked by a rule: " + b.String()
			return "", false
		}
		p.Error = "bot challenge"
		return "blocked", false
	}
	c.ruledPage(false)
	if c.rateLimited(doc.Status) {
		p.Error = fmt.Sprintf("status %d three times in a row", doc.Status)
		return "rate-limited", false
	}

	if k != nil {
		cause := k.check(e, doc, it.URL)
		if cause == "" && k.Epoch() != ep {
			// Another tab's page lost the session while this one loaded
			// (NEW-C4-03): it may have loaded logged out. Once more, alone.
			if k.lost() {
				p.Error = "the session was lost in another tab, and not restored"
				return "session-lost", false
			}
			if !c.blame(it.URL) {
				p.Error = "the session was lost in another tab while it loaded; visited again"
				return "", true
			}
		}
		if cause != "" {
			if !k.recover(ctx, e, ep, cause, it.URL) {
				p.Error = "session lost (" + cause + ") and not restored"
				return "session-lost", false
			}
			// Visit it again, once: the session may have ended on its own
			// (a timeout). A page that loses it again ends it itself
			// (a logout under another name), and is left at that.
			if !c.blame(it.URL) {
				p.Error = "session lost (" + cause + "); restored; visited again"
				return "", true
			}
			p.Error = "this page ends the session (" + cause + "); restored; not visited again"
			return "", false
		}
	}
	if dup := c.duplicate(it.URL, p.FinalURL); dup != "" {
		p.DuplicateOf = dup
		for _, md := range e.harvest.TakeMainDocuments() {
			d.marks = append(d.marks, md.URL)
		}
		return "", false
	}
	if it.How != frontier.Seed && c.pageScope != nil {
		if u, err := url.Parse(p.FinalURL); err == nil && u.Host != "" && !c.pageScope(u.Hostname()) {
			for _, md := range e.harvest.TakeMainDocuments() {
				d.marks = append(d.marks, md.URL)
			}
			e.takePageScripts()
			p.TookMS = time.Since(started).Milliseconds()
			return "", false
		}
	}

	var found []frontier.Found
	found = append(found, e.domURLs(p.FinalURL)...)
	for _, md := range e.harvest.TakeMainDocuments() {
		d.marks = append(d.marks, md.URL)
		found = append(found, frontier.FromHeaders(md.Headers, md.URL)...)
	}
	if c.takeKnown() {
		found = append(found, e.knownFiles(p.FinalURL)...)
		if c.specProbe {
			if u, err := url.Parse(p.FinalURL); err == nil {
				e.specFiles(ctx, c, u.Scheme+"://"+u.Host, p.FinalURL)
			}
		}
	}
	for _, o := range c.takeAPIOrigins() {
		e.specFiles(ctx, c, o, p.FinalURL)
	}
	if e.cfg.Resolve {
		e.resolve(ctx)
	}
	if x != nil {
		acted := x.stats.Actions
		before := 0
		for _, n := range acted {
			before += n
		}
		found = append(found, x.page(ctx, it)...)
		for _, n := range x.stats.Actions {
			p.Explored += n
		}
		p.Explored -= before
		if x.lost {
			p.Error = "session lost while exploring, and not restored"
			return "session-lost", false
		}
		// What the actions showed: a menu's links, a dialog's.
		found = append(found, e.domURLs(p.FinalURL)...)
	}
	d.found = found
	d.readScripts, d.scripts = true, e.takePageScripts()
	d.after = popups.take()
	p.TookMS = time.Since(started).Milliseconds()
	return "", false
}

// visit loads a page in the tab and lets it settle: network quiet, and at
// least the dwell, for the timers that navigate after a second.
func (e *engine) visit(ctx context.Context, it frontier.Item) Page {
	started := time.Now()
	p := Page{URL: it.URL, Visited: true, Depth: it.Depth, From: it.From, How: it.How, Started: started.UTC()}
	e.harvest.TakeMainDocuments()
	e.harvest.SetPage(it.URL)
	e.world = 0 // the isolated world goes with the document
	nctx, cancel := context.WithTimeout(e.tab, e.cfg.NavTimeout)
	err := chromedp.Do(nctx, chromedp.Navigate(it.URL))
	cancel()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			e.timedOut = true
		}
		p.Error = err.Error()
		slog.Debug("navigate", "url", it.URL, "err", err)
	}
	e.settle(ctx)
	if rest := e.cfg.PageDwell - time.Since(started); rest > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(rest):
		}
		e.settle(ctx) // what the timers started
	}
	e.world = 0
	return p
}

// domURLs reads the document's URLs: the whole tree, shadow roots and
// same-process frames included.
func (e *engine) domURLs(pageURL string) []frontier.Found {
	ctx, cancel := context.WithTimeout(e.tab, 20*time.Second)
	defer cancel()
	depth, pierce := int64(-1), true
	res, err := chromedp.Call(ctx, dom.GetDocument, dom.GetDocumentParams{Depth: &depth, Pierce: &pierce})
	if err != nil || res.Root == nil {
		if errors.Is(err, context.DeadlineExceeded) {
			e.timedOut = true
		}
		slog.Debug("dom", "err", err)
		return nil
	}
	found := frontier.FromDOM(res.Root, pageURL)
	// The tree leaves out what <template> elements hold; their markup has
	// it, and is read as HTML.
	if html, err := chromedp.Call(ctx, dom.GetOuterHTML, dom.GetOuterHTMLParams{NodeID: res.Root.NodeID}); err == nil {
		found = append(found, frontier.FromHTML(html.OuterHTML, baseOf(res.Root, pageURL))...)
	}
	return found
}

// baseOf is a document's base URL, as <base href> sets it.
func baseOf(root *cdp.Node, pageURL string) string {
	if root.BaseURL != "" {
		return root.BaseURL
	}
	return pageURL
}

// knownFiles reads robots.txt and the sitemaps it names (or /sitemap.xml)
// through the page, once, at the start.
func (e *engine) knownFiles(pageURL string) []frontier.Found {
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	root := u.Scheme + "://" + u.Host
	var out []frontier.Found
	sitemaps := []string{root + "/sitemap.xml"}
	if r, _ := e.pageFetch(root+"/robots.txt", true); r.Status == 200 && r.Text != "" {
		pages, maps := frontier.FromRobots(r.Text, root+"/robots.txt")
		out = append(out, pages...)
		for _, m := range maps {
			if sameOrigin(m, root) && !slices.Contains(sitemaps, m) {
				sitemaps = append(sitemaps, m)
			}
		}
	}
	for i, m := range sitemaps {
		if i == 5 {
			break
		}
		if r, _ := e.pageFetch(m, true); r.Status == 200 && strings.Contains(r.Text, "<loc>") {
			out = append(out, frontier.FromSitemap(r.Text, m)...)
		}
	}
	return out
}

// scriptURLs reads the URLs of the scripts stored since the last page:
// those the scripts navigate to, their routes, and their paths.
// scriptURLs reads the URLs of scripts (ss, as endpoints.Analyze gives
// them) not read yet: those the scripts navigate to, their routes, and
// their paths. With mine, only those scripts: a page's own.
func scriptURLs(ss []endpoints.Script, pageURL string, done, mine map[string]bool) []frontier.Found {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	var out []frontier.Found
	for _, s := range ss {
		if done[s.SHA256] || s.ThirdParty || (mine != nil && !mine[s.SHA256]) {
			continue
		}
		done[s.SHA256] = true
		out = append(out, frontier.FromScript(s.Result, base, frontier.Vendor(s.URLs...))...)
	}
	return out
}

// popupWatch notes the pages the tab opens (window.open, target=_blank
// with a script) and closes them: the browser has requested their URL;
// the crawl names it.
type popupWatch struct {
	ch   chan string
	stop context.CancelFunc
}

func (e *engine) watchPopups(ctx context.Context) *popupWatch {
	w := &popupWatch{ch: make(chan string, 100)}
	tabCtx := e.tabCtx()
	tab := chromedp.FromContext(tabCtx).Target
	if tab == nil {
		return w
	}
	id := tab.TargetID
	lctx, stop := context.WithCancel(tabCtx)
	w.stop = stop
	context.AfterFunc(ctx, stop)
	opened := map[target.ID]bool{}
	go each(chromedp.BrowserEvents(lctx, target.TargetInfoChanged), func(ev *target.EventTargetInfoChanged) {
		t := ev.TargetInfo
		if t == nil || t.Type != "page" || t.OpenerID != id || opened[t.TargetID] || t.URL == "" || t.URL == "about:blank" {
			return
		}
		opened[t.TargetID] = true
		select {
		case w.ch <- t.URL:
		default:
		}
		cctx, cancel := context.WithTimeout(lctx, 5*time.Second)
		chromedp.CallBrowser(cctx, target.CloseTarget, target.CloseTargetParams{TargetID: t.TargetID})
		cancel()
	})
	return w
}

func (w *popupWatch) take() []frontier.Found {
	var out []frontier.Found
	for {
		select {
		case u := <-w.ch:
			// Opened already: named, not visited again.
			out = append(out, frontier.Found{URL: u, How: frontier.Popup, Visit: false})
		default:
			return out
		}
	}
}

// tabTarget is the target id of a tab context ("" when it has none).
func tabTarget(tab context.Context) target.ID {
	if c := chromedp.FromContext(tab); c != nil && c.Target != nil {
		return c.Target.TargetID
	}
	return ""
}
