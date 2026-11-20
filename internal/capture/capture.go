// Package capture records every JavaScript a tab runs or loads: in the page
// itself and in the workers, service workers, shared workers and cross-site
// frames that belong to it. It also tells when the tab has gone quiet.
package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/browser"
	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Script is one script the capture found, with its body.
type Script struct {
	Body      []byte
	Kind      string // file, inline or eval
	Via       string // network or debugger
	URL       string
	Target    string // page, iframe, worker, service_worker or shared_worker
	TargetURL string
	Page      string
	Status    int64
	MIME      string
	Headers   map[string]string
	Initiator *Initiator

	SourceMapURL string
	IsModule     bool
	Tags         []string
	// SHA256 is set, and Body left empty, for a script seen again whose
	// content was already captured.
	SHA256 string
}

type Initiator struct {
	Type string `json:"type"`
	URL  string `json:"url,omitempty"`
	Line int64  `json:"line,omitempty"`
	Col  int64  `json:"col,omitempty"`
}

type Options struct {
	// InScope reports whether a host belongs to the target. Workers and
	// frames of other hosts are still captured when they belong to the tab;
	// service and shared workers, which belong to no tab, must be in scope.
	InScope func(host string) bool

	BodyConcurrency   int           // parallel body fetches across all sessions
	MaxTotalBuffer    int64         // per session, bytes Chrome keeps for getResponseBody
	MaxResourceBuffer int64         // per resource, bytes
	AttachTimeout     time.Duration // longest wait to attach to a target
	CallTimeout       time.Duration // longest wait for one CDP call on a session
	NoDebugger        bool          // capture over the network only
	// NoSharedWorkers leaves service workers and shared workers to another
	// capture: tabs of one browser context at work at once (crawl -tabs)
	// would each attach to them, and log their requests as many times.
	NoSharedWorkers bool
	// SWWait is how long WaitIdle keeps going after a service worker
	// appears, so that it can precache the app.
	SWWait time.Duration
	// Record logs every request of every session (see RecordOptions).
	Record RecordOptions
	// OnClearSiteData and OnWebSocket, when set, hear of each response that
	// carries Clear-Site-Data and each WebSocket that opens, on any session:
	// the tab, its frames and its workers.
	OnClearSiteData func(requestID string)
	OnWebSocket     func(url string)
	// OnRedirect, when set, hears of each redirect a request followed, on
	// any session: the URL that answered with it, and where it led.
	OnRedirect func(from, to string)
	// OnAPIStatus, when set, hears of each XHR/fetch response the network
	// gave (not one from a cache or a service worker): its URL, its HTTP
	// status, and whether the guard made it up (X-Jsharvest-Guard). The
	// session keeper reads a run of 401s from it.
	OnAPIStatus func(url string, status int, fromGuard bool)
	// OnPrivateHit hears of each response a public origin got from a
	// private address (layer 3), on any session. PrivateRules are the
	// user's -host-resolver-rules (their hosts are exempt); NoPrivateCheck
	// turns the check off: a proxy (remoteIPAddress is its own), or an
	// internal target.
	OnPrivateHit   func(PrivateHit)
	PrivateRules   netsafe.Rules
	NoPrivateCheck bool
	// Actions reports what the user (or a driver) does in the tab and its
	// frames to OnEvent, and tags event handlers so that requests can be
	// traced to the event that caused them (see actions.go). NoTagger
	// reports actions but leaves the handlers alone.
	Actions  bool
	NoTagger bool
	OnEvent  func(flow.Event)
}

func (o *Options) recording() bool {
	return o.Record.Sink != nil && o.Record.Mode != "" && o.Record.Mode != traffic.Off
}

func (o *Options) defaults() {
	if o.InScope == nil {
		o.InScope = func(string) bool { return true }
	}
	if o.BodyConcurrency <= 0 {
		o.BodyConcurrency = 8
	}
	if o.MaxTotalBuffer <= 0 {
		o.MaxTotalBuffer = 512 << 20
	}
	if o.MaxResourceBuffer <= 0 {
		o.MaxResourceBuffer = 64 << 20
	}
	if o.AttachTimeout <= 0 {
		o.AttachTimeout = 5 * time.Second
	}
	if o.CallTimeout <= 0 {
		o.CallTimeout = 10 * time.Second
	}
	if o.SWWait < 0 {
		o.SWWait = 0
	}
}

// Stats counts what happened during a capture, for run.json and the summary.
type Stats struct {
	Targets      map[string]int `json:"targets"`       // attached sessions by target type
	AttachFailed map[string]int `json:"attach_failed"` // by reason
	Scripts      int            `json:"scripts"`       // handed to the sink
	BodiesLost   map[string]int `json:"bodies_lost"`   // by reason
	CDPInternal  int            `json:"cdp_internal"`  // scripts that chromedp itself evaluated, dropped
	// Challenge counts the bot-challenge scripts dropped (detect.IsChallengeScript):
	// never the target's code, they reach neither the sink nor the store.
	Challenge int `json:"challenge_scripts,omitempty"`
	// LNADenied counts the requests Chrome's Local Network Access refused
	// for the permission jsharvest denies (loadingFailed with
	// CorsErrorLocalNetworkAccessPermissionDenied: a secure public page
	// reaching a more private address, layer 2); LNAInsecure those it
	// refused on its own, the page not being a secure context
	// (CorsErrorInsecureLocalNetwork: Chrome 156 does so for any http public
	// page). LNASamples are the first few URLs of both, cut.
	// PrivateAddressHit are responses a public origin got from a private
	// address (layer 3, see PrivateHit); PrivateHitCount all of them.
	PrivateAddressHit []PrivateHit `json:"private_address_hit,omitempty"`
	PrivateHitCount   int          `json:"private_hit_count,omitempty"`
	LNADenied         int          `json:"lna_denied,omitempty"`
	LNAInsecure       int          `json:"lna_insecure,omitempty"`
	LNASamples        []string     `json:"lna_samples,omitempty"`
}

const (
	maxLNASamples = 5
	maxLNAURL     = 200
)

// noteLNADenied counts one request that Local Network Access refused:
// for the permission denied, or (insecure) for the page's context.
func (c *Capture) noteLNADenied(url string, insecure bool) {
	if len(url) > maxLNAURL {
		url = url[:maxLNAURL] + "…"
	}
	c.mu.Lock()
	if insecure {
		c.stats.LNAInsecure++
	} else {
		c.stats.LNADenied++
	}
	if len(c.stats.LNASamples) < maxLNASamples && !slices.Contains(c.stats.LNASamples, url) {
		c.stats.LNASamples = append(c.stats.LNASamples, url)
	}
	c.mu.Unlock()
}

type Capture struct {
	tab   context.Context
	opts  Options
	sink  func(Script)
	sinkM sync.Mutex // the sink is called from one goroutine at a time
	sem   chan struct{}
	wg    sync.WaitGroup // body fetches in flight

	mu           sync.Mutex
	page         string
	lastActivity time.Time
	sessions     map[target.ID]*session
	hashes       map[string]string // V8 script hash -> sha256 of its source; "" while being read
	hashWaiters  map[string][]Script
	initiators   map[string]*Initiator // network request id -> who made it, on any session
	requests     map[string]bool       // network request ids any session saw
	frames       map[string]bool       // frames those requests came from
	mainDoc      detect.Doc            // the last main-frame document response
	mainBlocked  bool                  // mainDoc is a challenge or deny page (detect.Check)
	// blockedPages are the page labels of the blocked main document: its
	// URL, and the label the tab had when it came. Only a script or request
	// of that page is the challenge's by its page alone; one of the page
	// before, read late, is not.
	blockedPages map[string]bool
	// suspect: the main document is a 403, 429 or 503 from behind a bot
	// vendor that its status and headers do not call blocked; its title
	// may (Cloudflare's "Attention Required!" deny page has no
	// cf-mitigated). The scripts of its page are held until MainDocument
	// reads the title: dropped with a block page, delivered otherwise
	// (round 18: a deny page's three inline scripts reached the store).
	suspect      bool
	suspectPages map[string]bool
	held         []Script
	challenges   map[string]bool // sha256 of the challenge scripts dropped; "url "+URL or V8 hash of those not read
	mainDocs     []detect.Doc    // every one since TakeMainDocuments, at most 20
	swSince      time.Time       // when the first service worker was attached
	swURLs       []string
	stats        Stats

	targets   *targetManager
	stopSweep func() // stops the request log's sweeps and waits for them
	hooks     []hook // action scripts installed, for Unhook
}

// Start begins capturing on the tab. Call it before navigating, so that the
// first requests of the page are not missed.
func Start(tab context.Context, opts Options, sink func(Script)) (*Capture, error) {
	opts.defaults()
	c := &Capture{
		tab:          tab,
		opts:         opts,
		sink:         sink,
		sem:          make(chan struct{}, opts.BodyConcurrency),
		lastActivity: time.Now(),
		sessions:     map[target.ID]*session{},
		hashes:       map[string]string{},
		hashWaiters:  map[string][]Script{},
		challenges:   map[string]bool{},
		initiators:   map[string]*Initiator{},
		requests:     map[string]bool{},
		frames:       map[string]bool{},
		stats: Stats{
			Targets:      map[string]int{},
			AttachFailed: map[string]int{},
			BodiesLost:   map[string]int{},
		},
	}

	tabTarget := chromedp.FromContext(tab).Target
	if tabTarget == nil {
		return nil, fmt.Errorf("capture: the context has no tab")
	}
	page := c.newSession(tab, tabTarget.TargetID, "page", "", func() {})
	if err := page.start(); err != nil {
		return nil, fmt.Errorf("capture: tab: %w", err)
	}

	tm, err := startTargets(c, tabTarget.TargetID)
	if err != nil {
		return nil, err
	}
	c.targets = tm
	sweepCtx, cancelSweep := context.WithCancel(tab)
	sweepDone := make(chan struct{})
	c.stopSweep = func() { cancelSweep(); <-sweepDone }
	if opts.recording() {
		go c.sweepLoop(sweepCtx, sweepDone)
	} else {
		close(sweepDone)
	}
	return c, nil
}

// sweepLoop writes the requests that are complete, twice a second.
func (c *Capture) sweepLoop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		c.mu.Lock()
		sessions := slices.Collect(maps.Values(c.sessions))
		c.mu.Unlock()
		for _, s := range sessions {
			if s.rec != nil {
				s.rec.sweep(false)
			}
		}
	}
}

// SetPage labels the scripts that load from now on with the page URL.
func (c *Capture) SetPage(u string) {
	c.mu.Lock()
	c.page = u
	c.mu.Unlock()
}

// noteRequest notes a request one of the sessions saw: who made it, and
// that it, and its frame, are this tab's.
func (c *Capture) noteRequest(id, frame string, in *Initiator) {
	c.mu.Lock()
	if id != "" {
		if in != nil {
			c.initiators[id] = in
		}
		c.requests[id] = true
	}
	if frame != "" {
		c.frames[frame] = true
	}
	c.mu.Unlock()
}

// forgetRequest drops a request that is over and that the guard did not
// hold back: nothing will ask who owns it. Not called from finishTab:
// finishRun still asks the guard's records about the held ones.
func (c *Capture) forgetRequest(id string) {
	c.mu.Lock()
	delete(c.requests, id)
	delete(c.initiators, id)
	c.mu.Unlock()
}

// Owns reports whether a request the guard held back is this tab's: one of
// its sessions saw the request, or it came from one of the tab's frames,
// or from a popup the tab opened (opener). Several tabs share one guard in
// crawl -tabs.
func (c *Capture) Owns(networkID, frame, opener string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return (networkID != "" && c.requests[networkID]) || (frame != "" && c.frames[frame]) || (opener != "" && c.frames[opener])
}

// InitiatorOf returns who made a network request, as any session saw it,
// or nil. The guard uses it to say which code made a request it held back.
func (c *Capture) InitiatorOf(id string) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if in, ok := c.initiators[id]; ok {
		return in
	}
	return nil
}

// Page returns the URL the tab is on, as the main frame last reported it.
func (c *Capture) Page() string { return c.currentPage() }

func (c *Capture) currentPage() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.page
}

func (c *Capture) touch() {
	c.mu.Lock()
	c.lastActivity = time.Now()
	c.mu.Unlock()
}

func (c *Capture) emit(s Script) {
	if s.SHA256 == "" && c.thirdParty(s.URL) {
		s.Tags = append(s.Tags, "third-party")
	}
	if c.challenge(&s) || c.hold(s) {
		return
	}
	c.deliver(s)
}

// deliver hands a script to the sink.
func (c *Capture) deliver(s Script) {
	c.sinkM.Lock()
	defer c.sinkM.Unlock()
	c.mu.Lock()
	c.stats.Scripts++
	c.mu.Unlock()
	c.sink(s)
}

// challengeSHA stands for the content of a script that was not read
// because it is a challenge's (its initiator was the challenge platform):
// the sightings that waited for it are dropped with it.
const challengeSHA = "challenge"

// challenge drops a bot-challenge script, and the sightings of one: such
// code is the vendor's, and in the store it would pass for the target's
// (Cloudflare's VM alone is several 1.3 MB eval blocks per page).
func (c *Capture) challenge(s *Script) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.SHA256 != "" {
		if s.SHA256 == challengeSHA || c.challenges[s.SHA256] {
			return true
		}
		return false
	}
	ini := ""
	if s.Initiator != nil {
		ini = s.Initiator.URL
	}
	if !detect.IsChallengeScript(s.URL, ini, s.Kind, s.Body, false) {
		// A blocked main document makes every script of its page the
		// challenge's; a worker or frame of another site is judged alone.
		// Dropped, not remembered: the same code on a healthy page is the
		// site's.
		if s.Target == "page" && c.onBlockedPage(s.Page) {
			c.stats.Challenge++
			slog.Debug("script of a challenge page dropped", "kind", s.Kind, "url", s.URL, "page", s.Page)
			return true
		}
		return false
	}
	sum := sha256.Sum256(s.Body)
	byURL := ""
	if s.Kind == "file" && s.URL != "" {
		byURL = "url " + s.URL
	}
	if sha := hex.EncodeToString(sum[:]); !c.challenges[sha] && (byURL == "" || !c.challenges[byURL]) {
		c.challenges[sha] = true
		if byURL != "" {
			c.challenges[byURL] = true
		}
		c.stats.Challenge++ // once per content and URL: Network and the Debugger both see a file
	}
	slog.Debug("bot-challenge script dropped", "kind", s.Kind, "url", s.URL, "initiator", ini, "size", len(s.Body))
	return true
}

// onBlockedPage reports whether a page label is the blocked main
// document's. Call it with c.mu held.
func (c *Capture) onBlockedPage(page string) bool {
	return c.mainBlocked && page != "" && c.blockedPages[stripFragment(page)]
}

// skipChallenge counts a challenge script that was not even read, once
// for its URL (a file is seen by Network and by the Debugger) or, with
// none, for its V8 hash.
func (c *Capture) skipChallenge(key, url, initiator string) {
	if url != "" {
		key = "url " + url
	}
	c.mu.Lock()
	if !c.challenges[key] {
		c.challenges[key] = true
		c.stats.Challenge++
	}
	c.mu.Unlock()
	slog.Debug("bot-challenge script not read", "url", url, "initiator", initiator)
}

// thirdParty reports whether a script URL is on a host outside the
// target's scope. Inline and eval code have no URL of their own.
func (c *Capture) thirdParty(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return !c.opts.InScope(u.Hostname())
}

func (c *Capture) lost(reason string) {
	c.mu.Lock()
	c.stats.BodiesLost[reason]++
	c.mu.Unlock()
}

// acquire takes a body-fetch slot, or gives up when ctx ends, so a hung
// session can never hold up the others.
func (c *Capture) acquire(ctx context.Context) bool {
	select {
	case c.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Capture) release() { <-c.sem }

func (c *Capture) setMainDoc(d detect.Doc) {
	c.mu.Lock()
	// What a suspect page left unjudged was no block page's that a title
	// said: kept.
	left := c.held
	c.held = nil
	c.mainDoc = d
	c.mainBlocked = detect.Check(d).Blocked
	c.blockedPages = nil
	pages := map[string]bool{stripFragment(d.URL): true, stripFragment(c.page): true}
	if c.mainBlocked {
		c.blockedPages = pages
	}
	c.suspect, c.suspectPages = !c.mainBlocked && detect.Suspect(d), nil
	if c.suspect {
		c.suspectPages = pages
	}
	if len(c.mainDocs) < 20 {
		c.mainDocs = append(c.mainDocs, d)
	}
	c.mu.Unlock()
	for _, s := range left {
		c.deliver(s)
	}
}

// hold keeps a script of a suspect page (see Capture.suspect) for the
// verdict.
func (c *Capture) hold(s Script) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.suspect || s.Target != "page" || s.Page == "" || !c.suspectPages[stripFragment(s.Page)] {
		return false
	}
	c.held = append(c.held, s)
	return true
}

// judge settles a suspect page by its document with the title: a block
// page drops what was held and makes the page blocked; otherwise what was
// held is delivered. With no title yet, it waits.
func (c *Capture) judge(d detect.Doc) {
	c.mu.Lock()
	if !c.suspect || d.Title == "" || d.URL != c.mainDoc.URL {
		c.mu.Unlock()
		return
	}
	held := c.held
	c.held, c.suspect = nil, false
	if detect.Check(d).Blocked {
		c.mainBlocked, c.blockedPages = true, c.suspectPages
		c.stats.Challenge += len(held)
		c.mu.Unlock()
		slog.Debug("scripts of a block page dropped", "count", len(held), "url", d.URL, "title", d.Title)
		return
	}
	c.mu.Unlock()
	for _, s := range held {
		c.deliver(s)
	}
}

// TakeMainDocuments returns the main-frame documents received since the
// last call: a page that sends the tab on (Refresh, a timer) has its own
// headers, which the last document no longer shows.
func (c *Capture) TakeMainDocuments() []detect.Doc {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.mainDocs
	c.mainDocs = nil
	return d
}

// MainDocument returns the last main-frame document the tab received, with
// the tab's title. The title comes from the target info, so that no script
// runs in the page to read it.
func (c *Capture) MainDocument() detect.Doc {
	c.mu.Lock()
	d := c.mainDoc
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(c.tab, c.opts.CallTimeout)
	defer cancel()
	if res, err := chromedp.CallBrowser(ctx, target.GetTargetInfo, target.GetTargetInfoParams{TargetID: c.targets.tabID}); err == nil && res.TargetInfo != nil {
		d.Title = res.TargetInfo.Title
	}
	c.judge(d)
	return d
}

// IdleResult says why WaitIdle returned.
type IdleResult struct {
	Reason   string   `json:"reason"`             // quiet, max or canceled
	Inflight []string `json:"inflight,omitempty"` // requests still open when it returned, at most 10
}

// WaitIdle returns once at most maxInflight requests are open across all
// sessions and nothing has happened for quiet, or when max has passed. A few
// requests may stay open because long polls and event streams never end.
func (c *Capture) WaitIdle(ctx context.Context, quiet, max time.Duration, maxInflight int) IdleResult {
	deadline := time.Now().Add(max)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return IdleResult{Reason: "canceled"}
		case <-tick.C:
		}
		open := c.inflight()
		c.mu.Lock()
		idleFor := time.Since(c.lastActivity)
		swWaiting := !c.swSince.IsZero() && time.Since(c.swSince) < c.opts.SWWait
		c.mu.Unlock()
		// A target being attached may be about to load scripts; its attach
		// is bounded by the watchdog, so this cannot wait for ever.
		attaching := c.targets != nil && c.targets.pending() > 0
		if len(open) <= maxInflight && idleFor >= quiet && !swWaiting && !attaching {
			return IdleResult{Reason: "quiet"}
		}
		if time.Now().After(deadline) {
			if len(open) > 10 {
				open = open[:10]
			}
			return IdleResult{Reason: "max", Inflight: open}
		}
	}
}

func (c *Capture) inflight() []string {
	c.mu.Lock()
	sessions := slices.Collect(maps.Values(c.sessions))
	c.mu.Unlock()
	var open []string
	for _, s := range sessions {
		open = append(open, s.net.open()...)
	}
	return open
}

// Drain waits until every body fetch has finished, or until ctx ends.
func (c *Capture) Drain(ctx context.Context) {
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Stop detaches from every target the capture attached to. The tab itself
// is left to its owner.
//
// Requests still open are written to the request log as incomplete, so
// call Drain first, to let the bodies being read arrive.
func (c *Capture) Stop() {
	c.targets.stop()
	c.stopSweep()
	c.mu.Lock()
	sessions := slices.Collect(maps.Values(c.sessions))
	left := c.held // never judged: no title said block page
	c.held, c.suspect = nil, false
	c.mu.Unlock()
	for _, s := range left {
		c.deliver(s)
	}
	for _, s := range sessions {
		if s.rec != nil {
			s.rec.sweep(true)
		}
		s.cancel()
	}
}

// Stats returns a copy of the counters.
func (c *Capture) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{
		Targets:           maps.Clone(c.stats.Targets),
		AttachFailed:      maps.Clone(c.stats.AttachFailed),
		Scripts:           c.stats.Scripts,
		BodiesLost:        maps.Clone(c.stats.BodiesLost),
		CDPInternal:       c.stats.CDPInternal,
		Challenge:         c.stats.Challenge,
		LNADenied:         c.stats.LNADenied,
		LNAInsecure:       c.stats.LNAInsecure,
		PrivateAddressHit: slices.Clone(c.stats.PrivateAddressHit),
		PrivateHitCount:   c.stats.PrivateHitCount,
		LNASamples:        slices.Clone(c.stats.LNASamples),
	}
}

// session is one CDP session on one target: the tab, or a target the
// capture attached to.
type session struct {
	c         *Capture
	ctx       context.Context
	cancel    context.CancelFunc
	id        target.ID
	kind      string // target type
	targetURL string
	docs      map[cdp.FrameID]string // the document URL of each frame this session saw load (guarded by c.mu)
	net       *netTracker
	scripts   *scriptTracker
	rec       *recorder // nil unless recording
}

func (c *Capture) newSession(ctx context.Context, id target.ID, kind, targetURL string, cancel context.CancelFunc) *session {
	s := &session{c: c, ctx: ctx, cancel: cancel, id: id, kind: kind, targetURL: targetURL}
	c.mu.Lock()
	c.frames[string(id)] = true // a tab's or a frame's target id is its frame id
	c.mu.Unlock()
	s.net = newNetTracker(s)
	s.scripts = newScriptTracker(s)
	if c.opts.recording() {
		s.rec = newRecorder(s, c.opts.Record)
	}
	return s
}

// start subscribes to the session's events and raises its network buffers.
// The session counts toward idle only once it is registered here.
func (s *session) start() error {
	// The launched browser's User-Agent, not HeadlessChrome (CF-06), on
	// this session before it asks for anything more.
	if ua := browser.UAOf(s.c.tab); ua != nil {
		ctx, cancel := context.WithTimeout(s.ctx, s.c.opts.CallTimeout)
		if err := ua.Apply(ctx, s.kind == "page" || s.kind == "iframe"); err != nil {
			slog.Debug("user agent", "target", s.kind, "err", err)
		}
		cancel()
	}
	s.net.start()
	if s.rec != nil {
		s.rec.start()
	}
	s.watchSignals()
	if s.kind == "page" {
		s.followMainFrame()
	}
	if err := s.net.raiseBuffers(); err != nil {
		slog.Debug("raise network buffers", "target", s.kind, "err", err)
	}
	if !s.c.opts.NoDebugger {
		if err := s.scripts.start(); err != nil {
			slog.Debug("debugger", "target", s.kind, "err", err)
		}
	}
	if o := s.c.opts; o.Actions && o.OnEvent != nil && isActionTarget(s.kind) {
		if err := s.installActions(); err != nil {
			slog.Warn("capture: cannot record actions here; its requests will be grouped by time only", "target", s.kind, "url", traffic.LogURL(s.targetURL), "err", err)
		}
	}
	s.c.mu.Lock()
	s.c.sessions[s.id] = s
	s.c.stats.Targets[s.kind]++
	if s.kind == "service_worker" {
		if s.c.swSince.IsZero() {
			s.c.swSince = time.Now()
		}
		s.c.swURLs = append(s.c.swURLs, s.targetURL)
	}
	s.c.mu.Unlock()
	return nil
}

// followMainFrame keeps the page label on the URL the tab is actually on:
// after a redirect, and after client-side navigation. The main frame has the
// id of the tab target.
func (s *session) followMainFrame() {
	navigated := chromedp.Events(s.ctx, page.FrameNavigated)
	within := chromedp.Events(s.ctx, page.NavigatedWithinDocument)
	go func() {
		for ev, err := range navigated {
			if err != nil {
				return
			}
			if ev.Frame != nil && ev.Frame.ParentID == "" {
				s.c.SetPage(ev.Frame.URL)
			}
		}
	}()
	go func() {
		for ev, err := range within {
			if err != nil {
				return
			}
			if string(ev.FrameID) == string(s.id) {
				s.c.SetPage(ev.URL)
			}
		}
	}()
}

// remove forgets a session whose target went away, so its open requests no
// longer hold up idle.
func (c *Capture) remove(id target.ID) {
	c.mu.Lock()
	s := c.sessions[id]
	delete(c.sessions, id)
	c.mu.Unlock()
	if s != nil {
		if s.rec != nil {
			s.rec.sweep(true)
		}
		s.cancel()
	}
}
