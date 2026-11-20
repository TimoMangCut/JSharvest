package guard

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Record is one request the guard held back.
type Record struct {
	Time         time.Time         `json:"ts"`
	Action       Action            `json:"action"`
	Reason       string            `json:"reason"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	ResourceType string            `json:"resource_type"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         string            `json:"body,omitempty"`
	FrameID      string            `json:"frame_id,omitempty"`
	NetworkID    string            `json:"network_id,omitempty"`
	Page         string            `json:"page,omitempty"`
	Opener       string            `json:"opener,omitempty"` // the tab that opened the popup it came from
	Initiator    any               `json:"initiator,omitempty"`
}

// Stats goes into run.json.
type Stats struct {
	Blocked           int            `json:"blocked"`
	ByReason          map[string]int `json:"by_reason"`
	PassedOtherTabs   int            `json:"passed_other_tabs"`
	PassedLogin       int            `json:"passed_login,omitempty"`     // writes of a login done again (AllowWrites)
	HeldNavigations   int            `json:"held_navigations,omitempty"` // navigations explore's clicks started (HoldNavigations)
	ClearSiteDataSeen int            `json:"clear_site_data_seen"`
	WebSocketsSeen    int            `json:"websockets_not_blocked"`
	AnswerErrors      int            `json:"answer_errors"`
	// TargetsGuarded counts the targets that existed when the guard started
	// and so needed interception of their own (see guardExisting).
	TargetsGuarded int `json:"targets_guarded"`
}

type Options struct {
	Rules Rules
	// Attach: the browser is the user's own, with tabs that are not ours.
	// Their requests pass when, and only when, their frame is known to
	// belong to such a tab; anything that cannot be placed is guarded.
	Attach bool
	// InScope reports whether a host is the target's: its service and
	// shared workers that already run are guarded on their own sessions.
	// Nil means every host.
	InScope func(host string) bool
	// HostRules are the user's -host-resolver-rules: a host they map to a
	// private address is an internal host that is allowed (layer 1).
	HostRules netsafe.Rules
}

const maxBody = 1 << 20

// Guard intercepts every request of the browser at the Request stage. Every
// paused request is
// answered: passed on, or fulfilled with a harmless success. A request the
// rules hold back is never continued, not even on an error: Chrome would
// send it.
//
// Interception at browser level only reaches the documents and workers
// that start after it is turned on. Those already running when the guard
// starts (an attached tab's page, its frames and workers, a service worker
// the user's visit started) get interception on their own sessions: a
// stage of their own, ahead of the browser's. A request is answered on the
// stage that paused it.
type Guard struct {
	opts  Options
	base  context.Context // browser-level calls; outlives the tab
	tabID target.ID
	stop  context.CancelFunc

	mu         sync.Mutex
	writers    map[string]int            // frames whose writes pass for now: a login being done again
	passedBy   map[string]int            // writes passed as a login's, by frame
	navHold    map[string]int            // frames whose navigations are answered 204 for now: explore at work
	navHeld    map[string][]string       // the GET navigations held since TakeNavigations, by the holding frame
	inflight   int                       // handlers running
	lastPaused time.Time                 // the latest requestPaused, at any stage
	pending    map[fetch.RequestID]*held // held back, answer not yet confirmed
	stages     []*stage                  // the targets with interception of their own
	csd        map[string]bool           // Clear-Site-Data responses seen, by request id
	records    []Record
	stats      Stats
	hostBlock  map[string]bool                            // hosts failed for the rest of the run (layer 3)
	tops       map[string]string                          // the last document let through, by main frame (layer 1's origin)
	answerFn   func(on context.Context, params any) error // tests: stands in for the browser
	pages      map[target.ID]target.Info                  // page targets of the browser, for attach mode
	ours       map[target.ID]bool                         // the tool's own tabs: the first, and each AddTab
	pageOf     func(frame, networkID string) string       // the page a held request's tab is on, for the records
}

// Start enables interception on the browser of tab. Call it before the
// tab navigates.
func Start(tab context.Context, opts Options) (*Guard, error) {
	c := chromedp.FromContext(tab)
	if c == nil || c.Target == nil {
		return nil, fmt.Errorf("guard: the context has no tab")
	}
	// Browser-level calls must still work after the tab is closed, so that
	// the guard can answer what is pending; the browser's own life ends them.
	base := context.WithoutCancel(tab)
	evCtx, stop := context.WithCancel(base)
	g := &Guard{
		opts: opts, base: base, tabID: c.Target.TargetID, stop: stop,
		pending:  map[fetch.RequestID]*held{},
		passedBy: map[string]int{},
		csd:      map[string]bool{},
		stats:    Stats{ByReason: map[string]int{}},
		pages:    map[target.ID]target.Info{},
		ours:     map[target.ID]bool{c.Target.TargetID: true},
	}

	paused := chromedp.BrowserEvents(evCtx, fetch.RequestPaused)
	// The pages of the browser: in attach mode, to let the user's other
	// tabs be; in any mode, to know the popups a held frame opens.
	g.trackPages(evCtx)

	ctx, cancel := context.WithTimeout(base, 10*time.Second)
	defer cancel()
	// Every request pauses at the Request stage.
	_, err := chromedp.CallBrowser(ctx, fetch.Enable, fetch.EnableParams{Patterns: []*fetch.RequestPattern{
		{URLPattern: "*", RequestStage: fetch.RequestStageRequest},
	}})
	if err != nil {
		stop()
		return nil, fmt.Errorf("guard: enable interception: %w", err)
	}

	go func() {
		for ev, err := range paused {
			if err != nil {
				return
			}
			g.dispatch(&ev, nil)
		}
	}()
	if err := g.guardExisting(tab); err != nil {
		g.Stop()
		return nil, fmt.Errorf("guard: %w (nothing was loaded; stopping rather than run unguarded)", err)
	}
	return g, nil
}

// held is a request held back, with the stage it waits on.
type held struct {
	ev      *fetch.EventRequestPaused
	headers map[string]string
	reason  string
	on      context.Context // the session of its stage; nil for the browser's
}

// stage is a target with interception of its own.
type stage struct {
	on     context.Context
	cancel context.CancelFunc // detaches; nil for the tab, which its owner closes
	kind   string
	url    string
}

// dispatch handles a paused request in a goroutine of its own, counting it
// so that Stop can wait for it.
func (g *Guard) dispatch(ev *fetch.EventRequestPaused, on context.Context) {
	g.mu.Lock()
	g.inflight++
	g.lastPaused = time.Now()
	g.mu.Unlock()
	go func() {
		defer func() {
			g.mu.Lock()
			g.inflight--
			g.mu.Unlock()
		}()
		g.handle(ev, on)
	}()
}

// guardExisting turns interception on, on its own session, for every
// target already running that the guard is for: the tab if it has a page
// loaded, the tab's frames and dedicated workers, and the service and
// shared workers in scope or of an origin one of the tab's frames is on.
// Browser-level interception does not reach them (measured: an attached
// tab's page, a service worker the user's visit started). Any that cannot
// be guarded fails the start.
func (g *Guard) guardExisting(tab context.Context) error {
	ctx, cancel := context.WithTimeout(g.base, 10*time.Second)
	res, err := chromedp.CallBrowser(ctx, target.GetTargets, target.GetTargetsParams{})
	cancel()
	if err != nil {
		return fmt.Errorf("list targets: %w", err)
	}
	infos := map[target.ID]*target.Info{}
	for _, ti := range res.TargetInfos {
		infos[ti.TargetID] = ti
	}
	tabInfo := infos[g.tabID]
	if tabInfo == nil {
		return fmt.Errorf("the tab is not among the targets")
	}
	descends := func(ti *target.Info) bool {
		for range 16 {
			if ti.ParentID == g.tabID {
				return true
			}
			if ti = infos[ti.ParentID]; ti == nil {
				return false
			}
		}
		return false
	}
	origins := map[string]bool{}
	note := func(raw string) {
		if u, err := url.Parse(raw); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			origins[u.Scheme+"://"+u.Host] = true
		}
	}
	note(tabInfo.URL)
	ctx, cancel = context.WithTimeout(tab, 10*time.Second)
	if tree, err := chromedp.Call(ctx, page.GetFrameTree, struct{}{}); err == nil {
		var walk func(*page.FrameTree)
		walk = func(t *page.FrameTree) {
			if t.Frame != nil {
				note(t.Frame.URL)
			}
			for _, c := range t.ChildFrames {
				walk(c)
			}
		}
		walk(tree.FrameTree)
	}
	cancel()
	for _, ti := range res.TargetInfos {
		if ti.Type == "iframe" && descends(ti) {
			note(ti.URL)
		}
	}
	inScope := g.opts.InScope
	if inScope == nil {
		inScope = func(string) bool { return true }
	}
	if web(tabInfo.URL) {
		if err := g.guardSession(tab, nil, "page", tabInfo.URL); err != nil {
			return fmt.Errorf("the tab: %w", err)
		}
	}
	for _, ti := range res.TargetInfos {
		if !web(ti.URL) {
			continue
		}
		var want bool
		switch ti.Type {
		case "iframe", "worker":
			want = descends(ti)
		case "service_worker", "shared_worker":
			u, _ := url.Parse(ti.URL)
			want = ti.BrowserContextID == tabInfo.BrowserContextID && (inScope(u.Hostname()) || origins[u.Scheme+"://"+u.Host])
		}
		if !want {
			continue
		}
		if err := g.attach(ti); err != nil {
			return fmt.Errorf("%s %s: %w", ti.Type, ti.URL, err)
		}
	}
	return nil
}

func web(raw string) bool {
	return strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")
}

// attach opens a session of the guard's own on a target, under a watchdog
// (chromedp's attach can block), and turns interception on there.
func (g *Guard) attach(ti *target.Info) error {
	ctx, cancel := chromedp.NewContext(g.base, chromedp.WithTargetID(ti.TargetID), chromedp.WithDetachOnCancel())
	done := make(chan error, 1)
	go func() { done <- chromedp.Do(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			cancel()
			return fmt.Errorf("attach: %w", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		return fmt.Errorf("attach: timed out")
	}
	if err := g.guardSession(ctx, cancel, ti.Type, ti.URL); err != nil {
		cancel()
		return err
	}
	return nil
}

// guardSession turns interception on for one session, and hears what it
// pauses and the Clear-Site-Data its responses carry.
func (g *Guard) guardSession(on context.Context, cancel context.CancelFunc, kind, u string) error {
	evCtx, stopEvents := context.WithCancel(on)
	paused := chromedp.Events(evCtx, fetch.RequestPaused)
	extra := chromedp.Events(evCtx, network.ResponseReceivedExtraInfo)
	ctx, done := context.WithTimeout(on, 10*time.Second)
	_, err := chromedp.Call(ctx, fetch.Enable, fetch.EnableParams{Patterns: []*fetch.RequestPattern{
		{URLPattern: "*", RequestStage: fetch.RequestStageRequest},
	}})
	done()
	if err != nil {
		stopEvents()
		return fmt.Errorf("enable interception: %w", err)
	}
	go func() {
		for ev, err := range paused {
			if err != nil {
				return
			}
			g.dispatch(&ev, on)
		}
	}()
	go func() {
		for ev, err := range extra {
			if err != nil {
				return
			}
			for k := range ev.Headers {
				if strings.EqualFold(k, "Clear-Site-Data") {
					g.NoteClearSiteData(string(ev.RequestID))
				}
			}
		}
	}()
	g.mu.Lock()
	g.stages = append(g.stages, &stage{on: on, cancel: func() {
		stopEvents()
		if cancel != nil {
			cancel()
		}
	}, kind: kind, url: u})
	g.stats.TargetsGuarded++
	g.mu.Unlock()
	slog.Debug("guard: interception on an existing target", "type", kind, "url", u)
	return nil
}

// NoteClearSiteData records a response that carried Clear-Site-Data, as
// the capture saw it on any of its sessions. It cannot be held back:
// Chrome acts on it before interception sees the response (tried: dropping
// the header, rewriting all headers, fulfilling the response anew; the
// cookies went each time). So it is detected and reported; restoring the
// session is the login step's job.
func (g *Guard) NoteClearSiteData(requestID string) {
	g.mu.Lock()
	seen := g.csd[requestID]
	g.csd[requestID] = true
	if !seen {
		g.stats.ClearSiteDataSeen++
	}
	g.mu.Unlock()
	if seen {
		return // heard on two sessions
	}
	slog.Warn("guard: a response carried Clear-Site-Data; the session's cookies or storage may be gone", "request", requestID)
}

// NoteWebSocket records a WebSocket that opened, as the capture saw it on
// any of its sessions. WebSockets cannot be intercepted over CDP; the page
// stub stops them in pages, so one seen here came from a worker or a frame
// the stub did not reach.
func (g *Guard) NoteWebSocket(url string) {
	g.mu.Lock()
	g.stats.WebSocketsSeen++
	g.mu.Unlock()
	slog.Warn("guard: a WebSocket opened and could not be held back", "url", traffic.LogURL(url))
}

// AddTab marks another tab as the tool's own, so that in attach mode its
// requests are guarded. Call it before the tab navigates.
func (g *Guard) AddTab(id target.ID) {
	g.mu.Lock()
	g.ours[id] = true
	g.mu.Unlock()
}

// RemoveTab is AddTab undone, for a tab that is closed.
func (g *Guard) RemoveTab(id target.ID) {
	g.mu.Lock()
	delete(g.ours, id)
	g.mu.Unlock()
}

// AllowWrites lets the writes of one frame (a tab's main frame has the
// tab's id) pass until done is called: a login script that jsharvest runs
// again to restore a session posts its form. Destructive requests are
// still held back.
func (g *Guard) AllowWrites(frame string) (done func()) {
	g.mu.Lock()
	if g.writers == nil {
		g.writers = map[string]int{}
	}
	g.writers[frame]++
	g.mu.Unlock()
	return func() {
		g.mu.Lock()
		if g.writers[frame]--; g.writers[frame] <= 0 {
			delete(g.writers, frame)
		}
		g.mu.Unlock()
	}
}

// HoldNavigations answers every navigation of one frame (a tab's main
// frame has the tab's id) with 204 until done is called. A 204 leaves the
// page and its state as they were, and the request never reaches the
// server: explore clicks a button that navigates and stays on the page,
// and TakeNavigations hands the URLs of the GET ones to the crawl. A
// navigation that writes (a POST form) is held back as any write is.
func (g *Guard) HoldNavigations(frame string) (done func()) {
	g.mu.Lock()
	if g.navHold == nil {
		g.navHold = map[string]int{}
	}
	g.navHold[frame]++
	g.mu.Unlock()
	return func() {
		g.mu.Lock()
		if g.navHold[frame]--; g.navHold[frame] <= 0 {
			delete(g.navHold, frame)
		}
		g.mu.Unlock()
	}
}

// holder is the frame whose navigations are held that a frame's
// navigation belongs to: the frame itself, or, for the main frame of a
// popup a held frame opened (or one such a popup opened), that frame: its
// first navigation is the held frame's own, as a click on a target=_blank
// link is. The popup's target is created before its request pauses
// (measured), so it is known by then. "" when none. Call it with g.mu held.
func (g *Guard) holder(frame string) string {
	if g.navHold[frame] > 0 {
		return frame
	}
	info, ok := g.pages[target.ID(frame)]
	for range 16 {
		if !ok || info.OpenerID == "" {
			return ""
		}
		if g.navHold[string(info.OpenerID)] > 0 {
			return string(info.OpenerID)
		}
		info, ok = g.pages[info.OpenerID]
	}
	return ""
}

// opener is the page that opened a popup's frame, through popups that
// opened popups: "" for a frame no page opened. A popup's held requests
// are its opener's tab's (crawl -tabs claims them by it). Call it with
// g.mu held.
func (g *Guard) opener(frame string) string {
	root := ""
	info, ok := g.pages[target.ID(frame)]
	for range 16 {
		if !ok || info.OpenerID == "" {
			break
		}
		root = string(info.OpenerID)
		info, ok = g.pages[info.OpenerID]
	}
	return root
}

// PassedLogin is how many writes of a frame passed as a login's
// (AllowWrites), since the guard started.
func (g *Guard) PassedLogin(frame string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.passedBy[frame]
}

// TakeNavigations returns the URLs of the GET navigations frame held (by
// HoldNavigations) since the last call: a tab's, popups it opened
// included; another tab's are its own (crawl -tabs).
func (g *Guard) TakeNavigations(frame string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := g.navHeld[frame]
	delete(g.navHeld, frame)
	return n
}

// handle answers one paused request, on the stage that paused it (on: its
// session, or nil for the browser's).
func (g *Guard) handle(ev *fetch.EventRequestPaused, on context.Context) {
	// Only the browser stage sees other tabs; a target stage is the guard's.
	if on == nil && g.opts.Attach && g.otherTab(string(ev.FrameID)) {
		g.answer(on, fetch.ContinueRequestParams{RequestID: ev.RequestID})
		g.mu.Lock()
		g.stats.PassedOtherTabs++
		g.mu.Unlock()
		return
	}
	req := ev.Request
	headers := flat(req.Headers)
	body := postData(req)
	// Layer 1, before every rule (Allow too: -guard-allow lets writes pass,
	// it does not open the internal network): a public page's request to a
	// private address is failed.
	if reason := g.privateRefused(ev, headers, on); reason != "" {
		h := &held{ev: ev, headers: headers, reason: reason, on: on}
		g.mu.Lock()
		g.pending[ev.RequestID] = h
		g.mu.Unlock()
		if err := g.answer(on, fetch.FailRequestParams{RequestID: ev.RequestID, ErrorReason: network.ErrorReasonBlockedByClient}); err != nil {
			g.answerHeld(h) // never left paused: it would be sent on Stop
		}
		g.record(ev, headers, body, Decision{Fail, reason})
		return
	}
	d := g.opts.Rules.Classify(Request{
		Method: req.Method, URL: req.URL, ContentType: headers["content-type"],
		Body: body, ResourceType: string(ev.ResourceType), Override: OverrideHeader(headers),
	})
	if d.Action == Fake && d.Reason != "destructive" {
		g.mu.Lock()
		w := g.writers[string(ev.FrameID)] > 0
		g.mu.Unlock()
		if w {
			d = Decision{Pass, "login"}
			g.mu.Lock()
			g.stats.PassedLogin++
			g.passedBy[string(ev.FrameID)]++
			g.mu.Unlock()
		}
	}
	if d.Action == Pass && ev.ResourceType == network.ResourceTypeDocument {
		g.mu.Lock()
		by := g.holder(string(ev.FrameID))
		hold := by != ""
		if hold {
			g.stats.HeldNavigations++
			if strings.EqualFold(req.Method, "GET") {
				if g.navHeld == nil {
					g.navHeld = map[string][]string{}
				}
				g.navHeld[by] = append(g.navHeld[by], req.URL)
			}
		}
		g.mu.Unlock()
		if hold {
			if err := g.answer(on, fake(ev, headers, "explore-navigation")); err != nil {
				g.answer(on, fetch.FailRequestParams{RequestID: ev.RequestID, ErrorReason: network.ErrorReasonAborted})
			}
			slog.Debug("guard: navigation held", "url", req.URL)
			return
		}
	}
	if d.Action == Pass {
		g.noteDocument(ev)
		g.answer(on, fetch.ContinueRequestParams{RequestID: ev.RequestID})
		return
	}

	// Held back: answer first, record afterwards.
	h := &held{ev: ev, headers: headers, reason: d.Reason, on: on}
	g.mu.Lock()
	g.pending[ev.RequestID] = h
	g.mu.Unlock()
	g.answerHeld(h)
	g.record(ev, headers, body, d)
}

// record notes one request the guard answered, and forgets it as pending.
func (g *Guard) record(ev *fetch.EventRequestPaused, headers map[string]string, body string, d Decision) {
	req := ev.Request
	g.mu.Lock()
	pageOf := g.pageOf
	g.mu.Unlock()
	page := ""
	if pageOf != nil {
		page = pageOf(string(ev.FrameID), string(ev.NetworkID))
	}
	if len(body) > maxBody {
		body = body[:maxBody]
	}
	g.mu.Lock()
	delete(g.pending, ev.RequestID)
	g.stats.Blocked++
	g.stats.ByReason[d.Reason]++
	g.records = append(g.records, Record{
		Time: time.Now().UTC(), Action: d.Action, Reason: d.Reason, Method: req.Method, URL: req.URL,
		ResourceType: string(ev.ResourceType), Headers: headers, Body: body,
		FrameID: string(ev.FrameID), NetworkID: string(ev.NetworkID), Page: page, Opener: g.opener(string(ev.FrameID)),
	})
	g.mu.Unlock()
	slog.Info("guard: held back", "reason", d.Reason, "method", req.Method, "url", traffic.LogURL(req.URL))
}

// answerHeld gives a held-back request its made-up answer, or, if that
// fails, fails it. It is never continued: Chrome would send it.
func (g *Guard) answerHeld(h *held) {
	if err := g.answer(h.on, fake(h.ev, h.headers, h.reason)); err != nil {
		g.answer(h.on, fetch.FailRequestParams{RequestID: h.ev.RequestID, ErrorReason: network.ErrorReasonBlockedByClient})
	}
}

// fake is the harmless success a held-back request gets. A navigation
// gets 204, which cancels it and leaves the page and its state as they
// were; a service worker proxies navigations as plain fetches, so a request
// that asks for HTML as a navigation does counts as one. Anything else gets
// an empty JSON object, with CORS headers that let a credentialed
// cross-origin caller read it. Either carries the guard's mark, so that the
// request log knows it from a server response.
func fake(ev *fetch.EventRequestPaused, headers map[string]string, reason string) fetch.FulfillRequestParams {
	mark := &fetch.HeaderEntry{Name: traffic.GuardHeader, Value: reason}
	if ev.ResourceType == network.ResourceTypeDocument || navigation(headers) {
		return fetch.FulfillRequestParams{RequestID: ev.RequestID, ResponseCode: 204, ResponseHeaders: []*fetch.HeaderEntry{mark}}
	}
	h := []*fetch.HeaderEntry{{Name: "Content-Type", Value: "application/json"}, {Name: "Cache-Control", Value: "no-store"}, mark}
	if o := headers["origin"]; o != "" {
		h = append(h,
			&fetch.HeaderEntry{Name: "Access-Control-Allow-Origin", Value: o},
			&fetch.HeaderEntry{Name: "Access-Control-Allow-Credentials", Value: "true"},
			&fetch.HeaderEntry{Name: "Vary", Value: "Origin"})
	}
	return fetch.FulfillRequestParams{RequestID: ev.RequestID, ResponseCode: 200, ResponseHeaders: h, Body: []byte("{}")}
}

// navigation reports whether a request is a navigation by its headers.
func navigation(h map[string]string) bool {
	return strings.HasPrefix(strings.TrimSpace(h["accept"]), "text/html") || h["upgrade-insecure-requests"] != "" ||
		h["sec-fetch-mode"] == "navigate"
}

// answer sends an answer on a stage: on a target's session, or (on nil)
// at browser level.
func (g *Guard) answer(on context.Context, params any) error {
	if g.answerFn != nil {
		return g.answerFn(on, params)
	}
	if on != nil && on.Err() != nil {
		return on.Err() // a session gone: a call on it would hang
	}
	parent := g.base
	if on != nil {
		parent = on
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	call := func(method string, p, res any) error {
		if on == nil {
			return chromedp.FromContext(g.base).Browser.Call(ctx, method, p, res)
		}
		return chromedp.FromContext(on).Target.Call(ctx, method, p, res)
	}
	var err error
	switch p := params.(type) {
	case fetch.ContinueRequestParams:
		err = call(fetch.ContinueRequest.Method, p, nil)
	case fetch.FulfillRequestParams:
		err = call(fetch.FulfillRequest.Method, p, nil)
	case fetch.FailRequestParams:
		err = call(fetch.FailRequest.Method, p, nil)
	}
	if err != nil {
		g.mu.Lock()
		g.stats.AnswerErrors++
		g.mu.Unlock()
		slog.Debug("guard: answer", "err", err)
	}
	return err
}

// trackPages follows the page targets of the browser, so that in attach
// mode the requests of the user's other tabs can pass.
func (g *Guard) trackPages(ctx context.Context) {
	created := chromedp.BrowserEvents(ctx, target.TargetCreated)
	changed := chromedp.BrowserEvents(ctx, target.TargetInfoChanged)
	destroyed := chromedp.BrowserEvents(ctx, target.TargetDestroyed)
	put := func(i *target.Info) {
		if i != nil && i.Type == "page" {
			g.mu.Lock()
			g.pages[i.TargetID] = *i
			g.mu.Unlock()
		}
	}
	go func() {
		for ev, err := range created {
			if err != nil {
				return
			}
			put(ev.TargetInfo)
		}
	}()
	go func() {
		for ev, err := range changed {
			if err != nil {
				return
			}
			put(ev.TargetInfo)
		}
	}()
	go func() {
		for ev, err := range destroyed {
			if err != nil {
				return
			}
			g.mu.Lock()
			delete(g.pages, ev.TargetID)
			delete(g.tops, string(ev.TargetID))
			g.mu.Unlock()
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if res, err := chromedp.CallBrowser(cctx, target.GetTargets, target.GetTargetsParams{}); err == nil {
		for _, i := range res.TargetInfos {
			put(i)
		}
	}
}

// otherTab reports whether a frame is, for sure, the main frame of a page
// that is not one of the tool's tabs and was not opened from one. Workers,
// service workers, popups, frames not yet seen: all are guarded.
func (g *Guard) otherTab(frame string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	info, ok := g.pages[target.ID(frame)]
	if !ok {
		return false
	}
	for range 16 {
		if g.ours[info.TargetID] {
			return false
		}
		if info.OpenerID == "" {
			return true
		}
		opener, ok := g.pages[info.OpenerID]
		if !ok {
			// Opened by a page we cannot see any more: not provably another tab.
			return false
		}
		info = opener
	}
	return false
}

// Stop ends interception. The caller closes the tab and its popups first,
// so that nothing new is paused (a beacon or keepalive request sent as the
// page unloads still is, a few milliseconds later). Stop then:
//  1. waits until no handler runs and nothing has been paused for 400 ms,
//     for at most 5 s;
//  2. answers whatever is still held back with its made-up answer (never a
//     failure, which a service worker's background sync would send again
//     later, after the guard is gone);
//  3. turns interception off on the targets' own stages and detaches:
//     anything paused there is paused again at the browser stage, which
//     is still on;
//  4. in attach mode only, turns the browser stage off. (Turning it off
//     sends paused requests on; in launch mode the browser dies with the
//     tool, so interception simply stays on.)
func (g *Guard) Stop() {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		quiet := g.inflight == 0 && time.Since(g.lastPaused) >= 400*time.Millisecond
		g.mu.Unlock()
		if quiet {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	g.mu.Lock()
	left := slices.Collect(maps.Values(g.pending))
	stages := g.stages
	g.stages = nil
	g.mu.Unlock()
	for _, h := range left {
		g.answerHeld(h)
	}
	for _, st := range stages {
		if st.on.Err() == nil {
			ctx, cancel := context.WithTimeout(st.on, 5*time.Second)
			chromedp.Call(ctx, fetch.Disable, struct{}{})
			cancel()
		}
		st.cancel()
	}
	if g.opts.Attach {
		ctx, cancel := context.WithTimeout(g.base, 5*time.Second)
		chromedp.CallBrowser(ctx, fetch.Disable, struct{}{})
		cancel()
	}
	g.stop()
}

// SetPage tells the guard where to read the page the tab is on.
func (g *Guard) SetPage(page func() string) {
	g.SetPageOf(func(string, string) string { return page() })
}

// SetPageOf tells the guard how to find the page of a held request, by
// its frame and network id: several tabs of one run (crawl -tabs) are on
// pages of their own.
func (g *Guard) SetPageOf(pageOf func(frame, networkID string) string) {
	g.mu.Lock()
	g.pageOf = pageOf
	g.mu.Unlock()
}

// Take returns what was held back since the last Take, with initiators
// filled in by lookup (by network id, from the capture's sessions).
func (g *Guard) Take(initiator func(networkID string) any) []Record {
	return g.TakeFor(nil, initiator)
}

// TakeFor is Take for one of several tabs at work at once (crawl -tabs):
// it returns only the records claim says are the tab's, and keeps the
// others for their own tab. A nil claim takes every record.
func (g *Guard) TakeFor(claim func(Record) bool, initiator func(networkID string) any) []Record {
	g.mu.Lock()
	var out, rest []Record
	for _, r := range g.records {
		if claim == nil || claim(r) {
			out = append(out, r)
		} else {
			rest = append(rest, r)
		}
	}
	g.records = rest
	g.mu.Unlock()
	for i := range out {
		if out[i].Initiator == nil && out[i].NetworkID != "" && initiator != nil {
			out[i].Initiator = initiator(out[i].NetworkID)
		}
	}
	return out
}

// Sub returns what was counted since prev, for one page of a batch that
// shares the guard.
func (s Stats) Sub(prev Stats) Stats {
	out := Stats{
		Blocked: s.Blocked - prev.Blocked, ByReason: map[string]int{},
		PassedOtherTabs: s.PassedOtherTabs - prev.PassedOtherTabs, ClearSiteDataSeen: s.ClearSiteDataSeen - prev.ClearSiteDataSeen,
		WebSocketsSeen: s.WebSocketsSeen - prev.WebSocketsSeen, AnswerErrors: s.AnswerErrors - prev.AnswerErrors,
		PassedLogin: s.PassedLogin - prev.PassedLogin, HeldNavigations: s.HeldNavigations - prev.HeldNavigations,
		// Counted once, at the guard's start, for every page it protects.
		TargetsGuarded: s.TargetsGuarded,
	}
	for k, n := range s.ByReason {
		if d := n - prev.ByReason[k]; d != 0 {
			out.ByReason[k] = d
		}
	}
	return out
}

func (g *Guard) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.stats
	s.ByReason = maps.Clone(g.stats.ByReason)
	return s
}

// socketStub runs in every page and frame before the page's own scripts.
// It replaces WebSocket and WebTransport, since CDP cannot intercept their
// traffic and the only way to keep their messages from the server is not
// to connect (a stubbed socket fails as a refused connection would); and it
// removes speculation rules, whose prefetches bypass interception.
const socketStub = `(() => {
  const note = () => {};
  class WebSocket extends EventTarget {
    constructor(url) {
      super(); this.url = String(url); this.readyState = 3; this.protocol = ""; this.extensions = "";
      this.bufferedAmount = 0; this.binaryType = "blob"; note(this.url);
      setTimeout(() => {
        const err = new Event("error"); this.dispatchEvent(err); if (this.onerror) this.onerror(err);
        const close = new CloseEvent("close", {code: 1006, wasClean: false}); this.dispatchEvent(close); if (this.onclose) this.onclose(close);
      }, 0);
    }
    send() {} close() {}
  }
  Object.assign(WebSocket, {CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3});
  window.WebSocket = WebSocket;
  if (window.WebTransport) window.WebTransport = class WebTransport { constructor(u) { note(u); throw new TypeError("Failed to construct 'WebTransport': Opening handshake failed."); } };
  // Speculation rules make the browser prefetch or prerender URLs outside
  // request interception. A launched browser has prediction turned off in
  // its profile; an attached one cannot, so the rules are removed as the
  // parser inserts them, before the browser acts on them.
  const drop = (n) => { if (n.tagName === "SCRIPT" && (n.type || "").toLowerCase() === "speculationrules") { n.remove(); } };
  new MutationObserver((ms) => { for (const m of ms) for (const n of m.addedNodes) { drop(n); if (n.querySelectorAll) n.querySelectorAll("script").forEach(drop); } })
    .observe(document, {childList: true, subtree: true});
})()
//# sourceURL=` + marker.Internal

// StubSockets installs the socket stub in the tab, for documents loaded
// from now on. Workers keep their sockets; those are recorded when seen.
// The identifier lets UnstubSockets take it out again.
func StubSockets(tab context.Context) (page.ScriptIdentifier, error) {
	ctx, cancel := context.WithTimeout(tab, 10*time.Second)
	defer cancel()
	res, err := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: socketStub})
	if err != nil {
		return "", err
	}
	return res.Identifier, nil
}

// UnstubSockets removes the stub from the documents to come.
func UnstubSockets(tab context.Context, id page.ScriptIdentifier) error {
	ctx, cancel := context.WithTimeout(tab, 10*time.Second)
	defer cancel()
	_, err := chromedp.Call(ctx, page.RemoveScriptToEvaluateOnNewDocument, page.RemoveScriptToEvaluateOnNewDocumentParams{Identifier: id})
	return err
}

func flat(h network.Headers) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = fmt.Sprint(v)
	}
	return out
}

func postData(r *network.Request) string {
	var b strings.Builder
	for _, e := range r.PostDataEntries {
		b.Write(e.Bytes)
	}
	return b.String()
}
