package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Login is a saved login a crawl runs with (see package session).
type Login struct {
	Profile  string
	Snapshot *session.Snapshot
	Steps    []session.Step // the login script, to log in again; nil when there is none
}

// SessionStats goes into run.json.
type SessionStats struct {
	Profile  string         `json:"profile"`
	Signs    []string       `json:"signs"` // the cookies that tell a logged-in browser
	CheckURL string         `json:"check_url,omitempty"`
	Events   []SessionEvent `json:"events,omitempty"`
	Restored int            `json:"restored"` // losses put right with the saved cookies and storage
	Relogins int            `json:"relogins"` // and with the login script
	// Lost: the session went and could not be restored; the crawl stopped
	// there, and what came before is kept.
	Lost bool `json:"lost"`
	// Refreshed: times the saved cookies and storage were brought up to
	// what the browser holds (a rotated refresh token); Saved: the
	// profile's snapshot was written with them at the run's end.
	Refreshed int  `json:"refreshed,omitempty"`
	Saved     bool `json:"saved,omitempty"`
	// API: the keeper's watch of 401s on the app's own XHR/fetch calls.
	API *APIStats `json:"api,omitempty"`
}

// APIStats counts the API-level watch: a run of 401s reaching the
// threshold (Triggers), and what the check that follows found.
type APIStats struct {
	Threshold    int `json:"threshold"`
	Triggers     int `json:"triggers"`
	Confirmed    int `json:"confirmed"`
	NotConfirmed int `json:"not_confirmed"`
}

type SessionEvent struct {
	At      time.Time `json:"at"`
	Page    string    `json:"page"`
	Cause   string    `json:"cause"`   // clear-site-data, cookies, login-page, status
	Outcome string    `json:"outcome"` // restored, relogin, failed
	Detail  string    `json:"detail,omitempty"`
}

// maxRecoveries bounds the work a run spends on its session.
const maxRecoveries = 10

// keeper keeps the crawl's session, for every tab of the run: they share
// one browser context, and so one session (crawl -tabs).
type keeper struct {
	login   *Login
	stats   *SessionStats
	target  string                           // the crawl's start: a crawl of the login page is not a loss
	tabs    []*engine                        // the first is the one install and the cookies go through
	scripts map[string]page.ScriptIdentifier // the storage script, by tab (main frame)

	// tabsMu guards tabs and joined when the keeper is shared by the
	// runs of a batch (join, leave); a frontier's tabs are fixed.
	tabsMu    sync.RWMutex
	imu       sync.Mutex // install: once, then a joining tab only gets its script
	installed bool

	// smu guards the snapshot's cookies, storage and saved time, which
	// refresh replaces while other tabs read them. The slices and maps are
	// replaced, never edited, so what a reader copied stays whole.
	smu   sync.RWMutex
	dirty bool // refreshed since the profile's snapshot was last written

	refreshing  atomic.Bool
	lastRefresh atomic.Int64 // unix nanos

	// override: scripts put in the tabs set the snapshot's storage keys
	// over what the browser holds (install, recover) until the first page
	// is checked, then only the missing ones (RestoreScript).
	override atomic.Bool
	finalOps *finalOps // test seam

	api        apiWatch
	apiMu      sync.Mutex // pending confirmations (apiCond), and the verdict
	apiCond    *sync.Cond
	apiPending int
	apiLost    bool               // a confirmed run of 401s: the next check says "api-401"
	apiWait    time.Duration      // test seam; 0 is apiConfirmWait
	apiGoneFn  func(*engine) bool // test seam; nil is keeper.apiGone

	mu    sync.Mutex   // one recovery at a time; stats
	epoch atomic.Int64 // recoveries begun: a page that saw it change loaded while the session was lost

	rmu        sync.Mutex
	rcond      *sync.Cond
	recovering bool        // no tab starts a page, nor an action, meanwhile (wait)
	relogging  atomic.Bool // login steps are running: capture redacts credentials
}

func newKeeper(tabs []*engine, l *Login) *keeper {
	k := &keeper{login: l, tabs: tabs, scripts: map[string]page.ScriptIdentifier{},
		stats: &SessionStats{Profile: l.Profile, Signs: l.Snapshot.Signs.Cookies, CheckURL: l.Snapshot.Signs.CheckURL}}
	if len(tabs) > 0 {
		k.target = tabs[0].cfg.Target.String()
	}
	k.rcond = sync.NewCond(&k.rmu)
	k.apiCond = sync.NewCond(&k.apiMu)
	return k
}

func (k *keeper) call(e *engine) (context.Context, context.CancelFunc) {
	return context.WithTimeout(e.tabCtx(), 15*time.Second)
}

// Epoch is the count of recoveries begun: a tab notes it before a page,
// and a page after which it changed loaded while the session was lost.
func (k *keeper) Epoch() int64 { return k.epoch.Load() }

// wait holds a tab while another puts the session back.
func (k *keeper) wait() {
	k.rmu.Lock()
	for k.recovering {
		k.rcond.Wait()
	}
	k.rmu.Unlock()
}

func (k *keeper) setRecovering(on bool) {
	k.rmu.Lock()
	k.recovering = on
	k.rmu.Unlock()
	k.rcond.Broadcast()
}

func (k *keeper) isRelogging() bool {
	return k != nil && k.relogging.Load()
}

// lost reports whether the session went for good.
func (k *keeper) lost() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.stats.Lost
}

// install puts the saved session into the browser before the first page:
// its cookies, and the script that fills the storage each document of a
// saved origin is missing.
//
// The profile is kept for the login, not for the app's caches: an
// installed service worker and its CacheStorage hide scripts the crawl is
// there to see (the worker installed on the login's visit is not fetched
// again), and the HTTP cache serves what the server served on an earlier
// run, not what it serves now. They are cleared first; cookies and
// localStorage stay.
func (k *keeper) install() error {
	k.clearAppCaches()
	k.override.Store(true)
	if err := k.setCookies(k.first()); err != nil {
		return err
	}
	return k.setScript()
}

func (k *keeper) clearAppCaches() {
	origins := map[string]bool{}
	for o := range k.snapCopy().Storage {
		origins[o] = true
	}
	for _, raw := range []string{k.target, k.login.Snapshot.FinalURL, k.login.Snapshot.LoginURL} {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			origins[u.Scheme+"://"+u.Host] = true
		}
	}
	ctx, cancel := k.call(k.first())
	defer cancel()
	if _, err := chromedp.Call(ctx, network.ClearBrowserCache, cdp.Empty{}); err != nil {
		slog.Debug("clear the HTTP cache", "err", err)
	}
	for o := range origins {
		if _, err := chromedp.Call(ctx, storage.ClearDataForOrigin, storage.ClearDataForOriginParams{Origin: o,
			StorageTypes: "service_workers,cache_storage"}); err != nil {
			slog.Debug("clear the app's caches", "origin", o, "err", err)
		}
	}
}

func (k *keeper) setCookies(e *engine) error {
	ctx, cancel := k.call(e)
	defer cancel()
	if _, err := chromedp.CallBrowser(ctx, storage.SetCookies, storage.SetCookiesParams{Cookies: k.snapCopy().Params(), BrowserContextID: browserContext(e.tabCtx())}); err != nil {
		return fmt.Errorf("session cookies: %w", err)
	}
	return nil
}

// setScript puts the storage script in every tab: a document runs the
// scripts of its own tab (REV-C-03), and a new login's storage is every
// tab's.
func (k *keeper) setScript() error {
	for _, t := range k.tabList() {
		if err := k.setTabScriptLocked(t); err != nil {
			return err
		}
	}
	return nil
}

// setTabScript installs the storage script on one newly recycled tab.
func (k *keeper) setTabScript(t *engine) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.setTabScriptLocked(t)
}

func (k *keeper) setTabScriptLocked(t *engine) error {
	snap := k.snapCopy()
	src := snap.RestoreScript()
	if k.override.Load() {
		src = snap.OverrideScript()
	}
	mid := t.mainFrameID()
	old := k.scripts[mid]
	if src == "" {
		if old != "" {
			ctx, cancel := k.call(t)
			chromedp.Call(ctx, page.RemoveScriptToEvaluateOnNewDocument, page.RemoveScriptToEvaluateOnNewDocumentParams{Identifier: old})
			cancel()
			delete(k.scripts, mid)
		}
		return nil
	}
	ctx, cancel := k.call(t)
	if old != "" {
		chromedp.Call(ctx, page.RemoveScriptToEvaluateOnNewDocument, page.RemoveScriptToEvaluateOnNewDocumentParams{Identifier: old})
	}
	res, err := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: src})
	cancel()
	if err != nil {
		return fmt.Errorf("session storage: %w", err)
	}
	k.scripts[mid] = res.Identifier
	return nil
}

// browserContext is the browser context of a tab: "" for the browser's
// own, another for each URL of crawl -urls -tabs.
func browserContext(tab context.Context) cdp.BrowserContextID {
	if c := chromedp.FromContext(tab); c != nil {
		return c.BrowserContextID
	}
	return ""
}

func (k *keeper) cookies(e *engine) ([]*network.Cookie, error) {
	ctx, cancel := k.call(e)
	defer cancel()
	res, err := chromedp.CallBrowser(ctx, storage.GetCookies, storage.GetCookiesParams{BrowserContextID: browserContext(e.tabCtx())})
	if err != nil {
		return nil, err
	}
	return session.InScope(res.Cookies, e.cfg.InScope), nil
}

// check tells whether the session was lost by the page a tab just loaded,
// and why: a Clear-Site-Data response in that tab, a sign cookie gone, the
// login page, or a 401 or 403 for the page.
func (k *keeper) check(e *engine, doc detect.Doc, requested string) string {
	if k.override.Load() {
		// The first page of the run is loaded: from here the snapshot only
		// fills the keys that are missing, never undoing what the app rotated.
		k.mu.Lock()
		k.endOverride()
		k.mu.Unlock()
	}
	cause := k.checkPage(e, doc, requested)
	if cause == "" {
		k.refresh(e, false)
	}
	return cause
}

func (k *keeper) checkPage(e *engine, doc detect.Doc, requested string) string {
	if k.takeAPILost() {
		// A run of 401s on the app's calls, confirmed by the server: the
		// session ended while pages loaded (see apiStatus).
		e.keeperCSD.Store(0)
		e.keeperLogin.Store(0)
		return "api-401"
	}
	sentToLogin := e.keeperLogin.Swap(0) > 0
	if e.keeperCSD.Swap(0) > 0 {
		return "clear-site-data"
	}
	if cs, err := k.cookies(e); err == nil {
		if miss := k.login.Snapshot.Missing(cs); len(miss) > 0 {
			return "cookies"
		}
	}
	if pathOf(requested) == pathOf(k.login.Snapshot.LoginURL) {
		// The crawl went to the login page itself: no sign of a loss.
		return ""
	}
	if cause := k.pageCause(doc); cause != "" {
		return cause
	}
	if sentToLogin && k.goneOnServer(e) {
		// The document came while logged in, but a request of the page
		// (its chunk, its API call) was sent to the login page, and the
		// session is gone now: it ended on the server meanwhile (another
		// tab's page ended it, or it timed out), and what the page loaded
		// after is missing.
		return "login-redirect"
	}
	return ""
}

// goneOnServer confirms a loss a redirect to the login page suggests,
// without touching the tab's page: the check URL fails, or, with none, the
// page the login ended on is itself sent away (a fetch that does not
// follow redirects reads 0) or refused. A redirect to the login page alone
// is no loss: an app sends there a script the role may not have (a user's
// page asking for an admin's chunk) while the session lives, and each such
// page would spend a recovery. Unconfirmed, the signal is left: a URL of
// another origin than the tab's (asked without the session's cookies), a
// fetch that failed.
func (k *keeper) goneOnServer(e *engine) bool {
	page := e.harvest.Page()
	if c := k.login.Snapshot.Signs.CheckURL; c != "" && sameOrigin(c, page) {
		r, err := e.pageFetchMode(c, false, "no-store")
		if err != nil || r.Status < 0 {
			return false
		}
		return r.Status < 200 || r.Status > 299 // 0: sent away
	}
	landed := k.login.Snapshot.FinalURL
	if landed == "" || pathOf(landed) == pathOf(k.login.Snapshot.LoginURL) || !sameOrigin(landed, page) {
		return false
	}
	r, err := e.pageFetchMode(landed, false, "no-store")
	return err == nil && (r.Status == 0 || r.Status == 401 || r.Status == 403)
}

// loginRedirect tells whether a redirect from one URL to another sends a
// request to the login page: the login URL's host and path, from another
// path. A crawl that starts on the login page has none (its own redirects
// are the login's), nor a login page at "/" (every redirect home would be
// one).
func (k *keeper) loginRedirect(from, to string) bool {
	return isLoginRedirect(k.login.Snapshot.LoginURL, k.target, from, to)
}

func isLoginRedirect(loginURL, target, from, to string) bool {
	login := pathOf(loginURL)
	if login == "" || login == "/" || pathOf(target) == login || pathOf(to) != login || pathOf(from) == login {
		return false
	}
	lu, err1 := url.Parse(loginURL)
	tu, err2 := url.Parse(to)
	return err1 == nil && err2 == nil && strings.EqualFold(lu.Host, tu.Host)
}

// pageCause tells whether a page shows a logged-out browser: the login
// page, or a 401 or 403.
func (k *keeper) pageCause(doc detect.Doc) string {
	if login := pathOf(k.login.Snapshot.LoginURL); login != "" && login != "/" && pathOf(doc.URL) == login &&
		pathOf(k.target) != login {
		return "login-page"
	}
	if _, fromGuard := doc.Headers[strings.ToLower(traffic.GuardHeader)]; fromGuard {
		return "" // the guard made that answer up: no word of the server
	}
	if doc.Status == 401 || doc.Status == 403 {
		// A login kept in storage (no sign cookie) puts its token on the
		// app's own requests, never on a navigation: a document the
		// frontier opens (an API URL from the code, P5.6 Jellyfin) answers
		// 401/403 whatever the session is. Its loss shows on the app's own
		// requests (the API watch) and the check URL instead.
		if k.login != nil && k.login.Snapshot != nil && len(k.login.Snapshot.Signs.Cookies) == 0 &&
			len(k.login.Snapshot.Signs.Keys) == 0 {
			return ""
		}
		return "status"
	}
	return ""
}

func pathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimRight(u.Path, "/") + "/"
}

// verify tells whether the browser is logged in, after recover loaded a
// page in tab e: the sign cookies are there, that page was not sent back
// to the login page, and the check URL, if any, answers 2xx.
func (k *keeper) verify(e *engine) (bool, string) {
	cs, err := k.cookies(e)
	if err != nil {
		return false, err.Error()
	}
	if miss := k.login.Snapshot.Missing(cs); len(miss) > 0 {
		return false, "missing cookies " + strings.Join(miss, ",")
	}
	doc := e.harvest.MainDocument()
	if cause := k.pageCause(doc); cause != "" {
		return false, fmt.Sprintf("%s led to %s (%s)", k.login.Snapshot.FinalURL, doc.URL, cause)
	}
	return k.checkURL(e)
}

func (k *keeper) checkURL(e *engine) (bool, string) {
	if c := k.login.Snapshot.Signs.CheckURL; c != "" {
		r, err := e.pageFetchMode(c, false, "no-store")
		if err != nil || r.Status < 200 || r.Status > 299 {
			return false, fmt.Sprintf("%s answered %d", c, r.Status)
		}
	}
	return true, ""
}

// alive tells whether the session another tab put back is still there, as
// seen from tab e, whose page is where the loss left it (NEW-C4-01): the
// sign cookies and the check URL; with no check URL, a page loaded anew.
func (k *keeper) alive(ctx context.Context, e *engine) bool {
	cs, err := k.cookies(e)
	if err != nil || len(k.login.Snapshot.Missing(cs)) > 0 {
		return false
	}
	if k.login.Snapshot.Signs.CheckURL != "" {
		ok, _ := k.checkURL(e)
		return ok
	}
	e.reload(ctx, k.login.Snapshot.FinalURL)
	ok, _ := k.verify(e)
	return ok
}

// recover puts the session back after tab e saw it lost on a page begun
// at epoch ep: the saved cookies (the storage script is in place already),
// then, if that is not enough and there is a login script, a new login. It
// reports whether the browser is logged in again; when not, the session is
// lost for the run. If another tab put it back after the page began, it
// only checks that it is still there.
func (k *keeper) recover(ctx context.Context, e *engine, ep int64, cause, pageURL string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.stats.Lost {
		return false
	}
	if k.epoch.Load() != ep && k.alive(ctx, e) {
		e.keeperCSD.Store(0)
		e.keeperLogin.Store(0)
		return true
	}
	k.setRecovering(true)
	defer k.setRecovering(false)
	k.epoch.Add(1)
	ev := SessionEvent{At: time.Now().UTC(), Page: pageURL, Cause: cause}
	defer func() {
		k.stats.Events = append(k.stats.Events, ev)
		if ev.Outcome == "failed" {
			k.stats.Lost = true
		}
	}()
	if k.stats.Restored+k.stats.Relogins >= maxRecoveries {
		ev.Outcome, ev.Detail = "failed", fmt.Sprintf("%d recoveries in this run already", maxRecoveries)
		return false
	}
	slog.Warn("session lost; restoring it", "cause", cause, "page", logURL(pageURL), "tab", e.lane)
	if err := k.setCookies(e); err != nil {
		ev.Outcome, ev.Detail = "failed", err.Error()
		return false
	}
	// The snapshot is the better word for the storage too: the page that
	// loads next gets its keys over what the browser holds.
	k.override.Store(true)
	k.setScript()
	defer k.endOverride()
	// The check URL is asked from the page: load one of the target's.
	e.reload(ctx, k.login.Snapshot.FinalURL)
	ok, why := k.verify(e)
	defer e.keeperCSD.Store(0) // what recovering loaded is not a new loss
	defer e.keeperLogin.Store(0)
	if ok {
		k.stats.Restored++
		ev.Outcome = "restored"
		slog.Info("session restored from the saved cookies and storage")
		return true
	}
	if len(k.login.Steps) == 0 {
		ev.Outcome, ev.Detail = "failed", why+"; no login script to log in again"
		return false
	}
	snap, err := k.relogin(ctx, e)
	if err != nil {
		ev.Outcome, ev.Detail = "failed", why+"; login again: "+err.Error()
		return false
	}
	if ok, why2 := k.finishRelogin(snap, func() (bool, string) { return k.verify(e) }); !ok {
		ev.Outcome, ev.Detail = "failed", "after logging in again: "+why2
		return false
	}
	k.stats.Relogins++
	ev.Outcome, ev.Detail = "relogin", why
	slog.Info("session restored by logging in again")
	return true
}

// relogin runs the login script in tab e, the guard letting that tab's
// writes through (destructive ones still held back), and builds the candidate
// snapshot without saving or pushing scripts until verify succeeds.
func (k *keeper) relogin(ctx context.Context, e *engine) (*session.Snapshot, error) {
	k.relogging.Store(true)
	defer k.relogging.Store(false)
	if g := e.guard; g != nil {
		done := g.AllowWrites(e.mainFrameID())
		defer done()
	}
	before, _ := k.cookies(e)
	if err := session.Run(e.tabCtx(), k.login.Steps, 30*time.Second); err != nil {
		return nil, err
	}
	e.settle(ctx)
	after, err := k.cookies(e)
	if err != nil {
		return nil, err
	}
	var stPtr *originStorage
	if st, err := e.readStorage(); err == nil {
		stPtr = &st
	}
	return k.buildReloginSnapshot(before, after, stPtr), nil
}

func (k *keeper) buildReloginSnapshot(before, after []*network.Cookie, st *originStorage) *session.Snapshot {
	snap := *k.snapCopy()
	snap.Storage = maps.Clone(snap.Storage)
	snap.Cookies, snap.Saved = after, time.Now().UTC()
	if fresh := session.NewCookies(before, after); len(fresh) > 0 && len(snap.Signs.Cookies) == 0 {
		snap.Signs.Cookies, snap.Signs.Keys = fresh, session.NewCookieKeys(before, after)
	}
	if st != nil {
		if snap.Storage == nil {
			snap.Storage = map[string]session.Storage{}
		}
		snap.Storage[st.origin] = st.Storage
	}
	return &snap
}

// finishRelogin installs snap in memory so verify can inspect it, and only
// saves it to disk and updates tab scripts when verify passes. Call with k.mu held.
func (k *keeper) finishRelogin(snap *session.Snapshot, verify func() (bool, string)) (bool, string) {
	k.smu.Lock()
	prev, prevDirty := k.login.Snapshot, k.dirty
	k.login.Snapshot = snap
	k.smu.Unlock()

	if ok, why := verify(); !ok {
		k.smu.Lock()
		k.login.Snapshot, k.dirty = prev, prevDirty
		k.smu.Unlock()
		return false, why
	}

	k.smu.Lock()
	k.dirty = false
	prof := k.login.Profile
	k.smu.Unlock()
	if prof != "" {
		if err := snap.Save(prof); err != nil {
			slog.Warn("save the new session", "err", err)
		} else {
			k.stats.Saved = true
		}
	}
	if err := k.setScript(); err != nil {
		slog.Warn("save the new session script", "err", err)
	}
	return true, ""
}

type originStorage struct {
	origin string
	session.Storage
}

// readStorage reads the current document's localStorage and
// sessionStorage, from the isolated world: the page cannot answer for it.
func (e *engine) readStorage() (originStorage, error) {
	ctx, cancel := context.WithTimeout(e.tabCtx(), 10*time.Second)
	defer cancel()
	world, err := e.isolatedWorld(ctx)
	if err != nil {
		return originStorage{}, err
	}
	byValue := true
	res, err := chromedp.Call(ctx, runtime.Evaluate, runtime.EvaluateParams{Expression: session.StorageScript, ReturnByValue: &byValue, ContextID: world})
	if err != nil {
		e.world = 0
		return originStorage{}, err
	}
	var v struct {
		Origin  string            `json:"origin"`
		Local   map[string]string `json:"local"`
		Session map[string]string `json:"session"`
	}
	if res.Result == nil || json.Unmarshal(res.Result.Value, &v) != nil {
		return originStorage{}, fmt.Errorf("no storage")
	}
	return originStorage{origin: v.Origin, Storage: session.Storage{Local: v.Local, Session: v.Session}}, nil
}

// reload loads a URL in the tab and lets it settle, for the session's
// own needs (not a page of the crawl).
func (e *engine) reload(ctx context.Context, u string) {
	if u == "" {
		u = e.cfg.Target.String()
	}
	e.world = 0
	nctx, cancel := context.WithTimeout(e.tabCtx(), e.cfg.NavTimeout)
	if err := chromedp.Do(nctx, chromedp.Navigate(u)); err != nil {
		slog.Debug("session: load", "url", u, "err", err)
	}
	cancel()
	e.settle(ctx)
	e.world = 0
}
