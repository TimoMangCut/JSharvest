package engine

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/domstorage"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/session"
)

const (
	// refreshEvery bounds how often a run reads the browser's cookies and
	// storage back into the snapshot (after a page that kept the session).
	refreshEvery = 5 * time.Second
	// apiThreshold is the run of 401s, on the app's own XHR/fetch calls
	// with no 2xx between, that makes the keeper doubt the session.
	apiThreshold = 5
	// apiConfirmWait is the pause before the doubt is checked against the
	// server: a SPA refreshes its token on a 401 by itself, and its calls
	// that follow answer 2xx.
	apiConfirmWait = 3 * time.Second
)

// ---- tabs of a shared keeper (crawl -urls -role, plan-28 section 5) ----

func (k *keeper) first() *engine {
	k.tabsMu.RLock()
	defer k.tabsMu.RUnlock()
	if len(k.tabs) == 0 {
		return nil
	}
	return k.tabs[0]
}

func (k *keeper) tabList() []*engine {
	k.tabsMu.RLock()
	defer k.tabsMu.RUnlock()
	return slices.Clone(k.tabs)
}

// join adds a tab of another run to a keeper the runs of one host share
// (C4: one browser context and one keeper for each host and role). It
// reports whether the tab is the first: only it attaches to the context's
// service and shared workers, as tab 1 of a frontier does.
func (k *keeper) join(e *engine) (first bool) {
	k.tabsMu.Lock()
	defer k.tabsMu.Unlock()
	first = len(k.tabs) == 0
	k.tabs = append(k.tabs, e)
	if k.target == "" {
		k.target = e.cfg.Target.String()
	}
	return first
}

func (k *keeper) leave(e *engine) {
	k.tabsMu.Lock()
	k.tabs = slices.DeleteFunc(k.tabs, func(t *engine) bool { return t == e })
	k.tabsMu.Unlock()
	k.mu.Lock()
	delete(k.scripts, e.mainFrameID())
	k.mu.Unlock()
}

// installFor puts the saved session into the browser for tab e: whole for
// the first run of the keeper; for a tab that joins later only its storage
// script. The context's cookies are live, maybe rotated since the snapshot
// was taken: putting the snapshot's back would undo that.
func (k *keeper) installFor(e *engine) error {
	k.imu.Lock()
	defer k.imu.Unlock()
	if !k.installed {
		if err := k.install(); err != nil {
			return err
		}
		k.installed = true
		return nil
	}
	k.wait()
	return k.setTabScript(e)
}

// statsCopy is the stats as of now, for a run record of a shared keeper.
func (k *keeper) statsCopy() *SessionStats {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := *k.stats
	s.Events = slices.Clone(k.stats.Events)
	if k.stats.API != nil {
		a := *k.stats.API
		s.API = &a
	}
	return &s
}

// ---- A: the rotated session goes back into the snapshot ----

// snapCopy is a shallow copy of the snapshot, safe to read: refresh
// replaces Cookies, Storage and Saved, never edits them.
func (k *keeper) snapCopy() *session.Snapshot {
	k.smu.RLock()
	defer k.smu.RUnlock()
	s := *k.login.Snapshot
	return &s
}

func (k *keeper) inScope() func(string) bool {
	if t := k.first(); t != nil {
		return t.cfg.InScope
	}
	return nil
}

func (k *keeper) isRecovering() bool {
	k.rmu.Lock()
	defer k.rmu.Unlock()
	return k.recovering
}

// refresh reads what tab e's browser holds (the context's cookies in scope,
// the storage of the page it is on) into the snapshot, when the session is
// alive: not mid-recovery, not lost, and the sign cookies there. It is
// called after a page that kept the session (check), at most every
// refreshEvery; force is the run's last call. A recovery that begins
// meanwhile (the epoch changes) voids what was read.
func (k *keeper) refresh(e *engine, force bool) {
	if !force && time.Since(time.Unix(0, k.lastRefresh.Load())) < refreshEvery {
		return
	}
	if !k.refreshing.CompareAndSwap(false, true) {
		return
	}
	defer k.refreshing.Store(false)
	if k.isRecovering() || k.lost() {
		return
	}
	ep := k.Epoch()
	cs, err := k.cookies(e)
	if err != nil {
		slog.Debug("session refresh: cookies", "err", err)
		return
	}
	r := session.Refresh{Cookies: cs}
	// Only the page's own origin can be read; the others keep what they had.
	if st, err := e.readStorage(); err == nil {
		r.Storage = map[string]session.Storage{st.origin: st.Storage}
	}
	k.lastRefresh.Store(time.Now().UnixNano())
	k.apply(r, ep, time.Now().UTC())
}

// apply is refresh without the browser: it takes r into the snapshot if no
// recovery began since epoch ep, the session is not lost, and r looks
// logged in.
func (k *keeper) apply(r session.Refresh, ep int64, now time.Time) bool {
	k.mu.Lock() // a recovery holds it: after it, the epoch has changed
	defer k.mu.Unlock()
	if k.stats.Lost || k.Epoch() != ep || k.isRecovering() {
		return false
	}
	k.smu.Lock()
	defer k.smu.Unlock()
	ok, why := k.login.Snapshot.Refresh(r, k.inScope(), now)
	if !ok {
		slog.Debug("session refresh skipped", "why", why)
		return false
	}
	k.dirty = true
	k.stats.Refreshed++
	return true
}

// finalize ends the keeper's run in tab e: one last refresh, and, if the
// session was never lost in this run, the profile's snapshot written with
// it (what else the file holds is kept), so that a later run, and
// authz -peers, find the token that lives. A lost session writes nothing:
// what the browser holds then is not the session.
func (k *keeper) finalize(e *engine) {
	k.waitAPI()
	if k.lost() || k.apiLostPending() {
		return
	}
	if !k.finalRead(e) {
		k.refresh(e, true)
	}
	k.saveState()
}

// endOverride goes back to the script that only fills missing keys; the
// caller holds k.mu.
func (k *keeper) endOverride() {
	if k.override.CompareAndSwap(true, false) {
		k.setScript()
	}
}

// finalOps are the browser's part of finalRead, apart for tests.
type finalOps struct {
	stop   func(e *engine) error // no more script of the app runs in e's page
	resume func(e *engine)
	read   func(e *engine, origins []string) (session.Refresh, error)
}

func (k *keeper) ops() finalOps {
	if k.finalOps != nil {
		return *k.finalOps
	}
	return finalOps{stop: stopScripts, resume: resumeScripts, read: k.readFinal}
}

// finalRead takes the run's last state of the session with the app stopped:
// a script read while the app lives can be older than the token the server
// holds by the time Chrome closes. Every tab's scripts are switched off
// (Emulation.setScriptExecutionDisabled: its timers and callbacks run no
// more, and the page and its frame stay, which DOMStorage needs), and then
// cookies and storage are read through CDP (storage.getCookies and
// DOMStorage), not through the page. It reports whether it applied a read;
// false leaves the caller the old way (refresh).
func (k *keeper) finalRead(e *engine) bool {
	o := k.ops()
	tabs := k.tabList()
	if len(tabs) == 0 {
		tabs = []*engine{e}
	}
	var stopped []*engine
	defer func() {
		for _, t := range stopped {
			o.resume(t)
		}
	}()
	for _, t := range tabs {
		if err := o.stop(t); err != nil {
			slog.Debug("final session read: stop the page", "err", err)
			continue
		}
		stopped = append(stopped, t)
	}
	if len(stopped) == 0 || k.isRecovering() || k.lost() {
		return false
	}
	ep := k.Epoch()
	var origins []string
	for origin := range k.snapCopy().Storage {
		origins = append(origins, origin)
	}
	r, err := o.read(e, origins)
	if err != nil {
		slog.Debug("final session read", "err", err)
		return false
	}
	return k.apply(r, ep, time.Now().UTC())
}

func stopScripts(e *engine) error {
	ctx, cancel := context.WithTimeout(e.tabCtx(), 5*time.Second)
	defer cancel()
	_, err := chromedp.Call(ctx, emulation.SetScriptExecutionDisabled, emulation.SetScriptExecutionDisabledParams{Value: true})
	return err
}

func resumeScripts(e *engine) {
	ctx, cancel := context.WithTimeout(e.tabCtx(), 5*time.Second)
	defer cancel()
	if _, err := chromedp.Call(ctx, emulation.SetScriptExecutionDisabled, emulation.SetScriptExecutionDisabledParams{Value: false}); err != nil {
		slog.Debug("final session read: resume the page", "err", err)
	}
}

// readFinal reads the context's cookies and the storage of each origin
// through CDP. An origin that cannot be read (no frame of it is open in
// the tab) is left out, and keeps what the snapshot had; none read at all
// is an error when the snapshot has storage.
func (k *keeper) readFinal(e *engine, origins []string) (session.Refresh, error) {
	cs, err := k.cookies(e)
	if err != nil {
		return session.Refresh{}, err
	}
	r := session.Refresh{Cookies: cs, Storage: map[string]session.Storage{}}
	ctx, cancel := k.call(e)
	defer cancel()
	chromedp.Call(ctx, domstorage.Enable, cdp.Empty{})
	defer chromedp.Call(ctx, domstorage.Disable, cdp.Empty{})
	var last error
	for _, o := range origins {
		st := session.Storage{}
		okAny := false
		for _, local := range []bool{true, false} {
			res, err := chromedp.Call(ctx, domstorage.GetDOMStorageItems, domstorage.GetDOMStorageItemsParams{
				StorageID: &domstorage.StorageID{SecurityOrigin: o, IsLocalStorage: local}})
			if err != nil {
				last = err
				continue
			}
			okAny = true
			m := map[string]string{}
			for _, it := range res.Entries {
				if len(it) == 2 {
					m[it[0]] = it[1]
				}
			}
			if local {
				st.Local = m
			} else {
				st.Session = m
			}
		}
		if okAny {
			r.Storage[o] = st
		}
	}
	if len(origins) > 0 && len(r.Storage) == 0 {
		return session.Refresh{}, fmt.Errorf("DOMStorage: %w", last)
	}
	return r, nil
}

func (k *keeper) saveState() bool {
	k.mu.Lock()
	lost := k.stats.Lost
	k.mu.Unlock()
	k.smu.Lock()
	if lost || !k.dirty || k.login.Profile == "" {
		k.smu.Unlock()
		return false
	}
	err := k.login.Snapshot.SaveState(k.login.Profile)
	if err == nil {
		k.dirty = false
	}
	k.smu.Unlock()
	if err != nil {
		slog.Warn("save the refreshed session", "err", err)
		return false
	}
	k.mu.Lock()
	k.stats.Saved = true
	k.mu.Unlock()
	return true
}

// ---- B: a run of 401s on the app's calls ----

// apiWatch counts the 401s of same-origin API calls since the last 2xx.
type apiWatch struct {
	mu   sync.Mutex
	n    int
	busy bool // a confirmation is under way
}

// note takes one response (already known to be same-origin and not the
// guard's) and reports whether it makes the run reach the threshold. Only
// 401 counts: a 403 on an XHR is as often a role's RBAC as an ended
// session. Any 2xx resets the count.
func (w *apiWatch) note(status, threshold int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case status >= 200 && status <= 299:
		w.n = 0
	case status == 401:
		w.n++
		if w.n >= threshold && !w.busy {
			w.busy = true
			return true
		}
	}
	return false
}

func (w *apiWatch) done() {
	w.mu.Lock()
	w.n, w.busy = 0, false
	w.mu.Unlock()
}

// countsAPI tells whether a response counts for the watch: the app's own
// origin (the target's, or the page's), and not made up by the guard,
// which is no word of the server (a 2xx of it must not reset the run, nor
// its 403/422 start one).
func countsAPI(target, page, rawURL string, guard bool) bool {
	return !guard && (sameOrigin(rawURL, target) || (page != "" && sameOrigin(rawURL, page)))
}

// apiStatus hears of an XHR/fetch response seen by tab e's capture
// (capture.Options.OnAPIStatus).
func (k *keeper) apiStatus(e *engine, rawURL string, status int, guard bool) {
	page := ""
	if e != nil {
		if h := e.currentHarvest(); h != nil {
			page = h.Page()
		}
	}
	if !countsAPI(k.target, page, rawURL, guard) || !k.api.note(status, apiThreshold) {
		return
	}
	k.apiMu.Lock()
	k.apiPending++
	k.apiMu.Unlock()
	k.mu.Lock()
	if k.stats.API == nil {
		k.stats.API = &APIStats{Threshold: apiThreshold}
	}
	k.stats.API.Triggers++
	k.mu.Unlock()
	go k.confirmAPI(e, page)
}

// confirmAPI waits a beat for the app to refresh its token by itself, then
// asks the server (the check URL, the sign cookies, the page the login
// ended on). Still failing: the verdict is set and the next check of any
// tab says "api-401", which takes the existing path to recover (on a page
// boundary, not under a page being loaded). Alive: the run is counted from
// zero again and an event notes it.
func (k *keeper) confirmAPI(e *engine, page string) {
	defer func() {
		k.api.done()
		k.apiMu.Lock()
		k.apiPending--
		k.apiMu.Unlock()
		k.apiCond.Broadcast()
	}()
	wait := k.apiWait
	if wait == 0 {
		wait = apiConfirmWait
	}
	time.Sleep(wait)
	gone := k.apiGone
	if k.apiGoneFn != nil {
		gone = k.apiGoneFn
	}
	if k.lost() || k.isRecovering() {
		return
	}
	g := gone(e)
	k.mu.Lock()
	defer k.mu.Unlock()
	if g {
		k.stats.API.Confirmed++
		k.apiMu.Lock()
		k.apiLost = true
		k.apiMu.Unlock()
		return
	}
	k.stats.API.NotConfirmed++
	k.stats.Events = append(k.stats.Events, SessionEvent{At: time.Now().UTC(), Page: page, Cause: "api-401",
		Outcome: "not-confirmed", Detail: "the session is alive on the server; the app refreshed its token or the 401s were its own"})
}

// apiGone tells whether the server says the session is gone: a sign cookie
// missing, or the check URL (or the landing page) failing.
func (k *keeper) apiGone(e *engine) bool {
	if cs, err := k.cookies(e); err == nil && len(k.snapCopy().Missing(cs)) > 0 {
		return true
	}
	return k.goneOnServer(e)
}

// waitAPI holds until the confirmations under way are done.
func (k *keeper) waitAPI() {
	k.apiMu.Lock()
	for k.apiPending > 0 {
		k.apiCond.Wait()
	}
	k.apiMu.Unlock()
}

func (k *keeper) apiLostPending() bool {
	k.apiMu.Lock()
	defer k.apiMu.Unlock()
	return k.apiLost
}

// takeAPILost waits for a confirmation under way, then takes the verdict.
func (k *keeper) takeAPILost() bool {
	k.waitAPI()
	k.apiMu.Lock()
	defer k.apiMu.Unlock()
	v := k.apiLost
	k.apiLost = false
	return v
}
