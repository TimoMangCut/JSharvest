package capture

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

// targetManager finds the targets that belong to the tab and attaches a
// session to each.
//
// It listens at browser level, which also reports shared workers and nested
// workers that the tab's own auto-attach never shows. That level sees every
// target of the browser, so each one is checked against the tab:
//   - a frame or a worker must lead back to the tab through its ParentID chain;
//   - a service or shared worker belongs to no tab, so it must share the tab's
//     browser context and have an in-scope URL;
//   - only http(s) targets count, which leaves out extensions.
type targetManager struct {
	c        *Capture
	tabID    target.ID
	tabCtxID cdp.BrowserContextID
	ctx      context.Context
	cancel   context.CancelFunc

	mu        sync.Mutex
	infos     map[target.ID]target.Info
	tried     map[target.ID]bool // attached, attaching, or failed; never retried
	gone      map[target.ID]bool
	bySession map[target.SessionID]target.ID
	attaching int // attaches in progress; idle waits for them
	stopped   bool
	// held are the workers paused at start, by the tab's auto-attach
	// session that holds each; done are the targets whose attach has
	// returned. See holdWorkers.
	held map[target.ID]target.SessionID
	done map[target.ID]bool

	// attachFn attaches to one target; attach in production, a recorder in
	// tests. It must call attachDone when it returns.
	attachFn func(target.Info)
}

var wantedTypes = map[string]bool{"iframe": true, "worker": true, "service_worker": true, "shared_worker": true}

func startTargets(c *Capture, tabID target.ID) (*targetManager, error) {
	ctx, cancel := context.WithCancel(c.tab)
	tm := newTargetManager(c, tabID, ctx, cancel)

	// The first browser context reports an empty id through chromedp, so ask
	// Chrome for the tab's own.
	cctx, ccancel := context.WithTimeout(ctx, c.opts.CallTimeout)
	res, err := chromedp.CallBrowser(cctx, target.GetTargetInfo, target.GetTargetInfoParams{TargetID: tabID})
	ccancel()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("capture: tab info: %w", err)
	}
	tm.tabCtxID = res.TargetInfo.BrowserContextID

	created := chromedp.BrowserEvents(ctx, target.TargetCreated)
	changed := chromedp.BrowserEvents(ctx, target.TargetInfoChanged)
	destroyed := chromedp.BrowserEvents(ctx, target.TargetDestroyed)
	detached := chromedp.BrowserEvents(ctx, target.DetachedFromTarget)

	go func() {
		for ev, err := range created {
			if err != nil {
				return
			}
			tm.consider(*ev.TargetInfo)
		}
	}()
	go func() {
		for ev, err := range changed {
			if err != nil {
				return
			}
			tm.consider(*ev.TargetInfo)
		}
	}()
	go func() {
		for ev, err := range destroyed {
			if err != nil {
				return
			}
			tm.targetGone(ev.TargetID)
		}
	}()
	go func() {
		for ev, err := range detached {
			if err != nil {
				return
			}
			tm.mu.Lock()
			id, ok := tm.bySession[ev.SessionID]
			tm.mu.Unlock()
			if ok {
				tm.targetGone(id)
			}
		}
	}()

	if c.opts.recording() {
		if err := tm.holdWorkers(); err != nil {
			// Not fatal: a worker's first requests may go unrecorded.
			slog.Warn("capture: cannot pause workers at start; their first requests may be missed", "err", err)
		}
	}

	// Discovery reports every existing target too, so this also catches what
	// started before the subscriptions.
	cctx, ccancel = context.WithTimeout(ctx, c.opts.CallTimeout)
	_, err = chromedp.CallBrowser(cctx, target.SetDiscoverTargets, target.SetDiscoverTargetsParams{Discover: true})
	ccancel()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("capture: discover targets: %w", err)
	}
	return tm, nil
}

func newTargetManager(c *Capture, tabID target.ID, ctx context.Context, cancel context.CancelFunc) *targetManager {
	tm := &targetManager{
		c: c, tabID: tabID, ctx: ctx, cancel: cancel,
		infos:     map[target.ID]target.Info{},
		tried:     map[target.ID]bool{},
		gone:      map[target.ID]bool{},
		bySession: map[target.SessionID]target.ID{},
		held:      map[target.ID]target.SessionID{},
		done:      map[target.ID]bool{},
	}
	tm.attachFn = tm.attach
	return tm
}

// consider records a target's latest info and attaches to every known
// target that now belongs to the tab. A worker or frame often has no URL yet
// when it is created, so TargetInfoChanged gives it a second chance; and the
// events of a child and of its parent arrive on separate subscriptions, so a
// child can come first and only qualify once its parent is known. Each event
// therefore looks at all the targets not tried yet.
func (tm *targetManager) consider(info target.Info) {
	tm.c.touch()
	tm.mu.Lock()
	tm.infos[info.TargetID] = info
	var ready []target.Info
	if !tm.stopped {
		for id, cand := range tm.infos {
			if tm.tried[id] || tm.gone[id] || !tm.wanted(cand) {
				continue
			}
			tm.tried[id] = true
			tm.attaching++
			ready = append(ready, cand)
		}
	}
	tm.mu.Unlock()
	for _, cand := range ready {
		go tm.attachFn(cand)
	}
}

// attachDone ends an attach that consider started.
func (tm *targetManager) attachDone() {
	tm.mu.Lock()
	tm.attaching--
	tm.mu.Unlock()
	tm.c.touch()
}

// pending reports how many attaches are still running.
func (tm *targetManager) pending() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.attaching
}

// wanted is called with tm.mu held.
func (tm *targetManager) wanted(info target.Info) bool {
	if !wantedTypes[info.Type] {
		return false
	}
	u, err := url.Parse(info.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	switch info.Type {
	case "service_worker", "shared_worker":
		return !tm.c.opts.NoSharedWorkers && info.BrowserContextID == tm.tabCtxID && tm.c.opts.InScope(u.Hostname())
	default:
		return tm.descendsFromTab(info)
	}
}

// descendsFromTab follows ParentID up to the tab. Called with tm.mu held.
func (tm *targetManager) descendsFromTab(info target.Info) bool {
	for range 16 {
		if info.ParentID == tm.tabID {
			return true
		}
		parent, ok := tm.infos[info.ParentID]
		if !ok {
			return false
		}
		info = parent
	}
	return false
}

// holdWorkers makes the tab's dedicated workers wait at start until the
// capture has a session on them, so that the request log sees their first
// requests (Debugger replays scripts that already ran; Network has no such
// replay).
//
// The tab's auto-attach pauses each new worker and holds it with a session
// of its own. Detaching that session lets the worker run, whether our own
// attach worked or not; release does so when the attach returns, when the
// worker is not one to attach to, after a deadline, and on stop, so that
// no worker stays paused. (Frames and service workers are left alone: on
// test, neither ran again after its holding session detached, and chromedp
// cannot send the command that would resume them on that session.)
func (tm *targetManager) holdWorkers() error {
	c := tm.c
	attached := chromedp.Events(tm.ctx, target.AttachedToTarget)
	go func() {
		for ev, err := range attached {
			if err != nil {
				return
			}
			if ev.WaitingForDebugger && ev.TargetInfo != nil {
				tm.hold(*ev.TargetInfo, ev.SessionID)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(c.tab, c.opts.CallTimeout)
	defer cancel()
	// This replaces chromedp's own auto-attach of the tab, which pauses
	// nothing; the capture finds frames and workers by discovery anyway.
	_, err := chromedp.Call(ctx, target.SetAutoAttach, target.SetAutoAttachParams{
		AutoAttach: true, WaitForDebuggerOnStart: true, Flatten: ptr(true),
		Filter: target.Filter{{Type: "worker"}, {Exclude: true}},
	})
	return err
}

func ptr[T any](v T) *T { return &v }

// hold notes a worker that waits for us, and starts its attach.
func (tm *targetManager) hold(info target.Info, session target.SessionID) {
	tm.mu.Lock()
	tm.held[info.TargetID] = session
	finished := tm.done[info.TargetID]
	tm.infos[info.TargetID] = info
	wanted := !tm.stopped && tm.wanted(info)
	tm.mu.Unlock()
	if finished || !wanted {
		tm.release(info.TargetID)
		return
	}
	time.AfterFunc(tm.c.opts.AttachTimeout+time.Second, func() { tm.release(info.TargetID) })
	tm.consider(info)
}

// release lets a held worker run. It is safe to call more than once.
func (tm *targetManager) release(id target.ID) {
	tm.mu.Lock()
	session, ok := tm.held[id]
	delete(tm.held, id)
	tm.mu.Unlock()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(tm.c.tab, tm.c.opts.CallTimeout)
	defer cancel()
	if _, err := chromedp.Call(ctx, target.DetachFromTarget, target.DetachFromTargetParams{SessionID: session}); err != nil {
		slog.Warn("capture: could not resume a worker paused at start; it may stay paused until the tab closes", "target", id, "err", err)
	}
}

// attach opens a session on the target. chromedp's attach can block for
// good (it never returns for a nested dedicated worker, whose Runtime.enable
// gets no reply), so it runs under a watchdog that cancels the session. The
// context handed to Do must not carry the timeout itself: the target's
// message loop lives as long as that context.
func (tm *targetManager) attach(info target.Info) {
	defer tm.attachDone()
	// Whatever happens, a worker held at start runs again once this returns.
	defer func() {
		tm.mu.Lock()
		tm.done[info.TargetID] = true
		tm.mu.Unlock()
		tm.release(info.TargetID)
	}()
	c := tm.c
	wctx, cancel := chromedp.NewContext(c.tab, chromedp.WithTargetID(info.TargetID), chromedp.WithDetachOnCancel())
	done := make(chan error, 1)
	go func() { done <- chromedp.Do(wctx) }()

	select {
	case err := <-done:
		if err != nil {
			cancel()
			tm.failed(info, "error", err)
			return
		}
	case <-time.After(c.opts.AttachTimeout):
		cancel()
		tm.failed(info, "timeout", nil)
		return
	case <-tm.ctx.Done():
		cancel()
		return
	}

	s := c.newSession(wctx, info.TargetID, info.Type, info.URL, cancel)
	tm.mu.Lock()
	tm.bySession[chromedp.FromContext(wctx).Target.SessionID] = info.TargetID
	gone := tm.gone[info.TargetID]
	tm.mu.Unlock()
	if gone {
		cancel()
		return
	}
	if err := s.start(); err != nil {
		cancel()
		tm.failed(info, "start", err)
		return
	}
	if info.Type == "worker" {
		// A worker held at start runs on this as well as on release's
		// detach, so that one failing does not leave it paused. Harmless
		// on a worker that is not waiting.
		rctx, rcancel := context.WithTimeout(wctx, c.opts.CallTimeout)
		chromedp.Call(rctx, runtime.RunIfWaitingForDebugger, struct{}{})
		rcancel()
	}
	slog.Debug("attached", "type", info.Type, "url", info.URL)
}

func (tm *targetManager) failed(info target.Info, reason string, err error) {
	tm.c.mu.Lock()
	tm.c.stats.AttachFailed[reason]++
	tm.c.mu.Unlock()
	slog.Debug("attach failed", "type", info.Type, "url", info.URL, "reason", reason, "err", err)
}

func (tm *targetManager) targetGone(id target.ID) {
	tm.c.touch()
	tm.mu.Lock()
	tm.gone[id] = true
	tm.mu.Unlock()
	tm.c.remove(id)
}

// stop ends discovery. Targets keep being accepted until then, so that the
// ones created while waiting for idle are not lost.
func (tm *targetManager) stop() {
	if tm.c.opts.recording() {
		// Nothing will release a worker started after this, so stop pausing
		// them first.
		ctx, cancel := context.WithTimeout(tm.c.tab, tm.c.opts.CallTimeout)
		_, err := chromedp.Call(ctx, target.SetAutoAttach, target.SetAutoAttachParams{
			AutoAttach: true, Flatten: ptr(true), Filter: target.Filter{{Type: "worker"}, {Exclude: true}},
		})
		cancel()
		if err != nil {
			slog.Debug("capture: stop pausing workers", "err", err)
		}
	}
	tm.mu.Lock()
	tm.stopped = true
	var held []target.ID
	for id := range tm.held {
		held = append(held, id)
	}
	tm.mu.Unlock()
	for _, id := range held {
		tm.release(id)
	}
	tm.cancel()
}
