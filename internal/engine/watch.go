package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/scope"
)

// WatchOptions picks the tab to watch and when to stop.
type WatchOptions struct {
	Tab  string   // regexp of the URL of the one open tab to watch
	Open *url.URL // or open a new tab, then load this URL in it
	// Duration stops the watch after this long; zero waits for an
	// interrupt or for the tab to close.
	Duration time.Duration
	Reload   bool // reload the tab once watching, so that every handler is traced
	// ReloadOnExit takes jsharvest's scripts out and reloads the tab, which
	// otherwise keeps them (and the guard's socket stub) until reloaded.
	ReloadOnExit bool
}

// Watch records what someone else does in a tab of a running Chrome: a
// person, an AI agent, or a Playwright script. It does not navigate, apart
// from -open's first load. It returns when ctx ends (an interrupt is the
// normal way to stop), when the duration is up, or when the tab closes.
func Watch(ctx context.Context, cfg Config, w WatchOptions) error {
	if cfg.Browser.Attach == "" {
		return errors.New("watch needs -attach: the browser being driven")
	}
	id, tabURL, err := pickTab(cfg.Browser.Attach, w)
	if err != nil {
		return err
	}
	if w.Open != nil {
		tabURL = w.Open.String()
	}
	u, err := url.Parse(tabURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("watch: the tab is on %q; open the target first, or use -open URL", tabURL)
	}
	cfg.Target = u
	cfg.Browser.TabID = id
	cfg.Actions = true
	in, err := scope.New(u.Hostname(), cfg.ScopeMode)
	if err != nil {
		return err
	}
	cfg.InScope = in

	// The watch's own life: an interrupt ends it, but not the work after.
	work := context.WithoutCancel(ctx)
	sess, g, err := openBrowser(work, cfg)
	if err != nil {
		return err
	}
	defer closeBrowser(sess, g)
	tab := sess.Tab

	e := newRun(cfg, tab, g)
	if err := e.open(); err != nil {
		return err
	}
	defer e.close()
	e.run.Mode = "watch"
	if err := e.start(); err != nil {
		return err
	}
	var stub page.ScriptIdentifier
	if g != nil {
		e.guardAt = g.Stats()
		g.SetPage(e.harvest.Page)
		if !cfg.AllowWebSocket {
			if stub, err = guard.StubSockets(tab); err != nil {
				return fmt.Errorf("guard: %w", err)
			}
		}
	}
	switch {
	case w.Open != nil:
		e.navigate()
	case w.Reload:
		rctx, rcancel := context.WithTimeout(tab, cfg.NavTimeout)
		if _, err := chromedp.Call(rctx, page.Reload, page.ReloadParams{}); err != nil {
			slog.Warn("reload", "err", err)
		}
		rcancel()
	default:
		slog.Warn("watch: handlers the page registered before now are not traced; their requests are grouped by time. Use -reload to trace them all")
	}
	if g != nil {
		slog.Warn("watch: the guard holds back writes of every worker, service worker and frame in this browser it cannot place, other tabs' too; use a browser profile for this target only")
	}
	if err := e.writeLive(time.Now().UTC()); err != nil {
		return fmt.Errorf("write %s: %w", results.LiveFile, err)
	}
	// After finish has written flows.jsonl: until then, a reader goes by
	// the snapshot.
	defer results.RemoveLive(e.st.Dir())
	slog.Info("watching; act in the tab, and stop with Ctrl-C", "tab", logURL(tabURL), "guard", g != nil)

	why := e.watchUntil(ctx, id, w.Duration)
	slog.Info("watch stopped", "why", why)

	err = e.finish(work)
	switch {
	case w.ReloadOnExit:
		e.harvest.Unhook()
		if stub != "" {
			guard.UnstubSockets(tab, stub)
		}
		rctx, rcancel := context.WithTimeout(tab, 10*time.Second)
		chromedp.Call(rctx, page.Reload, page.ReloadParams{})
		rcancel()
	case why != "tab closed":
		slog.Warn("watch: the tab still runs jsharvest's scripts (and the guard's socket stub, if on) until it is reloaded")
	}
	return err
}

// watchUntil waits for the end of the watch. Meanwhile it keeps a snapshot
// of the flows (flows.partial.jsonl) and of its state (watch.json) for
// jsharvest mcp to answer from, and so that a crash loses little: every
// second when something new was recorded, but never spending more than a
// twentieth of the time on grouping (and waiting 30 s at most).
func (e *engine) watchUntil(ctx context.Context, id target.ID, d time.Duration) string {
	closed := make(chan struct{})
	lctx, stop := context.WithCancel(e.tab)
	defer stop()
	go each(chromedp.BrowserEvents(lctx, target.TargetDestroyed), func(ev *target.EventTargetDestroyed) {
		if ev.TargetID == id {
			select {
			case <-closed:
			default:
				close(closed)
			}
		}
	})
	var limit <-chan time.Time
	if d > 0 {
		limit = time.After(d)
	}
	every := time.Second
	tick := time.NewTimer(every)
	defer tick.Stop()
	reqs, events := 0, 0   // what the snapshot has
	var cost time.Duration // of grouping, smoothed
	for {
		select {
		case <-ctx.Done():
			return "interrupted"
		case <-limit:
			return "duration"
		case <-closed:
			return "tab closed"
		case <-e.tab.Done():
			return "browser gone"
		case <-tick.C:
			// What was recorded before now is in what is read next.
			at := time.Now().UTC()
			e.mu.Lock()
			nr, ne := len(e.summary), len(e.events)
			e.mu.Unlock()
			ok := true
			if nr != reqs || ne != events {
				started := time.Now()
				fs := e.buildFlows()
				took := time.Since(started)
				if err := e.writeFlows(fs, results.PartialFlows, false); err != nil {
					slog.Debug("checkpoint flows", "err", err)
					ok = false
				} else {
					reqs, events = nr, ne
				}
				// The grouping's cost, smoothed: one slow write or a busy
				// moment must not stall the snapshot that jsharvest mcp
				// waits on.
				cost = (4*cost + took) / 5
				every = min(max(time.Second, 20*cost), 30*time.Second)
				if all := time.Since(started); all > 500*time.Millisecond {
					slog.Warn("watch: the flows snapshot was slow", "group", took.Round(time.Millisecond), "all", all.Round(time.Millisecond))
				}
				slog.Debug("snapshot", "requests", nr, "events", ne, "took", took)
			}
			if ok {
				if err := e.writeLive(at); err != nil {
					slog.Debug("write watch state", "err", err)
				}
			}
			e.analyzeNew()
			tick.Reset(every)
		}
	}
}

// writeLive writes watch.json: the snapshot has everything recorded
// before at.
func (e *engine) writeLive(at time.Time) error {
	e.mu.Lock()
	n, heard := len(e.summary), e.heard
	e.mu.Unlock()
	l := results.Live{Run: e.run.RunID, PID: os.Getpid(), Tab: e.harvest.Page(), Started: e.run.Started, Updated: at, Scope: e.run.Scope,
		Guard: e.guard != nil, Requests: n, LastEvent: heard}
	if l.Tab == "" {
		l.Tab = e.cfg.Target.String()
	}
	if e.redactor != nil {
		l.Tab = e.redactor.URL(l.Tab)
	}
	if e.run.Flows != nil {
		l.Actions = e.run.Flows.Actions
	}
	return results.WriteLive(e.st.Dir(), l)
}

func each[T any](events iter.Seq2[T, error], f func(*T)) {
	for ev, err := range events {
		if err != nil {
			return
		}
		f(&ev)
	}
}

// pickTab finds the tab to watch through the endpoint's HTTP interface:
// the one tab whose URL matches w.Tab, or a new blank tab for w.Open, made
// in the browser's default context so that it shares the user's session.
func pickTab(endpoint string, w WatchOptions) (target.ID, string, error) {
	base := strings.TrimRight(endpoint, "/")
	if strings.HasPrefix(base, "ws") {
		return "", "", errors.New("watch: give -attach as the http:// endpoint, which lists the tabs")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	if w.Open != nil {
		req, _ := http.NewRequest(http.MethodPut, base+"/json/new?about:blank", nil)
		resp, err := client.Do(req)
		if err != nil {
			return "", "", fmt.Errorf("open a tab: %w", err)
		}
		defer resp.Body.Close()
		var t struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&t); err != nil || t.ID == "" {
			return "", "", fmt.Errorf("open a tab: bad answer from %s", base)
		}
		return target.ID(t.ID), "about:blank", nil
	}
	re, err := regexp.Compile(w.Tab)
	if err != nil {
		return "", "", fmt.Errorf("-tab: %w", err)
	}
	resp, err := client.Get(base + "/json/list")
	if err != nil {
		return "", "", fmt.Errorf("list tabs: %w", err)
	}
	defer resp.Body.Close()
	var list []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return "", "", fmt.Errorf("list tabs: %w", err)
	}
	var found []int
	for i, t := range list {
		if t.Type == "page" && re.MatchString(t.URL) {
			found = append(found, i)
		}
	}
	if len(found) != 1 {
		var urls []string
		for _, i := range found {
			urls = append(urls, list[i].URL)
		}
		return "", "", fmt.Errorf("-tab %q matches %d tabs %v; it must match exactly one", w.Tab, len(found), urls)
	}
	t := list[found[0]]
	return target.ID(t.ID), t.URL, nil
}
