package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/browser"
	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/store"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// PageResult is one URL of a batch run.
type PageResult struct {
	URL        string `json:"url"`
	ExitCode   int    `json:"exit_code"`
	NewScripts int    `json:"new_scripts"`
	Unique     int    `json:"unique_scripts"`
	DurationMS int64  `json:"duration_ms"`
	RunID      string `json:"run_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

// BatchRecord is written to <out>/batch-<time>.json.
type BatchRecord struct {
	Started time.Time    `json:"started"`
	Ended   time.Time    `json:"ended"`
	Pages   []PageResult `json:"pages"`
	Failed  int          `json:"failed"`
	Blocked int          `json:"blocked"`
	// SessionLost: pages whose saved login was lost and not restored
	// (the batch exits 4, as a crawl does).
	SessionLost int  `json:"session_lost,omitempty"`
	Canceled    bool `json:"canceled,omitempty"`
	Tabs        int  `json:"tabs"`
	// Unclaimed: held-back requests no tab could be told the owner of
	// (-tabs N), kept in blocked.jsonl of the URL whose scope they are in.
	Unclaimed int `json:"unclaimed_held,omitempty"`
}

// RunURLs harvests each URL in its own tab of one browser, at most rate
// pages per second, cfg.Tabs of them at once. Each URL is its own target:
// its store and its scope come from its host, since the user who wrote the
// list chose them. A failing URL
// does not stop the batch; an interrupt does. It returns ErrBlocked when any
// page was answered by a bot challenge.
func RunURLs(ctx context.Context, cfg Config, urls []*url.URL, rate float64) error {
	var scopes []scope.Func
	for _, u := range urls {
		in, err := scope.New(u.Hostname(), cfg.ScopeMode)
		if err != nil {
			return err
		}
		scopes = append(scopes, in)
	}
	cfg.GuardScope = func(host string) bool {
		for _, in := range scopes {
			if in(host) {
				return true
			}
		}
		return false
	}
	if cfg.Tabs > 1 && cfg.Browser.Attach != "" {
		return errors.New("-tabs: not with -attach (the browser is the user's)")
	}
	sess, g, err := openBrowser(ctx, cfg)
	if err != nil {
		return err
	}
	var leftover []guard.Record
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			// closeBrowser's order, and in between, once the guard is
			// quiet, what no tab claimed.
			sess.CloseTab()
			if g != nil {
				g.Stop()
				if cfg.Tabs > 1 {
					leftover = g.Take(nil)
				}
			}
			sess.Close()
		})
	}
	defer shutdown()
	base := sess.Tab

	hk := &hostKeepers{}
	batch := BatchRecord{Started: time.Now().UTC(), Tabs: max(1, cfg.Tabs)}
	pages := make([]*PageResult, len(urls))
	var mu sync.Mutex // batch's counts
	one := func(i int, u *url.URL) {
		slog.Info("page", "n", i+1, "of", len(urls), "url", logURL(u.String()))
		pc := cfg
		pc.Target = u
		pc.InScope = nil
		if cfg.Logins != nil {
			pc.Login = cfg.Logins[scope.TargetDir(u)]
		}
		pc.sharedKeeper = hk.forPage(scope.TargetDir(u), pc.Login)
		started := time.Now()
		run, err := batchPage(ctx, pc, base, g)
		res := PageResult{URL: u.String(), ExitCode: run.ExitCode, NewScripts: run.NewScripts,
			Unique: run.UniqueScripts, DurationMS: time.Since(started).Milliseconds(), RunID: run.RunID}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case errors.Is(err, ErrBlocked):
			batch.Blocked++
		case errors.Is(err, ErrSessionLost):
			batch.SessionLost++
			slog.Warn("page lost its session", "url", logURL(u.String()))
		case err != nil && ctx.Err() != nil:
			batch.Canceled = true
		case err != nil:
			res.Error, res.ExitCode = err.Error(), 1
			batch.Failed++
			slog.Warn("page failed", "url", logURL(u.String()), "err", err)
		}
		pages[i] = &res
	}
	// -page-rate paces the starts, whatever the number of tabs.
	limit := newLimiter(rate)
	next := make(chan int)
	var wg sync.WaitGroup
	for range batch.Tabs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if ctx.Err() != nil {
					continue // interrupted: no new page
				}
				one(i, urls[i])
			}
		}()
	}
	for i := range urls {
		mu.Lock()
		canceled := batch.Canceled
		mu.Unlock()
		if !canceled && limit.wait(ctx) == nil {
			select {
			case next <- i:
				continue
			case <-ctx.Done():
			}
		}
		mu.Lock()
		batch.Canceled = true
		mu.Unlock()
		break
	}
	close(next)
	wg.Wait()
	for _, p := range pages {
		if p != nil {
			batch.Pages = append(batch.Pages, *p)
		}
	}
	shutdown()
	if len(leftover) > 0 {
		// What no tab claimed (held after its tab's run ended, or with
		// neither a network id nor a frame of a tab): kept all the same,
		// with the URL whose scope it is in.
		batch.Unclaimed = len(leftover)
		keepUnclaimed(cfg, urls, leftover)
	}
	batch.Ended = time.Now().UTC()
	if err := writeBatch(cfg.OutRoot, batch); err != nil {
		slog.Error("write batch record", "err", err)
	}
	slog.Info("batch done", "pages", len(batch.Pages), "failed", batch.Failed, "blocked", batch.Blocked, "session_lost", batch.SessionLost)
	switch {
	case batch.Canceled:
		return ctx.Err()
	case batch.Blocked > 0:
		return ErrBlocked
	case batch.SessionLost > 0:
		return ErrSessionLost
	}
	return nil
}

// hostKeepers makes the keeper of each host of a batch that has a saved
// login (C4): the pages of that host, at work at once, share one keeper
// and, as batchPage does for them, one browser context.
type hostKeepers struct {
	mu sync.Mutex
	by map[string]*keeper
}

// forPage returns the keeper for a page of host dir, or nil for a page with
// no login (it keeps its own context and no keeper).
func (h *hostKeepers) forPage(dir string, l *Login) *keeper {
	if l == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.by == nil {
		h.by = map[string]*keeper{}
	}
	k := h.by[dir]
	if k == nil {
		k = newKeeper(nil, l)
		h.by[dir] = k
	}
	return k
}

// batchPage harvests one URL of a batch in a tab of its own: with -tabs N
// and no saved login, in a browser context of its own too, so that tabs at
// work at once share no cookie, cache, storage or service worker. The
// context starts with the cookies of the browser's own (a profile's).
//
// With a saved login (-role) the pages of a host share the browser's
// context and one keeper (C4): a copy of the cookies for each context would
// leave each tab holding its own refresh token, and a server that rotates
// them revokes the session when the older is used (measured in 28B:
// -urls 6 -tabs 3 lost the session, -depth 2 -tabs 3, one context, did
// not). Copying the latest cookies when a tab opens does not solve it: a
// tab at work keeps the token it has. Known limit: URLs of several orgs of
// one host and role share that host's storage.
func batchPage(ctx context.Context, cfg Config, base context.Context, g *guard.Guard) (Record, error) {
	own := cfg.Tabs > 1 && cfg.Login == nil
	var opts []chromedp.ContextOption
	if own {
		opts = append(opts, chromedp.WithNewBrowserContext())
	}
	// A new context opens its tab on the first action, and the capture
	// needs the tab to exist.
	tab, closeTab := chromedp.NewContext(base, opts...)
	defer closeTab()
	if err := chromedp.Do(tab); err != nil {
		return Record{}, err
	}
	if own {
		// A context of its own has permissions of its own.
		tab = browser.DenyLocalNetwork(tab, browserContext(tab))
	}
	if g != nil {
		// In attach mode the guard passes other tabs' requests; this
		// one is ours.
		id := chromedp.FromContext(tab).Target.TargetID
		g.AddTab(id)
		defer g.RemoveTab(id)
	}
	if own {
		if err := copyCookies(tab); err != nil {
			return Record{}, fmt.Errorf("the profile's cookies: %w", err)
		}
	}
	return runPage(ctx, cfg, tab, g)
}

// copyCookies puts the cookies of the browser's own context into the tab's.
func copyCookies(tab context.Context) error {
	ctx, cancel := context.WithTimeout(tab, 15*time.Second)
	defer cancel()
	res, err := chromedp.CallBrowser(ctx, storage.GetCookies, storage.GetCookiesParams{})
	if err != nil || len(res.Cookies) == 0 {
		return err
	}
	params := make([]*network.CookieParam, 0, len(res.Cookies))
	for _, c := range res.Cookies {
		p := &network.CookieParam{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path, Secure: c.Secure,
			HTTPOnly: c.HTTPOnly, SameSite: c.SameSite, Priority: c.Priority, SourceScheme: c.SourceScheme,
			SourcePort: c.SourcePort, PartitionKey: c.PartitionKey}
		if !c.Session {
			p.Expires = cdp.TimeSinceEpoch(c.Expires)
		}
		params = append(params, p)
	}
	_, err = chromedp.CallBrowser(ctx, storage.SetCookies, storage.SetCookiesParams{Cookies: params, BrowserContextID: browserContext(tab)})
	return err
}

// keepUnclaimed writes held-back requests no tab claimed to blocked.jsonl
// of the first URL whose scope their host is in (of the first URL when
// none is): what the guard held is never dropped.
func keepUnclaimed(cfg Config, urls []*url.URL, records []guard.Record) {
	by := map[string][]guard.Record{}
	for _, r := range records {
		target := urls[0]
		if u, err := url.Parse(r.URL); err == nil {
			for _, t := range urls {
				if in, err := scope.New(t.Hostname(), cfg.ScopeMode); err == nil && in(u.Hostname()) {
					target = t
					break
				}
			}
		}
		by[scope.TargetDir(target)] = append(by[scope.TargetDir(target)], r)
	}
	for host, rs := range by {
		slog.Warn("held-back requests no tab claimed", "count", len(rs), "kept_with", host)
		d, err := openOutDir(filepath.Join(cfg.OutRoot, host, cfg.Role), store.Options{MaxBody: cfg.MaxBody})
		if err != nil {
			slog.Error("write blocked.jsonl", "err", err)
			continue
		}
		if cfg.Redact {
			rs = guard.Redact(rs, traffic.NewRedactor())
		}
		d.mu.Lock()
		if err := guard.Append(d.st.Dir(), rs); err != nil {
			slog.Error("write blocked.jsonl", "err", err)
		}
		d.mu.Unlock()
		d.release()
	}
}

func writeBatch(root string, b BatchRecord) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	name := fmt.Sprintf("batch-%s.json", b.Started.Format("20060102-150405"))
	return writeFileAtomic(filepath.Join(root, name), append(data, '\n'))
}
