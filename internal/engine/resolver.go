package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/capture"
	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/resolve"
)

const (
	resolveRounds = 10      // rounds go on while fetched chunks name new ones
	maxParseBody  = 5 << 20 // larger scripts are vendor bundles or data, not routers
)

// ResolverStats goes into run.json.
type ResolverStats struct {
	Candidates int `json:"candidates"`
	Fetched    int `json:"fetched"`
	Known      int `json:"already_captured"`
	OutOfScope int `json:"out_of_scope"`
	Private    int `json:"private_address"`
	Failed     int `json:"failed"`
	NotJS      int `json:"not_js"`
	// Source maps read through the page, and the app's own sources they
	// held (MAX-07).
	Maps       int `json:"source_maps,omitempty"`
	MapSources int `json:"map_sources,omitempty"`
	// MapGuessesHeld: <script>.map guesses not made, their origin having
	// missed sourcemap.GuessMisses with no map found.
	MapGuessesHeld int            `json:"map_guesses_held,omitempty"`
	ByMethod       map[string]int `json:"by_method"`
	Stopped        string         `json:"stopped,omitempty"`
}

// ref is a captured script waiting to be read by the resolver.
type ref struct {
	url, page string
	body      []byte
	// mapURL is the map the Debugger or a header names; headers are the
	// response's.
	mapURL     string
	headers    map[string]string
	inline     bool
	thirdParty bool
}

// noteCaptured records what the sink stored: the URL as seen, and the body
// for the next resolver round. It also labels scripts the resolver fetched.
// Called from the sink, which capture serializes.
func (e *engine) noteCaptured(s *capture.Script) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s.URL != "" {
		k := normURL(s.URL)
		e.seen[k] = true
		if c, ok := e.resolved[k]; ok {
			s.Tags = append(s.Tags, "resolved", "resolved:"+c.Method)
			if s.Initiator == nil {
				s.Initiator = &capture.Initiator{Type: "resolver", URL: c.From}
			}
		}
	}
	// Only a run that resolves (or reads source maps through the resolver)
	// takes the bodies back: kept otherwise, each script's body (up to
	// maxParseBody) stayed in the heap for the whole of a watch or a
	// -resolve=false crawl (architecture review 2026-11-13).
	if e.cfg.Resolve && len(s.Body) > 0 && len(s.Body) <= maxParseBody && !slices.Contains(s.Tags, detect.TagCDNInfra) {
		u := s.URL
		if u == "" {
			u = s.Page
		}
		if !e.parsed[u] || s.URL == "" {
			e.parsed[u] = true
			e.pending = append(e.pending, ref{
				url: u, page: s.Page, body: s.Body, mapURL: s.SourceMapURL, headers: s.Headers,
				inline: s.URL == "", thirdParty: slices.Contains(s.Tags, "third-party"),
			})
		}
	}
}

func (e *engine) takePending() []ref {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.pending
	e.pending = nil
	return p
}

// resolve reads the captured scripts for chunks the app could load, fetches
// the in-scope ones through the page, and repeats on what that brings in.
func (e *engine) resolve(ctx context.Context) {
	e.resolveMu.Lock()
	defer e.resolveMu.Unlock()
	stats := &e.run.Resolver
	// A crawl resolves after every page: the counts, -resolve-max and a
	// stop (429, a challenge) are the run's.
	if stats.ByMethod == nil {
		stats.ByMethod = map[string]int{}
	}
	if stats.Stopped != "" {
		e.takePending() // not read again: dropped
		return
	}
	noDNS := e.cfg.Browser.Proxy != "" || e.cfg.Browser.HostRules != ""
	policy := resolve.NewPolicy(e.cfg.Target.Hostname(), e.cfg.InScope, noDNS)
	limit := newLimiter(e.cfg.ResolveRate)
	tried := map[string]bool{}
	ngswTried := false
	fetched := stats.Fetched + stats.Failed

	for round := 1; round <= resolveRounds && ctx.Err() == nil; round++ {
		// Bodies of the last round are fetched asynchronously; let them land.
		drain, cancel := context.WithTimeout(ctx, 10*time.Second)
		e.harvest.Drain(drain)
		cancel()

		var cands []resolve.Candidate
		pending := e.takePending()
		if !e.sourceMaps(ctx, pending, policy, limit, &fetched) {
			return
		}
		for _, r := range pending {
			cands = append(cands, resolve.Static(r.body, r.url, r.page)...)
			cands = append(cands, e.webpack.Add(r.body, r.url, r.page, r.inline, r.thirdParty)...)
			if !ngswTried && strings.HasSuffix(r.url, "/ngsw-worker.js") {
				ngswTried = true
				cands = append(cands, e.readNgsw(ctx, r.url, policy, limit)...)
			}
		}

		var todo []resolve.Candidate
		for _, c := range cands {
			stats.Candidates++
			k := normURL(c.URL)
			e.mu.Lock()
			known := e.seen[k]
			e.mu.Unlock()
			switch {
			case known:
				stats.Known++
				continue
			case tried[k]:
				continue
			}
			tried[k] = true
			// Only scripts: manifests can list pages and endpoints too, and a
			// GET on one of those can have side effects.
			if !isScriptPath(c.URL) {
				stats.NotJS++
				continue
			}
			switch policy.Check(c.URL) {
			case resolve.Allow:
				todo = append(todo, c)
			case resolve.OutOfScope:
				stats.OutOfScope++
				e.externalRef(c, "out_of_scope")
			case resolve.Private:
				stats.Private++
				e.externalRef(c, "private_address")
			}
		}
		if len(todo) == 0 {
			break
		}
		slog.Info("resolver", "round", round, "fetching", len(todo))
		hostFails := map[string]int{}
		for _, c := range todo {
			if fetched >= e.cfg.ResolveMax {
				stats.Stopped = fmt.Sprintf("reached -resolve-max %d", e.cfg.ResolveMax)
				break
			}
			var host string
			if u, err := url.Parse(c.URL); err == nil {
				host = strings.ToLower(u.Hostname())
			}
			if host != "" && hostFails[host] >= 3 {
				stats.Failed++
				continue
			}
			if err := limit.wait(ctx); err != nil {
				return
			}
			e.mu.Lock()
			e.resolved[normURL(c.URL)] = c
			e.mu.Unlock()
			res, err := e.pageFetch(c.URL, false)
			fetched++
			stats.ByMethod[c.Method]++
			if err != nil || res.Status <= 0 || res.Status >= 400 {
				stats.Failed++
				if err != nil || res.Status <= 0 {
					if host != "" {
						hostFails[host]++
						if hostFails[host] == 3 {
							slog.Debug("resolver: skipping remaining chunks on unresponsive host", "host", host)
						}
					}
				} else if host != "" {
					hostFails[host] = 0
				}
				slog.Debug("resolver fetch", "url", c.URL, "status", res.Status, "err", err)
			} else {
				if host != "" {
					hostFails[host] = 0
				}
				stats.Fetched++
			}
			if res.Status == 429 || res.Challenge {
				stats.Stopped = fmt.Sprintf("target answered %d%s; stopped to stay polite", res.Status, map[bool]string{true: " with a challenge", false: ""}[res.Challenge])
				slog.Warn("resolver stopped", "reason", stats.Stopped)
				e.warn("resolver: " + stats.Stopped)
				return
			}
		}
		if stats.Stopped != "" {
			e.warn("resolver: " + stats.Stopped)
			return
		}
		e.quiet(ctx) // what the chunks started; the page load's idle stays the run's
	}
}

// readNgsw fetches an Angular service worker manifest next to the worker.
func (e *engine) readNgsw(ctx context.Context, workerURL string, policy *resolve.Policy, limit *limiter) []resolve.Candidate {
	u, err := url.Parse(workerURL)
	if err != nil {
		return nil
	}
	u.Path = path.Join(path.Dir(u.Path), "ngsw.json")
	u.RawQuery = ""
	if policy.Check(u.String()) != resolve.Allow || limit.wait(ctx) != nil {
		return nil
	}
	res, err := e.pageFetch(u.String(), true)
	if err != nil || res.Status != 200 {
		return nil
	}
	return resolve.NgswURLs([]byte(res.Text), u.String())
}

type fetchResult struct {
	Status      int    `json:"status"`
	Challenge   bool   `json:"challenge"`
	ContentType string `json:"contentType"`
	Text        string `json:"text"`
}

// pageFetch fetches a URL from inside the page, so the request carries the
// page's cookies, proxy and fingerprint, and the response goes through the
// capture like any other.
//   - It runs in an isolated world, with the browser's own fetch: the page's
//     window.fetch may be wrapped by monitoring or HTTP libraries.
//   - Redirects are not followed: a redirect could lead out of scope.
//   - Credentials go only to the page's own origin: a cross-origin script
//     host answering "Access-Control-Allow-Origin: *" rejects credentialed
//     requests, and the body would be lost without an error.
//   - The script is tagged so that the capture drops it.
func (e *engine) pageFetch(rawURL string, wantText bool) (fetchResult, error) {
	return e.pageFetchMode(rawURL, wantText, "default")
}

// maxFetchText is what pageFetch reads of a body; a source map may be
// larger, up to maxMapText.
const (
	maxFetchText = 4 << 20
	maxMapText   = 16 << 20
)

// pageFetchMode is pageFetch with a cache mode: "no-store" asks the
// server itself, as checking a session needs (a cached page says nothing
// of whether the server still knows the session).
func (e *engine) pageFetchMode(rawURL string, wantText bool, cache string) (fetchResult, error) {
	return e.pageFetchText(rawURL, wantText, cache, maxFetchText)
}

var (
	resolverHeaderTimeoutMS = 8000
	resolverBodyTimeoutMS   = 25000
)

func (e *engine) pageFetchText(rawURL string, wantText bool, cache string, maxText int) (fetchResult, error) {
	u, _ := json.Marshal(rawURL)
	creds := "omit"
	if sameOrigin(rawURL, e.harvest.Page()) {
		creds = "include"
	}
	drainBody := wantText || cache != "no-store"
	expr := fmt.Sprintf(`(async () => {
  const ctl = new AbortController();
  let timer = setTimeout(() => ctl.abort(), %d);
  try {
    const r = await fetch(%s, {credentials: %q, redirect: "manual", cache: %q, signal: ctl.signal});
    clearTimeout(timer);
    timer = null;
    const out = {status: r.status, challenge: r.headers.get("cf-mitigated") === "challenge"};
    if (%t && r.ok) {
      timer = setTimeout(() => ctl.abort(), %d);
      if (%t) out.text = (await r.text()).slice(0, %d);
      else await r.arrayBuffer();
    }
    return out;
  } catch (e) { return {status: -1}; }
  finally { if (timer !== null) clearTimeout(timer); }
})()
//# sourceURL=`+marker.Internal, resolverHeaderTimeoutMS, u, creds, cache, drainBody, resolverBodyTimeoutMS, wantText, maxText)
	callTimeout := 12 * time.Second
	if drainBody {
		callTimeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(e.tabCtx(), callTimeout)
	defer cancel()
	world, err := e.isolatedWorld(ctx)
	if err != nil {
		return fetchResult{Status: -1}, err
	}
	await, byValue := true, true
	res, err := chromedp.Call(ctx, runtime.Evaluate, runtime.EvaluateParams{
		Expression: expr, AwaitPromise: &await, ReturnByValue: &byValue, ContextID: world,
	})
	if err != nil {
		// The world goes away with a navigation; make a new one next time.
		e.world = 0
		return fetchResult{Status: -1}, err
	}
	var out fetchResult
	if res.Result != nil {
		if err := json.Unmarshal(res.Result.Value, &out); err != nil {
			return fetchResult{Status: -1}, err
		}
	}
	return out, nil
}

// pageFetchHeaders fetches a spec candidate from inside the page with
// optional static client_headers.
func (e *engine) pageFetchHeaders(rawURL string, hdrMap map[string]string) (fetchResult, error) {
	u, _ := json.Marshal(rawURL)
	hb := []byte("{}")
	if len(hdrMap) > 0 {
		hb, _ = json.Marshal(hdrMap)
	}
	creds := "omit"
	if sameOrigin(rawURL, e.harvest.Page()) {
		creds = "include"
	}
	expr := fmt.Sprintf(`(async () => {
  const ctl = new AbortController();
  let timer = setTimeout(() => ctl.abort(), %d);
  try {
    const r = await fetch(%s, {credentials: %q, headers: %s, redirect: "manual", cache: "default", signal: ctl.signal});
    clearTimeout(timer);
    timer = null;
    const out = {status: r.status, challenge: r.headers.get("cf-mitigated") === "challenge", contentType: r.headers.get("content-type") || ""};
    if (r.ok || r.status === 400 || r.status === 401 || r.status === 403 || r.status === 404) {
      timer = setTimeout(() => ctl.abort(), %d);
      const limit = r.ok ? %d : 8192;
      out.text = (await r.text()).slice(0, limit);
    }
    return out;
  } catch (e) { return {status: -1}; }
  finally { if (timer !== null) clearTimeout(timer); }
})()
//# sourceURL=`+marker.Internal, resolverHeaderTimeoutMS, u, creds, hb, resolverBodyTimeoutMS, maxFetchText)
	ctx, cancel := context.WithTimeout(e.tabCtx(), 30*time.Second)
	defer cancel()
	world, err := e.isolatedWorld(ctx)
	if err != nil {
		return fetchResult{Status: -1}, err
	}
	await, byValue := true, true
	res, err := chromedp.Call(ctx, runtime.Evaluate, runtime.EvaluateParams{
		Expression: expr, AwaitPromise: &await, ReturnByValue: &byValue, ContextID: world,
	})
	if err != nil {
		e.world = 0
		return fetchResult{Status: -1}, err
	}
	var out fetchResult
	if res.Result != nil {
		if err := json.Unmarshal(res.Result.Value, &out); err != nil {
			return fetchResult{Status: -1}, err
		}
	}
	return out, nil
}

// isolatedWorld returns an execution context of the main frame that the
// page's scripts cannot reach. The main frame has the id of the tab target.
func (e *engine) isolatedWorld(ctx context.Context) (runtime.ExecutionContextID, error) {
	if e.world != 0 {
		return e.world, nil
	}
	frame := cdp.FrameID(chromedp.FromContext(e.tabCtx()).Target.TargetID)
	res, err := chromedp.Call(ctx, page.CreateIsolatedWorld, page.CreateIsolatedWorldParams{FrameID: frame, WorldName: "jsharvest"})
	if err != nil {
		return 0, fmt.Errorf("isolated world: %w", err)
	}
	e.world = res.ExecutionContextID
	return e.world, nil
}

func sameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

func isScriptPath(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(path.Ext(u.Path)) {
	case ".js", ".mjs", ".cjs":
		return true
	}
	return false
}

// externalRef records a reference the resolver did not fetch.
func (e *engine) externalRef(c resolve.Candidate, reason string) {
	line, err := json.Marshal(map[string]string{"url": c.URL, "method": c.Method, "from": c.From, "reason": reason})
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(e.st.Dir(), "external_refs.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	f.Write(append(line, '\n'))
	f.Close()
}

// normURL makes URLs that the browser and Go spell differently compare
// equal: escaping of the path ([id] vs %5Bid%5D), host case, fragment.
func normURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.Path + "?" + u.RawQuery
}

// limiter spaces requests at a rate, with ±30% jitter so they do not beat
// at a fixed interval.
// limiter paces starts; the tabs of a crawl share one (-page-rate).
type limiter struct {
	mu   sync.Mutex
	gap  time.Duration
	last time.Time
}

func newLimiter(perSecond float64) *limiter {
	if perSecond <= 0 {
		perSecond = 5
	}
	return &limiter{gap: time.Duration(float64(time.Second) / perSecond)}
}

func (l *limiter) wait(ctx context.Context) error {
	gap := time.Duration(float64(l.gap) * (0.7 + 0.6*rand.Float64()))
	// The slot is taken under the lock, the wait outside it: several tabs
	// wait their turns, one gap apart.
	l.mu.Lock()
	at := l.last.Add(gap)
	if now := time.Now(); at.Before(now) {
		at = now
	}
	l.last = at
	l.mu.Unlock()
	if d := time.Until(at); d > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	return nil
}
