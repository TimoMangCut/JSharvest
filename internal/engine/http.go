package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/httpcrawl"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/sourcemap"
	"github.com/TimoMangCut/JSharvest/internal/store"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
	"github.com/TimoMangCut/JSharvest/internal/uahints"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
)

// HTTPOptions are what the HTTP engine takes on top of Config.
type HTTPOptions struct {
	Rate        float64 // requests a second
	Probe       bool    // the well-known files
	NoSpecProbe bool    // skip OpenAPI/Swagger and OIDC probes
	SourceMaps  bool
	GuessMaps   bool
	// Fallback runs when the first page is a challenge and no script of the
	// site was reached (CF-04b: the archives, and the live files their old
	// pages name). What it returns goes into run.json as fallback.
	Fallback func(ctx context.Context) any
	// Archive runs after every crawl that was not stopped (crawl -archive,
	// the default before a login: the pre-auth phase reads the target's
	// history too). It takes the place of Fallback; on a blocked first page
	// with no script its result goes into run.json as fallback, otherwise
	// as archive.
	Archive func(ctx context.Context) any
	// Escalate takes the pages the crawl met a challenge on to a browser
	// (crawl -engine auto: Escalate in Chrome), after the crawl and its
	// catalog, before the archives.
	// Escalate goes on in Chrome with the challenged pages, and the
	// application's cookies the HTTP crawl got (CookieParams).
	Escalate func(ctx context.Context, pages []httpcrawl.Challenged, cookies []*network.CookieParam) *Escalation
	// SPABoot, when set (crawl -spa-boot with -engine auto), loads the
	// SPA origins in Chrome when the crawl saw no API call (PIP-04).
	SPABoot func(ctx context.Context, origins []string) []EscalatedRun
}

// RunHTTP is a crawl without a browser (internal/httpcrawl): the same
// output directory, store, index, endpoint catalog, pages.jsonl and run
// record as a browser's, its requests in requests.jsonl (target "http"),
// and the original sources of the source maps it finds. It returns
// ErrBlocked when the first page is a challenge.
func RunHTTP(ctx context.Context, cfg Config, ho HTTPOptions) (Record, error) {
	if cfg.InScope == nil {
		in, err := scope.New(cfg.Target.Hostname(), cfg.ScopeMode)
		if err != nil {
			return Record{}, err
		}
		cfg.InScope = in
	}
	pageScope := cfg.PageScope
	if pageScope == nil {
		ps, err := scope.PageScope(cfg.Target.Hostname(), cfg.ScopeMode, cfg.PageScopeMode)
		if err != nil {
			return Record{}, err
		}
		pageScope = ps
	}
	d, err := openOutDir(cfg.outDir(), store.Options{MaxBody: cfg.MaxBody})
	if err != nil {
		return Record{}, err
	}
	defer d.release()
	st := d.st
	started := time.Now().UTC()
	run := Record{
		Version: 2, RunID: newRunID(started), Target: cfg.Target.String(), Role: cfg.Role, Mode: "http", Scope: scopeMode(cfg.ScopeMode),
		Config: &RunConfig{Depth: cfg.Depth, MaxPages: cfg.MaxPages, Resolve: true, Record: string(cfg.Record), ResolveMax: cfg.ResolveMax,
			Engine: "http"},
		Started: started, StoreErrors: map[string]int{},
	}
	var redactor *traffic.Redactor
	if cfg.Redact {
		redactor = traffic.NewRedactor()
	}
	var tw *traffic.Writer
	if cfg.Record != "" && cfg.Record != traffic.Off {
		if tw, err = traffic.Create(st.Dir(), run.RunID, redactor); err != nil {
			return run, fmt.Errorf("request log: %w", err)
		}
	}
	pages, err := os.OpenFile(filepath.Join(st.Dir(), "pages.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return run, err
	}
	defer pages.Close()

	var mu sync.Mutex
	scripts, newScripts := map[string]bool{}, 0
	put := func(r store.Record, label string) {
		key, isNew, err := st.Put(r)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if errors.Is(err, store.ErrTooLarge) {
				run.StoreErrors["too_large"]++
			} else {
				run.StoreErrors["write"]++
				slog.Error("store script", "url", r.URL, "err", err)
			}
			return
		}
		if key == "" {
			return
		}
		scripts[key] = true
		if isNew {
			newScripts++
			slog.Info(label, "kind", r.Kind, "size", len(r.Body), "url", r.URL)
		}
	}
	mapsDir := filepath.Join(st.Dir(), "maps")
	enc := json.NewEncoder(pages)
	var visited, listedN int
	var proxyURL *url.URL
	if cfg.Browser.Proxy != "" {
		if proxyURL, err = url.Parse(cfg.Browser.Proxy); err != nil {
			return run, fmt.Errorf("-proxy: %w", err)
		}
		// Behind a proxy the AIA fetch would leave outside it: it is off, and
		// an incomplete certificate chain is not completed (P2.3).
		run.Warnings = append(run.Warnings, "aia disabled: a proxy is in use (-proxy): a server's incomplete certificate chain is not completed")
	}
	o := httpcrawl.Options{
		Proxy:  proxyURL,
		Target: cfg.Target, InScope: cfg.InScope, PageScope: pageScope, Depth: cfg.Depth, MaxPages: cfg.MaxPages, Rate: ho.Rate,
		MaxFiles: cfg.ResolveMax, MaxBody: cfg.MaxBody, Timeout: cfg.NavTimeout, UserAgent: httpUA(cfg),
		HostRules: cfg.Browser.HostRules, NoDNS: cfg.Browser.Proxy != "" || cfg.Browser.HostRules != "", Insecure: cfg.Browser.Insecure, RecordBody: cfg.RecordBody,
		Probe: ho.Probe, NoSpecProbe: cfg.NoSpecProbe || ho.NoSpecProbe, SourceMaps: ho.SourceMaps, GuessMaps: ho.GuessMaps,
		Destructive: func(u string) bool {
			return guard.Destructive(u) || (cfg.GuardRules.Deny != nil && cfg.GuardRules.Deny.MatchString(u))
		},
		Extract: func(body []byte, urlHint string) jsapi.Result {
			return endpoints.ExtractCached(st.Dir(), body, urlHint)
		},
		Log: func(f string, a ...any) { slog.Debug(fmt.Sprintf(f, a...)) },
		Script: func(s httpcrawl.Script) {
			tags := s.Tags
			if u, err := url.Parse(s.URL); err == nil && s.Kind == "file" && !cfg.InScope(u.Hostname()) {
				tags = append(tags, "third-party")
			}
			tags = append(tags, detect.ScriptTags(s.URL)...)
			r := store.Record{Body: s.Body, URL: s.URL, Kind: s.Kind, Via: "http", Target: "http", Page: s.Page, MIME: s.MIME,
				Headers: s.Headers, Tags: tags, Source: "live"}
			if s.From != "" && s.From != s.Page {
				r.Initiator = &store.Initiator{Type: "resolver", URL: s.From}
			}
			if r.Headers != nil {
				r.SourceMapURL = r.Headers["sourcemap"]
			}
			put(r, "script")
		},
		SourceMap: func(m httpcrawl.SourceMap) {
			sm, err := sourcemap.Parse(m.Body)
			if err != nil {
				return
			}
			if os.MkdirAll(mapsDir, 0o700) == nil {
				sum := sha256.Sum256(m.Body)
				writeFileAtomic(filepath.Join(mapsDir, hex.EncodeToString(sum[:])+".map"), m.Body)
			}
			where := m.URL
			if where == "" {
				where = m.ScriptURL + "#inline-map"
			}
			n := 0
			for _, f := range sm.Files() {
				if f.Vendor {
					continue // a dependency's: noise for the target's endpoints
				}
				n++
				put(store.Record{Body: []byte(f.Content), URL: where + "#" + f.Path, Kind: "source", Via: "sourcemap", Target: "http",
					Page: m.ScriptURL, Tags: []string{"sourcemap", "source:" + f.Path}, Source: "live",
					Initiator: &store.Initiator{Type: "sourcemap", URL: m.ScriptURL}}, "source")
			}
			slog.Info("source map", "url", where, "sources", len(sm.Sources), "own", n)
		},
		Request: func(e traffic.Entry) {
			if tw == nil || !cfg.Record.Wants(e.ResourceType) {
				return
			}
			e.Run = run.RunID
			tw.Write(e)
		},
		Page: func(p httpcrawl.Page) {
			mu.Lock()
			defer mu.Unlock()
			if p.Visited {
				visited++
				slog.Info("page", "url", p.URL, "status", p.Status, "found", p.Discovered)
			} else {
				listedN++
			}
			enc.Encode(Page{Run: run.RunID, URL: p.URL, Visited: p.Visited, FinalURL: p.FinalURL, Status: int64(p.Status), Depth: p.Depth,
				From: p.From, How: p.How, Method: p.Method, Reason: p.Reason, Discovered: p.Discovered, Started: p.Started, TookMS: p.TookMS, Error: p.Error})
		},
	}
	res, cerr := httpcrawl.Crawl(ctx, o)
	if res != nil {
		run.HTTP = &res.Stats
		run.Blocked = res.Blocked
		run.Fronted, run.FrontedBy = res.Fronted, res.FrontedBy
		run.Frontier = &FrontierStats{Visited: res.Visited, Queued: res.Queued, Listed: res.Listed, Stopped: res.Stats.Stopped}
		run.Stats.Challenge = res.Stats.Challenge
		if res.Stats.Stopped != "" {
			run.Warnings = append(run.Warnings, "stopped: "+res.Stats.Stopped)
		}
		if res.Stats.Capped != "" {
			run.Warnings = append(run.Warnings, res.Stats.Capped+": scripts past it were not fetched (-resolve-max to raise it)")
		}
		for _, h := range res.IncompleteChains {
			run.Warnings = append(run.Warnings, "the server of "+h+" sends an incomplete certificate chain: its intermediates were fetched from the AIA, as a browser does (intel.json security_notes)")
		}
	}
	// The first page never answered (TLS, DNS, a refused connection): no
	// run of the site, whatever came after.
	seedFailed := res != nil && res.SeedError != "" && res.Stats.Scripts == 0
	if seedFailed {
		w := "seed request failed: " + res.SeedError
		if strings.Contains(res.SeedError, "x509") || strings.Contains(res.SeedError, "certificate") {
			w += " (-insecure accepts any certificate, for a lab or staging target)"
		}
		run.Warnings = append(run.Warnings, w)
		slog.Warn("the first page could not be fetched", "url", cfg.Target.String(), "err", res.SeedError)
	}
	if tw != nil {
		run.Requests, run.InternalRequests = tw.Count(), tw.Internal()
		run.PageRequests = run.Requests - run.InternalRequests
		if err := tw.Close(); err != nil {
			run.Warnings = append(run.Warnings, "request log: "+err.Error())
		}
	}
	if err := st.Flush(); err != nil {
		return run, fmt.Errorf("write index: %w", err)
	}
	// The catalog, as a browser's run writes it.
	tmp := &engine{runState: &runState{cfg: cfg, st: st, dir: d, redactor: redactor}}
	tmp.run.Warnings = run.Warnings
	tmp.writeEndpoints()
	run.Endpoints, run.StaticAnalysis, run.Warnings = tmp.run.Endpoints, tmp.run.StaticAnalysis, tmp.run.Warnings
	mu.Lock()
	run.Scripts = slices.Sorted(maps.Keys(scripts))
	run.UniqueScripts, run.NewScripts = st.Len(), newScripts
	mu.Unlock()
	for reason, n := range run.StoreErrors {
		run.Warnings = append(run.Warnings, fmt.Sprintf("%d scripts not stored: %s", n, reason))
	}
	var toEscalate []httpcrawl.Challenged
	if res != nil {
		var refused []string
		toEscalate, refused = browserPassable(res.Challenged)
		if len(refused) > 0 {
			run.Warnings = append(run.Warnings, fmt.Sprintf("not escalated to Chrome: %s answered with a WAF rule or a ban, which a browser meets alike",
				strings.Join(refused, ", ")))
		}
	}
	switch {
	case ho.Escalate != nil && len(toEscalate) > 0 && ctx.Err() == nil &&
		(cerr == nil || errors.Is(cerr, httpcrawl.ErrStopped) && challengeStop(res.Stats.Stopped)):
		run.Escalated = ho.Escalate(ctx, toEscalate, CookieParams(res.Cookies))
		if run.Blocked.Blocked && run.Escalated.Passed(cfg.Target.Hostname()) {
			run.Warnings = append(run.Warnings, "the first page is a bot challenge to plain HTTP; Chrome got past it (escalated)")
		}
	case ho.Escalate != nil && seedFailed && escalatable(res.SeedError) && ctx.Err() == nil:
		// What Go's TLS or HTTP/2 cannot speak, Chrome may (its own roots,
		// its handshake): one try.
		slog.Info("plain HTTP could not reach the first page: Chrome tries it", "err", res.SeedError)
		run.Escalated = ho.Escalate(ctx, []httpcrawl.Challenged{{URL: cfg.Target.String(), Asked: true}}, nil)
		if run.Escalated.Passed(cfg.Target.Hostname()) {
			run.Warnings = append(run.Warnings, "plain HTTP could not reach the first page; Chrome did (escalated)")
		}
	}
	if run.Escalated != nil && len(run.Escalated.Runs) > 0 {
		// Chrome's runs added scripts and requests to the directory: the
		// catalog again, before the archive reads it (PIP-01).
		tmp.run.Warnings = run.Warnings
		tmp.writeEndpoints()
		run.Endpoints, run.StaticAnalysis, run.Warnings = tmp.run.Endpoints, tmp.run.StaticAnalysis, tmp.run.Warnings
	}
	seedPassed := run.Escalated.Passed(cfg.Target.Hostname())
	seedDead := seedFailed && !seedPassed && len(run.Scripts) == 0
	if ho.SPABoot != nil && res != nil && res.Stats.SPA && !seedDead && ctx.Err() == nil &&
		run.Endpoints[endpoints.Both]+run.Endpoints[endpoints.ObservedOnly] == 0 {
		run.SPABoot = ho.SPABoot(ctx, res.Stats.SPAOrigins)
		for _, r := range run.SPABoot {
			if r.Error != "" && r.RunID == "" {
				run.Warnings = append(run.Warnings, "-spa-boot: "+r.Error)
			}
		}
		tmp.run.Warnings = run.Warnings
		tmp.writeEndpoints()
		run.Endpoints, run.StaticAnalysis, run.Warnings = tmp.run.Endpoints, tmp.run.StaticAnalysis, tmp.run.Warnings
	}
	blockedEmpty := run.Blocked.Blocked && len(run.Scripts) == 0 && !seedPassed
	if blockedEmpty {
		// Nothing of the site: the CDP engine would have met the same page.
		run.Warnings = append(run.Warnings, "the first page is a bot challenge and no script of the site was reached")
	}
	fallback := ho.Fallback
	if ho.Archive != nil {
		fallback = ho.Archive
	}
	switch {
	case ctx.Err() != nil || (cerr != nil && !errors.Is(cerr, httpcrawl.ErrStopped)):
	case seedDead:
		// Not the archives: a target that cannot be reached is a mistake to
		// fix (a URL, a certificate), not minutes of listing to wait out;
		// jsharvest archive runs them on its own.
	case blockedEmpty && fallback != nil:
		slog.Info("the first page is a challenge: trying the archives, and the live files their old pages name")
		run.Fallback = fallback(ctx)
	case ho.Archive != nil:
		slog.Info("the crawl is done; now the target's history: old pages and scripts in the archives, each checked live first (-archive=false to skip)")
		run.Archive = ho.Archive(ctx)
		if ctx.Err() == nil {
			// The archive's catalog fills what today's lines lack (a
			// document's path an old bundle calls): the catalog again
			// (PIP-01, endpoints.EnrichFromArchive).
			tmp.run.Warnings = run.Warnings
			tmp.writeEndpoints()
			run.Endpoints, run.StaticAnalysis, run.Warnings = tmp.run.Endpoints, tmp.run.StaticAnalysis, tmp.run.Warnings
		}
	}
	run.Ended = time.Now().UTC()
	run.DurationMS = run.Ended.Sub(run.Started).Milliseconds()
	err = cerr
	switch {
	case ctx.Err() != nil:
		run.ExitCode, err = 130, ctx.Err()
	case seedDead:
		run.ExitCode, err = 1, fmt.Errorf("the first page could not be fetched: %s", res.SeedError)
	case run.Blocked.Blocked && seedPassed:
		err = nil // Chrome got past it: its run has the pages
	case run.Blocked.Blocked:
		run.ExitCode, err = 3, ErrBlocked
		slog.Warn("bot challenge on the first page", "vendor", run.Blocked.Vendor, "evidence", run.Blocked.Evidence)
	case errors.Is(cerr, httpcrawl.ErrStopped):
		err = nil // polite: what came before is the run's
	case cerr != nil:
		run.ExitCode = 1
	}
	if run.Fronted != "" && !run.Blocked.Blocked {
		slog.Info("fronted by a bot/WAF vendor", "vendor", run.Fronted, "evidence", run.FrontedBy)
	}
	d.mu.Lock()
	werr := writeRun(st.Dir(), run)
	d.mu.Unlock()
	if werr != nil {
		slog.Error("write run.json", "err", werr)
	}
	slog.Info("done", "engine", "http", "pages", visited, "listed", listedN, "unique_scripts", run.UniqueScripts, "new_this_run", run.NewScripts,
		"requests", run.Requests, "page_requests", run.PageRequests, "internal_requests", run.InternalRequests, "challenge_dropped", run.Stats.Challenge)
	return run, err
}

// challengeStop reports a crawl stopped by challenges (a browser may get
// past them), not by a 429 or a Retry-After (a browser would only add to
// the load).
func challengeStop(why string) bool {
	return strings.Contains(why, "challenge") || strings.Contains(why, " block ")
}

// escalatable reports a first page's failure Chrome may not share: a TLS
// or HTTP/2 matter (its own roots, its handshake), not a name that does
// not resolve, a refused connection or a timeout.
func escalatable(err string) bool {
	e := strings.ToLower(err)
	for _, s := range []string{"no such host", "connection refused", "network is unreachable", "no route to host",
		"timeout", "deadline exceeded", "server misbehaving", "out of scope"} {
		if strings.Contains(e, s) {
			return false
		}
	}
	return true
}

// browserPassable keeps the challenged pages of the hosts where a browser
// may pass (round 25J): a host one of whose pages was a challenge or a
// signature refusal, or of a kind not told. A host whose every page
// blocked was a WAF rule, a client ban or a rate limit is left (it is
// named in refused): Chrome would be refused alike, a launch for nothing
// (portal.example.biz's "Sorry, you have been blocked", 2026-11-10 and
// -12).
func browserPassable(pages []httpcrawl.Challenged) (keep []httpcrawl.Challenged, refused []string) {
	may, seen := map[string]bool{}, map[string]bool{}
	var order []string
	hostOf := func(raw string) string {
		if u, err := url.Parse(raw); err == nil {
			return u.Host
		}
		return raw
	}
	for _, p := range pages {
		h := hostOf(p.URL)
		if !seen[h] {
			seen[h] = true
			order = append(order, h)
		}
		if p.Asked && (p.Kind == "" || detect.BlockKind(p.Kind).BrowserMayPass()) {
			may[h] = true
		}
	}
	for _, p := range pages {
		if may[hostOf(p.URL)] {
			keep = append(keep, p)
		}
	}
	for _, h := range order {
		if !may[h] {
			refused = append(refused, h)
		}
	}
	return keep, refused
}

// httpUA is the User-Agent the HTTP engine presents: -ua or the login's,
// else the Chrome installed's, the one an escalation to Chrome presents
// too (round 25K); "" leaves httpcrawl's fallback.
func httpUA(cfg Config) string {
	if cfg.Browser.UserAgent != "" {
		return cfg.Browser.UserAgent
	}
	return uahints.LocalChromeUA(cfg.Browser.ChromePath, "")
}

// CookieParams are the HTTP crawl's cookies as CDP takes them: a host-only
// cookie by the URL that set it, a domain cookie by its Domain.
func CookieParams(cs []httpcrawl.Cookie) []*network.CookieParam {
	var out []*network.CookieParam
	for _, c := range cs {
		p := &network.CookieParam{Name: c.Name, Value: c.Value, Path: c.Path, Secure: c.Secure, HTTPOnly: c.HTTPOnly}
		if c.Domain != "" {
			p.Domain = c.Domain
		} else {
			p.URL = c.URL
		}
		switch c.SameSite {
		case http.SameSiteStrictMode:
			p.SameSite = network.CookieSameSiteStrict
		case http.SameSiteLaxMode:
			p.SameSite = network.CookieSameSiteLax
		case http.SameSiteNoneMode:
			p.SameSite = network.CookieSameSiteNone
		}
		if !c.Expires.IsZero() {
			p.Expires = cdp.TimeSinceEpoch(float64(c.Expires.UnixNano()) / 1e9)
		}
		out = append(out, p)
	}
	return out
}
