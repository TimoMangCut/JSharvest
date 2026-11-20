package engine

import (
	"context"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/TimoMangCut/JSharvest/internal/httpcrawl"
	"github.com/TimoMangCut/JSharvest/internal/scope"
)

// Escalation is what Chrome made of the pages the HTTP engine could not get
// past a bot challenge on (crawl -engine auto): a run a host, filed with the
// crawl's seed, its pages that host's alone. A clean Chrome passes many a
// JavaScript challenge that plain HTTP cannot; an interactive one, or a
// deny page, stays blocked, and the run says so.
type Escalation struct {
	Pages []httpcrawl.Challenged `json:"pages"`
	Runs  []EscalatedRun         `json:"runs"`
	// Skipped: hosts past MaxEscalatedHosts, not tried.
	Skipped []string `json:"skipped_hosts,omitempty"`
}

// EscalatedRun is one host's run in Chrome.
type EscalatedRun struct {
	Host             string `json:"host"`
	Target           string `json:"target"`
	RunID            string `json:"run_id,omitempty"`
	Pages            int    `json:"pages"` // pages visited
	Requests         int    `json:"requests,omitempty"`
	PageRequests     int    `json:"page_requests,omitempty"`
	InternalRequests int    `json:"internal_requests,omitempty"`
	NewScripts       int    `json:"new_scripts"`
	Blocked          bool   `json:"blocked"`
	ExitCode         int    `json:"exit_code"`
	Error            string `json:"error,omitempty"`
}

// MaxEscalatedHosts bounds the browsers one crawl starts for its
// challenged hosts.
const MaxEscalatedHosts = 5

// maxEscalatedSeeds bounds the pages of one host handed on as seeds.
const maxEscalatedSeeds = 50

// Passed reports whether Chrome got past the challenge on host.
func (e *Escalation) Passed(host string) bool {
	if e == nil {
		return false
	}
	for _, r := range e.Runs {
		if strings.EqualFold(r.Host, host) && !r.Blocked && r.ExitCode == 0 && r.Error == "" {
			return true
		}
	}
	return false
}

// Escalate runs Chrome (the CDP engine) on the pages the HTTP crawl of
// cfg.Target met a challenge on. Each host gets one run: its shallowest
// challenged page is the target, its others are seeds, and its pages are
// crawled to what is left of cfg.Depth, that host's alone (the others
// HTTP read already), or the whole scope when the seed was the page. Scripts and requests keep the crawl's scope; the
// output is the seed's.
func Escalate(ctx context.Context, cfg Config, pages []httpcrawl.Challenged, cookies []*network.CookieParam) *Escalation {
	cfg = escalationConfig(cfg, cookies)
	if cfg.InScope == nil {
		in, err := scope.New(cfg.Target.Hostname(), cfg.ScopeMode)
		if err != nil {
			return &Escalation{Pages: pages, Runs: []EscalatedRun{{Error: err.Error()}}}
		}
		cfg.InScope = in
	}
	esc := &Escalation{Pages: pages}
	seedHost := strings.ToLower(cfg.Target.Hostname())
	byHost := map[string][]httpcrawl.Challenged{}
	var hosts []string
	for _, p := range pages {
		u, err := url.Parse(p.URL)
		if err != nil {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if byHost[h] == nil {
			hosts = append(hosts, h)
		}
		byHost[h] = append(byHost[h], p)
	}
	// The seed's host first: the crawl's own pages.
	slices.SortStableFunc(hosts, func(a, b string) int {
		switch {
		case a == seedHost && b != seedHost:
			return -1
		case b == seedHost && a != seedHost:
			return 1
		}
		return 0
	})
	for i, h := range hosts {
		if ctx.Err() != nil {
			break
		}
		if i >= MaxEscalatedHosts {
			esc.Skipped = append(esc.Skipped, h)
			continue
		}
		ps := byHost[h]
		slices.SortStableFunc(ps, func(a, b httpcrawl.Challenged) int { return a.Depth - b.Depth })
		target, err := url.Parse(ps[0].URL)
		if err != nil {
			continue
		}
		c := cfg
		c.Target = target
		c.OutHost = scope.TargetDir(cfg.Target)
		if cfg.OutHost != "" {
			c.OutHost = cfg.OutHost
		}
		c.Depth = max(0, cfg.Depth-ps[0].Depth)
		c.Seeds = nil
		for _, p := range ps[1:] {
			if len(c.Seeds) < maxEscalatedSeeds {
				c.Seeds = append(c.Seeds, p.URL)
			}
		}
		host := h
		c.PageScope = func(x string) bool { return strings.EqualFold(x, host) }
		if h == seedHost && ps[0].Depth == 0 {
			c.PageScope = nil // the seed itself: HTTP read nothing of the site
		}
		slog.Info("a bot challenge HTTP could not pass: Chrome takes the host's pages", "host", h, "target", logURL(target.String()),
			"pages", len(ps), "depth", c.Depth)
		rec, err := RunRecord(ctx, c)
		r := EscalatedRun{Host: h, Target: target.String(), RunID: rec.RunID,
			Requests: rec.Requests, PageRequests: rec.PageRequests, InternalRequests: rec.InternalRequests,
			NewScripts: rec.NewScripts, Blocked: rec.Blocked.Blocked, ExitCode: rec.ExitCode}
		if rec.Frontier != nil {
			r.Pages = rec.Frontier.Visited
		} else if rec.RunID != "" {
			r.Pages = 1
		}
		if err != nil && !r.Blocked {
			r.Error = err.Error()
		}
		esc.Runs = append(esc.Runs, r)
		slog.Info("chrome on the challenged host", "host", h, "passed", !r.Blocked && r.Error == "", "pages", r.Pages, "new_scripts", r.NewScripts)
	}
	return esc
}

// SPA boot (PIP-04, crawl -spa-boot): an SPA that the HTTP engine read
// whole but saw no API call of sends its first calls when it boots, which
// only a browser does. One guarded tab a SPA origin, a short budget.
const (
	MaxSPABootOrigins = 3
	SPABootBudget     = 8 * time.Second
)

// SPABoot loads the first page of each SPA origin (at most
// MaxSPABootOrigins) in Chrome, guarded, for SPABootBudget at most: its
// boot requests go to requests.jsonl, its lazy chunks to the store, both
// filed with the crawl. A browser that cannot start is a run's error,
// nothing more.
func SPABoot(ctx context.Context, cfg Config, origins []string) []EscalatedRun {
	var out []EscalatedRun
	for i, o := range origins {
		if i == MaxSPABootOrigins || ctx.Err() != nil {
			break
		}
		target, err := url.Parse(o + "/")
		if err != nil {
			continue
		}
		c := cfg
		c.Target = target
		if c.OutHost == "" {
			c.OutHost = scope.TargetDir(cfg.Target)
		}
		c.Depth, c.Seeds, c.Explore, c.SpecProbe = 0, nil, false, false
		c.Guard = true // the boot's writes are held, as ever with a browser
		c.NavTimeout = min(c.NavTimeout, SPABootBudget)
		if c.NavTimeout <= 0 {
			c.NavTimeout = SPABootBudget
		}
		c.IdleMax = min(c.IdleMax, SPABootBudget)
		if c.IdleMax <= 0 {
			c.IdleMax = SPABootBudget
		}
		bctx, cancel := context.WithTimeout(ctx, 3*SPABootBudget)
		slog.Info("an SPA with no API call seen: Chrome boots it (-spa-boot)", "origin", o)
		rec, err := RunRecord(bctx, c)
		cancel()
		r := EscalatedRun{Host: target.Hostname(), Target: target.String(), RunID: rec.RunID,
			Requests: rec.Requests, PageRequests: rec.PageRequests, InternalRequests: rec.InternalRequests,
			NewScripts: rec.NewScripts, Blocked: rec.Blocked.Blocked, ExitCode: rec.ExitCode, Pages: 1}
		if err != nil {
			r.Error = err.Error()
		}
		out = append(out, r)
	}
	return out
}

// escalationConfig is the configuration Chrome goes on with (round 25L):
// the HTTP engine's User-Agent (and so the client hints cleanUA gives
// it), the application's cookies the crawl got, a profile of its own
// (none of a role's).
func escalationConfig(cfg Config, cookies []*network.CookieParam) Config {
	cfg.Browser.UserAgent = httpUA(cfg)
	if cfg.Browser.UserAgent == "" {
		cfg.Browser.UserAgent = httpcrawl.DefaultUserAgent
	}
	cfg.Browser.ProfileDir = ""
	cfg.Cookies = cookies
	return cfg
}
