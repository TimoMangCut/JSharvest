package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/archive"
	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/sourcemap"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

// archiveSources are the archives listed by default, by archive and by
// crawl -archive: all of them (Common Crawl's index is slow, a minute or
// so for a host, and gives up on a 503 without failing the run).
const archiveSources = "wayback,otx,commoncrawl,urlscan"

// runArchive lists the target's history in public archives, fetches its
// old scripts, and writes the endpoints only they call (see
// docs/gd5-archive-design.md).
func runArchive(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	_, err := archiveRun(ctx, args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

// archiveRun is jsharvest archive with its context: one whole run.
func archiveRun(ctx context.Context, args []string) (*archive.Summary, error) {
	cfg, err := parseArchiveFlags(args)
	if err != nil {
		return nil, err
	}
	e, err := newArchiveEnv(cfg)
	if err != nil {
		return nil, err
	}
	defer e.Close()
	return e.Run(ctx, archive.ModeFull)
}

// archiveConfig is jsharvest archive's flags, parsed and checked. crawl
// -archive builds one too, from the same flags, so that both read them the
// same way (round 37.1, B1).
type archiveConfig struct {
	out, target, sources, scopeMode string
	from                            time.Time
	live                            bool
	liveHosts                       string
	liveRate                        float64
	maxFiles, maxHTML, pageSize     int
	maxSourceFiles, maxStoreMB      int
	maxPages, concurrency           int
	ccCollections                   int
	collapse                        string
	vendor, insecure                bool
	archiveUA                       string
	proxyURL                        *url.URL
	hostRules                       netsafe.Rules
	waitLock                        time.Duration
	shardedWB                       bool
}

// parseArchiveFlags reads jsharvest archive's flags. A bad one is an error,
// never an exit: crawl parses them in its own process.
func parseArchiveFlags(args []string) (archiveConfig, error) {
	fs := flag.NewFlagSet("archive", flag.ContinueOnError)
	out := fs.String("o", env("JSHARVEST_OUTPUT", "output"), "output root (env JSHARVEST_OUTPUT)")
	target := fs.String("target", "", "the target's host (its subdomains are listed too)")
	sources := fs.String("sources", archiveSources, "archives to list: wayback, otx, commoncrawl, urlscan (listed at once; Common Crawl is slow; urlscan: its public scans, searched, never submitted; URLSCAN_API_KEY raises its limit)")
	scopeMode := fs.String("scope", "rdn", "rdn or fqdn: which hosts are the target's")
	since := fs.String("since", "", "only captures from this date on (YYYY-MM-DD)")
	live := fs.Bool("live", true, "ask the target whether an old script's URL still serves it (GET, no credentials, only hosts the crawls reached)")
	liveHosts := fs.String("live-hosts", "", "the hosts (host:port) the live check may ask, comma separated; default: those the crawls reached")
	liveRate := fs.Float64("live-rate", 5, "live checks per second, at most")
	maxFiles := fs.Int("max-files", 0, "old scripts to fetch, at most, newest first (0: all)")
	maxSourceFiles := fs.Int("max-source-files", sourcemap.DefaultMaxSourceFilesPerRun, "most original source files extracted from source maps per run (<0: unlimited)")
	maxStoreMB := fs.Int("max-store-mb", store.DefaultMaxStoreMB, "most new MiB written to js/ and maps/ in one run (0: unlimited)")
	maxHTML := fs.Int("max-html", 10, "old pages (text/html captures) to read for the scripts they load, the root first (0: none)")
	vendor := fs.Bool("vendor", false, "fetch vendor libraries too (jquery, react…)")
	pageSize := fs.Int("page-size", 25000, "rows of a CDX page (when not using ZipNum sharding)")
	maxPages := fs.Int("max-pages", 0, "CDX pages to list, at most (0: all)")
	collapse := fs.String("collapse", "digest", "Wayback CDX field collapse (e.g. digest, urlkey, or none)")
	concurrency := fs.Int("concurrency", 8, "concurrent archive listing, live-check and fetch workers")
	memCacheMB := fs.Int("mem-cache-mb", 512, "RAM budget in MiB for in-memory JS AST & script cache (0: off)")
	ccCollections := fs.Int("cc-collections", 3, "Common Crawl's newest collections to list")
	proxy := fs.String("proxy", "", "send everything through this proxy: the archives and the live checks (default JSHARVEST_PROXY, HTTPS_PROXY, HTTP_PROXY; none: no proxy)")
	hostRules := fs.String("host-resolver-rules", env("JSHARVEST_HOST_RESOLVER_RULES", ""), `Chrome host resolver rules for the live check, e.g. "MAP *.example.test 127.0.0.1" (env JSHARVEST_HOST_RESOLVER_RULES)`)
	archiveUA := fs.String("archive-ua", archive.DefaultUA, "User-Agent sent to archive services (default identifies jsharvest per Internet Archive etiquette; override for stricter OpSec)")
	insecure := fs.Bool("insecure", false, "the live check accepts any TLS certificate (a self-signed lab target)")
	waitLock := waitLockFlag(fs)
	if err := fs.Parse(args); err != nil {
		return archiveConfig{}, err
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if os.Getenv("JSHARVEST_MEM_CACHE_MB") == "" || given["mem-cache-mb"] {
		endpoints.SetMemCacheMB(*memCacheMB)
	}
	if *target == "" {
		return archiveConfig{}, errors.New("archive: -target is required")
	}
	if *concurrency < 1 {
		return archiveConfig{}, errors.New("archive: -concurrency must be 1 or more")
	}
	if *maxStoreMB < 0 {
		return archiveConfig{}, errors.New("archive: -max-store-mb must not be negative")
	}
	c := archiveConfig{out: *out, target: *target, sources: *sources, scopeMode: *scopeMode, live: *live, liveHosts: *liveHosts,
		liveRate: *liveRate, maxFiles: *maxFiles, maxSourceFiles: *maxSourceFiles, maxStoreMB: *maxStoreMB, maxHTML: *maxHTML, pageSize: *pageSize, maxPages: *maxPages,
		concurrency: *concurrency, ccCollections: *ccCollections, vendor: *vendor, insecure: *insecure, archiveUA: *archiveUA, waitLock: *waitLock,
		shardedWB: !given["page-size"] && os.Getenv("JSHARVEST_WAYBACK_URL") == ""}
	c.collapse = *collapse
	if c.collapse == "none" || (!c.shardedWB && !given["collapse"]) {
		c.collapse = ""
	}
	// One proxy for the archives' client and the live check alike.
	proxyVal, err := resolveProxy(*proxy)
	if err != nil {
		return archiveConfig{}, err
	}
	if proxyVal != "" {
		if c.proxyURL, err = url.Parse(proxyVal); err != nil {
			return archiveConfig{}, fmt.Errorf("-proxy: %w", err)
		}
	}
	if c.hostRules, err = netsafe.ParseHostRules(*hostRules); err != nil {
		return archiveConfig{}, fmt.Errorf("-host-resolver-rules: %w", err)
	}
	if *since != "" {
		if c.from, err = time.Parse(time.DateOnly, *since); err != nil {
			return archiveConfig{}, fmt.Errorf("-since: %w", err)
		}
	}
	return c, nil
}

// archiveEnv is one target's archive work: its lock, its clients and their
// budgets, built once. crawl runs stage 1 and stage 2 on the same env, so
// the lock is held from the first to the last request and each service's
// pacing (a budget widened by a 429, a client that saw refusals) carries
// over (round 37.1, B).
type archiveEnv struct {
	cfg    archiveConfig
	in     func(string) bool
	dir    string
	opts   archive.Options
	unlock func()

	prepared bool // the crawls' hosts read, the live sender built
	sender   *replay.Sender

	mu        sync.Mutex
	stage1Ran bool  // a stage 1 listed the indexes to the end (or to a block)
	stage1Err error // a block stage 1 met, reported with stage 2's result
}

func newArchiveEnv(cfg archiveConfig) (*archiveEnv, error) {
	in, err := scope.New(hostOnly(cfg.target), cfg.scopeMode)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(cfg.out, hostOnly(cfg.target)) // the host's, whatever port the crawls were on
	dir := filepath.Join(root, "archive")
	unlock, err := lockDirs("archive", cfg.waitLock, dir)
	if err != nil {
		return nil, err
	}
	e := &archiveEnv{cfg: cfg, in: in, dir: dir, unlock: unlock}
	if err := e.buildClients(); err != nil {
		unlock()
		return nil, err
	}
	return e, nil
}

func (e *archiveEnv) buildClients() error {
	cfg := e.cfg
	o := archive.Options{Dir: e.dir, Root: cfg.out, Host: hostOnly(cfg.target), InScope: e.in, Since: cfg.from, Live: cfg.live,
		MaxFiles: cfg.maxFiles, MaxPages: cfg.maxPages, MaxHTML: cfg.maxHTML, MaxSourceFiles: cfg.maxSourceFiles, MaxStoreBytes: int64(cfg.maxStoreMB) << 20,
		Vendor: cfg.vendor, MaxBody: 32 << 20, Workers: cfg.concurrency, Sources: strings.Split(cfg.sources, ","),
		Log: func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }}

	// Patient budgets (EDGI's client keeps under 0.4/s for the CDX server
	// at its request); the gate shortens them.
	scale := 1.0
	if s, err := strconv.ParseFloat(os.Getenv("JSHARVEST_ARCHIVE_SCALE"), 64); err == nil && s > 0 {
		scale = s
	}
	gap := func(d time.Duration) time.Duration { return time.Duration(float64(d) * scale) }
	parseServiceURL := func(envName, raw string) (*url.URL, error) {
		u, perr := url.Parse(raw)
		if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("archive: bad %s URL %q", envName, raw)
		}
		return u, nil
	}
	wbBase := env("JSHARVEST_WAYBACK_URL", "https://web.archive.org")
	wb, err := parseServiceURL("JSHARVEST_WAYBACK_URL", wbBase)
	if err != nil {
		return err
	}
	otxBase := env("JSHARVEST_OTX_URL", "https://otx.alienvault.com")
	if _, err := parseServiceURL("JSHARVEST_OTX_URL", otxBase); err != nil {
		return err
	}
	ccIndexURL := env("JSHARVEST_CC_INDEX_URL", "https://index.commoncrawl.org")
	ccIdxU, err := parseServiceURL("JSHARVEST_CC_INDEX_URL", ccIndexURL)
	if err != nil {
		return err
	}
	ccDataURL := env("JSHARVEST_CC_DATA_URL", "https://data.commoncrawl.org")
	ccDataU, err := parseServiceURL("JSHARVEST_CC_DATA_URL", ccDataURL)
	if err != nil {
		return err
	}
	usBase := env("JSHARVEST_URLSCAN_URL", "https://urlscan.io")
	if _, err := parseServiceURL("JSHARVEST_URLSCAN_URL", usBase); err != nil {
		return err
	}
	proxyURL, hostRuleSet := cfg.proxyURL, cfg.hostRules
	// The services' URLs the user (or a gate) declared are allowed whatever
	// their address; nothing else is.
	services := []string{wbBase, otxBase, ccIndexURL, ccDataURL, usBase}
	// Separate Client per archive service — and separate Wayback CDX vs Memento
	// clients — so connection-reset circuit breakers are strictly isolated per
	// upstream cluster.
	wbIndexClient := archive.NewClientSafe(proxyURL, hostRuleSet, services)
	wbIndexClient.Wait = gap(60 * time.Second)
	wbIndexClient.HTTP.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != wb.Host || len(via) >= 4 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	wbFilesClient := archive.NewClientSafe(proxyURL, hostRuleSet, services)
	wbFilesClient.Wait = gap(60 * time.Second)
	// A memento may move to the nearest capture, at times by a few hops
	// (/web/2id_/ → a time stamp → the scheme the capture has): within the
	// Wayback only (ARC-06).
	wbFilesClient.HTTP.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != wb.Host || len(via) >= 8 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	// Keep CDX index pacing <= 24 req/min (2.5s gap = 80% of Internet Archive's
	// ~30 req/min hard CDX limit), with AIMD expansion up to 10s on 429/503.
	wbIndexGap := gap(2500 * time.Millisecond)
	wbIndexMaxGap := gap(10 * time.Second)
	wbFilesGap := gap(time.Second)
	if cfg.concurrency > 1 {
		wbFilesGap = gap(300 * time.Millisecond)
	}
	o.Wayback = &archive.Wayback{Base: wbBase, Client: wbFilesClient, IndexClient: wbIndexClient,
		Index: &archive.Budget{Gap: wbIndexGap, MaxGap: wbIndexMaxGap}, Files: &archive.Budget{Gap: wbFilesGap, MaxGap: gap(5 * time.Second)},
		PageSize: cfg.pageSize, Collapse: cfg.collapse, Sharded: cfg.shardedWB}

	otxClient := archive.NewClientSafe(proxyURL, hostRuleSet, services)
	otxClient.Wait = gap(60 * time.Second)
	otxClient.HTTP.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	o.OTX = &archive.OTX{Base: otxBase, Client: otxClient, Budget: &archive.Budget{Gap: gap(time.Second)}}

	// Common Crawl's index answers 504 when busy: two fast tries across
	// parallel collections so dead collections fail fast (MAX-01).
	ccClient := archive.NewClientSafe(proxyURL, hostRuleSet, services)
	ccClient.Tries, ccClient.Wait = 2, gap(6*time.Second)
	ccClient.HTTP.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 || (req.URL.Host != ccIdxU.Host && req.URL.Host != ccDataU.Host) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	o.CC = &archive.CommonCrawl{Index: ccIndexURL,
		Data: ccDataURL, Client: ccClient,
		Budget: &archive.Budget{Gap: gap(3 * time.Second)}, Files: &archive.Budget{Gap: gap(500 * time.Millisecond)}, Collections: cfg.ccCollections}

	usClient := archive.NewClientSafe(proxyURL, hostRuleSet, services)
	usClient.Wait = gap(60 * time.Second)
	usClient.HTTP.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	if cfg.archiveUA != "" {
		for _, cl := range []*archive.Client{wbIndexClient, wbFilesClient, otxClient, ccClient, usClient} {
			cl.UA = cfg.archiveUA
		}
	}
	o.URLScan = &archive.URLScan{Base: usBase, Key: os.Getenv("URLSCAN_API_KEY"), Client: usClient,
		Budget: &archive.Budget{Gap: gap(2 * time.Second)}, Pages: 10, Results: 10}
	e.opts = o
	return nil
}

// prepare reads what the crawls found (the hosts OTX and urlscan are asked
// of, the hosts and addresses the live check may ask) and builds the live
// sender: once, before the first run that is not a stage 1, so that a
// stage 2 sees every host the crawl reached.
func (e *archiveEnv) prepare(ctx context.Context) error {
	if e.prepared {
		return nil
	}
	e.prepared = true
	cfg := e.cfg
	if cfg.scopeMode != "rdn" && !cfg.live {
		return nil
	}
	crawled, recorded, ua := archive.CrawlHostsWithUA(cfg.out, hostOnly(cfg.target), "", e.in)
	if cfg.scopeMode == "rdn" {
		// The other hosts the crawls reached: OTX and urlscan are asked of
		// them too (MAX-06).
		seen := map[string]bool{hostOnly(cfg.target): true}
		for h := range crawled {
			if h = hostOnly(h); !seen[h] {
				seen[h] = true
				e.opts.ExtraHosts = append(e.opts.ExtraHosts, h)
			}
		}
		sort.Strings(e.opts.ExtraHosts)
	}
	if !cfg.live {
		return nil
	}
	hosts := crawled
	if cfg.liveHosts != "" {
		hosts = map[string]bool{}
		for _, h := range strings.Split(cfg.liveHosts, ",") {
			hosts[strings.TrimSpace(h)] = true
		}
	} else {
		// The target itself, crawled or not (ARC-01): the operator named
		// it. An old subdomain is asked only once a crawl reached it: it
		// may point at someone else's service now.
		if len(hosts) == 0 {
			fmt.Fprintln(os.Stderr, "note: no crawl of the target yet: the live check asks the target's own host only (-live-hosts to name more)")
		}
		hosts[liveHost(cfg.target)] = true
		hosts[hostOnly(cfg.target)] = true
	}
	so := replay.SenderOptions{Hosts: hosts, Recorded: recorded, Max: 10 * cfg.maxFiles, Concurrency: cfg.concurrency, Rate: time.Duration(float64(time.Second) / cfg.liveRate),
		Log: filepath.Join(e.dir, "live-checks.jsonl"), Insecure: cfg.insecure,
		UserAgent: ua}
	so.Proxy, so.HostRules = cfg.proxyURL, cfg.hostRules
	so.AllowPrivate = netsafe.InternalTargetVia(ctx, liveHost(cfg.target), so.HostRules, nil, cfg.proxyURL != nil)
	s, err := replay.NewSender(so)
	if err != nil {
		return err
	}
	e.sender = s
	e.opts.Sender, e.opts.LiveHosts = s, hosts
	return nil
}

// Stage1Ran says a stage 1 listed the indexes to the end (or to a block):
// the next run is a stage 2.
func (e *archiveEnv) Stage1Ran() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stage1Ran
}

// RunListOnly runs Stage 1 index listing, optionally streaming newly
// discovered in-scope subdomains into OTX and urlscan when -scope rdn is set.
func (e *archiveEnv) RunListOnly(ctx context.Context, extraHosts <-chan string) (*archive.Summary, error) {
	o := e.opts
	o.Mode = archive.ModeListOnly
	if e.cfg.scopeMode == "rdn" {
		o.ExtraHostCh = extraHosts
	}
	sum, err := archive.Run(ctx, o)
	e.mu.Lock()
	if ctx.Err() == nil && (err == nil || errors.Is(err, archive.ErrBlocked)) {
		e.stage1Ran = true
		if err != nil {
			e.stage1Err = err
		}
	}
	e.mu.Unlock()
	return sum, err
}

// Run is one run of the archive work in mode.
func (e *archiveEnv) Run(ctx context.Context, mode archive.Mode) (*archive.Summary, error) {
	if mode == archive.ModeListOnly {
		return e.RunListOnly(ctx, nil)
	}
	if err := e.prepare(ctx); err != nil {
		return nil, err
	}
	o := e.opts
	o.Mode = mode
	e.mu.Lock()
	stage1Err := e.stage1Err
	e.mu.Unlock()
	if mode == archive.ModeResume && o.Wayback.CarryIndexBlock() {
		fmt.Fprintln(os.Stderr, "note: the Wayback refused stage 1's connections: its mementos wait, and stop at the first refusal")
	}
	sum, err := archive.Run(ctx, o)
	if err == nil && stage1Err != nil {
		err = stage1Err
	}
	e.report(sum, err)
	return sum, err
}

func (e *archiveEnv) report(sum *archive.Summary, err error) {
	if sum != nil {
		var listed []string
		for k, v := range sum.Listed {
			listed = append(listed, fmt.Sprintf("%s %d", k, v))
		}
		sort.Strings(listed)
		fmt.Fprintf(os.Stderr, "archive %s: listed %s; %d URLs, %d script contents; fetched %d (alive %d, the same live %d), already held %d, digest mismatch %d, failed %d\n",
			e.cfg.target, strings.Join(listed, ", "), sum.URLs, sum.Digests, sum.Fetched, sum.Alive, sum.LiveSame, sum.Known, sum.Mismatch, sum.Failed)
		if sum.Pages > 0 || sum.HTML > 0 {
			fmt.Fprintf(os.Stderr, "old pages: %d listed, %d read; %d scripts named, %d inline; %d chunks resolved; %d not archived\n",
				sum.HTML, sum.Pages, sum.PageScripts, sum.Inline, sum.Resolved, sum.NotArchived)
		}
		if len(sum.Historical) > 0 {
			fmt.Fprintf(os.Stderr, "historical endpoints: %v (historical.jsonl)\n", sum.Historical)
		}
		if n := len(sum.Credential); n > 0 {
			fmt.Fprintf(os.Stderr, "finding: %d archived URLs carry a credential (masked in archive.json): check whether they still work, by hand\n", n)
		}
		for _, n := range sum.Notes {
			fmt.Fprintln(os.Stderr, "note:", n)
		}
	}
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "stopped: run again to resume")
	}
	if err == nil {
		fmt.Fprintln(os.Stderr, "wrote", e.dir)
	}
}

// Close ends the env: the live sender, then the lock.
func (e *archiveEnv) Close() {
	if e == nil {
		return
	}
	if e.sender != nil {
		e.sender.Close()
		e.sender = nil
	}
	if e.unlock != nil {
		e.unlock()
		e.unlock = nil
	}
}

// liveHost is the host:port the live check may ask of what -target is
// given (app.example.com_3016 → app.example.com:3016).
func liveHost(raw string) string {
	if d := targetDir(raw); d != hostOnly(raw) && strings.HasPrefix(d, hostOnly(raw)+"_") {
		return hostOnly(raw) + ":" + strings.TrimPrefix(d, hostOnly(raw)+"_")
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}
