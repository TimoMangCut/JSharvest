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
	"syscall"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/archive"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/scope"
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
	return err
}

// archiveRun is jsharvest archive with its context: crawl calls it too,
// when the first page is a challenge (CF-04b).
func archiveRun(ctx context.Context, args []string) (*archive.Summary, error) {
	fs := flag.NewFlagSet("archive", flag.ExitOnError)
	out := fs.String("o", env("JSHARVEST_OUTPUT", "output"), "output root (env JSHARVEST_OUTPUT)")
	target := fs.String("target", "", "the target's host (its subdomains are listed too)")
	sources := fs.String("sources", archiveSources, "archives to list: wayback, otx, commoncrawl, urlscan (listed at once; Common Crawl is slow; urlscan: its public scans, searched, never submitted; URLSCAN_API_KEY raises its limit)")
	scopeMode := fs.String("scope", "rdn", "rdn or fqdn: which hosts are the target's")
	since := fs.String("since", "", "only captures from this date on (YYYY-MM-DD)")
	live := fs.Bool("live", true, "ask the target whether an old script's URL still serves it (GET, no credentials, only hosts the crawls reached)")
	liveHosts := fs.String("live-hosts", "", "the hosts (host:port) the live check may ask, comma separated; default: those the crawls reached")
	liveRate := fs.Float64("live-rate", 2, "live checks per second, at most")
	maxFiles := fs.Int("max-files", 0, "old scripts to fetch, at most, newest first (0: all)")
	maxHTML := fs.Int("max-html", 10, "old pages (text/html captures) to read for the scripts they load, the root first (0: none)")
	vendor := fs.Bool("vendor", false, "fetch vendor libraries too (jquery, react…)")
	pageSize := fs.Int("page-size", 25000, "rows of a CDX page (when not using ZipNum sharding)")
	maxPages := fs.Int("max-pages", 0, "CDX pages to list, at most (0: all)")
	collapse := fs.String("collapse", "digest", "Wayback CDX field collapse (e.g. digest, urlkey, or none)")
	concurrency := fs.Int("concurrency", 8, "concurrent archive listing, live-check and fetch workers")
	ccCollections := fs.Int("cc-collections", 3, "Common Crawl's newest collections to list")
	proxy := fs.String("proxy", "", "send everything through this proxy: the archives and the live checks (default JSHARVEST_PROXY, HTTPS_PROXY, HTTP_PROXY; none: no proxy)")
	hostRules := fs.String("host-resolver-rules", env("JSHARVEST_HOST_RESOLVER_RULES", ""), `Chrome host resolver rules for the live check, e.g. "MAP *.example.test 127.0.0.1" (env JSHARVEST_HOST_RESOLVER_RULES)`)
	insecure := fs.Bool("insecure", false, "the live check accepts any TLS certificate (a self-signed lab target)")
	waitLock := waitLockFlag(fs)
	fs.Parse(args)
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if *target == "" {
		return nil, errors.New("archive: -target is required")
	}
	if *concurrency < 1 {
		return nil, errors.New("archive: -concurrency must be 1 or more")
	}
	in, err := scope.New(hostOnly(*target), *scopeMode)
	if err != nil {
		return nil, err
	}
	// One proxy for the archives' client and the live check alike.
	proxyVal, err := resolveProxy(*proxy)
	if err != nil {
		return nil, err
	}
	var proxyURL *url.URL
	if proxyVal != "" {
		if proxyURL, err = url.Parse(proxyVal); err != nil {
			return nil, fmt.Errorf("-proxy: %w", err)
		}
	}
	hostRuleSet, err := netsafe.ParseHostRules(*hostRules)
	if err != nil {
		return nil, fmt.Errorf("-host-resolver-rules: %w", err)
	}
	var from time.Time
	if *since != "" {
		if from, err = time.Parse(time.DateOnly, *since); err != nil {
			return nil, fmt.Errorf("-since: %w", err)
		}
	}
	root := filepath.Join(*out, hostOnly(*target)) // the host's, whatever port the crawls were on
	dir := filepath.Join(root, "archive")
	unlock, err := lockDirs("archive", *waitLock, dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	o := archive.Options{Dir: dir, Root: *out, Host: hostOnly(*target), InScope: in, Since: from, Live: *live, MaxFiles: *maxFiles, MaxPages: *maxPages, MaxHTML: *maxHTML,
		Vendor: *vendor, MaxBody: 32 << 20, Workers: *concurrency, Sources: strings.Split(*sources, ","),
		Log: func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }}

	// Patient budgets (EDGI's client keeps under 0.4/s for the CDX server
	// at its request); the gate shortens them.
	scale := 1.0
	if s, err := strconv.ParseFloat(os.Getenv("JSHARVEST_ARCHIVE_SCALE"), 64); err == nil && s > 0 {
		scale = s
	}
	gap := func(d time.Duration) time.Duration { return time.Duration(float64(d) * scale) }
	// The services' URLs the user (or a gate) declared are allowed whatever
	// their address; nothing else is.
	services := []string{env("JSHARVEST_WAYBACK_URL", "https://web.archive.org"), env("JSHARVEST_OTX_URL", "https://otx.alienvault.com"),
		env("JSHARVEST_CC_INDEX_URL", "https://index.commoncrawl.org"), env("JSHARVEST_CC_DATA_URL", "https://data.commoncrawl.org"),
		env("JSHARVEST_URLSCAN_URL", "https://urlscan.io")}
	client := archive.NewClientSafe(proxyURL, hostRuleSet, services)
	client.Wait = gap(60 * time.Second)
	wbBase := env("JSHARVEST_WAYBACK_URL", "https://web.archive.org")
	wb, _ := url.Parse(wbBase)
	// A memento may move to the nearest capture, at times by a few hops
	// (/web/2id_/ → a time stamp → the scheme the capture has): within the
	// Wayback only (ARC-06).
	client.HTTP.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != wb.Host || len(via) >= 8 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	shardedWB := !given["page-size"] && os.Getenv("JSHARVEST_WAYBACK_URL") == ""
	collapseVal := *collapse
	if collapseVal == "none" || (!shardedWB && !given["collapse"]) {
		collapseVal = ""
	}
	wbIndexGap := gap(4 * time.Second)
	if shardedWB {
		wbIndexGap = gap(1500 * time.Millisecond)
	}
	wbFilesGap := gap(time.Second)
	if *concurrency > 1 {
		wbFilesGap = gap(250 * time.Millisecond)
	}
	o.Wayback = &archive.Wayback{Base: wbBase, Client: client, Index: &archive.Budget{Gap: wbIndexGap},
		Files: &archive.Budget{Gap: wbFilesGap}, PageSize: *pageSize, Collapse: collapseVal, Sharded: shardedWB}
	o.OTX = &archive.OTX{Base: env("JSHARVEST_OTX_URL", "https://otx.alienvault.com"), Client: client, Budget: &archive.Budget{Gap: gap(2 * time.Second)}}
	// Common Crawl's index answers 504 when busy: three tries, 15 s apart,
	// then the next collection (MAX-01).
	ccClient := archive.NewClientSafe(proxyURL, hostRuleSet, services)
	ccClient.Tries, ccClient.Wait = 3, gap(15*time.Second)
	o.CC = &archive.CommonCrawl{Index: env("JSHARVEST_CC_INDEX_URL", "https://index.commoncrawl.org"),
		Data: env("JSHARVEST_CC_DATA_URL", "https://data.commoncrawl.org"), Client: ccClient,
		Budget: &archive.Budget{Gap: gap(10 * time.Second)}, Files: &archive.Budget{Gap: gap(time.Second)}, Collections: *ccCollections}

	o.URLScan = &archive.URLScan{Base: env("JSHARVEST_URLSCAN_URL", "https://urlscan.io"), Key: os.Getenv("URLSCAN_API_KEY"), Client: client,
		Budget: &archive.Budget{Gap: gap(2 * time.Second)}, Pages: 10, Results: 10}

	if *scopeMode == "rdn" {
		// The other hosts the crawls reached: OTX and urlscan are asked of
		// them too (MAX-06).
		crawled, _ := archive.CrawlHosts(*out, in)
		seen := map[string]bool{hostOnly(*target): true}
		for h := range crawled {
			if h = hostOnly(h); !seen[h] {
				seen[h] = true
				o.ExtraHosts = append(o.ExtraHosts, h)
			}
		}
		sort.Strings(o.ExtraHosts)
	}
	if *live {
		hosts, recorded := archive.CrawlHosts(*out, in)
		if *liveHosts != "" {
			hosts = map[string]bool{}
			for _, h := range strings.Split(*liveHosts, ",") {
				hosts[strings.TrimSpace(h)] = true
			}
		} else {
			// The target itself, crawled or not (ARC-01): the operator named
			// it. An old subdomain is asked only once a crawl reached it: it
			// may point at someone else's service now.
			if len(hosts) == 0 {
				fmt.Fprintln(os.Stderr, "note: no crawl of the target yet: the live check asks the target's own host only (-live-hosts to name more)")
			}
			hosts[liveHost(*target)] = true
			hosts[hostOnly(*target)] = true
		}
		so := replay.SenderOptions{Hosts: hosts, Recorded: recorded, Max: 10 * *maxFiles, Concurrency: *concurrency, Rate: time.Duration(float64(time.Second) / *liveRate),
			Log: filepath.Join(dir, "live-checks.jsonl"), Insecure: *insecure,
			UserAgent: observedUA(filepath.Join(root, "*"), filepath.Join(*out, hostOnly(*target)+"_*", "*"))}
		so.Proxy, so.HostRules = proxyURL, hostRuleSet
		so.AllowPrivate = netsafe.InternalTargetVia(ctx, liveHost(*target), so.HostRules, nil, proxyURL != nil)
		if o.Sender, err = replay.NewSender(so); err != nil {
			return nil, err
		}
		defer o.Sender.Close()
		o.LiveHosts = hosts
	}
	sum, err := archive.Run(ctx, o)
	if sum != nil {
		var listed []string
		for k, v := range sum.Listed {
			listed = append(listed, fmt.Sprintf("%s %d", k, v))
		}
		sort.Strings(listed)
		fmt.Fprintf(os.Stderr, "archive %s: listed %s; %d URLs, %d script contents; fetched %d (alive %d, the same live %d), already held %d, digest mismatch %d, failed %d\n",
			*target, strings.Join(listed, ", "), sum.URLs, sum.Digests, sum.Fetched, sum.Alive, sum.LiveSame, sum.Known, sum.Mismatch, sum.Failed)
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
		fmt.Fprintln(os.Stderr, "wrote", dir)
	}
	return sum, err
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
