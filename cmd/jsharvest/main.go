package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/TimoMangCut/JSharvest/internal/archive"
	"github.com/TimoMangCut/JSharvest/internal/browser"
	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/engine"
	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/httpcrawl"
	"github.com/TimoMangCut/JSharvest/internal/mcpserver"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

const version = "0.31.0"

const usage = `jsharvest — collect the JavaScript and the requests of a web target

Usage:
  jsharvest crawl -u URL [flags]
  jsharvest crawl -urls FILE [flags]
  jsharvest watch -attach ENDPOINT (-tab REGEXP | -open URL) -guard on|off [flags]
  jsharvest login -u URL -role ROLE [-steps FILE | -attach ENDPOINT] [-check-url URL]
  jsharvest mcp [-o OUTPUT] [-target HOST] [-role ROLE] [-reveal]
  jsharvest endpoints -target HOST [-o OUTPUT] [-role ROLE] [-status static|observed|both]
  jsharvest diff -target HOST [-o OUTPUT] [-roles anon,user,admin] [-all] [-reveal]
  jsharvest export -target HOST [-o OUTPUT] [-role ROLE] [-run ID|all] [-dest DIR] [-redact] [-drafts [-include-docs] [-include-strings] [-include-source-only]]
  jsharvest archive -target HOST [-sources wayback,otx,commoncrawl (default: all)] [-since DATE] [-live=false]
  jsharvest monitor -target HOST [-fail-on high] [-webhook-file F] [-dry-run]
  jsharvest replay -target HOST -flow ACTION [-role ROLE] [-as ROLE] [-allow-write] [-dry-run]
  jsharvest authz -target HOST [-o OUTPUT] [-profiles DIR] [-allow-write] [-rate N] [-max N] [-proxy URL] [-dry-run]
  jsharvest authz -target HOST -peers a,b -relation same-org|cross-org [-private REGEX] [-substitute] [-reveal] [...]
  jsharvest verify -target HOST [-o OUTPUT] [-role ROLE] [-include-historical] [-include-docs] [-include-strings] [-include-source-only] [-no-cloud-probe] [-allow-write] [-rate N] [-max N] [-dry-run]

crawl loads pages itself; watch records what a person, an AI agent or a
Playwright script does in a tab of a running Chrome, and groups the
requests by the action that caused them (flows.jsonl). mcp answers an AI
agent's questions about what was recorded, over MCP on stdin and stdout;
it only reads the output (add it to the agent as a stdio MCP server).
login saves a role's login (cookies, storage, how to tell it is still
there, and its script) in <profiles>/<host>/<role>; crawl -role uses it,
and puts the session back when the site loses it. endpoints lists what the
target's scripts call, from the code that has not
run (static) to what the traffic shows (both, observed); crawl and watch
write the same list to endpoints.jsonl. diff compares the roles' crawls of
one target: what a higher role uses that a lower one does not, or has only
as code, or is refused (diff.json, diff.md); it sends nothing. export
writes a role's traffic for fuzzers, by flow and by endpoint: HAR, raw
requests (ffuf -request, sqlmap -r, Burp), and params.jsonl; it sends
nothing. authz SENDS requests: the diff's suspects of the higher roles,
under the lower roles' identities, to tell what the server enforces
(authz.json, authz.md); reads only unless -allow-write, never a logout or
a login flow, at -rate. replay SENDS one flow again, the values earlier
answers gave (a CSRF token, a new id) taken fresh. Use both on authorized
targets only. verify SENDS requests too: a draft of each endpoint of the
catalog (sample values in), and a canary of its gateway prefix, to tell a
route that is there from what any path gets (verify/verify.json); reads
only unless -allow-write, never a logout, a login flow or a destructive
URL; -dry-run writes the plan and the drafts and sends nothing. export
-drafts writes the drafts alone, from the catalog. archive lists the target in public archives (Wayback, OTX,
Common Crawl), fetches its old scripts, and writes the endpoints only they
call (archive/historical.jsonl): an old API the interface dropped.
monitor compares the crawls since its last snapshot with the baseline:
endpoints new or gone, parameters, statuses that turned, scripts, ranked
(monitor/latest.md); run it after each periodic crawl.

Run "jsharvest <command> -h" for the flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "crawl":
		err = runCrawl(os.Args[2:])
	case "watch":
		err = runWatch(os.Args[2:])
	case "mcp":
		err = runMCP(os.Args[2:])
	case "endpoints":
		err = runEndpoints(os.Args[2:])
	case "login":
		err = runLogin(os.Args[2:])
	case "monitor":
		err = runMonitor(os.Args[2:])
	case "archive":
		err = runArchive(os.Args[2:])
	case "replay":
		err = runReplay(os.Args[2:])
	case "authz":
		err = runAuthz(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "export":
		err = runExport(os.Args[2:])
	case "diff":
		err = runDiff(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if errors.Is(err, context.Canceled) {
		slog.Warn("interrupted; partial results were saved")
		os.Exit(130)
	}
	if errors.Is(err, engine.ErrSessionLost) {
		slog.Error(err.Error())
		os.Exit(4)
	}
	if errors.Is(err, errChanges) {
		os.Exit(5)
	}
	if errors.Is(err, engine.ErrBlocked) || errors.Is(err, archive.ErrBlocked) {
		slog.Error(err.Error())
		os.Exit(3)
	}
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

var roleRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func runCrawl(args []string) error {
	fs := flag.NewFlagSet("crawl", flag.ExitOnError)
	target := fs.String("u", "", "target URL")
	urlsFile := fs.String("urls", "", `file of target URLs, one per line ("-" for stdin); each URL is its own target, harvested in turn in one browser`)
	urlsRate := fs.Float64("urls-rate", 2, "pages per second with -urls")
	tabs := fs.Int("tabs", 1, "how many tabs work at once: with -urls, URLs at once, each in a browser context of its own (cookies of the profile copied in), -urls-rate the ceiling on starts; with -depth, pages of the crawl at once, in one browser context, -page-rate the ceiling on starts")
	out := fs.String("o", env("JSHARVEST_OUTPUT", "output"), "output root (env JSHARVEST_OUTPUT)")
	role := fs.String("role", "anon", "role label; output goes to <output>/<host>/<role>")
	attach := fs.String("attach", env("JSHARVEST_ATTACH", ""), "CDP endpoint of a running Chrome, e.g. http://127.0.0.1:9222 (env JSHARVEST_ATTACH)")
	chrome := fs.String("chrome", env("JSHARVEST_CHROME", ""), "Chrome binary (env JSHARVEST_CHROME); default: search PATH")
	profile := fs.String("profile", env("JSHARVEST_PROFILE", ""), "Chrome user data dir to reuse (env JSHARVEST_PROFILE); default: the role's login from jsharvest login, if any, else throwaway")
	profiles := fs.String("profiles", env("JSHARVEST_PROFILES", "profiles"), "profiles root of jsharvest login (env JSHARVEST_PROFILES)")
	headful := fs.Bool("headful", false, "show the browser window")
	noSandbox := fs.Bool("no-sandbox", envBool("JSHARVEST_NO_SANDBOX"), "disable the Chrome sandbox, needed as root in containers (env JSHARVEST_NO_SANDBOX)")
	ua := fs.String("ua", env("JSHARVEST_UA", ""), "User-Agent override (env JSHARVEST_UA)")
	proxy := fs.String("proxy", env("JSHARVEST_PROXY", ""), "proxy server, e.g. http://127.0.0.1:8080 (env JSHARVEST_PROXY)")
	navTimeout := fs.Duration("nav-timeout", 30*time.Second, "timeout of the navigation")
	idle := fs.Duration("idle", 1500*time.Millisecond, "network quiet time that counts as idle")
	idleMax := fs.Duration("idle-max", 30*time.Second, "longest wait for the network to go idle")
	maxBody := fs.Int("max-body", 50<<20, "largest script body to keep, in bytes")
	swWait := fs.Duration("sw-wait", 8*time.Second, "keep waiting this long after a service worker appears, so it can precache the app")
	scopeMode := fs.String("scope", "rdn", "what counts as the target: rdn (its registrable domain, e.g. *.example.com) or fqdn (its host and subdomains); out-of-scope scripts are kept and tagged third-party")
	pageScopeMode := fs.String("page-scope", "auto", "pages followed by -depth: auto (fqdn on a subdomain, rdn on the apex or www), fqdn or rdn; scripts and APIs still use -scope")
	hostRules := fs.String("host-resolver-rules", env("JSHARVEST_HOST_RESOLVER_RULES", ""), `Chrome host resolver rules, e.g. "MAP *.example.test 127.0.0.1" (env JSHARVEST_HOST_RESOLVER_RULES)`)
	resolveOn := fs.Bool("resolve", true, "fetch the lazy chunks the app names but has not loaded (in scope only, through the page)")
	depth := fs.Int("depth", 0, "crawl: follow the links, GET forms, redirects and script URLs of the target, this many links away from -u (0: the one page; with the http engine and no -depth given: 3)")
	maxPages := fs.Int("max-pages", 0, "with -depth, the most pages visited (0: unlimited)")
	pageRate := fs.Float64("page-rate", 2, "with -depth, pages per second at most")
	pageDwell := fs.Duration("page-dwell", 1500*time.Millisecond, "with -depth, the least time spent on a page, for its timers to run (meta refresh, delayed navigation)")
	exploreOn := fs.Bool("explore", false, "on each page, do what a person could: click, type, choose, hover, scroll; each action a flow. Turns the guard on, which holds back writes and navigations")
	exploreActions := fs.Int("explore-actions", 50, "with -explore, the most actions on one page")
	exploreTime := fs.Duration("explore-time", 2*time.Minute, "with -explore, the most time on one page")
	exploreTotal := fs.Duration("explore-total", 30*time.Minute, "with -explore, the most time in all; pages after it are crawled, not explored")
	exploreWait := fs.Duration("explore-wait", 800*time.Millisecond, "with -explore, the least wait after each action")
	resolveRate := fs.Float64("resolve-rate", 5, "resolver requests per second")
	resolveMax := fs.Int("resolve-max", 0, "most resolver requests per run (0: unlimited)")
	guardMode := fs.String("guard", "auto", "hold back writes, logouts and destructive calls, and record them: on, off, or auto (on with -profile or -attach)")
	guardAllow := fs.String("guard-allow", "", "regexp of URLs the guard always lets through")
	guardDeny := fs.String("guard-deny", "", "regexp of extra URLs the guard holds back")
	allowWrite := fs.Bool("allow-write", false, "let writes through the guard (destructive URLs are still held back); only on systems where that is agreed")
	allowWS := fs.Bool("guard-allow-websocket", false, "keep page WebSockets with the guard on (it cannot inspect them, so it stubs them out by default)")
	record := fs.String("record", "api", "request log requests.jsonl: api (all but scripts, styles, images, fonts, media), all, or off")
	recordBody := fs.Int("record-body", 128<<10, "bytes kept of each request and response body in the request log; 0 keeps none")
	redact := fs.Bool("redact", false, "hide cookies, tokens, passwords and other credentials in requests.jsonl and blocked.* (keep it off for fuzzing; turn it on to share)")
	noDebugger := fs.Bool("no-debugger", false, "capture over the network only (no inline, eval or already-run worker scripts)")
	engineMode := fs.String("engine", env("JSHARVEST_ENGINE", "auto"), "http (no browser: pages, manifests and every chunk they name, read statically), cdp (Chrome), or auto: http before a login (no -role, -profile, -attach, -explore, -headful), cdp after (env JSHARVEST_ENGINE)")
	httpRate := fs.Float64("http-rate", 5, "with the http engine, requests per second, of every kind")
	probe := fs.Bool("probe", true, "read the well-known files: with the http engine robots.txt, the sitemaps and the bundlers' manifests (asset-manifest.json, ngsw.json, .vite/manifest.json, a service worker); with either engine (the cdp one with -depth or -explore) the API descriptions of the target's origin and of the API hosts its scripts name (openapi.json/.yaml, /api-json, /docs-json, /v3/api-docs, /v2/api-docs, /swagger-resources, /swagger/doc.json, /.well-known/openid-configuration)")
	noSpecProbe := fs.Bool("no-spec-probe", false, "skip OpenAPI/Swagger and OIDC discovery probes while keeping other -probe files")
	sourceMaps := fs.Bool("sourcemaps", true, "fetch the source maps the scripts name (the CDP engine through the page, with the resolver), and keep their original sources (not node_modules)")
	sourceMapGuess := fs.Bool("sourcemap-guess", true, "with -sourcemaps, also ask <script>.map when nothing names a map: one more request a script, the app's only (not vendors.js, polyfills…); -sourcemap-guess=false to skip")
	challengeWait := fs.Duration("challenge-wait", 6*time.Second, "with the cdp engine, how long a page that is a bot challenge is given to pass on its own and reload before it counts as blocked (0: no wait)")
	archiveAfter := fs.Bool("archive", true, "with the http engine (anon, before a login): after the crawl, run jsharvest archive for the host: old pages and scripts in the Wayback, OTX and Common Crawl, each checked on the live server first (-archive=false: only when the first page is a challenge, see -archive-fallback)")
	escalate := fs.Bool("escalate", true, "with -engine auto (the http engine before a login): the pages a bot challenge stops plain HTTP on go to Chrome, one run a challenged host, filed with this crawl (the run.json escalated field); -engine http never starts a browser")
	archiveFallback := fs.Bool("archive-fallback", true, "with the http engine, when the first page is a bot challenge and no script was reached: run jsharvest archive for the host (old pages and scripts, live first)")
	spaBoot := fs.Bool("spa-boot", false, "with -engine auto: when the http engine finds an SPA and sees no API call, open one guarded headless tab a SPA origin (3 at most, 8 s each) to capture the requests it sends when it boots")
	memCacheMB := fs.Int("mem-cache-mb", 512, "RAM budget in MiB for in-memory JS AST & script cache (0: off)")
	insecure := fs.Bool("insecure", false, "accept any TLS certificate (a self-signed lab or staging target): the http engine, Chrome, and the archive's live check")
	verbose := fs.Bool("v", false, "debug logging")
	waitLock := waitLockFlag(fs)
	fs.Parse(args)
	if os.Getenv("JSHARVEST_MEM_CACHE_MB") == "" || setFlagProvided(fs, "mem-cache-mb") {
		endpoints.SetMemCacheMB(*memCacheMB)
	}

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	// One proxy for the run (-proxy, JSHARVEST_PROXY, HTTPS_PROXY, HTTP_PROXY;
	// -proxy none for none): Chrome, the HTTP engine, the archive's client
	// and its live check all take this value.
	proxyVal, perr := resolveProxy(*proxy)
	if perr != nil {
		return perr
	}
	*proxy = proxyVal
	rules, err := guardRules(*guardAllow, *guardDeny, *allowWrite)
	rules.Explore = *exploreOn
	if err != nil {
		return err
	}
	// The role's saved login: -profile, or what jsharvest login left for
	// this host and role.
	var login *engine.Login
	loadLogin := func(dir string) (*engine.Login, error) {
		snap, err := session.Load(dir)
		if err != nil {
			return nil, err
		}
		l := &engine.Login{Profile: dir, Snapshot: snap}
		if snap.Steps != "" {
			if l.Steps, err = session.ReadSteps(snap.Steps); err != nil {
				slog.Warn("the login script cannot run: a lost session will not be logged in again", "err", err)
			}
		}
		slog.Info("crawling with the saved login", "role", *role, "profile", dir, "saved", snap.Saved.Format(time.RFC3339),
			"can_log_in_again", l.Steps != nil)
		return l, nil
	}
	if *attach == "" && *urlsFile == "" {
		if *profile == "" {
			if u, err := parseTarget(*target); err == nil {
				if d := filepath.Join(*profiles, scope.TargetDir(u), *role); session.Exists(d) {
					*profile = d
				}
			}
		}
		if *profile != "" && session.Exists(*profile) {
			if login, err = loadLogin(*profile); err != nil {
				return err
			}
		}
	}
	// The login's User-Agent, unless -ua says otherwise: a session may be
	// tied to it (cf_clearance), and a headless browser's own differs.
	if *ua == "" && login != nil && login.Snapshot != nil && login.Snapshot.UserAgent != "" {
		*ua = login.Snapshot.UserAgent
		slog.Info("presenting the login's User-Agent", "ua", *ua)
	}
	var guardOn bool
	switch *guardMode {
	case "on":
		guardOn = true
	case "off":
	case "auto":
		// A logged-in session is where a stray write costs something.
		guardOn = *profile != "" || *attach != ""
	default:
		return fmt.Errorf("-guard: want on, off or auto, got %q", *guardMode)
	}
	if *exploreOn {
		// Explore clicks everything: never without the guard, nor without
		// the record of what each click sent.
		if *guardMode == "off" {
			return errors.New("-explore needs the guard: it clicks every control; use -allow-write where writes are agreed")
		}
		guardOn = true
		if traffic.Mode(*record) == traffic.Off {
			return errors.New("-explore needs the request log: -record api or all")
		}
		if *urlsFile != "" {
			return errors.New("-explore goes with -u")
		}
		if *exploreActions < 1 || *exploreTime <= 0 {
			return errors.New("-explore-actions and -explore-time must be positive")
		}
	}
	switch traffic.Mode(*record) {
	case traffic.API, traffic.All, traffic.Off:
	default:
		return fmt.Errorf("-record: want api, all or off, got %q", *record)
	}
	if *recordBody < 0 {
		return fmt.Errorf("-record-body: must not be negative")
	}
	if *depth > 0 && *urlsFile != "" {
		return errors.New("crawl: -depth goes with -u; -urls harvests each URL on its own")
	}
	if (*target == "") == (*urlsFile == "") {
		fs.Usage()
		return errors.New("give either -u or -urls")
	}
	// A list of pages wants a shorter wait on each, unless one was asked for.
	setFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
	if *urlsFile != "" && !setFlags["idle-max"] {
		*idleMax = 15 * time.Second
	}
	var targets []*url.URL
	if *urlsFile != "" {
		in := os.Stdin
		if *urlsFile != "-" {
			f, err := os.Open(*urlsFile)
			if err != nil {
				return err
			}
			defer f.Close()
			in = f
		}
		list, err := parseURLList(in)
		if err != nil {
			return err
		}
		targets = list
	} else {
		u, err := parseTarget(*target)
		if err != nil {
			return err
		}
		targets = []*url.URL{u}
	}
	if _, err := scope.PageScope(targets[0].Hostname(), *scopeMode, *pageScopeMode); err != nil {
		return err
	}
	// The role names a directory under the output root; keep it there.
	if !roleRe.MatchString(*role) || strings.Contains(*role, "..") {
		return fmt.Errorf("bad role %q: use letters, digits, '.', '_' and '-'", *role)
	}
	// One crawl at a time writes a host's role directory.
	{
		var dirs []string
		for _, u := range targets {
			dirs = append(dirs, filepath.Join(*out, scope.TargetDir(u), *role))
		}
		unlock, err := lockDirs("crawl", *waitLock, dirs...)
		if err != nil {
			return err
		}
		defer unlock()
	}
	// A list: each URL with the saved login of its host, if any. The
	// browser keeps the login's profile only when one host has it all.
	var logins map[string]*engine.Login
	if *attach == "" && *urlsFile != "" {
		logins = map[string]*engine.Login{}
		hosts := map[string]bool{}
		for _, u := range targets {
			hosts[scope.TargetDir(u)] = true
		}
		for h := range hosts {
			d := filepath.Join(*profiles, h, *role)
			if *profile != "" && len(hosts) == 1 {
				d = *profile
			}
			if !session.Exists(d) {
				continue
			}
			l, err := loadLogin(d)
			if err != nil {
				return err
			}
			logins[h] = l
			if len(hosts) == 1 && *profile == "" {
				*profile = d
			}
		}
	}

	if *ua == "" && len(logins) == 1 {
		for _, l := range logins {
			if l.Snapshot != nil && l.Snapshot.UserAgent != "" {
				*ua = l.Snapshot.UserAgent
				slog.Info("presenting the login's User-Agent", "ua", *ua)
			}
		}
	}
	// The guard's allow rules: -guard-allow, ORed with those a login saved.
	if *guardAllow != "" {
		if err := guard.AnchoredAllow(*guardAllow, func(string) bool { return true }); err != nil {
			slog.Warn("-guard-allow is not anchored to an origin: it can let more than the refresh call through; "+
				"prefer ^https://host\\.example\\.com/path", "err", err)
		}
	}
	var saved []*engine.Login
	if login != nil {
		saved = append(saved, login)
	}
	for _, l := range logins {
		saved = append(saved, l)
	}
	for _, l := range saved {
		extra := sessionGuardAllow(l.Snapshot, *scopeMode)
		if len(extra) == 0 {
			continue
		}
		if rules, err = rules.WithAllow(extra...); err != nil {
			return err
		}
		slog.Info("guard: the login's saved allow rules are in force", "rules", len(extra))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := engine.Config{
		Target:        targets[0],
		OutRoot:       *out,
		Role:          *role,
		ScopeMode:     *scopeMode,
		PageScopeMode: *pageScopeMode,
		Browser: browser.Options{
			Attach:     *attach,
			ChromePath: *chrome,
			ProfileDir: *profile,
			Headful:    *headful,
			NoSandbox:  *noSandbox,
			UserAgent:  *ua,
			Proxy:      *proxy,
			HostRules:  *hostRules,
			Insecure:   *insecure,
		},
		MaxBody:    *maxBody,
		NavTimeout: *navTimeout,
		Idle:       *idle,
		IdleMax:    *idleMax,
		SWWait:     *swWait,
		NoDebugger: *noDebugger,

		Guard:          guardOn,
		GuardRules:     rules,
		AllowWebSocket: *allowWS,

		Record:     traffic.Mode(*record),
		RecordBody: *recordBody,
		Redact:     *redact,

		Login:   login,
		Explore: *exploreOn, ExploreActions: *exploreActions, ExploreTime: *exploreTime, ExploreTotal: *exploreTotal, ExploreWait: *exploreWait,
		Actions: *exploreOn,
		Resolve: *resolveOn,
		Depth:   *depth, MaxPages: *maxPages, PageRate: *pageRate, PageDwell: *pageDwell,
		ResolveRate: *resolveRate,
		ResolveMax:  *resolveMax,
		SourceMaps:  *sourceMaps, GuessMaps: *sourceMapGuess,

		ChallengeWait: *challengeWait,
		SpecProbe:     *probe && !*noSpecProbe,
		NoSpecProbe:   *noSpecProbe,
	}
	switch {
	case *tabs < 1:
		return errors.New("crawl: -tabs must be 1 or more")
	case *tabs > 1 && *urlsFile == "" && *depth == 0 && !*exploreOn:
		return errors.New("crawl: -tabs works with -urls, or with -depth or -explore (a crawl of the site in several tabs)")
	case *tabs > 1 && *attach != "":
		return errors.New("crawl: -tabs cannot be used with -attach: the browser is the user's")
	}
	cfg.Tabs = *tabs
	cfg.Logins = logins
	if *guardMode == "auto" && len(logins) > 0 && !cfg.Guard {
		// A list's saved logins are found after -guard auto was read: a
		// logged-in session is where a stray write costs something.
		cfg.Guard = true
		slog.Info("guard on: the URLs run with a saved login")
	}
	// The engine: before a login, the target's JavaScript is static files,
	// which plain HTTP gets fast and without a browser's marks; after one,
	// or to act on the page, Chrome.
	needsBrowser := *attach != "" || *exploreOn || *profile != "" || login != nil || len(logins) > 0 || *role != "anon" || *headful
	autoEngine := *engineMode == "auto"
	switch *engineMode {
	case "auto":
		*engineMode = map[bool]string{true: "cdp", false: "http"}[needsBrowser]
	case "http":
		if *attach != "" || *exploreOn || login != nil || len(logins) > 0 || *headful {
			return errors.New("crawl -engine http: no browser, so no -attach, -explore, -headful or saved login; use -engine cdp")
		}
	case "cdp":
	default:
		return fmt.Errorf("-engine: want auto, http or cdp, got %q", *engineMode)
	}
	if *engineMode == "http" {
		slog.Info("engine: http (no browser); -engine cdp for the page's runtime (events, workers, eval, flows)")
		ho := engine.HTTPOptions{Rate: *httpRate, Probe: *probe, NoSpecProbe: *noSpecProbe, SourceMaps: *sourceMaps, GuessMaps: *sourceMapGuess}
		given := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
		if !given["depth"] && *urlsFile == "" {
			// Before a login the pages are cheap to read without a browser:
			// the site, not its first page, unless -depth says otherwise.
			cfg.Depth = httpDepth
			slog.Info("depth: the http engine follows the site's links", "depth", httpDepth, "max_pages", cfg.MaxPages, "set", "-depth 0 for the one page")
		}
		var last error
		archived := map[string]bool{}
		for _, t := range targets {
			c := cfg
			c.Target = t
			ho.Fallback, ho.Archive = nil, nil
			if *archiveFallback || *archiveAfter {
				run := func(ctx context.Context) any {
					args := []string{"-o", *out, "-target", t.Hostname(), "-scope", *scopeMode, "-sources", archiveSources,
						"-concurrency", fmt.Sprint(max(*tabs*4, 8)), "-live-rate", fmt.Sprint(max(*httpRate, 5)), "-mem-cache-mb", fmt.Sprint(*memCacheMB)}
					if *proxy != "" {
						args = append(args, "-proxy", *proxy)
					} else {
						args = append(args, "-proxy", netsafe.ProxyNone)
					}
					if *hostRules != "" {
						args = append(args, "-host-resolver-rules", *hostRules)
					}
					if *insecure {
						args = append(args, "-insecure")
					}
					sum, err := archiveRun(ctx, args)
					if err != nil {
						slog.Warn("archive", "err", err)
						return map[string]any{"archive": filepath.Join(*out, t.Hostname(), "archive"), "error": err.Error()}
					}
					return map[string]any{"archive": filepath.Join(*out, t.Hostname(), "archive"), "summary": sum}
				}
				switch {
				case *archiveAfter && !archived[t.Hostname()]:
					// Once a host in a list: the archive is the host's.
					archived[t.Hostname()] = true
					ho.Archive = run
				case *archiveFallback:
					ho.Fallback = run
				}
			}
			ho.Escalate, ho.SPABoot = nil, nil
			if autoEngine && *escalate {
				ho.Escalate = func(ctx context.Context, pages []httpcrawl.Challenged, cookies []*network.CookieParam) *engine.Escalation {
					return engine.Escalate(ctx, c, pages, cookies)
				}
			}
			if autoEngine && *spaBoot {
				ho.SPABoot = func(ctx context.Context, origins []string) []engine.EscalatedRun {
					return engine.SPABoot(ctx, c, origins)
				}
			}
			if _, err := engine.RunHTTP(ctx, c, ho); err != nil {
				last = err
				if ctx.Err() != nil {
					break
				}
			}
		}
		return last
	}
	if *urlsFile != "" {
		return engine.RunURLs(ctx, cfg, targets, *urlsRate)
	}
	return engine.Run(ctx, cfg)
}

// httpDepth is the http engine's -depth when none is given.
const httpDepth = 3

func parseTarget(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("bad target URL %q: want an absolute http(s) URL", s)
	}
	return u, nil
}

// parseURLList reads one URL per line; blank lines and lines starting with
// "#" are skipped, and repeats are dropped. Every line is checked before
// anything runs, so a typo stops the batch at once rather than half-way.
func parseURLList(r io.Reader) ([]*url.URL, error) {
	var out []*url.URL
	var bad []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := parseTarget(line)
		if err != nil {
			bad = append(bad, fmt.Sprintf("line %d: %q", n, line))
			continue
		}
		if !seen[u.String()] {
			seen[u.String()] = true
			out = append(out, u)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("bad URLs in the list (want absolute http(s)): %s", strings.Join(bad, "; "))
	}
	if len(out) == 0 {
		return nil, errors.New("the URL list is empty")
	}
	return out, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string) bool {
	switch os.Getenv(key) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// sessionGuardAllow returns the allow rules a login saved, those that are
// still anchored to a host of its target (the file may have been edited):
// a rule that is not is left out, with a warning, never trusted.
func sessionGuardAllow(snap *session.Snapshot, scopeMode string) []string {
	if snap == nil || len(snap.GuardAllow) == 0 {
		return nil
	}
	var in func(string) bool
	if u, err := parseTarget(snap.Target); err == nil {
		in, _ = scope.New(u.Hostname(), scopeMode)
	}
	var out []string
	for _, re := range snap.GuardAllow {
		if err := guard.AnchoredAllow(re, in); err != nil {
			slog.Warn("a saved guard-allow rule is ignored", "err", err)
			continue
		}
		out = append(out, re)
	}
	return out
}

func guardRules(allow, deny string, allowWrite bool) (guard.Rules, error) {
	rules := guard.Rules{AllowWrite: allowWrite}
	for _, r := range []struct {
		flag string
		val  string
		dst  **regexp.Regexp
	}{{"guard-allow", allow, &rules.Allow}, {"guard-deny", deny, &rules.Deny}} {
		if r.val == "" {
			continue
		}
		re, err := regexp.Compile(r.val)
		if err != nil {
			return rules, fmt.Errorf("-%s: %w", r.flag, err)
		}
		*r.dst = re
	}
	return rules, nil
}

func runWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	attach := fs.String("attach", env("JSHARVEST_ATTACH", ""), "CDP endpoint of the running Chrome, e.g. http://127.0.0.1:9222 (env JSHARVEST_ATTACH)")
	tab := fs.String("tab", "", "regexp of the URL of the open tab to watch (must match exactly one)")
	open := fs.String("open", "", "open a new tab in the browser's default profile and load this URL in it")
	duration := fs.Duration("duration", 0, "stop after this long (default: at Ctrl-C, or when the tab closes)")
	reload := fs.Bool("reload", false, "reload the tab once watching, so that every event handler is traced")
	reloadOnExit := fs.Bool("reload-on-exit", false, "take jsharvest's scripts out and reload the tab when done")
	out := fs.String("o", env("JSHARVEST_OUTPUT", "output"), "output root (env JSHARVEST_OUTPUT)")
	role := fs.String("role", "anon", "role label; output goes to <output>/<host>/<role>")
	guardMode := fs.String("guard", "", "required: on (hold back writes, logouts and destructive calls) or off")
	guardAllow := fs.String("guard-allow", "", "regexp of URLs the guard always lets through")
	guardDeny := fs.String("guard-deny", "", "regexp of extra URLs the guard holds back")
	allowWrite := fs.Bool("allow-write", false, "let writes through the guard (destructive URLs are still held back)")
	allowWS := fs.Bool("guard-allow-websocket", false, "keep page WebSockets with the guard on")
	record := fs.String("record", "api", "request log: api or all")
	recordBody := fs.Int("record-body", 128<<10, "bytes kept of each request and response body; 0 keeps none")
	redact := fs.Bool("redact", false, "hide credentials in requests.jsonl, flows.jsonl and blocked.*")
	scopeMode := fs.String("scope", "rdn", "rdn or fqdn: which scripts count as the target's")
	flowTag := fs.Bool("flow-tag", true, "trace requests to actions through the page's async stacks; false groups by time only")
	maxBody := fs.Int("max-body", 50<<20, "largest script body to keep, in bytes")
	verbose := fs.Bool("v", false, "debug logging")
	waitLock := waitLockFlag(fs)
	fs.Parse(args)
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	if *attach == "" {
		return errors.New("watch: -attach is required (start Chrome with --remote-debugging-port and --user-data-dir)")
	}
	if (*tab == "") == (*open == "") {
		return errors.New("watch: give either -tab or -open")
	}
	var guardOn bool
	switch *guardMode {
	case "on":
		guardOn = true
	case "off":
	default:
		return errors.New("watch: choose -guard on or -guard off: the tab is someone's real session, and the choice is theirs")
	}
	switch traffic.Mode(*record) {
	case traffic.API, traffic.All:
	default:
		return fmt.Errorf("-record: want api or all, got %q", *record)
	}
	if !roleRe.MatchString(*role) || strings.Contains(*role, "..") {
		return fmt.Errorf("bad role %q: use letters, digits, '.', '_' and '-'", *role)
	}
	rules, err := guardRules(*guardAllow, *guardDeny, *allowWrite)
	if err != nil {
		return err
	}
	// The directory is the tab's host: -open names it, -tab is looked up in
	// the browser's tab list (as engine.Watch will).
	watchHost := ""
	if *open != "" {
		if u, err := parseTarget(*open); err == nil {
			watchHost = scope.TargetDir(u)
		}
	} else if u, err := watchTabURL(*attach, *tab); err != nil {
		return err
	} else {
		watchHost = scope.TargetDir(u)
	}
	if watchHost != "" {
		unlock, err := lockDirs("watch", *waitLock, filepath.Join(*out, watchHost, *role))
		if err != nil {
			return err
		}
		defer unlock()
	}
	w := engine.WatchOptions{Tab: *tab, Duration: *duration, Reload: *reload, ReloadOnExit: *reloadOnExit}
	if *open != "" {
		u, err := parseTarget(*open)
		if err != nil {
			return err
		}
		w.Open = u
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The first Ctrl-C ends the watch and writes the results; a second one,
	// with the default handling back, stops at once.
	go func() { <-ctx.Done(); stop() }()
	cfg := engine.Config{
		OutRoot: *out, Role: *role, ScopeMode: *scopeMode,
		Browser: browser.Options{Attach: *attach},
		MaxBody: *maxBody, NavTimeout: 30 * time.Second, Idle: 1500 * time.Millisecond, IdleMax: 30 * time.Second,
		Guard: guardOn, GuardRules: rules, AllowWebSocket: *allowWS,
		Record: traffic.Mode(*record), RecordBody: *recordBody, Redact: *redact,
		NoTagger: !*flowTag,
	}
	err = engine.Watch(ctx, cfg, w)
	if errors.Is(err, context.Canceled) {
		return nil // Ctrl-C is how a watch ends
	}
	return err
}

func runMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	out := fs.String("o", env("JSHARVEST_OUTPUT", "output"), "output root (env JSHARVEST_OUTPUT)")
	target := fs.String("target", "", "only this host's output (default: where a watch runs, else what changed last)")
	role := fs.String("role", "", "only this role's output")
	reveal := fs.Bool("reveal", false, "give cookies, tokens and passwords as recorded; by default they are redacted, since the answers go to the agent's model")
	verbose := fs.Bool("v", false, "debug logging (to stderr)")
	fs.Parse(args)
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *target != "" {
		*target = scope.NormalizeTargetArg(*target)
	}
	srv := mcpserver.New(mcpserver.Options{Root: *out, Target: *target, Role: *role, Reveal: *reveal, Version: version})
	err := srv.Run(ctx, &mcp.StdioTransport{})
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func runEndpoints(args []string) error {
	fs := flag.NewFlagSet("endpoints", flag.ExitOnError)
	out := fs.String("o", env("JSHARVEST_OUTPUT", "output"), "output root (env JSHARVEST_OUTPUT)")
	target := fs.String("target", "", "the target's host, as its output directory is named")
	role := fs.String("role", "anon", "role")
	scopeMode := fs.String("scope", "rdn", "rdn or fqdn: which hosts are the target's")
	status := fs.String("status", "", "list only static (in the code, never seen run), observed or both")
	thirdParty := fs.Bool("third-party", false, "also list third parties' endpoints")
	asJSON := fs.Bool("json", false, "print JSON lines instead of a table")
	waitLock := waitLockFlag(fs)
	fs.Parse(args)
	if *target == "" {
		return errors.New("endpoints: -target is required")
	}
	if !roleRe.MatchString(*role) {
		return fmt.Errorf("endpoints: bad -role %q", *role)
	}
	in, err := scope.New(hostOnly(*target), *scopeMode)
	if err != nil {
		return err
	}
	*target = scope.NormalizeTargetArg(*target)
	dir := filepath.Join(*out, *target, *role)
	if _, err := os.Stat(filepath.Join(dir, "index.jsonl")); err != nil {
		return fmt.Errorf("endpoints: no harvest in %s", dir)
	}
	// It rewrites endpoints.jsonl and the intel files of the directory.
	unlock, err := lockDirs("endpoints", *waitLock, dir)
	if err != nil {
		return err
	}
	defer unlock()
	eps, st, err := endpoints.CatalogWithStats(dir, in, true)
	if err != nil {
		return err
	}
	if st.BundleParseErrors > 0 || st.BundleASTLowered > 0 || st.SourceParseFallback > 0 {
		fmt.Fprintf(os.Stderr, "scripts analysed: %d (bundle parse fallbacks: %d, AST lowered: %d, source fallbacks: %d)\n",
			st.Total, st.BundleParseErrors, st.BundleASTLowered, st.SourceParseFallback)
		if len(st.FailedBundles) > 0 {
			fmt.Fprintf(os.Stderr, "warning: bundle parse fallback to ExtractLoose: %s\n", strings.Join(st.FailedBundles, ", "))
		}
	}
	if err := endpoints.Write(dir, eps); err != nil {
		return err
	}
	if intel, err := endpoints.SaveIntel(dir, in, nil); err != nil {
		return err
	} else if len(intel.Headers) > 0 || len(intel.Cloud) > 0 || len(intel.Bases) > 0 {
		fmt.Fprintf(os.Stderr, "%s: client headers [%s], bases [%s], %d cloud URL(s)\n", filepath.Join(dir, endpoints.IntelFile),
			strings.Join(intel.Names(), " "), strings.Join(intel.Bases, " "), len(intel.Cloud))
	}
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	enc := json.NewEncoder(w)
	counts := map[string]int{}
	for _, e := range eps {
		if (e.ThirdParty && !*thirdParty) || (*status != "" && e.Status != *status) {
			continue
		}
		counts[e.Status]++
		if *asJSON {
			enc.Encode(e)
			continue
		}
		where := ""
		if len(e.Static) > 0 {
			s := e.Static[0]
			where = fmt.Sprintf("%s:%d:%d", path.Base(s.Script), s.Line, s.Col)
		}
		seen := ""
		if o := e.Observed; o != nil {
			seen = fmt.Sprintf("%d req", o.Requests)
		}
		method := e.Method
		if method == "" {
			method = "?"
		}
		p := e.Host + e.Base + e.Path
		if e.Base == "" && len(e.Bases) == 1 {
			p = "[" + e.Bases[0] + "]" + e.Path // the client's base, by the code; not confirmed
		}
		fmt.Fprintf(w, "%-8s %-7s %-50s %-8s %-30s %s\n", e.Status, method, p, seen, strings.Join(append(e.Query, e.Body...), ","), where)
	}
	if !*asJSON {
		fmt.Fprintf(w, "\n%d in the code only, %d both, %d in the traffic only; written to %s\n",
			counts[endpoints.Static], counts[endpoints.Both], counts[endpoints.ObservedOnly], filepath.Join(dir, endpoints.File))
	}
	return nil
}

func setFlagProvided(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
