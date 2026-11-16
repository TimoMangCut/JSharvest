package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"

	"github.com/TimoMangCut/JSharvest/internal/httpcrawl"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// A first page that never answers (a self-signed certificate) is
// a failed run, said so, with no archive after it; -insecure crawls it.
func TestRunHTTPSeedFails(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>lab</title><script src="/app.js"></script></head><body></body></html>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`fetch("/api/me")`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	for _, insecure := range []bool{false, true} {
		cfg := Config{Target: u, OutRoot: t.TempDir(), Role: "anon", ScopeMode: "rdn", MaxBody: 1 << 20, NavTimeout: 5 * time.Second,
			Record: traffic.API}
		cfg.Browser.Insecure = insecure
		archived := false
		ho := HTTPOptions{Rate: 100, Archive: func(context.Context) any { archived = true; return nil }}
		rec, err := RunHTTP(context.Background(), cfg, ho)
		warned := slices.ContainsFunc(rec.Warnings, func(w string) bool { return strings.HasPrefix(w, "seed request failed") })
		if !insecure {
			if err == nil || rec.ExitCode != 1 || !warned || archived || !strings.Contains(strings.Join(rec.Warnings, " "), "-insecure") {
				t.Errorf("self-signed: exit %d, err %v, warnings %q, archived %v", rec.ExitCode, err, rec.Warnings, archived)
			}
			continue
		}
		if err != nil || rec.ExitCode != 0 || warned || !archived || rec.UniqueScripts != 1 {
			t.Errorf("-insecure: exit %d, err %v, warnings %q, archived %v, scripts %d", rec.ExitCode, err, rec.Warnings, archived, rec.UniqueScripts)
		}
	}
}

func TestRunHTTPSeedOutOfScopeRedirectFailsWithoutEscalation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://sso.external.invalid/login", http.StatusFound)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	cfg := Config{
		Target:     u,
		OutRoot:    t.TempDir(),
		Role:       "anon",
		ScopeMode:  "fqdn",
		MaxBody:    1 << 20,
		NavTimeout: 5 * time.Second,
		Record:     traffic.API,
	}
	archived := false
	rec, err := RunHTTP(context.Background(), cfg, HTTPOptions{
		Rate:    100,
		Archive: func(context.Context) any { archived = true; return nil },
	})
	if err == nil || rec.ExitCode != 1 || archived {
		t.Fatalf("expected exit 1 and no archive on out-of-scope seed redirect, got exit=%d err=%v archived=%v warnings=%v", rec.ExitCode, err, archived, rec.Warnings)
	}
	if escalatable(err.Error()) {
		t.Errorf("out-of-scope seed redirect error %q should not escalate to Chrome", err)
	}
}

func TestEngineTabConcurrencyAndRecycleFailureSafety(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	deadRoot, cancelDeadRoot := context.WithCancel(context.Background())
	cancelDeadRoot()

	e := newRun(Config{}, deadRoot, nil)
	lctx1 := e.resetListenCtx(parent)
	if lctx1.Err() != nil {
		// deadRoot is already cancelled, so test listener cancellation on an active tab context:
	}
	activeTab, cancelActive := context.WithCancel(context.Background())
	defer cancelActive()
	e.tabMu.Lock()
	e.tab = activeTab
	e.mainID = "frame-1"
	e.tabMu.Unlock()

	lctx1 = e.resetListenCtx(parent)
	if lctx1.Err() != nil {
		t.Fatal("expected active listenCtx")
	}

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_ = e.tabCtx()
				_ = e.mainFrameID()
				_ = e.tabListenCtx()
			}
		}()
	}
	lctx2 := e.resetListenCtx(parent)
	if lctx1.Err() == nil {
		t.Fatal("resetListenCtx did not cancel previous tab listener context")
	}
	if lctx2.Err() != nil {
		t.Fatal("new listenCtx should still be active")
	}
	wg.Wait()

	// When rootTab is cancelled, recycleTab must fail cleanly (replaced=false),
	// record a warning, and keep existing listeners untouched until lane exit.
	popups := &popupWatch{ch: make(chan string, 1)}
	gotPopups, replaced := e.recycleTab(parent, nil, popups)
	if replaced || gotPopups != popups {
		t.Fatalf("recycleTab on dead rootTab: replaced=%v, popups=%v", replaced, gotPopups)
	}
	if !slices.ContainsFunc(e.run.Warnings, func(w string) bool { return strings.Contains(w, "could not open replacement tab") }) {
		t.Errorf("expected replacement tab warning in %v", e.run.Warnings)
	}
	e.stopTabListeners()
	if lctx2.Err() == nil {
		t.Fatal("stopTabListeners did not cancel active listenCtx")
	}
}

// Round 25J: Chrome is launched only for hosts where a browser may pass:
// a host whose blocked pages were all WAF rules or bans is left.
func TestBrowserPassable(t *testing.T) {
	pages := []httpcrawl.Challenged{
		{URL: "https://portal.x.test/", Asked: true, Kind: "request"},
		{URL: "https://portal.x.test/a", Asked: true, Kind: "request"},
		{URL: "https://portal.x.test/b"}, // not asked: its host was given up
		{URL: "https://shop.x.test/", Asked: true, Kind: "challenge"},
		{URL: "https://shop.x.test/c"},
		{URL: "https://old.x.test/", Asked: true}, // a kind not told: may pass
		{URL: "https://ban.x.test/", Asked: true, Kind: "client"},
	}
	keep, refused := browserPassable(pages)
	var got []string
	for _, p := range keep {
		got = append(got, p.URL)
	}
	if want := []string{"https://shop.x.test/", "https://shop.x.test/c", "https://old.x.test/"}; !slices.Equal(got, want) {
		t.Errorf("kept %v, want %v", got, want)
	}
	if want := []string{"portal.x.test", "ban.x.test"}; !slices.Equal(refused, want) {
		t.Errorf("refused %v, want %v", refused, want)
	}
}

// Round 25L: an escalation goes on as the HTTP engine was: its
// User-Agent, the crawl's cookies (host-only by URL, domain by Domain), no
// role's profile.
func TestEscalationConfig(t *testing.T) {
	cfg := Config{}
	cfg.Browser.UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
	cfg.Browser.ProfileDir = "/profiles/x/user"
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	params := CookieParams([]httpcrawl.Cookie{
		{Name: "region", Value: "vn", Path: "/", URL: "https://app.x.test/", HTTPOnly: true, SameSite: http.SameSiteLaxMode},
		{Name: "consent", Value: "1", Domain: ".x.test", Path: "/", Expires: exp},
	})
	c := escalationConfig(cfg, params)
	if c.Browser.UserAgent != cfg.Browser.UserAgent || c.Browser.ProfileDir != "" || len(c.Cookies) != 2 {
		t.Fatalf("%+v", c.Browser)
	}
	a, b := c.Cookies[0], c.Cookies[1]
	if a.URL != "https://app.x.test/" || a.Domain != "" || !a.HTTPOnly || a.SameSite != network.CookieSameSiteLax {
		t.Errorf("host-only: %+v", a)
	}
	if b.Domain != ".x.test" || b.URL != "" || int64(b.Expires) != exp.Unix() {
		t.Errorf("domain: %+v", b)
	}
}

// P2.3: through a proxy the AIA is off (its fetches would leave outside the
// proxy), and run.json says why.
func TestRunHTTPProxyDisablesAIAAndSaysSo(t *testing.T) {
	px := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>x</title><script src="/app.js"></script></head></html>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`fetch("/api/me")`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer px.Close()
	u, _ := url.Parse("http://app.example.test/")
	run := func(proxy string) Record {
		cfg := Config{Target: u, OutRoot: t.TempDir(), Role: "anon", ScopeMode: "fqdn", MaxBody: 1 << 20, NavTimeout: 5 * time.Second, Record: traffic.API}
		cfg.Browser.Proxy = proxy
		rec, err := RunHTTP(context.Background(), cfg, HTTPOptions{Rate: 100})
		if err != nil || rec.UniqueScripts != 1 {
			t.Fatalf("proxy %q: %v scripts %d warnings %q", proxy, err, rec.UniqueScripts, rec.Warnings)
		}
		return rec
	}
	has := func(r Record) bool {
		return slices.ContainsFunc(r.Warnings, func(w string) bool { return strings.HasPrefix(w, "aia disabled: a proxy is in use") })
	}
	if r := run(px.URL); !has(r) {
		t.Fatalf("no reason for the AIA being off: %q", r.Warnings)
	}
}
