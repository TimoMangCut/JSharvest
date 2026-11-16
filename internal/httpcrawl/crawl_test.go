package httpcrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// app is a small production build: an entry with a webpack chunk map, a
// module preload, inline code, an import()ed chunk, a source map, an
// asset-manifest, and a challenge page at /blocked.
func app(t *testing.T) (*httptest.Server, *sync.Map) {
	seen := &sync.Map{}
	mux := http.NewServeMux()
	js := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, body)
		}
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.URL.Path+" ua="+r.Header.Get("User-Agent"), true)
		if r.URL.Path != "/" && r.URL.Path != "/about" {
			// an SPA's fallback
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<!doctype html><html><body>app</body></html>")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><html><head><title>App</title>
<link rel="modulepreload" href="/assets/pre.js"></head><body>
<a href="/about">about</a>
<script>import('/assets/from-inline.js'); fetch('/api/inline')</script>
<script src="/static/js/main.js"></script></body></html>`)
	})
	mux.HandleFunc("/static/js/main.js", js(`fetch('/api/main');
r.u=e=>"static/js/"+e+"."+{7:"aa11",9:"bb22"}[e]+".chunk.js";r.p="/";
//# sourceMappingURL=main.js.map`))
	mux.HandleFunc("/static/js/main.js.map", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"version":3,"sources":["webpack:///./src/api.ts"],"sourcesContent":["export const x = () => fetch('/api/from-map');"]}`)
	})
	mux.HandleFunc("/static/js/7.aa11.chunk.js", js(`fetch('/api/chunk7')`))
	mux.HandleFunc("/static/js/9.bb22.chunk.js", js(`import('./deep.js')`))
	mux.HandleFunc("/static/js/deep.js", js(`fetch('/api/deep')`))
	mux.HandleFunc("/assets/pre.js", js(`fetch('/api/pre')`))
	mux.HandleFunc("/assets/from-inline.js", js(`fetch('/api/from-inline')`))
	mux.HandleFunc("/asset-manifest.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"files":{"main.js":"/static/js/main.js","only.js":"/static/js/manifest-only.js","main.css":"/static/css/main.css"},"entrypoints":["static/js/main.js"]}`)
	})
	mux.HandleFunc("/static/js/manifest-only.js", js(`fetch('/api/manifest-only')`))
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /secret-admin\n")
	})
	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(403)
		fmt.Fprint(w, `<!doctype html><title>Just a moment...</title><script>window._cf_chl_opt={}</script><script src="/should-not-load.js"></script>`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, seen
}

func TestCrawl(t *testing.T) {
	srv, seen := app(t)
	u, _ := url.Parse(srv.URL + "/")
	var mu sync.Mutex
	var files, inline, maps []string
	var reqs int
	res, err := Crawl(context.Background(), Options{
		Target: u, InScope: func(string) bool { return true }, Depth: 1, Rate: 1000, Probe: true, SourceMaps: true,
		Script: func(s Script) {
			mu.Lock()
			defer mu.Unlock()
			if s.Kind == "inline" {
				inline = append(inline, string(s.Body))
			} else {
				files = append(files, strings.TrimPrefix(s.URL, srv.URL))
			}
		},
		SourceMap: func(m SourceMap) { mu.Lock(); maps = append(maps, strings.TrimPrefix(m.URL, srv.URL)); mu.Unlock() },
		Request:   func(traffic.Entry) { mu.Lock(); reqs++; mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	want := []string{"/assets/from-inline.js", "/assets/pre.js", "/static/js/7.aa11.chunk.js", "/static/js/9.bb22.chunk.js",
		"/static/js/deep.js", "/static/js/main.js", "/static/js/manifest-only.js"}
	if !slices.Equal(files, want) {
		t.Errorf("files\n got  %v\n want %v", files, want)
	}
	if len(inline) != 1 { // the seed's; /about is the same shell, not read again
		t.Errorf("inline: %q", inline)
	}
	if !slices.Equal(maps, []string{"/static/js/main.js.map"}) {
		t.Errorf("maps: %v", maps)
	}
	if res.Blocked.Blocked || res.Visited != 3 {
		t.Errorf("blocked %v, visited %d (want the seed, /about and robots.txt's /secret-admin)", res.Blocked, res.Visited)
	}
	if reqs != res.Stats.Requests || reqs == 0 {
		t.Errorf("requests logged %d, counted %d", reqs, res.Stats.Requests)
	}
	seen.Range(func(k, _ any) bool {
		if s := k.(string); strings.Contains(s, "HeadlessChrome") || !strings.Contains(s, "Chrome/") {
			t.Errorf("a request with User-Agent %s", s)
		}
		return true
	})
	if _, ok := seen.Load("/secret-admin ua=" + DefaultUserAgent); !ok {
		t.Error("the page robots.txt names was not visited (depth 1)")
	}
}

func TestCrawlBlocked(t *testing.T) {
	srv, seen := app(t)
	u, _ := url.Parse(srv.URL + "/blocked")
	var files []string
	res, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Rate: 1000,
		Script: func(s Script) { files = append(files, s.URL) }})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Blocked.Blocked || res.Blocked.Vendor != "cloudflare" {
		t.Errorf("not blocked: %+v", res.Blocked)
	}
	if len(files) != 0 {
		t.Errorf("a challenge page's scripts were taken: %v", files)
	}
	seen.Range(func(k, _ any) bool {
		if strings.HasPrefix(k.(string), "/should-not-load.js") {
			t.Error("the challenge page's script was fetched")
		}
		return true
	})
}

func TestHostRules(t *testing.T) {
	rs, err := netsafe.ParseHostRules("MAP *.jsh.test 127.0.0.1, MAP jsh.test 127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{"www.jsh.test:8770": "127.0.0.1:8770", "jsh.test:80": "127.0.0.1:9", "other.test:80": "other.test:80"} {
		if got := rs.MapAddr(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
	if _, err := netsafe.ParseHostRules("EXCLUDE x"); err == nil {
		t.Error("an unknown rule was taken")
	}
}

// From the review: the HTTP engine goes through -proxy (Burp, an agreed
// egress), and a redirect into a credential URL is not followed.
func TestProxy(t *testing.T) {
	var mu sync.Mutex
	var via []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		via = append(via, r.URL.String())
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>x</title><script src="/a.js"></script>`)
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	u, _ := url.Parse("http://target.invalid/")
	if _, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Rate: 1000, Proxy: pu, NoDNS: true}); err != nil {
		t.Fatal(err)
	}
	if len(via) < 2 || via[0] != "http://target.invalid/" || via[1] != "http://target.invalid/a.js" {
		t.Errorf("through the proxy: %v", via)
	}
}

// An SPA: every path answers with the same shell. The crawl asks one path
// that cannot exist, sees the shell, and lists the routes and paths the
// scripts name (spa-route) instead of fetching each; a templated path and
// a versioned API path are never fetched either.
func TestCrawlSPA(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>Admin</title><div id=app></div><script src="/js/app.js"></script>`)
	})
	mux.HandleFunc("/js/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `const routes=[{path:"/dashboard",component:A},{path:"/users",component:B}];
location.href="/reports/home";
const t="/scooter/v1.0/scooters/{scooter_id}/status";
fetch("/scooter/v1.0/admin/search");`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/")
	listed := map[string]string{}
	res, err := Crawl(context.Background(), Options{
		Target: u, InScope: func(string) bool { return true }, Depth: 3, Rate: 1000,
		Script: func(Script) {},
		Page: func(p Page) {
			if !p.Visited {
				mu.Lock()
				listed[strings.TrimPrefix(p.URL, srv.URL)] = p.Reason
				mu.Unlock()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Stats.SPA {
		t.Fatal("the shell answering a path that cannot exist was not seen")
	}
	mu.Lock()
	defer mu.Unlock()
	// The path that cannot exist is a random route-like slug, never the
	// tool's name (round 25I).
	if len(asked) != 2 || asked[0] != "/" || !regexp.MustCompile(`^/[a-z][a-z0-9]{11}$`).MatchString(asked[1]) {
		t.Errorf("pages asked %v, want the seed and one path that cannot exist", asked)
	}
	for _, p := range []string{"/dashboard", "/users", "/reports/home"} {
		if listed[p] != "spa-route" {
			t.Errorf("%s: listed %q, want spa-route (all listed: %v)", p, listed[p], listed)
		}
	}
	if res.Visited != 1 {
		t.Errorf("visited %d pages, want the seed only", res.Visited)
	}
}

// Without an SPA's fallback the templated and versioned paths are still
// never fetched: they are a script's API, not pages.
func TestCrawlTemplates(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>Admin</title><script src="/js/app.js"></script>`)
	})
	mux.HandleFunc("/js/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `const a="/scooter/v1.0/scooters/{scooter_id}/status", b="/customer/v1.0/admin/no-scu/{vin}/visible";
const c="/scooter/v1.0/admin/scooters/x/commands/scooter-blocking";`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/")
	if _, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Depth: 3, Rate: 1000,
		Script: func(Script) {}, Page: func(Page) {}}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range asked {
		if strings.Contains(p, "{") || strings.Contains(p, "/v1.0/") {
			t.Errorf("fetched %s: a template or a versioned API path is no page", p)
		}
	}
}

// P0-3: when the seed redirects across -page-scope auto to another in-scope
// host (sub.jsh.test -> www.jsh.test/sub), httpcrawl follows the seed, probes
// and crawls the landing host, and still blocks unrelated sibling hosts; when
// the seed redirects out of -scope, SeedError is populated instead of empty 0.
func TestSeedRedirectAcrossPageScopeAndOutOfScope(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "sub.jsh.test" && r.URL.Path == "/":
			http.Redirect(w, r, "http://www.jsh.test/sub/", http.StatusFound)
		case r.Host == "sub.jsh.test" && r.URL.Path == "/out":
			http.Redirect(w, r, "http://sso.evil.test/login", http.StatusFound)
		case r.Host == "www.jsh.test" && r.URL.Path == "/sub/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><title>Sub</title><a href="/sub/about">about</a><a href="http://other.jsh.test/leak">other</a><script src="/sub/app.js"></script>`)
		case r.Host == "www.jsh.test" && r.URL.Path == "/sub/about":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><title>About</title><script src="/sub/about.js"></script>`)
		case r.Host == "www.jsh.test" && r.URL.Path == "/sub/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/sub")`)
		case r.Host == "www.jsh.test" && r.URL.Path == "/sub/about.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/about")`)
		case r.Host == "www.jsh.test" && r.URL.Path == "/robots.txt":
			fmt.Fprint(w, "User-agent: *\nAllow: /\n")
		case r.Host == "other.jsh.test":
			t.Errorf("sibling host other.jsh.test outside pageScope was requested: %s", r.URL.String())
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")
	rules := fmt.Sprintf("MAP *.jsh.test %s", addr)
	inScope := func(h string) bool { return h == "jsh.test" || strings.HasSuffix(h, ".jsh.test") }
	pageScope := func(h string) bool { return h == "sub.jsh.test" || strings.HasSuffix(h, ".sub.jsh.test") }

	u, _ := url.Parse("http://sub.jsh.test/")
	var mu sync.Mutex
	var scripts []string
	res, err := Crawl(context.Background(), Options{
		Target: u, InScope: inScope, PageScope: pageScope, Depth: 1, Rate: 1000, Probe: true,
		HostRules: rules, NoDNS: true,
		Script: func(s Script) {
			mu.Lock()
			scripts = append(scripts, s.URL)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.SeedError != "" {
		t.Fatalf("unexpected SeedError on in-scope seed redirect: %s", res.SeedError)
	}
	slices.Sort(scripts)
	if !slices.Equal(scripts, []string{"http://www.jsh.test/sub/about.js", "http://www.jsh.test/sub/app.js"}) {
		t.Errorf("scripts after seed redirect = %v", scripts)
	}
	if res.Stats.Probes["/robots.txt"] != 200 {
		t.Errorf("expected probe on landing host www.jsh.test, got probes=%v", res.Stats.Probes)
	}

	uOut, _ := url.Parse("http://sub.jsh.test/out")
	resOut, err := Crawl(context.Background(), Options{
		Target: uOut, InScope: inScope, PageScope: pageScope, Depth: 1, Rate: 1000, Probe: true,
		HostRules: rules, NoDNS: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resOut.SeedError, "out of scope") {
		t.Errorf("expected out-of-scope SeedError, got %q", resOut.SeedError)
	}
}
