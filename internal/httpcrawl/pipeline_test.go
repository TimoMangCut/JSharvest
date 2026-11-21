package httpcrawl

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Round 25K, step 2.3: pages whose scripts are fetched at once give the
// queue what one page at a time gives it: the same pages, in the same
// order, the same routes listed, the same API hosts probed; whatever order
// the scripts end in (their latencies differ from page to page).
func TestPipelinedPagesAreDeterministic(t *testing.T) {
	delay := func(p string) time.Duration {
		h := fnv.New32a()
		h.Write([]byte(p))
		return time.Duration(h.Sum32()%40) * time.Millisecond
	}
	var mu sync.Mutex
	var api []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay(r.URL.Path))
		p := strings.TrimPrefix(r.URL.Path, "/")
		switch {
		case strings.HasPrefix(p, "s/"):
			// Each page's script names a route a level deeper and an API host.
			name := strings.TrimSuffix(strings.TrimPrefix(p, "s/"), ".js")
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `const routes=[{path:"/r/%s",component:A}];fetch("https://api%s.x.test/v1/items");`, name, name)
		case strings.HasPrefix(p, "openapi") || strings.Contains(p, "api-docs") || strings.Contains(p, "swagger"):
			http.NotFound(w, r)
		case p == "" || strings.HasPrefix(p, "p") || strings.HasPrefix(p, "r/"):
			w.Header().Set("Content-Type", "text/html")
			var b strings.Builder
			fmt.Fprintf(&b, "<!doctype html><title>%s</title><h1>%s</h1>", p, p)
			if p == "" {
				for i := range 8 {
					fmt.Fprintf(&b, `<a href="/p%d">p</a>`, i)
				}
			}
			if strings.HasPrefix(p, "p") && !strings.Contains(p, "/") {
				fmt.Fprintf(&b, `<a href="/%s/deep">d</a><script src="/s/%s.js"></script><script src="/s/%s-b.js"></script>`, p, p, p)
			}
			w.Write([]byte(b.String()))
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/")
	run := func(inFlight int) string {
		maxPagesInFlight = inFlight
		defer func() { maxPagesInFlight = 4 }()
		var out []string
		res, err := Crawl(context.Background(), Options{Target: u, InScope: func(h string) bool { return h == u.Hostname() || strings.HasSuffix(h, ".x.test") },
			Depth: 2, Rate: 1000, MaxPages: 40, Probe: true, NoDNS: true, Resolver: nxResolver,
			Script: func(Script) {},
			Page: func(p Page) {
				mu.Lock()
				out = append(out, fmt.Sprintf("%v %s %s", p.Visited, strings.TrimPrefix(p.URL, srv.URL), p.Reason))
				mu.Unlock()
			},
			Log: func(string, ...any) {}})
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		// The API hosts probed (at most frontier.MaxAPIOrigins, the first
		// named first): which ones tells the order they were named in.
		api = nil
		for k := range res.Stats.Probes {
			if strings.Contains(k, ".x.test") {
				api = append(api, k)
			}
		}
		slices.Sort(api)
		return strings.Join(out, "\n") + fmt.Sprintf("\nqueued %d", res.Queued)
	}
	one := run(1)
	apiOne := strings.Join(api, ",")
	for range 3 {
		four := run(4)
		if four != one {
			t.Fatalf("pages in flight change the crawl:\n--- 1 at a time\n%s\n--- 4 at a time\n%s", one, four)
		}
		if got := strings.Join(api, ","); got != apiOne {
			t.Fatalf("API hosts: %s, one at a time %s", got, apiOne)
		}
	}
	if apiOne == "" {
		t.Fatal("no API host was probed")
	}
	if !strings.Contains(one, "/p7/deep") || !strings.Contains(one, "/r/p0") {
		t.Fatalf("the second level was not reached:\n%s", one)
	}
}

// Round 25L review: pages of a level sharing a script (an app's bundle)
// get its routes queued as a one-page-at-a-time crawl does: the first page
// taken that names it, whichever page's worker fetched it first. The
// shared bundle is named last by the first page and first by the others,
// so another page's worker reaches it first when pages are fetched at once.
func TestPipelinedSharedScriptAttribution(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		switch {
		case p == "s/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`const routes=[{path:"/shared/route",component:A}];`))
		case p == "s/a0-b.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`const routes=[{path:"/b/route",component:B}];`))
		case strings.HasPrefix(p, "s/"):
			time.Sleep(60 * time.Millisecond)
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`console.log(1)`))
		case p == "":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!doctype html><title>home</title><a href="/a/x">a</a><a href="/b/y">b</a><a href="/c/z">c</a>`))
		case strings.Count(p, "/") == 1 && !strings.HasPrefix(p, "shared"):
			// Each page's own slow scripts, then the shared bundle (first
			// page) or the shared bundle first (the others).
			w.Header().Set("Content-Type", "text/html")
			// The page's scripts are fetched in their URLs' order: the first
			// page's own sort before main.js, the others' after it.
			prefix := "z"
			if strings.HasPrefix(p, "a/") {
				prefix = "0"
			}
			own := ""
			for k := range 6 {
				own += fmt.Sprintf(`<script src="/s/%s-%s-%d.js"></script>`, prefix, strings.ReplaceAll(p, "/", "-"), k)
			}
			shared := `<script src="/s/main.js"></script>`
			if strings.HasPrefix(p, "b/") {
				// A route of b's own, named by a script that sorts before
				// main.js: had b's worker fetched main.js, its route would
				// be queued after this one.
				shared = `<script src="/s/a0-b.js"></script>` + shared
			}
			if strings.HasPrefix(p, "a/") {
				fmt.Fprintf(w, "<!doctype html><title>%s</title>%s%s", p, own, shared)
			} else {
				fmt.Fprintf(w, "<!doctype html><title>%s</title>%s%s", p, shared, own)
			}
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<!doctype html><title>%s</title>", p)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/")
	run := func(inFlight int) string {
		maxPagesInFlight = inFlight
		defer func() { maxPagesInFlight = 4 }()
		var mu sync.Mutex
		var out []string
		_, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Depth: 3, Rate: 1000, MaxPages: 40, NoDNS: true,
			Script: func(Script) {}, Log: func(string, ...any) {},
			Page: func(p Page) {
				mu.Lock()
				out = append(out, fmt.Sprintf("%v %s %s", p.Visited, strings.TrimPrefix(p.URL, srv.URL), p.From))
				mu.Unlock()
			}})
		if err != nil {
			t.Fatal(err)
		}
		// The pages visited in order; the files listed as a set (they are
		// listed as their fetches end, which is no order at all).
		var visited, listed []string
		for _, l := range out {
			if strings.HasPrefix(l, "true ") {
				visited = append(visited, l)
			} else {
				listed = append(listed, l)
			}
		}
		slices.Sort(listed)
		return strings.Join(visited, "\n") + "\n--\n" + strings.Join(listed, "\n")
	}
	one := run(1)
	if i, j := strings.Index(one, "true /shared/route"), strings.Index(one, "true /b/route"); i < 0 || j < 0 || i > j {
		t.Fatalf("the shared bundle is not the first page's, or its route was not visited:\n%s", one)
	}
	for range 3 {
		if four := run(4); four != one {
			t.Fatalf("a shared script's routes went with another page:\n--- 1 at a time\n%s\n--- 4 at a time\n%s", one, four)
		}
	}
}

// Round 25L review: a stop ends what is in flight: a script waiting out a
// Retry-After beside the next pages' does not hold the crawl, and the
// crawl says it stopped (ErrStopped), not that it was interrupted.
func TestStopEndsWorkInFlight(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch p := strings.TrimPrefix(r.URL.Path, "/"); p {
		case "":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!doctype html><title>home</title><a href="/a">a</a><a href="/b">b</a>`))
		case "a":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!doctype html><title>a</title><script src="/s/slow.js"></script>`))
		case "b":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!doctype html><title>b</title><script src="/s/chl.js"></script>`))
		case "s/slow.js":
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(429)
		case "s/chl.js":
			time.Sleep(200 * time.Millisecond)
			w.Header().Set("cf-mitigated", "challenge")
			w.WriteHeader(403)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/")
	began := time.Now()
	res, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Depth: 1, Rate: 1000, NoDNS: true,
		Script: func(Script) {}, Page: func(Page) {}, Log: func(string, ...any) {}})
	if !errors.Is(err, ErrStopped) || res == nil || res.Stats.Stopped == "" {
		t.Fatalf("err %v, stopped %q", err, res.Stats.Stopped)
	}
	if d := time.Since(began); d > 5*time.Second {
		t.Fatalf("the crawl ended after %s: the Retry-After in flight held it", d)
	}
}

// Round 25L review: a challenge met on a script names the page it was
// fetched for among the challenged (so -escalate opens that page in
// Chrome), never the script; a script out of scope names nothing.
func TestAssetChallengeNamesItsPage(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		want         bool
	}{
		{"in scope", "/s/app.js", true},
		{"out of scope", "http://cdn.other.test/s/app.js", false},
	} {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			switch p := strings.TrimPrefix(r.URL.Path, "/"); p {
			case "":
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(`<!doctype html><title>home</title><a href="/a">a</a>`))
			case "a":
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<!doctype html><title>a</title><script src=%q></script>`, tc.script)
			case "s/app.js":
				w.Header().Set("cf-mitigated", "challenge")
				w.WriteHeader(403)
			default:
				http.NotFound(w, r)
			}
		})
		srv := httptest.NewServer(mux)
		u, _ := url.Parse(srv.URL + "/")
		res, _ := Crawl(context.Background(), Options{Target: u, InScope: func(h string) bool { return h == u.Hostname() }, Depth: 1, Rate: 1000, NoDNS: true,
			HostRules: "MAP cdn.other.test " + u.Host, Resolver: nxResolver,
			Script: func(Script) {}, Page: func(Page) {}, Log: func(string, ...any) {}})
		srv.Close()
		var got []string
		for _, c := range res.Challenged {
			got = append(got, fmt.Sprintf("%s depth=%d kind=%s asked=%v", strings.TrimPrefix(c.URL, srv.URL), c.Depth, c.Kind, c.Asked))
		}
		if want := []string{"/a depth=1 kind=challenge asked=true"}; tc.want != (len(got) == 1 && got[0] == want[0]) || !tc.want && len(got) != 0 {
			t.Errorf("%s: challenged %q", tc.name, got)
		}
	}
}
