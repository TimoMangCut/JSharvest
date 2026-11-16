package httpcrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Round 18: a real SPA behind Cloudflare injects its bot script inline into
// every page, with that response's ray id. The shell is still the shell.
func TestShellPrintIgnoresChallengeScript(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			fmt.Fprint(w, "const r=['/a','/b','/c'];history.pushState({},'',r[0])")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><title>App</title><script type="module" src="/app.js"></script>
<script>(function(){window.__CF$cv$params={r:'%x',t:'MTc2'};var a=document.createElement('script');a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js';document.head.appendChild(a);})();</script>`, n.Add(1))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/")
	res, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Depth: 2, Rate: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Stats.SPA {
		t.Fatalf("the shell with a per-response challenge snippet was not seen as the shell: %+v", res.Stats)
	}
}

// A host that challenges every page the crawl asks (two, none passing) is
// asked no more: its other pages are handed on as challenged, unasked.
// Another host's pages go on.
func TestChallengedHostLeftAlone(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := strings.Cut(r.Host, ":")
		mu.Lock()
		asked[host+r.URL.Path] = true
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		if host == "localhost" {
			w.Header().Set("Cf-Mitigated", "challenge")
			w.WriteHeader(403)
			fmt.Fprint(w, `<!doctype html><title>Just a moment...</title>`)
			return
		}
		port := strings.TrimPrefix(r.Host, "127.0.0.1")
		if r.URL.Path == "/" {
			fmt.Fprintf(w, `<a href="http://localhost%[1]s/a">a</a><a href="http://localhost%[1]s/b">b</a><a href="/ok">ok</a><a href="http://localhost%[1]s/c">c</a>`, port)
			return
		}
		fmt.Fprint(w, `<title>ok</title>`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/")
	res, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Depth: 2, Rate: 1000, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if asked["localhost/c"] || !asked["127.0.0.1/ok"] {
		t.Fatalf("asked %v", asked)
	}
	var got []string
	for _, c := range res.Challenged {
		got = append(got, fmt.Sprintf("%s %v", strings.TrimPrefix(c.URL, "http://localhost"+strings.TrimPrefix(srv.URL, "http://127.0.0.1")), c.Asked))
	}
	if strings.Join(got, ",") != "/a true,/b true,/c false" || res.Listed[ChallengedHost] != 1 {
		t.Fatalf("challenged %v, listed %v", got, res.Listed)
	}
}

// An SPA's routes are its origin's: another host its scripts name (the
// developer portal next to the app) is another app, whose pages are
// visited. Round 18: one SPA origin left every other host unvisited.
func TestSPAIsPerOrigin(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, port, _ := strings.Cut(r.Host, ":")
		mu.Lock()
		asked[host+r.URL.Path] = true
		mu.Unlock()
		if host == "127.0.0.1" {
			if r.URL.Path == "/app.js" {
				fmt.Fprintf(w, "const r=['/home','/settings'];location.href='http://localhost:%s/docs/intro'", port)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><title>App</title><script type="module" src="/app.js"></script>`)
			return
		}
		// localhost: server-rendered pages, a 404 for what is not there.
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/docs/intro":
			fmt.Fprint(w, `<title>Intro</title><a href="/docs/next">next</a>`)
		case "/docs/next":
			fmt.Fprint(w, `<title>Next</title>`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/")
	res, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Depth: 3, Rate: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Stats.SPA || len(res.Stats.SPAOrigins) != 1 || asked["127.0.0.1/home"] {
		t.Fatalf("the app's own routes: spa %v %v, asked %v", res.Stats.SPA, res.Stats.SPAOrigins, asked)
	}
	if !asked["localhost/docs/intro"] || !asked["localhost/docs/next"] {
		t.Fatalf("the other host's pages were not visited: %v", asked)
	}
}
