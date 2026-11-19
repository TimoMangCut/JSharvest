package httpcrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// R39-B: when an SSR admin portal redirects / to /login (loading only vendor
// scripts) and blocks dotfiles (/.vite/* -> 403), httpcrawl's pre-auth probes
// still discover application bundles via /mix-manifest.json, /build/manifest.json,
// and /build/entrypoints.json.
func TestRound39PreAuthSSRManifestsBypassLoginGateAndDotfileBlock(t *testing.T) {
	var mu sync.Mutex
	var hits []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path)
		mu.Unlock()

		// Simulate Nginx blocking dotfiles like /.vite/manifest.json and /build/.vite/manifest.json.
		if strings.Contains(r.URL.Path, "/.") {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<html><body>403 Forbidden</body></html>")
			return
		}
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/login", http.StatusFound)
		case "/login":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><head><title>SSO Login</title></head><body><a href="https://sso.example.test/oauth2/v2.0/authorize">Sign in</a></body></html>`)
		case "/mix-manifest.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"/js/mix-admin.js":"/js/mix-admin.js?id=101"}`)
		case "/build/manifest.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"resources/js/orders.js":{"file":"assets/orders-abc.js","isEntry":true}}`)
		case "/build/entrypoints.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"entrypoints":{"billing":{"js":["/build/billing.js"]}}}`)
		case "/js/mix-admin.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/v1/mix-admin");`)
		case "/build/assets/orders-abc.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/v1/vite-orders");`)
		case "/build/billing.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/v1/encore-billing");`)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"Not Found"}`)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	var scriptMu sync.Mutex
	var gotScripts []string
	_, err := Crawl(context.Background(), Options{
		Target:  u,
		InScope: func(h string) bool { return h == u.Hostname() },
		Depth:   1,
		Rate:    500,
		Probe:   true,
		Script: func(s Script) {
			scriptMu.Lock()
			gotScripts = append(gotScripts, strings.TrimPrefix(s.URL, srv.URL))
			scriptMu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	scriptMu.Lock()
	slices.Sort(gotScripts)
	scriptMu.Unlock()

	for _, want := range []string{
		"/build/assets/orders-abc.js",
		"/build/billing.js",
		"/js/mix-admin.js?id=101",
	} {
		if !slices.Contains(gotScripts, want) {
			t.Fatalf("missing pre-auth manifest bundle %q in %v", want, gotScripts)
		}
	}
}
