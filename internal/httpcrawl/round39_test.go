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

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
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
		Target:   u,
		InScope:  func(h string) bool { return h == u.Hostname() },
		Depth:    1,
		Rate:     500,
		Probe:    true,
		NoDNS:    true,
		Resolver: nxResolver,
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

// R39-D: OriginSpecPaths (/api/documentation -> SwaggerUIBundle configUrl ->
// custom OpenAPI JSON) run on origin roots without multiplying across sub-path
// bases, while /swagger/v1/swagger.json, apple-app-site-association, and
// <link rel="manifest"> unlock hidden specs and routes pre-auth.
func TestRound39OriginSpecPathsSwaggerUIAndAppLinks(t *testing.T) {
	var mu sync.Mutex
	var requested []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.URL.Path)
		mu.Unlock()

		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><head><title>Portal</title><link rel="manifest" href="/site.webmanifest"><script src="/entry.js"></script></head><body>Home</body></html>`)
		case "/entry.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `const gw = axios.create({ baseURL: "/gw-sub" }); gw.get("/items");`)
		case "/site.webmanifest":
			w.Header().Set("Content-Type", "application/manifest+json")
			fmt.Fprint(w, `{"start_url":"/pwa/console"}`)
		case "/.well-known/apple-app-site-association":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"applinks":{"details":[{"paths":["/mobile/portal/*"]}]}}`)
		case "/pwa/console":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><head><title>PWA</title><script src="/pwa-bundle.js"></script></head><body>PWA</body></html>`)
		case "/pwa-bundle.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/pwa/status");`)
		case "/mobile/portal":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><head><title>Mobile</title><script src="/mobile-bundle.js"></script></head><body>Mobile</body></html>`)
		case "/mobile-bundle.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/mobile/orders");`)
		case "/api/documentation":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><body><div id="swagger-ui"></div><script>SwaggerUIBundle({ configUrl: "/custom-docs/swagger-config" })</script></body></html>`)
		case "/custom-docs/swagger-config":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"urls":[{"url":"/hidden-specs/crm-v1.json","name":"CRM"}]}`)
		case "/hidden-specs/crm-v1.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"openapi":"3.0.1","info":{"title":"CRM","version":"1.0"},"paths":{"/v1/crm/leads":{"get":{}}}}`)
		case "/gw-sub/swagger/v1/swagger.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"openapi":"3.0.1","info":{"title":"DotNetSvc","version":"1.0"},"paths":{"/gw-sub/invoices":{"get":{}}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	var resMu sync.Mutex
	var storedURLs []string
	res, err := Crawl(context.Background(), Options{
		Target:   u,
		InScope:  func(h string) bool { return h == u.Hostname() },
		Depth:    2,
		Rate:     500,
		Probe:    true,
		NoDNS:    true,
		Resolver: nxResolver,
		Extract:  func(b []byte, _ string) jsapi.Result { return jsapi.Extract(b) },
		Script: func(s Script) {
			resMu.Lock()
			storedURLs = append(storedURLs, strings.TrimPrefix(s.URL, srv.URL))
			resMu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.OpenAPI != 2 {
		t.Fatalf("OpenAPI specs stored = %d, want 2 (storedURLs=%v)", res.Stats.OpenAPI, storedURLs)
	}

	resMu.Lock()
	gotStored := slices.Clone(storedURLs)
	resMu.Unlock()
	for _, want := range []string{
		"/hidden-specs/crm-v1.json",
		"/gw-sub/swagger/v1/swagger.json",
		"/pwa-bundle.js",
		"/mobile-bundle.js",
	} {
		if !slices.Contains(gotStored, want) {
			t.Fatalf("missing discovered asset/spec %q in %v", want, gotStored)
		}
	}

	mu.Lock()
	gotReqs := slices.Clone(requested)
	mu.Unlock()
	if slices.Contains(gotReqs, "/gw-sub/api/documentation") || slices.Contains(gotReqs, "/gw-sub/docs/api-docs.json") {
		t.Fatalf("OriginSpecPaths must NOT be multiplied onto sub-path base /gw-sub: %v", gotReqs)
	}
}
