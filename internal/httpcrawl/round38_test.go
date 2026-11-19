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

const testSPAShell = `<!doctype html><html><head><title>Portal SPA</title><script src="/app.js"></script></head><body><div id="app">Portal Single Page App Shell</div></body></html>`

const testOpenAPIDoc = `{"openapi":"3.0.0","info":{"title":"Svc","version":"1.0"},"paths":{"/v1/orders":{"get":{}}}}`

// C (round 38): on an SPA origin (cr.spa[orig] == true), a sub-path gateway
// base (/api/svc-dead) that answers with the exact SPA shell stops after 4
// requests (first 3 SpecPaths + /v3/api-docs) and also suppresses leaked
// ServiceDocPaths probes on that same braked prefix.
func TestRound38SpecProbeSubPathBrakesOnConfirmedSPAShell(t *testing.T) {
	var mu sync.Mutex
	var deadHits []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			// Triggers both plan.Bases (/api/svc-dead) and plan.Services (/api/svc-dead).
			fmt.Fprint(w, `
				const api = axios.create({ baseURL: "/api/svc-dead" });
				api.get("/users");
				api.post("/orders", {});
				fetch("/api/svc-dead/items");
			`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/svc-dead/") {
			mu.Lock()
			deadHits = append(deadHits, r.URL.Path)
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, testSPAShell)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	res, err := Crawl(context.Background(), Options{
		Target:  u,
		InScope: func(string) bool { return true },
		Depth:   1,
		Rate:    500,
		Probe:   true,
		Extract: func(b []byte, _ string) jsapi.Result { return jsapi.Extract(b) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Stats.SPA {
		t.Fatal("expected origin to be detected as SPA")
	}

	mu.Lock()
	got := slices.Clone(deadHits)
	mu.Unlock()

	want := []string{
		"/api/svc-dead/openapi.json",
		"/api/svc-dead/openapi.yaml",
		"/api/svc-dead/api-json",
		"/api/svc-dead/v3/api-docs",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("sub-path SPA brake sent %v (%d reqs), want %v (4 reqs)", got, len(got), want)
	}
}

// C (round 38): pre-claimed SpecPaths (not actually sent by specProbeWithScope)
// neither increment nor reset spaShellHits, preventing premature braking before
// /docs-json when /openapi.yaml and /api-json were already claimed earlier.
func TestRound38SpecProbeClaimedPathsDoNotCountTowardSPABrake(t *testing.T) {
	const shellWithPreclaimed = `<!doctype html><html><head><title>Portal SPA</title>` +
		`<script src="/app.js"></script>` +
		`<script src="/api/svc-pre/openapi.yaml"></script>` +
		`<script src="/api/svc-pre/api-json"></script>` +
		`</head><body><div id="app">Portal Single Page App Shell</div></body></html>`

	var mu sync.Mutex
	counts := map[string]int{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counts[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `const c = axios.create({ baseURL: "/api/svc-pre" }); c.get("/ping");`)
		case "/api/svc-pre/docs-json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, testOpenAPIDoc)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, shellWithPreclaimed)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	var capMu sync.Mutex
	var captured []string
	_, err := Crawl(context.Background(), Options{
		Target:  u,
		InScope: func(string) bool { return true },
		Depth:   1,
		Rate:    500,
		Probe:   true,
		Extract: func(b []byte, _ string) jsapi.Result { return jsapi.Extract(b) },
		Script: func(s Script) {
			if slices.Contains(s.Tags, "openapi") {
				capMu.Lock()
				captured = append(captured, s.URL)
				capMu.Unlock()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	yamlHits := counts["/api/svc-pre/openapi.yaml"]
	apiJSONHits := counts["/api/svc-pre/api-json"]
	mu.Unlock()
	if yamlHits != 1 || apiJSONHits != 1 {
		t.Fatalf("expected pre-claimed paths to be fetched once (before Phase 2), got yaml=%d api-json=%d", yamlHits, apiJSONHits)
	}
	capMu.Lock()
	gotCap := slices.Clone(captured)
	capMu.Unlock()
	if !slices.Contains(gotCap, srv.URL+"/api/svc-pre/docs-json") {
		t.Fatalf("pre-claimed paths caused premature SPA brake before /docs-json: captured=%v", gotCap)
	}
}

// C (round 38): origin root NEVER brakes on SPA shell — both /v2/api-docs and
// /.well-known/openid-configuration on an SPA origin root are still captured.
func TestRound38SpecProbeOriginRootNeverBrakesOnSPAShell(t *testing.T) {
	var apiSrv *httptest.Server
	apiSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/api-docs":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, testOpenAPIDoc)
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":%q}`, apiSrv.URL, apiSrv.URL+"/oauth/token")
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, testSPAShell)
		}
	}))
	defer apiSrv.Close()

	seedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `fetch(%q + "/v1/orders");`, apiSrv.URL)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			// Link to apiSrv so cr.pages visits apiSrv and marks cr.spa[apiOrig] = true,
			// while scripts also register apiSrv in cr.apiOrigins (postPages=true root probe!).
			fmt.Fprintf(w, `<!doctype html><html><head><title>Seed</title><script src="/app.js"></script></head><body><a href="%s/home">API SPA</a></body></html>`, apiSrv.URL)
		}
	}))
	defer seedSrv.Close()

	u, _ := url.Parse(seedSrv.URL + "/")
	var mu sync.Mutex
	var captured []string
	_, err := Crawl(context.Background(), Options{
		Target:  u,
		InScope: func(string) bool { return true },
		Depth:   1,
		Rate:    500,
		Probe:   true,
		Extract: func(b []byte, _ string) jsapi.Result { return jsapi.Extract(b) },
		Script: func(s Script) {
			if slices.Contains(s.Tags, "openapi") {
				mu.Lock()
				captured = append(captured, s.URL)
				mu.Unlock()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := slices.Clone(captured)
	mu.Unlock()
	if !slices.Contains(got, apiSrv.URL+"/v2/api-docs") {
		t.Fatalf("origin root failed to capture /v2/api-docs: got %v", got)
	}
	if !slices.Contains(got, apiSrv.URL+"/.well-known/openid-configuration") {
		t.Fatalf("origin root failed to capture /.well-known/openid-configuration: got %v", got)
	}
}

// C (round 38): on the same SPA origin, braking on /api/svc-dead stays strictly
// local: /api/svc-live (answering 404 JSON before 200 OpenAPI at /v2/api-docs)
// and /realms/corp (answering SPA shell on Swagger paths but valid OIDC at
// /.well-known/openid-configuration) are both captured.
func TestRound38SpecProbeSubPathPreservesRealBackendAndOIDCRealm(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `
				const dead = axios.create({ baseURL: "/api/svc-dead" }); dead.get("/x");
				const live = axios.create({ baseURL: "/api/svc-live" }); live.get("/y");
				const idp  = axios.create({ baseURL: "/realms/corp" });  idp.get("/account");
			`)
		case r.URL.Path == "/api/svc-live/v2/api-docs":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, testOpenAPIDoc)
		case strings.HasPrefix(r.URL.Path, "/api/svc-live/"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not_found"}`)
		case r.URL.Path == "/realms/corp/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":%q}`, srv.URL+"/realms/corp", srv.URL+"/realms/corp/protocol/openid-connect/token")
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, testSPAShell)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	var mu sync.Mutex
	var captured []string
	_, err := Crawl(context.Background(), Options{
		Target:  u,
		InScope: func(string) bool { return true },
		Depth:   1,
		Rate:    500,
		Probe:   true,
		Extract: func(b []byte, _ string) jsapi.Result { return jsapi.Extract(b) },
		Script: func(s Script) {
			if slices.Contains(s.Tags, "openapi") {
				mu.Lock()
				captured = append(captured, s.URL)
				mu.Unlock()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := slices.Clone(captured)
	mu.Unlock()
	if !slices.Contains(got, srv.URL+"/api/svc-live/v2/api-docs") {
		t.Fatalf("failed to capture /api/svc-live/v2/api-docs on SPA origin: got %v", got)
	}
	if !slices.Contains(got, srv.URL+"/realms/corp/.well-known/openid-configuration") {
		t.Fatalf("failed to capture /realms/corp/.well-known/openid-configuration on SPA origin: got %v", got)
	}
}
