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

	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/scope"
)

// Test 1: Gateway + static client_headers + Springfox /v2/api-docs & /swagger-resources.
func TestSpecProbeGatewayHeadersAndSwaggerResources(t *testing.T) {
	var mu sync.Mutex
	var missingHeaderHits int

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><head><title>Portal</title></head><body><div id="app"></div><script src="/app.js"></script></body></html>`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api-gateway/") {
			if r.Header.Get("client_id") != "PORTAL_APP" || r.Header.Get("client_secret") != "STATIC_KEY_1" {
				mu.Lock()
				missingHeaderHits++
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"unauthorized_client"}`)
				return
			}
			switch r.URL.Path {
			case "/api-gateway/auth/v2/api-docs":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"swagger":"2.0","info":{"title":"Auth Service","version":"1.0"},"basePath":"/api-gateway/auth","paths":{"/v1/login":{"post":{"operationId":"login"}},"/v1/users":{"get":{"operationId":"listUsers"}}}}`)
				return
			case "/api-gateway/swagger-resources":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `[{"name":"orders","url":"/orders/v2/api-docs"}]`)
				return
			case "/api-gateway/orders/v2/api-docs":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"swagger":"2.0","info":{"title":"Orders Service","version":"1.0"},"basePath":"/api-gateway/orders","paths":{"/v1/orders":{"get":{"operationId":"listOrders"}}}}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"status":404,"error":"Not Found"}`)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `
const api = axios.create({
  baseURL: "/api-gateway",
  headers: {
    "client_id": "PORTAL_APP",
    "client_secret": "STATIC_KEY_1"
  }
});
function doLogin(payload) { return api.post("auth/v1/login", payload); }
function getInvoices() { return api.get("billing/v1/invoices"); }
`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/")

	var specs []string
	res, err := Crawl(context.Background(), Options{
		Target:  u,
		InScope: func(string) bool { return true },
		Probe:   true,
		Rate:    1000,
		Script: func(s Script) {
			if slices.Contains(s.Tags, "openapi") {
				mu.Lock()
				specs = append(specs, strings.TrimPrefix(s.URL, srv.URL))
				mu.Unlock()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	slices.Sort(specs)
	want := []string{
		"/api-gateway/auth/v2/api-docs",
		"/api-gateway/orders/v2/api-docs",
	}
	if !slices.Equal(specs, want) {
		t.Fatalf("discovered OpenAPI specs:\n got  %v\n want %v", specs, want)
	}
	if res.Stats.OpenAPI != 2 {
		t.Errorf("Stats.OpenAPI = %d, want 2", res.Stats.OpenAPI)
	}
	mu.Lock()
	defer mu.Unlock()
	if missingHeaderHits != 0 {
		t.Errorf("gateway received %d probe requests missing static client_headers", missingHeaderHits)
	}
}

// Test 2: D3 Uniform Gate Auto-Brake on 401 JSON wall and SPA HTML fallback shell.
func TestSpecProbeUniformGateAutoBrake(t *testing.T) {
	shell := `<!doctype html><html><head><title>Portal</title></head><body><div id="app"></div><script src="/app.js"></script></body></html>`

	var jsCalls strings.Builder
	jsCalls.WriteString(`const api = axios.create({ baseURL: "/api-gateway" });` + "\n")
	for i := 1; i <= 10; i++ {
		fmt.Fprintf(&jsCalls, "api.get(\"svc%d/v1/x\");\n", i)
	}
	appJS := jsCalls.String()

	for _, tc := range []struct {
		name string
		gate http.HandlerFunc
	}{
		{
			name: "uniform_401_json",
			gate: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"code":401,"msg":"unauthorized"}`)
			},
		},
		{
			name: "uniform_spa_shell",
			gate: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprint(w, shell)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var serviceDocReqs int

			mux := http.NewServeMux()
			mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/javascript")
				fmt.Fprint(w, appJS)
			})
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					fmt.Fprint(w, shell)
					return
				}
				if strings.HasPrefix(r.URL.Path, "/api-gateway/") {
					rest := strings.TrimPrefix(r.URL.Path, "/api-gateway/")
					if strings.HasPrefix(rest, "svc") && strings.HasSuffix(rest, "/api-docs") {
						mu.Lock()
						serviceDocReqs++
						mu.Unlock()
					}
					tc.gate(w, r)
					return
				}
				http.NotFound(w, r)
			})

			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			u, _ := url.Parse(srv.URL + "/")

			res, err := Crawl(context.Background(), Options{
				Target:  u,
				InScope: func(string) bool { return true },
				Depth:   1,
				Probe:   true,
				Rate:    1000,
			})
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			got := serviceDocReqs
			mu.Unlock()
			if got == 0 || got > 4 {
				t.Fatalf("%s: expected D3 auto-brake after initial uniform hits (1..4 service doc requests, vastly fewer than 20), got %d", tc.name, got)
			}
			if res.Stats.OpenAPI != 0 {
				t.Errorf("%s: Stats.OpenAPI = %d, want 0", tc.name, res.Stats.OpenAPI)
			}
		})
	}
}

// Test 3: Header Scope Isolation & -no-spec-probe.
func TestSpecProbeHeaderIsolationAndNoSpecProbe(t *testing.T) {
	t.Run("header_scope_isolation", func(t *testing.T) {
		var mu sync.Mutex
		var otherLeaked []string
		var otherProbed int
		var portalAuthLeaked bool

		otherSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			otherProbed++
			for _, h := range []string{"client_id", "client_secret", "x-portal-key", "authorization", "cookie"} {
				if v := r.Header.Get(h); v != "" {
					otherLeaked = append(otherLeaked, h+"="+v)
				}
			}
			mu.Unlock()
			if r.URL.Path == "/v2/api-docs" {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"swagger":"2.0","info":{"title":"Partner API","version":"1.0"},"paths":{"/v1/ping":{"get":{}}}}`)
				return
			}
			http.NotFound(w, r)
		}))
		t.Cleanup(otherSrv.Close)
		otherURL, _ := url.Parse(otherSrv.URL)

		portalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<!doctype html><html><head><title>Admin</title></head><body><script src="/app.js"></script></body></html>`)
				return
			}
			if r.URL.Path == "/app.js" {
				w.Header().Set("Content-Type", "application/javascript")
				fmt.Fprintf(w, `
const client = axios.create({
  baseURL: "/api-gateway",
  headers: {
    "client_id": "PORTAL_APP",
    "client_secret": "STATIC_KEY_1",
    "Authorization": "Bearer STATIC_SHOULD_NOT_SEND",
    "Cookie": "sid=STATIC_SHOULD_NOT_SEND"
  }
});
client.get("users/v1/me");
fetch("http://api.unrelated.test:%s/v1/ping");
`, otherURL.Port())
				return
			}
			if strings.HasPrefix(r.URL.Path, "/api-gateway/") {
				if r.Header.Get("Authorization") != "" || strings.Contains(r.Header.Get("Cookie"), "STATIC_SHOULD_NOT_SEND") {
					mu.Lock()
					portalAuthLeaked = true
					mu.Unlock()
				}
			}
			http.NotFound(w, r)
		}))
		t.Cleanup(portalSrv.Close)
		portalURL, _ := url.Parse(portalSrv.URL)

		target, _ := url.Parse("http://admin.example.test:" + portalURL.Port() + "/")
		inScope, err := scope.New("admin.example.test", "rdn")
		if err != nil {
			t.Fatal(err)
		}
		hostRules := fmt.Sprintf("MAP admin.example.test %s, MAP api.unrelated.test %s", portalURL.Hostname(), otherURL.Hostname())

		var specs []string
		_, err = Crawl(context.Background(), Options{
			Target:       target,
			InScope:      inScope,
			HostRules:    hostRules,
			NoDNS:        true,
			AllowPrivate: true,
			Probe:        true,
			Rate:         1000,
			Script: func(s Script) {
				if slices.Contains(s.Tags, "openapi") {
					mu.Lock()
					specs = append(specs, s.URL)
					mu.Unlock()
				}
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(otherLeaked) > 0 {
			t.Fatalf("client_headers leaked to unrelated host: %v", otherLeaked)
		}
		if portalAuthLeaked {
			t.Fatal("unsafe Authorization/Cookie client_headers were attached to spec probe")
		}
		if otherProbed == 0 || !slices.Contains(specs, fmt.Sprintf("http://api.unrelated.test:%s/v2/api-docs", otherURL.Port())) {
			t.Fatalf("expected D2 app-referenced API origin to be probed without headers; probed=%d specs=%v", otherProbed, specs)
		}
	})

	t.Run("no_spec_probe", func(t *testing.T) {
		var mu sync.Mutex
		var specHits []string
		var robotsHit bool

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			if r.URL.Path == "/robots.txt" {
				robotsHit = true
			}
			if slices.Contains(frontier.SpecPaths, r.URL.Path) || strings.HasPrefix(r.URL.Path, "/api-gateway") {
				specHits = append(specHits, r.URL.Path)
			}
			mu.Unlock()
			switch r.URL.Path {
			case "/":
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<!doctype html><html><head><title>App</title></head><body><script src="/app.js"></script></body></html>`)
			case "/app.js":
				w.Header().Set("Content-Type", "application/javascript")
				fmt.Fprint(w, `const api = axios.create({ baseURL: "/api-gateway", headers: { "client_id": "X" } }); api.get("auth/v1/login");`)
			case "/robots.txt":
				fmt.Fprint(w, "User-agent: *\nDisallow:\n")
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		u, _ := url.Parse(srv.URL + "/")

		_, err := Crawl(context.Background(), Options{
			Target:      u,
			InScope:     func(string) bool { return true },
			Probe:       true,
			NoSpecProbe: true,
			Rate:        1000,
		})
		if err != nil {
			t.Fatal(err)
		}

		mu.Lock()
		defer mu.Unlock()
		if !robotsHit {
			t.Error("expected /robots.txt probe to remain active when Probe=true, NoSpecProbe=true")
		}
		if len(specHits) != 0 {
			t.Fatalf("expected 0 spec probe requests with NoSpecProbe=true, got %d: %v", len(specHits), specHits)
		}
	})
}

// Implicit gateway base from full paths ("/api-gateway/auth/v1.0/login") and
// service prefix frequency ranking (MaxServiceDocPrefixes = 5).
func TestSpecProbeImplicitGatewayAndFrequencyRank(t *testing.T) {
	var mu sync.Mutex
	var probedServices []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><html><head><title>App</title></head><body><script src="/app.js"></script></body></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			// "zebra" has 3 endpoints (highest frequency), plus 5 other services (6 total > MaxServiceDocPrefixes=5).
			// Generic segments "/api/v1/x" and "/v1/items" must be skipped.
			fmt.Fprint(w, `
fetch("/api-gateway/zebra/v1.0/a");
fetch("/api-gateway/zebra/v1.0/b");
fetch("/api-gateway/zebra/v1.0/c");
fetch("/api-gateway/alpha/v1/a");
fetch("/api-gateway/ alpha2/v1/a");
fetch("/api-gateway/beta/v1/a");
fetch("/api-gateway/gamma/v1/a");
fetch("/api-gateway/delta/v1/a");
fetch("/api-gateway/omega/v1/a");
fetch("/api/v1/skipme");
fetch("/v1/skipme");
`)
		case "/api-gateway/zebra/v3/api-docs":
			mu.Lock()
			probedServices = append(probedServices, "zebra")
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"openapi":"3.0.1","info":{"title":"Zebra","version":"1.0"},"paths":{"/v1.0/a":{"get":{}}}}`)
		default:
			if rest, ok := strings.CutPrefix(r.URL.Path, "/api-gateway/"); ok && strings.HasSuffix(rest, "/v3/api-docs") {
				svc := strings.TrimSuffix(rest, "/v3/api-docs")
				if svc != "" && !strings.Contains(svc, "/") {
					mu.Lock()
					probedServices = append(probedServices, svc)
					mu.Unlock()
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, `{"openapi":"3.0.1","info":{"title":%q,"version":"1.0"},"paths":{"/v1/a":{"get":{}}}}`, svc)
					return
				}
			}
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/")

	res, err := Crawl(context.Background(), Options{
		Target:  u,
		InScope: func(string) bool { return true },
		Probe:   true,
		Rate:    1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	// Top 5 by frequency then lexicographically: zebra (freq 3), then alpha, beta, delta, gamma (omega dropped as #6).
	want := []string{"zebra", "alpha", "beta", "delta", "gamma"}
	if !slices.Equal(probedServices, want) {
		t.Fatalf("service probe order/cap:\n got  %v\n want %v", probedServices, want)
	}
	if res.Stats.OpenAPI != 5 {
		t.Errorf("Stats.OpenAPI = %d, want 5", res.Stats.OpenAPI)
	}
}
