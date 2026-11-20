package httpcrawl

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/scope"
)

// R40-B1: HTTP crawl blocks third-party SDK/IdP/map hosts completely, limits
// OriginSpecPaths & Phase-2 sub-path/service probes strictly to inScope hosts,
// and keeps root-only D2 SpecPaths for clean unlisted cross-origin APIs and
// sibling gateways under -scope fqdn.
func TestRound40SpecProbeScopeAndThirdPartyBlocking(t *testing.T) {
	runCase := func(t *testing.T, scopeMode string) map[string][]string {
		t.Helper()
		var mu sync.Mutex
		hits := map[string][]string{}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := strings.ToLower(strings.Split(r.Host, ":")[0])
			mu.Lock()
			hits[host] = append(hits[host], r.URL.Path)
			mu.Unlock()
			switch {
			case host == "www.example.test" && r.URL.Path == "/":
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<!doctype html><html><head><title>Portal</title><script src="/app.js"></script></head><body>ok</body></html>`)
			case host == "www.example.test" && r.URL.Path == "/app.js":
				w.Header().Set("Content-Type", "application/javascript")
				fmt.Fprint(w, `
					const msal = axios.create({ baseURL: "http://login.microsoftonline.com/common/oauth2/v2.0" });
					msal.get("/authorize");
					fetch("http://nominatim.openstreetmap.org/search?q=a");
					fetch("http://reactrouter.com/docs/v6");
					const partner = axios.create({ baseURL: "http://api-partner.example.net/gw" });
					partner.get("/billing/v1/invoices");
					const sibling = axios.create({ baseURL: "http://api.example.test/gw" });
					sibling.get("/auth/v1/me");
				`)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		inScope, err := scope.New("www.example.test", scopeMode)
		if err != nil {
			t.Fatal(err)
		}
		targetURL, _ := url.Parse("http://www.example.test/")
		_, err = Crawl(context.Background(), Options{
			Target:    targetURL,
			InScope:   inScope,
			HostRules: fmt.Sprintf("MAP * 127.0.0.1:%s", port),
			Depth:     1,
			Rate:      500,
			Probe:     true,
			Extract:   func(b []byte, _ string) jsapi.Result { return jsapi.Extract(b) },
		})
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		out := make(map[string][]string, len(hits))
		for k, v := range hits {
			out[k] = slices.Clone(v)
		}
		return out
	}

	// 1. -scope rdn: 0 requests to SDK/IdP/map; partner gets root SpecPaths only (no OriginSpecPaths, no /gw/*);
	// sibling api.example.test (inScope) gets OriginSpecPaths + /gw/* + /gw/auth/*.
	rdnHits := runCase(t, "rdn")
	for _, blocked := range []string{"login.microsoftonline.com", "nominatim.openstreetmap.org", "reactrouter.com"} {
		if len(rdnHits[blocked]) > 0 {
			t.Fatalf("expected 0 requests to %s, got %v", blocked, rdnHits[blocked])
		}
	}
	partnerHits := rdnHits["api-partner.example.net"]
	if !slices.Contains(partnerHits, "/openapi.json") {
		t.Fatalf("expected D2 root SpecPaths probe on clean partner host, got %v", partnerHits)
	}
	for _, p := range partnerHits {
		if strings.HasPrefix(p, "/gw/") || slices.Contains(frontier.OriginSpecPaths, p) {
			t.Fatalf("out-of-scope partner host received OriginSpecPaths or sub-path probe %q (all=%v)", p, partnerHits)
		}
	}
	sibRDN := rdnHits["api.example.test"]
	if !slices.Contains(sibRDN, "/swagger.json") {
		t.Fatalf("in-scope sibling in rdn mode should receive OriginSpecPaths (/swagger.json), got %v", sibRDN)
	}
	if !slices.Contains(sibRDN, "/gw/openapi.json") || !slices.Contains(sibRDN, "/gw/auth/v3/api-docs") {
		t.Fatalf("in-scope sibling in rdn mode should receive sub-path and service probes, got %v", sibRDN)
	}

	// 2. -scope fqdn: sibling api.example.test is out of scope -> root SpecPaths only (D2), no OriginSpecPaths or /gw/*.
	fqdnHits := runCase(t, "fqdn")
	sibFQDN := fqdnHits["api.example.test"]
	if !slices.Contains(sibFQDN, "/openapi.json") {
		t.Fatalf("fqdn mode sibling should still receive root D2 SpecPaths, got %v", sibFQDN)
	}
	for _, p := range sibFQDN {
		if strings.HasPrefix(p, "/gw/") || slices.Contains(frontier.OriginSpecPaths, p) {
			t.Fatalf("fqdn mode sibling should NOT receive OriginSpecPaths or sub-path probe %q (all=%v)", p, sibFQDN)
		}
	}
}

// R40-B2: soft-200 SPA HTML fallback responses stay in Stats.Probes (keeping
// "what was probed") and are also listed in Stats.SoftProbes, while genuine
// text/plain robots.txt and real Swagger UI HTML (/api/documentation) are not.
func TestRound40Soft200SPAShellMarkedInSoftProbes(t *testing.T) {
	// Case 1: SPA returning 200 HTML shell for manifest, OpenAPI, and robots.txt.
	spaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `console.log("spa");`)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, testSPAShell)
	}))
	defer spaSrv.Close()

	uSPA, _ := url.Parse(spaSrv.URL + "/")
	resSPA, err := Crawl(context.Background(), Options{
		Target:  uSPA,
		InScope: func(string) bool { return true },
		Depth:   1,
		Rate:    500,
		Probe:   true,
		Extract: func(b []byte, _ string) jsapi.Result { return jsapi.Extract(b) },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/robots.txt", "/.vite/manifest.json", "/openapi.json"} {
		if resSPA.Stats.Probes[want] != 200 {
			t.Fatalf("Probes[%q] = %d, want 200 (key must be kept)", want, resSPA.Stats.Probes[want])
		}
		if !slices.Contains(resSPA.Stats.SoftProbes, want) {
			t.Fatalf("expected %q in SoftProbes, got %v", want, resSPA.Stats.SoftProbes)
		}
	}

	// Case 2: Non-SPA origin returning genuine text/plain robots.txt and genuine
	// Swagger UI HTML at /api/documentation must NOT mark either in SoftProbes.
	docSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><head><title>Home</title></head><body>hi</body></html>`)
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "User-agent: *\nAllow: /\n")
		case "/api/documentation":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><body><script>SwaggerUIBundle({ url: "/docs/custom-openapi.json" })</script></body></html>`)
		case "/docs/custom-openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, testOpenAPIDoc)
		default:
			http.NotFound(w, r)
		}
	}))
	defer docSrv.Close()

	uDoc, _ := url.Parse(docSrv.URL + "/")
	resDoc, err := Crawl(context.Background(), Options{
		Target:  uDoc,
		InScope: func(string) bool { return true },
		Depth:   1,
		Rate:    500,
		Probe:   true,
		Extract: func(b []byte, _ string) jsapi.Result { return jsapi.Extract(b) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if resDoc.Stats.Probes["/robots.txt"] != 200 || resDoc.Stats.Probes["/api/documentation"] != 200 {
		t.Fatalf("expected 200 in Probes for robots.txt and /api/documentation, got %v", resDoc.Stats.Probes)
	}
	for _, genuine := range []string{"/robots.txt", "/api/documentation", "/docs/custom-openapi.json"} {
		if slices.Contains(resDoc.Stats.SoftProbes, genuine) {
			t.Fatalf("genuine response %q should not be marked in SoftProbes: %v", genuine, resDoc.Stats.SoftProbes)
		}
	}
}
