package httpcrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/scope"
)

func TestRoutesSkipsVendorAtDepthZeroAndDedupsBySHA256(t *testing.T) {
	const inlineBoot = `window.__APP_CFG__ = { apiBase: "/api-gateway" };`
	const appCode = `fetch("/api-gateway/orders/v1/list");`
	const vendorCode = `/*! vendor chunk */ window.__VENDOR__ = function(){};`
	const infraCode = `window.__CF_CHALLENGE__ = 1;`

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, `<!doctype html><html><head><title>Home</title><script>%s</script></head><body><a href="/second">Next</a><script src="/chunk-vendors.a1b2c3d4.js"></script><script src="/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js"></script><script src="/app.js"></script></body></html>`, inlineBoot)
		case "/second":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, `<!doctype html><html><head><title>Second Page</title><script>%s</script></head><body><p>Unique body</p><script src="/app.js"></script></body></html>`, inlineBoot)
		case "/chunk-vendors.a1b2c3d4.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, vendorCode)
		case "/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, infraCode)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, appCode)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	inScope, err := scope.New(u.Hostname(), "rdn")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Depth == 0 with Probe=true: vendor bundle must NOT be AST-parsed at all.
	var mu sync.Mutex
	callsDepth0 := map[string]int{}
	_, err = Crawl(context.Background(), Options{
		Target:       u,
		InScope:      inScope,
		Depth:        0,
		Probe:        true,
		AllowPrivate: true,
		Rate:         100,
		Extract: func(body []byte, hint string) jsapi.Result {
			mu.Lock()
			callsDepth0[string(body)]++
			mu.Unlock()
			return jsapi.ExtractSource(body, hint)
		},
	})
	if err != nil {
		t.Fatalf("Depth=0 crawl failed: %v", err)
	}
	if callsDepth0[vendorCode] != 0 || callsDepth0[infraCode] != 0 {
		t.Fatalf("non-app bundles were AST-parsed at Depth=0: vendor=%d infra=%d, want 0", callsDepth0[vendorCode], callsDepth0[infraCode])
	}
	if callsDepth0[appCode] != 1 || callsDepth0[inlineBoot] != 1 {
		t.Fatalf("unexpected Depth=0 extract counts: app=%d inline=%d", callsDepth0[appCode], callsDepth0[inlineBoot])
	}

	// 2. Depth == 1 across two pages sharing the same inline script and app.js:
	// each unique SHA256 must be extracted at most once.
	callsDepth1 := map[string]int{}
	_, err = Crawl(context.Background(), Options{
		Target:       u,
		InScope:      inScope,
		Depth:        1,
		Probe:        true,
		AllowPrivate: true,
		Rate:         100,
		Extract: func(body []byte, hint string) jsapi.Result {
			mu.Lock()
			callsDepth1[string(body)]++
			mu.Unlock()
			return jsapi.ExtractSource(body, hint)
		},
	})
	if err != nil {
		t.Fatalf("Depth=1 crawl failed: %v", err)
	}
	if callsDepth1[inlineBoot] != 1 {
		t.Fatalf("duplicate inline script extracted %d times across 2 pages, want 1", callsDepth1[inlineBoot])
	}
	if callsDepth1[appCode] != 1 {
		t.Fatalf("app.js extracted %d times, want 1", callsDepth1[appCode])
	}
}
