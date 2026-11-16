package httpcrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
)

// On an SPA's origin, the API's description its scripts fetch is
// fetched (not listed as a route), and kept for the catalog.
func TestOpenAPIOnSPA(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.Path] = true
		mu.Unlock()
		switch r.URL.Path {
		case "/app.js":
			fmt.Fprint(w, "function fe(){return'/openapi.yaml'}fetch(fe());const r=['/home','/settings']")
		case "/openapi.yaml":
			w.Header().Set("Content-Type", "application/yaml")
			fmt.Fprint(w, "openapi: 3.0.0\npaths:\n  /v1/x:\n    get: {}\n")
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><title>App</title><script type="module" src="/app.js"></script>`)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/")
	var kept []Script
	res, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Depth: 2, Rate: 1000,
		Script: func(s Script) {
			mu.Lock()
			kept = append(kept, s)
			mu.Unlock()
		}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Stats.SPA || asked["/home"] {
		t.Fatalf("spa %v, asked %v", res.Stats.SPA, asked)
	}
	found := false
	for _, s := range kept {
		found = found || s.URL == srv.URL+"/openapi.yaml" && slices.Contains(s.Tags, "openapi")
	}
	if !asked["/openapi.yaml"] || !found || res.Stats.OpenAPI != 1 {
		t.Fatalf("openapi.yaml: asked %v, kept %v, stat %d", asked["/openapi.yaml"], found, res.Stats.OpenAPI)
	}
}
