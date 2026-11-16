package httpcrawl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// PIP-02 and PIP-03: a JSON page is an API's answer (Fetch); the seed's
// origin is asked for its API's description, and one is kept; a JSON
// answer's body is kept for the request log.
func TestJSONPagesAndSpecProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><title>x</title><a href="/api/status">s</a><a href="/app-config.json">c</a></html>`))
		case "/api/status", "/app-config.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		case "/docs-json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"openapi":"3.0.0","paths":{"/v1/a":{"get":{}}}}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			w.Write([]byte(`{"statusCode":404,"message":"Cannot GET ` + r.URL.Path + `","error":"Not Found"}`))
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	var mu sync.Mutex
	types := map[string]string{}
	bodies := map[string]string{}
	var specs []string
	_, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Depth: 1, Rate: 200, Probe: true,
		RecordBody: 4096,
		Request: func(e traffic.Entry) {
			mu.Lock()
			defer mu.Unlock()
			types[e.URL] = e.ResourceType
			if e.Response != nil {
				bodies[e.URL] = e.Response.Body.Body
			}
		},
		Script: func(s Script) {
			mu.Lock()
			defer mu.Unlock()
			if slices.Contains(s.Tags, "openapi") {
				specs = append(specs, s.URL)
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	if types[srv.URL+"/api/status"] != "Fetch" || types[srv.URL+"/app-config.json"] != "Document" || types[srv.URL] != "Document" {
		t.Errorf("types: %v", types)
	}
	if !slices.Equal(specs, []string{srv.URL + "/docs-json"}) {
		t.Errorf("specs: %v", specs)
	}
	if !strings.Contains(bodies[srv.URL+"/openapi.json"], "statusCode") || bodies[srv.URL] != "" {
		t.Errorf("bodies: %v", bodies)
	}
	for _, p := range []string{"/openapi.json", "/openapi.yaml", "/api-json", "/docs-json", "/v3/api-docs", "/swagger/doc.json", "/.well-known/openid-configuration"} {
		if _, ok := types[srv.URL+p]; !ok {
			t.Errorf("%s not asked", p)
		}
	}
}
