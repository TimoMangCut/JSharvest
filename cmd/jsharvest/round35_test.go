package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestEnvHelperTreatsEmptyAsUnset(t *testing.T) {
	const key = "JSHARVEST_TEST_ROUND35_ENV"
	t.Setenv(key, "")
	if got := env(key, "https://default.example.test"); got != "https://default.example.test" {
		t.Fatalf("empty env var returned %q, want default", got)
	}
	t.Setenv(key, "   ")
	if got := env(key, "https://default.example.test"); got != "https://default.example.test" {
		t.Fatalf("whitespace env var returned %q, want default", got)
	}
	t.Setenv(key, "  https://custom.example.test  ")
	if got := env(key, "https://default.example.test"); got != "https://custom.example.test" {
		t.Fatalf("non-empty env var returned %q", got)
	}
}

func TestRunCrawlTabsWithoutExplicitDepthOnHTTPEngine(t *testing.T) {
	var mu sync.Mutex
	visited := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		visited[r.URL.Path] = true
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<!doctype html><html><head><title>Home</title></head><body><a href="/section">Section</a></body></html>`)
		case "/section":
			fmt.Fprint(w, `<!doctype html><html><head><title>Section</title></head><body><script>fetch("/api/section")</script></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	err := runCrawl([]string{
		"-u", srv.URL,
		"-o", t.TempDir(),
		"-engine", "http",
		"-tabs", "4",
		"-archive=false",
		"-no-spec-probe",
		"-http-rate", "1000",
	})
	if err != nil {
		t.Fatalf("runCrawl with -tabs 4 and auto HTTP depth failed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !visited["/section"] {
		t.Fatalf("expected child page /section to be visited with auto HTTP depth, visited=%v", visited)
	}
}
