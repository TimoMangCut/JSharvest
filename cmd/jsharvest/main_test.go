package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/frontier"
)

func TestParseURLList(t *testing.T) {
	in := "# targets\nhttp://h/a\n\n  https://h/b?x=1  \nhttp://h/a\n"
	got, err := parseURLList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].String() != "http://h/a" || got[1].String() != "https://h/b?x=1" {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{"http://h/a\nfile:///etc/passwd\n", "h/no-scheme\n", "# only comments\n", ""} {
		if _, err := parseURLList(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	_, err = parseURLList(strings.NewReader("http://h/a\nftp://h/b\njavascript:x\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error does not name the bad lines: %v", err)
	}
}

func TestRunCrawlNoSpecProbe(t *testing.T) {
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
			fmt.Fprint(w, `const api = axios.create({ baseURL: "/api-gateway" }); api.get("auth/v1/login");`)
		case "/robots.txt":
			fmt.Fprint(w, "User-agent: *\nDisallow:\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	err := runCrawl([]string{
		"-u", srv.URL,
		"-o", t.TempDir(),
		"-engine", "http",
		"-archive=false",
		"-http-rate", "1000",
		"-no-spec-probe",
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !robotsHit {
		t.Error("expected -probe well-known files (/robots.txt) to still run with -no-spec-probe")
	}
	if len(specHits) != 0 {
		t.Fatalf("expected 0 spec probe requests with -no-spec-probe, got %v", specHits)
	}
}
