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
	"sync/atomic"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Reviewer round 17, MAX-02: a 429 with a short Retry-After is waited out;
// one challenged page leaves that page, not the crawl; three in a row stop
// it; the script budget stops scripts, not pages.
func TestNoEarlyStop(t *testing.T) {
	var limited atomic.Int32
	mux := http.NewServeMux()
	page := func(links ...string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			var b strings.Builder
			for _, l := range links {
				fmt.Fprintf(&b, `<a href="%s">x</a>`, l)
			}
			fmt.Fprintf(&b, `<script src="/js%s.js"></script>`, strings.ReplaceAll(r.URL.Path, "/", "-"))
			fmt.Fprintf(w, "<!doctype html><html><head><title>%s</title></head><body>%s</body></html>", r.URL.Path, b.String())
		}
	}
	challenge := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cf-Mitigated", "challenge")
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(403)
		fmt.Fprint(w, `<!doctype html><title>Just a moment...</title>`)
	}
	mux.HandleFunc("/", page("/admin", "/b"))
	mux.HandleFunc("/admin", challenge)
	mux.HandleFunc("/b", page("/c1", "/c2", "/c3", "/d"))
	mux.HandleFunc("/c1", challenge)
	mux.HandleFunc("/c2", challenge)
	mux.HandleFunc("/c3", challenge)
	mux.HandleFunc("/d", page())
	mux.HandleFunc("/js-.js", func(w http.ResponseWriter, r *http.Request) {
		if limited.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		fmt.Fprint(w, "fetch('/api/root')")
	})
	mux.HandleFunc("/js-b.js", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "fetch('/api/b')") })
	mux.HandleFunc("/js-d.js", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "fetch('/api/d')") })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/")
	var mu sync.Mutex
	var files []string
	var logged int
	opts := Options{Target: u, InScope: func(string) bool { return true }, Depth: 3, Rate: 1000, MaxFiles: 500,
		Script: func(s Script) {
			mu.Lock()
			files = append(files, strings.TrimPrefix(s.URL, srv.URL))
			mu.Unlock()
		},
		Request: func(traffic.Entry) { mu.Lock(); logged++; mu.Unlock() },
	}
	start := time.Now()
	res, err := Crawl(context.Background(), opts)
	slices.Sort(files)
	// /admin is one path's challenge: /b goes on. /c1../c3 in a row stop it
	// before /d.
	if !slices.Equal(files, []string{"/js-.js", "/js-b.js"}) || err != ErrStopped || !strings.Contains(res.Stats.Stopped, "3 pages in a row") {
		t.Fatalf("files %v, err %v, stopped %q", files, err, res.Stats.Stopped)
	}
	if limited.Load() != 2 || time.Since(start) < time.Second {
		t.Fatalf("the 429 was not waited out: %d tries", limited.Load())
	}
	if logged != res.Stats.Requests {
		t.Fatalf("logged %d, made %d: each try is logged", logged, res.Stats.Requests)
	}
	// The script budget spent: the pages go on.
	files, limited = nil, atomic.Int32{}
	limited.Store(1)
	opts.MaxFiles = 1
	res, err = Crawl(context.Background(), opts)
	if res.Stats.Capped == "" || res.Visited != 6 || len(files) != 1 {
		t.Fatalf("capped %q, err %v, visited %d, files %v", res.Stats.Capped, err, res.Visited, files)
	}
}
