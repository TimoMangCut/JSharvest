package httpcrawl

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParallelPagesDeterministicOrder(t *testing.T) {
	delays := map[string]time.Duration{
		"/":      5 * time.Millisecond,
		"/slow1": 80 * time.Millisecond,
		"/fast2": 45 * time.Millisecond,
		"/mid3":  65 * time.Millisecond,
		"/fast4": 50 * time.Millisecond,
	}
	var inFlight atomic.Int32
	var peakInFlight atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/__") {
			cur := inFlight.Add(1)
			for {
				prev := peakInFlight.Load()
				if cur <= prev || peakInFlight.CompareAndSwap(prev, cur) {
					break
				}
			}
			defer inFlight.Add(-1)
		}
		if d := delays[r.URL.Path]; d > 0 {
			time.Sleep(d)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<!doctype html><html><body>
<a href="/slow1">1</a>
<a href="/fast2">2</a>
<a href="/mid3">3</a>
<a href="/fast4">4</a>
<script src="/bundle.js"></script>
</body></html>`)
			return
		}
		fmt.Fprintf(w, `<!doctype html><html><head><title>Page %s</title></head><body><script>fetch("/api%s")</script></body></html>`, r.URL.Path, r.URL.Path)
	})
	mux.HandleFunc("/bundle.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `fetch("/api/root")`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	runWithWorkers := func(pw int) ([]string, []string, *Result) {
		u, _ := url.Parse(srv.URL + "/")
		var mu sync.Mutex
		var pageOrder []string
		var scripts []string
		res, err := Crawl(context.Background(), Options{
			Target:      u,
			InScope:     func(string) bool { return true },
			Depth:       2,
			Rate:        1000,
			PageWorkers: pw,
			Page: func(p Page) {
				mu.Lock()
				pageOrder = append(pageOrder, strings.TrimPrefix(p.URL, srv.URL))
				mu.Unlock()
			},
			Script: func(s Script) {
				mu.Lock()
				scripts = append(scripts, s.Kind+":"+strings.TrimPrefix(s.URL, srv.URL))
				mu.Unlock()
			},
		})
		if err != nil {
			t.Fatalf("PageWorkers=%d failed: %v", pw, err)
		}
		slices.Sort(scripts)
		return pageOrder, scripts, res
	}

	peakInFlight.Store(0)
	order1, scripts1, res1 := runWithWorkers(1)
	peak1 := peakInFlight.Load()

	peakInFlight.Store(0)
	order6, scripts6, res6 := runWithWorkers(6)
	peak6 := peakInFlight.Load()

	if peak1 != 1 {
		t.Fatalf("expected peak in-flight == 1 for PageWorkers=1, got %d", peak1)
	}
	if peak6 < 3 {
		t.Fatalf("expected true single-origin parallel dispatch (>=3 in-flight) for PageWorkers=6, got %d", peak6)
	}
	if !slices.Equal(order1, order6) {
		t.Fatalf("non-deterministic Page commit order:\n  pw=1: %v\n  pw=6: %v", order1, order6)
	}
	if !slices.Equal(scripts1, scripts6) {
		t.Fatalf("script set mismatch:\n  pw=1: %v\n  pw=6: %v", scripts1, scripts6)
	}
	if res1.Visited != res6.Visited || !maps.Equal(res1.Listed, res6.Listed) {
		t.Fatalf("Visited/Listed mismatch: pw=1 (%d/%v) vs pw=6 (%d/%v)", res1.Visited, res1.Listed, res6.Visited, res6.Listed)
	}
}

func TestDocumentEarlyCloseRSSPreservesScriptAndSitemap(t *testing.T) {
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Direct <a href="/hung-rss"> forces a document fetch whose server replies
		// with application/rss+xml and stalls its body stream.
		fmt.Fprint(w, `<!doctype html><html><head><title>Portal</title></head><body>
<a href="/hung-rss">RSS</a>
<script src="/misconfigured-octet.js"></script>
</body></html>`)
	})
	mux.HandleFunc("/hung-rss", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-time.After(4 * time.Second):
		}
	})
	mux.HandleFunc("/misconfigured-octet.js", func(w http.ResponseWriter, r *http.Request) {
		// Misconfigured S3/CDN serving JS with application/octet-stream must still be read in full.
		w.Header().Set("Content-Type", "application/octet-stream")
		fmt.Fprint(w, `fetch("/api/from-octet-js")`)
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Sitemap: %s/sitemap.xml\n", srvURL)
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>%s/from-sitemap</loc></url></urlset>`, srvURL)
	})
	mux.HandleFunc("/from-sitemap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><head><title>Sitemap Page</title></head><body><script>fetch("/api/from-sitemap")</script></body></html>`)
	})

	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)

	u, _ := url.Parse(srv.URL + "/")
	var mu sync.Mutex
	var gotScripts []string
	start := time.Now()
	_, err := Crawl(context.Background(), Options{
		Target:      u,
		InScope:     func(string) bool { return true },
		Depth:       2,
		Rate:        1000,
		Timeout:     5 * time.Second,
		Probe:       true,
		PageWorkers: 4,
		Script: func(s Script) {
			mu.Lock()
			gotScripts = append(gotScripts, string(s.Body))
			mu.Unlock()
		},
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("document early-close did not abort hung application/rss+xml stream promptly: took %v", elapsed)
	}
	joined := strings.Join(gotScripts, "\n")
	if !strings.Contains(joined, "/api/from-octet-js") {
		t.Fatalf("scriptReq with application/octet-stream was truncated or skipped: %v", gotScripts)
	}
	if !strings.Contains(joined, "/api/from-sitemap") {
		t.Fatalf("dataReq sitemap.xml with application/xml was not parsed: %v", gotScripts)
	}
}
