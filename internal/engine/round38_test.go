package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/browser"
)

// A (round 38): RunHTTP streams newly discovered in-scope subdomains to
// ArchiveStage1Stream while crawling (before depth-2 finishes), closes the
// channel as soon as httpcrawl.Crawl returns, and never hangs or launches Stage 1
// when seedDead occurs.
func TestRound38HTTPStreamsDiscoveredHostsToStage1AndClosesOnSeedDead(t *testing.T) {
	// 1. Dead seed with ArchiveStage1Stream configured: must exit cleanly with no hang.
	deadSrv := httptest.NewServer(http.NotFoundHandler())
	deadURL, _ := url.Parse(deadSrv.URL + "/")
	deadSrv.Close()

	var deadCalled atomic.Bool
	_, _ = RunHTTP(context.Background(), Config{
		Target:     deadURL,
		OutRoot:    t.TempDir(),
		Role:       "anon",
		ScopeMode:  "rdn",
		Depth:      2,
		NavTimeout: 2 * time.Second,
	}, HTTPOptions{
		Rate: 100,
		Archive: func(ctx context.Context) any {
			return map[string]any{"ok": true}
		},
		ArchiveStage1Stream: func(ctx context.Context, extraHosts <-chan string) error {
			deadCalled.Store(true)
			for range extraHosts {
			}
			return nil
		},
	})
	if deadCalled.Load() {
		t.Fatal("ArchiveStage1Stream must not launch when seed fails to connect")
	}

	// 2. Live multi-subdomain crawl via HostRules: sub1.example.com and
	// api.example.com must arrive on extraHosts while depth-2 is still in flight,
	// and extraHosts must close cleanly before Stage 2 Archive runs.
	sub1Arrived := make(chan struct{})
	allowDepth2 := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "example.com" && r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><html><head><title>Root</title></head><body>`+
				`<a href="http://sub1.example.com/portal">Sub1</a>`+
				`<script src="http://cdn.example.com/app.js"></script>`+
				`</body></html>`)
		case r.Host == "cdn.example.com" && r.URL.Path == "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("http://example.com/api/ping");`)
		case r.Host == "sub1.example.com" && r.URL.Path == "/portal":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><html><head><title>Sub1</title></head><body><a href="http://sub1.example.com/deep">Deep</a></body></html>`)
		case r.Host == "sub1.example.com" && r.URL.Path == "/deep":
			<-allowDepth2
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><html><head><title>Deep</title></head><body>ok</body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	targetURL, _ := url.Parse("http://example.com/")

	var mu sync.Mutex
	var streamed []string
	var stage1Closed atomic.Bool
	var stage2SawClosed atomic.Bool

	_, err = RunHTTP(context.Background(), Config{
		Target:     targetURL,
		OutRoot:    t.TempDir(),
		Role:       "anon",
		ScopeMode:  "rdn",
		Depth:      2,
		NavTimeout: 5 * time.Second,
		Browser: browser.Options{
			HostRules: fmt.Sprintf("MAP example.com 127.0.0.1:%s, MAP *.example.com 127.0.0.1:%s", port, port),
		},
	}, HTTPOptions{
		Rate:        200,
		PageWorkers: 4,
		NoSpecProbe: true,
		ArchiveStage1Stream: func(ctx context.Context, extraHosts <-chan string) error {
			unblocked := false
			for h := range extraHosts {
				mu.Lock()
				streamed = append(streamed, h)
				hasSub1 := slices.Contains(streamed, "sub1.example.com")
				mu.Unlock()
				if hasSub1 && !unblocked {
					unblocked = true
					close(sub1Arrived)
					close(allowDepth2)
				}
			}
			stage1Closed.Store(true)
			return nil
		},
		Archive: func(ctx context.Context) any {
			if stage1Closed.Load() {
				stage2SawClosed.Store(true)
			}
			return map[string]any{"ok": true}
		},
	})
	if err != nil {
		t.Fatalf("RunHTTP failed: %v", err)
	}
	select {
	case <-sub1Arrived:
	default:
		t.Fatal("sub1.example.com did not stream to Stage 1 during crawl")
	}
	if !stage2SawClosed.Load() {
		t.Fatal("Stage 2 ran before Stage 1 extraHosts channel closed and joined")
	}
	mu.Lock()
	got := slices.Clone(streamed)
	mu.Unlock()
	slices.Sort(got)
	if !slices.Contains(got, "sub1.example.com") || !slices.Contains(got, "cdn.example.com") {
		t.Fatalf("expected sub1.example.com and cdn.example.com in streamed hosts, got %v", got)
	}
	if slices.Contains(got, "example.com") {
		t.Fatalf("root target host example.com should not be emitted as an extra host: %v", got)
	}
}
