package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestRound37ArchiveStage1OverlapsCrawlAndSkipsDeadSeed(t *testing.T) {
	// 1. Dead seed: ArchiveStage1 must NEVER launch.
	deadSrv := httptest.NewServer(http.NotFoundHandler())
	deadURL, _ := url.Parse(deadSrv.URL + "/")
	deadSrv.Close()

	var deadStage1Called atomic.Bool
	_, _ = RunHTTP(context.Background(), Config{
		Target:     deadURL,
		OutRoot:    t.TempDir(),
		Role:       "anon",
		ScopeMode:  "fqdn",
		Depth:      2,
		NavTimeout: 2 * time.Second,
	}, HTTPOptions{
		Rate: 100,
		Archive: func(ctx context.Context) any {
			return map[string]any{"ok": true}
		},
		ArchiveStage1: func(ctx context.Context) error {
			deadStage1Called.Store(true)
			return nil
		},
	})
	if deadStage1Called.Load() {
		t.Fatal("ArchiveStage1 must not run when seed fails to connect")
	}

	// 2. Live multi-page crawl: ArchiveStage1 must overlap in parallel with deeper page fetches
	// and complete before Stage 2 Archive runs!
	page2Started := make(chan struct{})
	allowPage2Finish := make(chan struct{})
	var stage1RanDuringCrawl atomic.Bool
	var stage2SawStage1Done atomic.Bool
	var stage1Completed atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<!doctype html><html><head><title>Home</title></head><body><a href="/sub">Sub</a><script>fetch("/api/home")</script></body></html>`)
			return
		}
		close(page2Started)
		<-allowPage2Finish
		fmt.Fprint(w, `<!doctype html><html><head><title>Sub</title></head><body><script>fetch("/api/sub")</script></body></html>`)
	}))
	defer srv.Close()
	liveURL, _ := url.Parse(srv.URL + "/")

	rec, err := RunHTTP(context.Background(), Config{
		Target:     liveURL,
		OutRoot:    t.TempDir(),
		Role:       "anon",
		ScopeMode:  "fqdn",
		Depth:      2,
		NavTimeout: 5 * time.Second,
	}, HTTPOptions{
		Rate:        100,
		NoSpecProbe: true,
		ArchiveStage1: func(ctx context.Context) error {
			<-page2Started
			stage1RanDuringCrawl.Store(true)
			close(allowPage2Finish)
			time.Sleep(20 * time.Millisecond)
			stage1Completed.Store(true)
			return nil
		},
		Archive: func(ctx context.Context) any {
			if stage1Completed.Load() {
				stage2SawStage1Done.Store(true)
			}
			return map[string]any{"ok": true}
		},
	})
	if err != nil {
		t.Fatalf("RunHTTP failed: %v (warnings=%v)", err, rec.Warnings)
	}
	if !stage1RanDuringCrawl.Load() {
		t.Fatal("expected ArchiveStage1 to run concurrently while depth-1 pages were in flight")
	}
	if !stage2SawStage1Done.Load() {
		t.Fatal("expected barrier to ensure Stage 1 finished before Stage 2 Archive started")
	}
}
