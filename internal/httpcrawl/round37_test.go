package httpcrawl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestRound37EarlyWorkerReclaimAvoidsHeadOfLineSerialization(t *testing.T) {
	// win[0] (/slow0) stalls 450ms while /fast1..7 take 15ms each, with PageWorkers=4 (maxWin=8).
	// Before P5a, /fast4..7 could not even start until /slow0 committed at 450ms (~900ms+ total).
	// With P5a early worker reclaim + workerFreed wakeup, /fast1..3 free their worker slots at
	// ~15ms so /fast4..7 complete while /slow0 is still in flight (~480ms total), while commit
	// order remains 100% identical to PageWorkers=1!
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/" {
			var sb strings.Builder
			sb.WriteString(`<!doctype html><html><head><title>Seed</title></head><body><a href="/slow0">0</a>`)
			for i := 1; i <= 7; i++ {
				fmt.Fprintf(&sb, `<a href="/fast%d">%d</a>`, i, i)
			}
			sb.WriteString(`</body></html>`)
			_, _ = w.Write([]byte(sb.String()))
			return
		}
		if r.URL.Path == "/slow0" {
			time.Sleep(450 * time.Millisecond)
		} else if strings.HasPrefix(r.URL.Path, "/fast") {
			time.Sleep(15 * time.Millisecond)
		}
		fmt.Fprintf(w, `<!doctype html><html><head><title>P %s</title></head><body><script>fetch("/api%s")</script></body></html>`, r.URL.Path, r.URL.Path)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	var visited []string
	start := time.Now()
	_, err := Crawl(context.Background(), Options{
		Target:      u,
		InScope:     func(string) bool { return true },
		Depth:       1,
		Rate:        1000,
		PageWorkers: 4,
		NoSpecProbe: true,
		Page: func(p Page) {
			if p.Visited {
				visited = append(visited, strings.TrimPrefix(p.URL, srv.URL))
			}
		},
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/", "/slow0", "/fast1", "/fast2", "/fast3", "/fast4", "/fast5", "/fast6", "/fast7"}
	if strings.Join(visited, ",") != strings.Join(want, ",") {
		t.Fatalf("commit order changed: got %v, want %v", visited, want)
	}
	if elapsed > 750*time.Millisecond {
		t.Fatalf("expected fast4..7 to run behind slow0 without full serialization (<750ms), took %v", elapsed)
	}
}

func TestRound37SourceMapSingleflightDedupAndStrippedFallback(t *testing.T) {
	// Case A: Full sourcesContent map shared by sub1 and sub2 (same script SHA-256).
	// Expect: .map fetched over HTTP only ONCE, yet SourceMap callback invoked for BOTH
	// hosts with their own ScriptURL and extracted OwnFiles!
	// Case B: Stripped map (no sourcesContent) on sub1, full map on sub2.
	// Expect: sub1's stripped map is NOT cached across hosts, so sub2 fetches its own full map!
	var fullMapHits atomic.Int32
	var stripMapHits atomic.Int32

	sharedBundleFull := `console.log("shared-full");` + "\n//# sourceMappingURL=shared-full.js.map"
	sharedBundleStrip := `console.log("shared-strip");` + "\n//# sourceMappingURL=shared-strip.js.map"

	fullMapJSON := `{"version":3,"file":"shared-full.js","sources":["src/api/client.ts"],"sourcesContent":["export const call = () => fetch('/api/v1/from-map');"]}`
	strippedMapJSON := `{"version":3,"file":"shared-strip.js","sources":["src/api/secret.ts"]}`
	stagingFullMapJSON := `{"version":3,"file":"shared-strip.js","sources":["src/api/secret.ts"],"sourcesContent":["export const s = () => fetch('/api/v1/staging-recovered');"]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.Split(r.Host, ":")[0]
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<!doctype html><html><head><title>Root</title></head><body>
				<a href="http://sub1.jsh.test:%s/p">1</a>
				<a href="http://sub2.jsh.test:%s/p">2</a>
			</body></html>`, strings.Split(r.Host, ":")[1], strings.Split(r.Host, ":")[1])
		case "/p":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<!doctype html><html><head><title>%s</title></head><body>
				<script src="/js/shared-full.js"></script>
				<script src="/js/shared-strip.js"></script>
			</body></html>`, host)
		case "/js/shared-full.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(sharedBundleFull))
		case "/js/shared-full.js.map":
			fullMapHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fullMapJSON))
		case "/js/shared-strip.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(sharedBundleStrip))
		case "/js/shared-strip.js.map":
			stripMapHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if strings.HasPrefix(host, "sub1.") {
				_, _ = w.Write([]byte(strippedMapJSON))
			} else {
				_, _ = w.Write([]byte(stagingFullMapJSON))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	u, _ := url.Parse("http://root.jsh.test:" + port + "/")

	var mu sync.Mutex
	ownByScript := map[string][]string{}
	_, err := Crawl(context.Background(), Options{
		Target:       u,
		InScope:      func(h string) bool { return strings.HasSuffix(h, ".jsh.test") },
		HostRules:    "MAP *.jsh.test 127.0.0.1",
		AllowPrivate: true,
		Depth:        1,
		Rate:         1000,
		PageWorkers:  1, // deterministic sub1 then sub2 order
		SourceMaps:   true,
		NoSpecProbe:  true,
		SourceMap: func(m SourceMap) {
			mu.Lock()
			for _, f := range m.OwnFiles {
				ownByScript[m.ScriptURL] = append(ownByScript[m.ScriptURL], f.Path)
			}
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := fullMapHits.Load(); got != 1 {
		t.Fatalf("expected shared-full.js.map to be downloaded only 1 time across 2 subdomains, got %d", got)
	}
	for _, sub := range []string{"sub1", "sub2"} {
		su := fmt.Sprintf("http://%s.jsh.test:%s/js/shared-full.js", sub, port)
		if len(ownByScript[su]) != 1 || ownByScript[su][0] != "src/api/client.ts" {
			t.Fatalf("missing origin attribution for %s: got %v", su, ownByScript[su])
		}
	}
	if got := stripMapHits.Load(); got != 2 {
		t.Fatalf("expected stripped map on sub1 NOT to block sub2 from downloading its full copy: got %d hits, want 2", got)
	}
	sub2Strip := fmt.Sprintf("http://sub2.jsh.test:%s/js/shared-strip.js", port)
	if len(ownByScript[sub2Strip]) != 1 || ownByScript[sub2Strip][0] != "src/api/secret.ts" {
		t.Fatalf("expected staging sub2 full map to recover src/api/secret.ts, got %v", ownByScript[sub2Strip])
	}
}

func TestRound37HostPortDialBreakerFastRefusedTimeoutAndHalfOpen(t *testing.T) {
	var calls atomic.Int32
	now := time.Now()
	var nowMu sync.Mutex
	getNow := func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now }
	advance := func(d time.Duration) { nowMu.Lock(); now = now.Add(d); nowMu.Unlock() }

	healthy := atomic.Bool{}
	b := &hostPortBreaker{
		cooldown: 3 * time.Minute,
		now:      getNow,
		states:   map[string]*endpointDialState{},
		next: func(ctx context.Context, network, addr string) (net.Conn, error) {
			calls.Add(1)
			if healthy.Load() {
				c1, c2 := net.Pipe()
				_ = c2.Close()
				return c1, nil
			}
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		},
	}

	// 2 ECONNREFUSED strikes trip the breaker; 10 subsequent calls fail fast with 0 network dials!
	for range 12 {
		_, err := b.dialContext(context.Background(), "tcp", "dead.example.test:8081")
		if err == nil {
			t.Fatal("expected error on dead port")
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected exactly 2 underlying dial attempts before breaker tripped, got %d", got)
	}

	// Policy errors (ErrPrivate) must never be swallowed or trip the breaker.
	privBreaker := newHostPortBreaker(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("not an OpError")
	})
	for range 5 {
		_, _ = privBreaker(context.Background(), "tcp", "x.example.test:443")
	}

	// After 3m cooldown, half-open trial succeeds and permanently marks host:port ok!
	advance(4 * time.Minute)
	healthy.Store(true)
	conn, err := b.dialContext(context.Background(), "tcp", "dead.example.test:8081")
	if err != nil {
		t.Fatalf("expected half-open recovery to succeed, got %v", err)
	}
	_ = conn.Close()
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 1 half-open probe (total 3 dials), got %d", got)
	}
}
