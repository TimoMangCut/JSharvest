package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

func TestRound33ShardedWaybackConcurrentFetchAndSingleflightLiveCheck(t *testing.T) {
	var liveHits atomic.Int32
	liveSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/static/shared.js":
			liveHits.Add(1)
			time.Sleep(25 * time.Millisecond) // hold in-flight so concurrent workers overlap
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`fetch("/api/v2/live-shared");`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer liveSrv.Close()
	liveHost := strings.TrimPrefix(liveSrv.URL, "http://")

	var cdxActive, cdxPeak atomic.Int32
	var collapseSeen atomic.Bool
	var shardMu sync.Mutex
	shardsFetched := map[int]int{}

	bodies := map[string]string{
		"20230101000000": `import("./chunk-a.js"); fetch("/api/v1/old-a");`,
		"20230201000000": `import("./chunk-b.js"); fetch("/api/v1/old-b");`,
		"20230301000000": `fetch("/api/v1/old-c");`,
		"20230401000000": `fetch("/api/v1/old-d");`,
	}
	chunks := map[string]string{
		"chunk-a.js": `fetch("/api/v1/from-chunk-a");`,
		"chunk-b.js": `fetch("/api/v1/from-chunk-b");`,
	}

	wbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cdx/search/cdx":
			q := r.URL.Query()
			if q.Get("collapse") == "digest" {
				collapseSeen.Store(true)
			}
			if q.Get("showNumPages") == "true" {
				fmt.Fprintln(w, "4")
				return
			}
			p, err := strconv.Atoi(q.Get("page"))
			if err != nil || p < 0 || p >= 4 {
				http.Error(w, "bad page", http.StatusBadRequest)
				return
			}
			cur := cdxActive.Add(1)
			for {
				old := cdxPeak.Load()
				if cur <= old || cdxPeak.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			cdxActive.Add(-1)

			shardMu.Lock()
			shardsFetched[p]++
			shardMu.Unlock()

			ts := fmt.Sprintf("20230%d01000000", p+1)
			body := bodies[ts]
			dig := store.SHA1B32([]byte(body))
			// All 4 shards reference the same URL http://<liveHost>/static/shared.js
			// with distinct historical digests so 4 workers race on liveCheckAs!
			rows := [][]string{
				{"timestamp", "original", "mimetype", "statuscode", "digest"},
				{ts, "http://" + liveHost + "/static/shared.js", "application/javascript", "200", dig},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(rows)

		case strings.HasPrefix(r.RequestURI, "/web/"):
			rest := strings.TrimPrefix(r.RequestURI, "/web/")
			ts, target, ok := strings.Cut(rest, "id_/")
			if !ok {
				http.NotFound(w, r)
				return
			}
			time.Sleep(10 * time.Millisecond)
			for name, code := range chunks {
				if strings.HasSuffix(target, "/"+name) {
					w.Header().Set("Content-Type", "application/javascript")
					w.Write([]byte(code))
					return
				}
			}
			if code, ok := bodies[ts]; ok {
				w.Header().Set("Content-Type", "application/javascript")
				w.Write([]byte(code))
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer wbSrv.Close()

	var otxHostsMu sync.Mutex
	otxHosts := map[string]bool{}
	otxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 5 {
			otxHostsMu.Lock()
			otxHosts[parts[4]] = true
			otxHostsMu.Unlock()
		}
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"url_list":[],"has_next":false}`))
	}))
	defer otxSrv.Close()

	root := t.TempDir()
	archDir := filepath.Join(root, "example.test", "archive")

	sender, err := replay.NewSender(replay.SenderOptions{
		AllowPrivate: true,
		Concurrency:  8,
		Hosts:        map[string]bool{liveHost: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	cl := NewClientSafe(nil, nil, []string{wbSrv.URL, otxSrv.URL})
	cl.Wait = time.Millisecond

	extra := []string{"s1.example.test", "s2.example.test", "s3.example.test", "s4.example.test", "s5.example.test", "s6.example.test"}
	sum, err := Run(context.Background(), Options{
		Dir:        archDir,
		Root:       root,
		Host:       "example.test",
		InScope:    func(h string) bool { return h == "127.0.0.1" || h == "example.test" || strings.HasSuffix(h, ".example.test") },
		Sources:    []string{"wayback", "otx"},
		ExtraHosts: extra,
		Live:       true,
		LiveHosts:  map[string]bool{liveHost: true},
		Sender:     sender,
		MaxBody:    1 << 20,
		Workers:    8,
		Wayback: &Wayback{
			Base:     wbSrv.URL,
			Client:   cl,
			Index:    &Budget{},
			Files:    &Budget{},
			Collapse: "digest",
			Sharded:  true,
		},
		OTX: &OTX{
			Base:   otxSrv.URL,
			Client: cl,
			Budget: &Budget{},
		},
		Log: func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if !collapseSeen.Load() {
		t.Errorf("expected collapse=digest to be sent on sharded CDX requests")
	}
	if cdxPeak.Load() < 2 {
		t.Errorf("expected concurrent CDX shard workers (peak=%d)", cdxPeak.Load())
	}
	shardMu.Lock()
	if len(shardsFetched) != 4 {
		t.Errorf("expected all 4 shards fetched once, got %v", shardsFetched)
	}
	shardMu.Unlock()

	otxHostsMu.Lock()
	for _, eh := range extra {
		if !otxHosts[eh] {
			t.Errorf("extra host %s was not queried on OTX", eh)
		}
	}
	otxHostsMu.Unlock()

	if got := liveHits.Load(); got != 1 {
		t.Errorf("singleflight live-check violated: /static/shared.js hit %d times, want 1", got)
	}
	// 4 archived versions + 2 dynamically resolved chunks = 6 fetched from Wayback.
	if sum.Fetched != 6 || sum.Resolved != 2 {
		t.Errorf("expected Fetched=6, Resolved=2, got Fetched=%d, Resolved=%d", sum.Fetched, sum.Resolved)
	}
}
