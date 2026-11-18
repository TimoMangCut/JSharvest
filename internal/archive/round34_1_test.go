package archive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

func TestFamilyDeadAnchorsAndLiveBodyNeverFalselyPruneHistory(t *testing.T) {
	// 16 historical captures of https://portal.example.test/assets/app.<hash>.js
	// on the SAME unhashed path /assets/app.js (or hashed family):
	// - Live server today returns v15 (`console.log("today")`, 0 endpoints).
	// - Anchor 0 returns 200 text/html soft-404 (`notScriptBody`), while `kept` has `live`!
	// - Anchor 15 is liveSame (0 endpoints).
	// - Intermediate anchors hit 404 (notArchived) or soft-404, EXCEPT version 3
	//   which contains `fetch("/api/v1/legacy-2020-hidden")`!
	// Verify that dead/soft-404 anchors NEVER match v15's empty signature or each
	// other to prune version 3!
	liveBody := []byte(`console.log("live-2026-build");`)
	type capItem struct {
		ts     string
		url    string
		body   []byte
		html   bool
		miss   bool
		digest string
	}
	var items []capItem
	byTS := map[string]capItem{}
	for i := 0; i < 16; i++ {
		ts := fmt.Sprintf("202201%02d100000", i+1)
		u := "http://127.0.0.1/assets/app.js" // rewritten below with test server host
		var it capItem
		it.ts = ts
		switch {
		case i == 3:
			it.body = []byte(`fetch("/api/v1/legacy-2020-hidden");`)
			it.digest = store.SHA1B32(it.body)
		case i == 15:
			it.body = liveBody
			it.digest = store.SHA1B32(liveBody)
		case i%2 == 0:
			it.html = true
			it.body = []byte(`<!doctype html><html><head><title>404 Not Found</title></head><body>missing</body></html>`)
			it.digest = fmt.Sprintf("HTMLSOFT404DIGEST%02d", i)
		default:
			it.miss = true
			it.digest = fmt.Sprintf("MISSINGDIGEST000%02d", i)
		}
		_ = u
		items = append(items, it)
		byTS[ts] = it
	}

	var liveSrv *httptest.Server
	liveSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write(liveBody)
	}))
	defer liveSrv.Close()

	targetURL := liveSrv.URL + "/assets/app.js"
	targetHost := strings.TrimPrefix(liveSrv.URL, "http://")
	onlyHost := strings.Split(targetHost, ":")[0]

	wbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cdx/search/cdx":
			rows := [][]string{{"timestamp", "original", "mimetype", "statuscode", "digest"}}
			for _, it := range items {
				rows = append(rows, []string{it.ts, targetURL, "application/javascript", "200", it.digest})
			}
			_ = json.NewEncoder(w).Encode(rows)
		case strings.HasPrefix(r.URL.Path, "/web/"):
			rest := strings.TrimPrefix(r.URL.Path, "/web/")
			idx := strings.Index(rest, "id_/")
			if idx < 0 {
				http.NotFound(w, r)
				return
			}
			ts := rest[:idx]
			it, ok := byTS[ts]
			if !ok || it.miss {
				http.NotFound(w, r)
				return
			}
			if it.html {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write(it.body)
				return
			}
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write(it.body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer wbSrv.Close()

	root := t.TempDir()
	archDir := filepath.Join(root, onlyHost, "archive")
	wbClient := NewClientSafe(nil, nil, []string{wbSrv.URL})
	wbClient.Tries, wbClient.Wait = 1, time.Millisecond

	sender, err := replay.NewSender(replay.SenderOptions{
		Hosts:        map[string]bool{targetHost: true, onlyHost: true},
		AllowPrivate: true,
		Concurrency:  4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	sum, err := Run(context.Background(), Options{
		Dir:       archDir,
		Root:      root,
		Host:      onlyHost,
		InScope:   func(h string) bool { return h == onlyHost },
		Live:      true,
		LiveHosts: map[string]bool{targetHost: true, onlyHost: true},
		Sender:    sender,
		Sources:   []string{"wayback"},
		MaxHTML:   0,
		MaxBody:   2 << 20,
		Workers:   4,
		Wayback: &Wayback{
			Base:     wbSrv.URL,
			Client:   wbClient,
			Index:    &Budget{},
			Files:    &Budget{},
			PageSize: 100,
			Collapse: "digest",
		},
		Log: func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sum.Skipped["family unchanged"] != 0 {
		t.Errorf("dead/soft-404 anchors must NEVER prune interior builds: Skipped=%v", sum.Skipped)
	}
	hist, err := os.ReadFile(filepath.Join(archDir, "historical.jsonl"))
	if err != nil || !strings.Contains(string(hist), "/api/v1/legacy-2020-hidden") {
		t.Fatalf("expected /api/v1/legacy-2020-hidden to be recovered, got err=%v hist=%s", err, string(hist))
	}
}

func TestDRRQueueCompactionNeverSkipsAdjacentBuckets(t *testing.T) {
	q := newDRRQueue()
	mk := func(host, name string) *group {
		u := fmt.Sprintf("https://%s/%s.js", host, name)
		return &group{key: u, latest: Capture{URL: u}}
	}
	// Origin A has 3 single-item families; Origin B has 2 single-item families.
	// Popping drains every bucket on first touch -> must visit all 5 without skipping any!
	want := map[string]bool{}
	for _, g := range []*group{
		mk("a.example.test", "f1"),
		mk("a.example.test", "f2"),
		mk("a.example.test", "f3"),
		mk("b.example.test", "g1"),
		mk("b.example.test", "g2"),
	} {
		want[g.key] = true
		q.push(g)
	}
	got := map[string]bool{}
	for q.len() > 0 {
		g, ok := q.pop()
		if !ok {
			t.Fatalf("pop returned false while q.len()=%d", q.len())
		}
		got[g.key] = true
	}
	if len(got) != len(want) {
		t.Fatalf("popped %d items (%v), want all %d (%v)", len(got), got, len(want), want)
	}
	if len(q.origins) != 0 || len(q.byHost) != 0 {
		t.Errorf("expected empty compacted drrQueue, got origins=%d byHost=%d", len(q.origins), len(q.byHost))
	}
}

func TestMaxHTMLZeroKeepsHTMLPoolEmpty(t *testing.T) {
	r := &runner{o: Options{MaxHTML: 0}}
	r.takeHTMLLocked(Capture{URL: "https://a.example.test/", MIME: "text/html", Status: "200", Time: time.Now()})
	if len(r.htmlPool) != 0 || r.snapshotHTMLTopLocked() != nil {
		t.Errorf("MaxHTML=0 should allocate nothing in htmlPool, got len=%d", len(r.htmlPool))
	}
}

func TestFamilyPreSeededFromCurrentCrawlAndPrefetchZeroRefetch(t *testing.T) {
	root := t.TempDir()
	host := "seed.example.test"
	anonDir := filepath.Join(root, host, "anon")
	archDir := filepath.Join(root, host, "archive")

	// Populate live crawl store (<root>/<host>/anon) with v0 of app.<hash>.js.
	anonStore, err := store.Open(anonDir, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v0Body := []byte(`fetch("/api/v2/profile"); console.log("build-0");`)
	v0URL := "https://seed.example.test/assets/app.build0000aaaa.js"
	if _, err := anonStore.Add(store.Record{Body: v0Body, URL: v0URL, Kind: "file", Via: "http", Source: "crawl"}); err != nil {
		t.Fatal(err)
	}
	if err := anonStore.Flush(); err != nil {
		t.Fatal(err)
	}

	// Build 12 chronological versions all having the EXACT SAME SemanticAPISig (/api/v2/profile).
	// Pre-populate v11 in archive store as "pre:" + digest so both endpoints [0, 11] are pre-seeded!
	archStore, err := store.Open(archDir, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v11Body := []byte(`fetch("/api/v2/profile"); console.log("build-11");`)
	v11Digest := store.SHA1B32(v11Body)
	v11URL := "https://seed.example.test/assets/app.build0011zzzz.js"
	if _, err := archStore.Add(store.Record{Body: v11Body, URL: v11URL, Kind: "file", Via: "archive", Source: "wayback"}); err != nil {
		t.Fatal(err)
	}

	cur := loadCurrent(root, func(h string) bool { return h == host })
	v0Digest := store.SHA1B32(v0Body)
	if _, ok := cur.bySHA1[v0Digest]; !ok {
		t.Fatalf("expected loadCurrent to map SHA1B32 -> curScript, got %+v", cur.bySHA1)
	}

	r := &runner{
		o:     Options{Dir: archDir, Root: root, Host: host, InScope: func(h string) bool { return h == host }},
		store: archStore,
		cur:   cur,
		done:  map[string]bool{"pre:" + v11Digest: true},
	}
	r.st.Summary.Skipped = map[string]int{}

	var gs []*group
	baseT := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 12; i++ {
		var u, dg string
		switch i {
		case 0:
			u, dg = v0URL, v0Digest
		case 11:
			u, dg = v11URL, v11Digest
		default:
			b := []byte(fmt.Sprintf(`fetch("/api/v2/profile"); console.log("build-%d");`, i))
			dg = store.SHA1B32(b)
			u = fmt.Sprintf("https://seed.example.test/assets/app.build%04dxxxx.js", i)
		}
		tm := baseT.Add(time.Duration(i) * 24 * time.Hour)
		gs = append(gs, &group{
			key:      dg,
			digest:   dg,
			latest:   Capture{URL: u, Source: "wayback", MIME: "application/javascript", Status: "200", Digest: dg, Time: tm},
			urls:     []string{u},
			sources:  []string{"wayback"},
			first:    tm,
			last:     tm,
			captures: 1,
		})
	}

	initial, _ := newFamilyController(r, gs)
	_ = archStore.Flush()
	// Anchors 0 and 11 were pre-seeded without network I/O; neither 0 nor 11 may appear in initial!
	for _, g := range initial {
		if g.digest == v0Digest || g.digest == v11Digest {
			t.Errorf("pre-seeded anchor %s must not be re-scheduled for network fetch", g.digest)
		}
	}
	if r.st.Summary.Known != 1 {
		t.Errorf("expected Known=1 from live crawl pre-seed, got %d", r.st.Summary.Known)
	}
}

func TestClientLeakyBucketBreakerLatchesDespiteInterleaved200And429(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	var okHits atomic.Int32
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if okHits.Add(1) == 1 {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer okSrv.Close()

	c := NewClientSafe(nil, nil, []string{deadURL, okSrv.URL})
	c.Wait, c.Tries = time.Millisecond, 3

	// 2 failed calls x 3 tries = 6 ECONNREFUSED? Wait: first do 2 tries (refused = 4),
	// then a 429 + 200 (429 does not decay; 200 decays 4 -> 3 instead of resetting to 0!),
	// then 4 more ECONNREFUSED tries (3 + 8 = 11 >= 10) -> ErrBlocked latched!
	c.Tries = 2
	_, _ = c.Get(context.Background(), &Budget{}, deadURL, 100) // refused = 4
	if _, err := c.Get(context.Background(), &Budget{}, okSrv.URL, 100); err != nil {
		t.Fatalf("okSrv: %v", err)
	}
	c.mu.Lock()
	refAfterOK := c.refused
	c.mu.Unlock()
	if refAfterOK != 3 {
		t.Fatalf("expected leaky-bucket decay from 4 -> 3 (not reset to 0), got %d", refAfterOK)
	}

	c.Tries = 4
	if _, err := c.Get(context.Background(), &Budget{}, deadURL, 100); !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got %v", err)
	}
	// Once latched, even healthy URLs on that client immediately return ErrBlocked.
	if _, err := c.Get(context.Background(), &Budget{}, okSrv.URL, 100); !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected latched ErrBlocked, got %v", err)
	}
}
