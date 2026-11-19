package archive

import (
	"bytes"
	"compress/gzip"
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

func TestRound37CoprimeStridePermutationAndProgressPct(t *testing.T) {
	for _, n := range []int{1, 2, 3, 8, 15, 100, 128, 1314} {
		order := coprimeStrideOrder(n)
		if len(order) != n {
			t.Fatalf("n=%d: len(order)=%d", n, len(order))
		}
		if order[0] != 0 {
			t.Fatalf("n=%d: expected order[0]=0, got %d", n, order[0])
		}
		seen := make([]bool, n)
		for _, p := range order {
			if p < 0 || p >= n || seen[p] {
				t.Fatalf("n=%d: invalid or duplicate shard %d in %v", n, p, order[:min(len(order), 20)])
			}
			seen[p] = true
		}
	}

	// Verify 150 shards out of 1314 span low, middle, and high SURT quarters.
	s1314 := coprimeStrideOrder(1314)[:150]
	var q [4]int
	for _, p := range s1314 {
		q[(p*4)/1314]++
	}
	for qi, cnt := range q {
		if cnt < 25 {
			t.Fatalf("expected uniform quarter dispersion across 1314 shards, got quarter %d = %d (%v)", qi, cnt, q)
		}
	}
}

func TestRound37AIMDBudgetSharedCooldownAndThrottleHook(t *testing.T) {
	var throttled atomic.Bool
	b := &Budget{
		Gap:        10 * time.Millisecond,
		MaxGap:     80 * time.Millisecond,
		OnThrottle: func() { throttled.Store(true) },
	}
	b.noteThrottle(40 * time.Millisecond)
	if !throttled.Load() {
		t.Fatal("expected OnThrottle callback to fire")
	}
	if b.curGap != 20*time.Millisecond {
		t.Fatalf("expected curGap doubled to 20ms, got %v", b.curGap)
	}
	start := time.Now()
	if err := b.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Fatalf("expected shared cooldown wait >=30ms, got %v", elapsed)
	}
	for range 16 {
		b.noteSuccess()
	}
	if b.curGap != b.Gap {
		t.Fatalf("expected AIMD additive recovery back to base Gap %v, got %v", b.Gap, b.curGap)
	}
}

func TestRound37BlockedWaybackPreservesOTXLiveAndCommonCrawlWARCFallback(t *testing.T) {
	// Live target still serves OTX-discovered script (/assets/otx-live.js).
	liveJS := []byte(`fetch("/api/v1/otx-still-alive");`)
	liveSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/assets/otx-live.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write(liveJS)
			return
		}
		http.NotFound(w, r)
	}))
	defer liveSrv.Close()
	targetHost := strings.TrimPrefix(liveSrv.URL, "http://")
	onlyHost := strings.Split(targetHost, ":")[0]

	// Wayback CDX serves 1 page (HTML capture + WB-only JS capture) on run 1,
	// while Wayback Memento refuses connections (tripping ErrBlocked in pages() & fetchOne()!).
	wbOnlyJS := []byte(`fetch("/api/v1/wb-resumed-later");`)
	wbOnlyDigest := store.SHA1B32(wbOnlyJS)
	wbAllowMemento := atomic.Bool{}

	wbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cdx/search/cdx" {
			if r.URL.Query().Get("showNumPages") == "true" {
				_, _ = w.Write([]byte("4\n"))
				return
			}
			p := r.URL.Query().Get("page")
			rows := [][]string{{"timestamp", "original", "mimetype", "statuscode", "digest"}}
			if p == "0" {
				rows = append(rows,
					[]string{"20230501120000", liveSrv.URL + "/old-index.html", "text/html", "200", "HTMLDIGEST0000000000000000000001"},
					[]string{"20230501120000", liveSrv.URL + "/assets/wb-only.js", "application/javascript", "200", wbOnlyDigest},
				)
			}
			_ = json.NewEncoder(w).Encode(rows)
			return
		}
		if !wbAllowMemento.Load() {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/old-index.html") {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write(wbOnlyJS)
	}))
	defer wbSrv.Close()

	// Common Crawl serves a WARC-backed JS capture (/assets/cc-warc.js) that must
	// be fetched via WARC fallback EVEN WHILE Wayback Memento returns ErrBlocked!
	ccJS := []byte(`fetch("/api/v1/cc-warc-recovered");`)
	ccDigest := store.SHA1B32(ccJS)
	httpPart := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: %d\r\n\r\n%s", len(ccJS), ccJS)
	rawRec := fmt.Sprintf("WARC/1.0\r\nWARC-Type: response\r\nWARC-Target-URI: %s/assets/cc-warc.js\r\nContent-Length: %d\r\n\r\n%s\r\n\r\n", liveSrv.URL, len(httpPart), httpPart)
	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	_, _ = zw.Write([]byte(rawRec))
	_ = zw.Close()
	warcBytes := gzBuf.Bytes()

	ccSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/collinfo.json":
			_, _ = w.Write([]byte(`[{"id":"CC-MAIN-2026-43"}]`))
		case strings.HasSuffix(r.URL.Path, "-index"):
			line := fmt.Sprintf(`{"timestamp":"20230601000000","url":"%s/assets/cc-warc.js","mime":"application/javascript","status":"200","digest":"%s","filename":"crawl-data/test.warc.gz","offset":"0","length":"%d"}`+"\n",
				liveSrv.URL, ccDigest, len(warcBytes))
			_, _ = w.Write([]byte(line))
		case r.URL.Path == "/crawl-data/test.warc.gz":
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(warcBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ccSrv.Close()

	otxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := fmt.Sprintf(`{"url_list":[{"url":"%s/assets/otx-live.js","date":"2024-01-01T00:00:00"}],"has_next":false}`, liveSrv.URL)
		_, _ = w.Write([]byte(resp))
	}))
	defer otxSrv.Close()

	services := []string{wbSrv.URL, ccSrv.URL, otxSrv.URL}
	mkClients := func(blockFiles bool) (*Client, *Client, *Client, *Client) {
		wbIdx := NewClientSafe(nil, nil, services)
		wbIdx.Tries, wbIdx.Wait = 2, time.Millisecond
		wbFiles := NewClientSafe(nil, nil, services)
		wbFiles.Tries, wbFiles.Wait = 1, time.Millisecond
		if blockFiles {
			for range 5 {
				wbFiles.recordConnTrouble()
			}
		}
		ccCl := NewClientSafe(nil, nil, services)
		ccCl.Tries, ccCl.Wait = 2, time.Millisecond
		otxCl := NewClientSafe(nil, nil, services)
		otxCl.Tries, otxCl.Wait = 2, time.Millisecond
		return wbIdx, wbFiles, ccCl, otxCl
	}

	root := t.TempDir()
	archDir := filepath.Join(root, onlyHost, "archive")
	sender, err := replay.NewSender(replay.SenderOptions{
		Hosts:        map[string]bool{targetHost: true, onlyHost: true},
		AllowPrivate: true,
		Concurrency:  2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	// Run 1: MaxPages=2 (50% of 4 shards), Wayback Memento is blocked!
	// Expect:
	// - errors.Is(err, ErrBlocked) == true (exit code 3 preserved)
	// - WaybackListedPct == 50.0 (2 of 4 shards)
	// - OTX live script AND Common Crawl WARC script ARE recovered and written to historical.jsonl!
	// - wb-only.js is NOT marked done so Run 2 (when Memento unblocks) fetches it!
	wbIdx, wbFiles, ccCl, otxCl := mkClients(true)
	sum1, err1 := Run(context.Background(), Options{
		Dir:       archDir,
		Root:      root,
		Host:      onlyHost,
		InScope:   func(h string) bool { return h == onlyHost },
		Sources:   []string{"wayback", "otx", "commoncrawl"},
		Live:      true,
		LiveHosts: map[string]bool{targetHost: true, onlyHost: true},
		Sender:    sender,
		MaxPages:  2,
		MaxHTML:   2,
		MaxBody:   2 << 20,
		Workers:   2,
		Wayback:   &Wayback{Base: wbSrv.URL, Client: wbFiles, IndexClient: wbIdx, Index: &Budget{}, Files: &Budget{}, Collapse: "digest", Sharded: true},
		CC:        &CommonCrawl{Index: ccSrv.URL, Data: ccSrv.URL, Client: ccCl, Budget: &Budget{}, Files: &Budget{}, Collections: 1},
		OTX:       &OTX{Base: otxSrv.URL, Client: otxCl, Budget: &Budget{}},
		Log:       func(string, ...any) {},
	})
	if !errors.Is(err1, ErrBlocked) {
		t.Fatalf("Run 1 expected ErrBlocked preserved for CLI contract, got %v", err1)
	}
	if sum1.WaybackShardsDone != 2 || sum1.WaybackShardsTotal != 4 || sum1.WaybackListedPct != 50.0 {
		t.Fatalf("unexpected shard progress: done=%d total=%d pct=%.1f", sum1.WaybackShardsDone, sum1.WaybackShardsTotal, sum1.WaybackListedPct)
	}
	hist1, herr := os.ReadFile(filepath.Join(archDir, "historical.jsonl"))
	if herr != nil {
		t.Fatalf("expected historical.jsonl to be written on partial/blocked run: %v", herr)
	}
	if !strings.Contains(string(hist1), "/api/v1/cc-warc-recovered") || !strings.Contains(string(hist1), "/api/v1/otx-still-alive") {
		t.Fatalf("expected both CC WARC and OTX live endpoints in historical.jsonl despite Wayback Memento block, got:\n%s", string(hist1))
	}

	// Run 2: Wayback Memento unblocks and MaxPages=0 finishes remaining 2 shards + fetches wb-only.js!
	wbAllowMemento.Store(true)
	wbIdx2, wbFiles2, ccCl2, otxCl2 := mkClients(false)
	sum2, err2 := Run(context.Background(), Options{
		Dir:       archDir,
		Root:      root,
		Host:      onlyHost,
		InScope:   func(h string) bool { return h == onlyHost },
		Sources:   []string{"wayback", "otx", "commoncrawl"},
		Live:      true,
		LiveHosts: map[string]bool{targetHost: true, onlyHost: true},
		Sender:    sender,
		MaxPages:  0,
		MaxHTML:   2,
		MaxBody:   2 << 20,
		Workers:   2,
		Wayback:   &Wayback{Base: wbSrv.URL, Client: wbFiles2, IndexClient: wbIdx2, Index: &Budget{}, Files: &Budget{}, Collapse: "digest", Sharded: true},
		CC:        &CommonCrawl{Index: ccSrv.URL, Data: ccSrv.URL, Client: ccCl2, Budget: &Budget{}, Files: &Budget{}, Collections: 1},
		OTX:       &OTX{Base: otxSrv.URL, Client: otxCl2, Budget: &Budget{}},
		Log:       func(string, ...any) {},
	})
	if err2 != nil {
		t.Fatalf("Run 2 expected clean completion, got %v", err2)
	}
	if sum2.WaybackListedPct != 100.0 {
		t.Fatalf("expected 100%% shard completion on Run 2, got %.1f%%", sum2.WaybackListedPct)
	}
	hist2, err := os.ReadFile(filepath.Join(archDir, "historical.jsonl"))
	if err != nil || !strings.Contains(string(hist2), "/api/v1/wb-resumed-later") {
		t.Fatalf("expected /api/v1/wb-resumed-later recovered on Run 2, got err=%v hist:\n%s", err, string(hist2))
	}
}

func TestRound37TwoStageOverlappedListingZeroTargetHitsAndDeltaExtraHosts(t *testing.T) {
	var wbCDXHits atomic.Int32
	var wbMementoHits atomic.Int32
	var targetHits atomic.Int32
	var otxSubHits atomic.Int32

	liveBundle := []byte(`fetch("/api/v2/live-already-crawled");`)
	liveDigest := store.SHA1B32(liveBundle)
	oldBundle := []byte(`fetch("/api/v1/legacy-from-stage1");`)
	oldDigest := store.SHA1B32(oldBundle)
	subBundle := []byte(`fetch("/api/v1/sub-extra-otx");`)

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if r.URL.Path == "/sub.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write(subBundle)
			return
		}
		http.NotFound(w, r)
	}))
	defer targetSrv.Close()
	targetHost := strings.TrimPrefix(targetSrv.URL, "http://")
	_, port := strings.Split(targetHost, ":")[0], strings.Split(targetHost, ":")[1]
	_ = port

	wbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cdx/search/cdx" {
			wbCDXHits.Add(1)
			if r.URL.Query().Get("showNumPages") == "true" {
				_, _ = w.Write([]byte("4\n"))
				return
			}
			rows := [][]string{{"timestamp", "original", "mimetype", "statuscode", "digest"}}
			if r.URL.Query().Get("page") == "0" {
				rows = append(rows,
					[]string{"20250101000000", "http://app.jsh.test:" + port + "/live.js", "application/javascript", "200", liveDigest},
					[]string{"20220101000000", "http://app.jsh.test:" + port + "/old.js", "application/javascript", "200", oldDigest},
				)
			}
			_ = json.NewEncoder(w).Encode(rows)
			return
		}
		wbMementoHits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write(oldBundle)
	}))
	defer wbSrv.Close()

	otxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "sub.jsh.test") {
			otxSubHits.Add(1)
			fmt.Fprintf(w, `{"url_list":[{"url":"http://sub.jsh.test:%s/sub.js","date":"2024-01-01T00:00:00"}],"has_next":false}`, port)
			return
		}
		_, _ = w.Write([]byte(`{"url_list":[],"has_next":false}`))
	}))
	defer otxSrv.Close()

	services := []string{wbSrv.URL, otxSrv.URL}
	mkWB := func() *Wayback {
		idx := NewClientSafe(nil, nil, services)
		idx.Tries, idx.Wait = 2, time.Millisecond
		fl := NewClientSafe(nil, nil, services)
		fl.Tries, fl.Wait = 2, time.Millisecond
		return &Wayback{Base: wbSrv.URL, Client: fl, IndexClient: idx, Index: &Budget{}, Files: &Budget{}, Collapse: "digest", Sharded: true}
	}
	mkOTX := func() *OTX {
		cl := NewClientSafe(nil, nil, services)
		cl.Tries, cl.Wait = 2, time.Millisecond
		return &OTX{Base: otxSrv.URL, Client: cl, Budget: &Budget{}}
	}

	root := t.TempDir()
	archDir := filepath.Join(root, "app.jsh.test", "archive")
	inScope := func(h string) bool { return h == "app.jsh.test" || strings.HasSuffix(h, ".jsh.test") }

	// Stage 1 (ModeListOnly, MaxPages=2 of 4 shards) runs BEFORE live crawl finishes!
	_, err := Run(context.Background(), Options{
		Dir:      archDir,
		Root:     root,
		Host:     "app.jsh.test",
		InScope:  inScope,
		Sources:  []string{"wayback", "otx"},
		MaxPages: 2,
		Mode:     ModeListOnly,
		Wayback:  mkWB(),
		OTX:      mkOTX(),
		Log:      func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("Stage 1 failed: %v", err)
	}
	if wbMementoHits.Load() != 0 || targetHits.Load() != 0 || otxSubHits.Load() != 0 {
		t.Fatalf("Stage 1 must send 0 memento/target/extra requests: memento=%d target=%d otxSub=%d",
			wbMementoHits.Load(), targetHits.Load(), otxSubHits.Load())
	}
	cdxAfterStage1 := wbCDXHits.Load() // 1 showNumPages + 2 shards = 3

	// Simulate live crawl finishing and storing liveBundle + discovering sub.jsh.test!
	anonDir := filepath.Join(root, "app.jsh.test_"+port, "anon")
	st, err := store.Open(anonDir, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = st.Add(store.Record{Body: liveBundle, URL: "http://app.jsh.test:" + port + "/live.js", Kind: "file", Via: "http", Source: "live"})
	_ = st.Flush()

	// Stage 2 (ModeResume) runs with ExtraHosts=["sub.jsh.test"]:
	// - Must send 0 additional Wayback CDX shard requests in this crawl!
	// - Must skip liveBundle via cur.sha1 (Known == 1, only 1 memento hit for oldBundle)!
	// - Must query delta ExtraHosts ("sub.jsh.test") on OTX!
	// - Must leave archive.json Listed == false because only 2/4 Wayback shards were listed!
	sum2, err := Run(context.Background(), Options{
		Dir:        archDir,
		Root:       root,
		Host:       "app.jsh.test",
		InScope:    inScope,
		Sources:    []string{"wayback", "otx"},
		ExtraHosts: []string{"sub.jsh.test"},
		Live:       false,
		MaxPages:   2,
		Mode:       ModeResume,
		MaxBody:    2 << 20,
		Wayback:    mkWB(),
		OTX:        mkOTX(),
		Log:        func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("Stage 2 failed: %v", err)
	}
	if wbCDXHits.Load() != cdxAfterStage1 {
		t.Fatalf("Stage 2 must not run a second Wayback shard batch in the same crawl: got %d CDX hits, want %d", wbCDXHits.Load(), cdxAfterStage1)
	}
	if otxSubHits.Load() != 1 {
		t.Fatalf("expected Stage 2 to query newly discovered ExtraHosts on OTX once, got %d", otxSubHits.Load())
	}
	if sum2.Known != 1 || wbMementoHits.Load() != 2 {
		// 1 memento for old.js + 1 memento probe for OTX sub.js (since Live=false); live.js skipped via Known=1!
		t.Fatalf("expected live.js skipped via cur.sha1 (Known=1), got Known=%d mementoHits=%d", sum2.Known, wbMementoHits.Load())
	}
	var saved state
	b, _ := os.ReadFile(filepath.Join(archDir, "archive.json"))
	_ = json.Unmarshal(b, &saved)
	if saved.Listed {
		t.Fatal("expected saved.Listed == false when 2/4 Wayback shards remain for future runs")
	}
}

