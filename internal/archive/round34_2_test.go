package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

func TestWaybackIndexClientSurvivesMementoPrefetchBlock(t *testing.T) {
	// CDX server serves 3 shards cleanly.
	cdxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("showNumPages") == "true" {
			_, _ = w.Write([]byte("3\n"))
			return
		}
		page := q.Get("page")
		rows := [][]string{
			{"timestamp", "original", "mimetype", "statuscode", "digest"},
			{fmt.Sprintf("2024010%s120000", page), fmt.Sprintf("https://app.example.test/static/chunk-%s.js", page), "application/javascript", "200", fmt.Sprintf("DIGEST0000000000000000000000000%s", page)},
		}
		_ = json.NewEncoder(w).Encode(rows)
	}))
	defer cdxSrv.Close()

	// Memento server returns 429 on every request, tripping wbFilesClient's breaker during prefetch!
	memSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer memSrv.Close()

	services := []string{cdxSrv.URL, memSrv.URL}
	idxClient := NewClientSafe(nil, nil, services)
	idxClient.Tries, idxClient.Wait = 2, time.Millisecond

	filesClient := NewClientSafe(nil, nil, services)
	filesClient.Tries, filesClient.Wait = 1, time.Millisecond

	// Route /cdx/search/cdx to cdxSrv and /web/ to memSrv via a gateway mux, using two distinct Clients!
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cdx/search/cdx" {
			cdxSrv.Config.Handler.ServeHTTP(w, r)
			return
		}
		memSrv.Config.Handler.ServeHTTP(w, r)
	}))
	defer gw.Close()

	idxClient = NewClientSafe(nil, nil, []string{gw.URL})
	idxClient.Tries, idxClient.Wait = 2, time.Millisecond
	filesClient = NewClientSafe(nil, nil, []string{gw.URL})
	filesClient.Tries, filesClient.Wait = 1, time.Millisecond
	// Pre-trip filesClient close to threshold so the very first prefetch 429 latches filesClient.blocked = true!
	for range 4 {
		filesClient.recordConnTrouble()
	}

	root := t.TempDir()
	dir := filepath.Join(root, "app.example.test", "archive")
	sum, err := Run(context.Background(), Options{
		Dir:     dir,
		Root:    root,
		Host:    "app.example.test",
		InScope: func(h string) bool { return h == "app.example.test" },
		Sources: []string{"wayback"},
		Workers: 4,
		Log:     func(string, ...any) {},
		Wayback: &Wayback{
			Base:        gw.URL,
			Client:      filesClient,
			IndexClient: idxClient,
			Index:       &Budget{Gap: time.Millisecond},
			Files:       &Budget{Gap: time.Millisecond},
			Collapse:    "digest",
			Sharded:     true,
		},
	})
	// Fetch phase is expected to return ErrBlocked (since memSrv returns 429),
	// BUT CDX listing MUST have completed 100% (all 3 URLs listed, Listed == true)!
	if sum == nil || sum.Listed["wayback"] != 3 {
		t.Fatalf("expected all 3 sharded CDX captures to be listed despite memento ErrBlocked, got sum=%+v err=%v", sum, err)
	}
	var st state
	b, rerr := os.ReadFile(filepath.Join(dir, "archive.json"))
	if rerr != nil || json.Unmarshal(b, &st) != nil {
		t.Fatalf("failed reading archive.json: %v", rerr)
	}
	if !st.Listed {
		t.Fatalf("expected st.Listed == true (CDX index client isolated from memento block), got false")
	}
}

func TestStreamingClassifyCtxMatchesInCurrentCodeAndDedupsSharedBundles(t *testing.T) {
	role1 := filepath.Join(t.TempDir(), "anon", "js")
	role2 := filepath.Join(t.TempDir(), "user", "js")
	if err := os.MkdirAll(role1, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(role2, 0o700); err != nil {
		t.Fatal(err)
	}
	shaName := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.js"
	liveCode := []byte(`const doc = "deprecated route /api/v1/billing/legacy-export/download";`)
	_ = os.WriteFile(filepath.Join(role1, shaName), liveCode, 0o600)
	_ = os.WriteFile(filepath.Join(role2, shaName), liveCode, 0o600)

	cur := &current{
		catalogs: [][]endpoints.Endpoint{{{Method: "GET", Path: "/api/v2/orders/{}"}}},
		jsDirs:   []string{role1, role2},
	}
	archived := []endpoints.Endpoint{
		{Method: "GET", Path: "/api/v1/billing/legacy-export/download", Confidence: "high"},
		{Method: "GET", Path: "/api/v1/orders/{}", Confidence: "high"},
		{Method: "POST", Path: "/api/v1/internal/debug-wipe", Confidence: "high"},
	}
	lines, inCode, err := classifyCtx(context.Background(), archived, cur, func(string) (store.Entry, bool) {
		return store.Entry{}, false
	})
	if err != nil {
		t.Fatalf("classifyCtx failed: %v", err)
	}
	if inCode != 1 || len(lines) != 3 {
		t.Fatalf("unexpected classifyCtx counts: inCode=%d len=%d lines=%+v", inCode, len(lines), lines)
	}
	got := map[string]string{}
	for _, l := range lines {
		got[l.Path] = l.Class
	}
	if got["/api/v1/billing/legacy-export/download"] != "in_current_code" ||
		got["/api/v1/orders/{}"] != "version_changed" ||
		got["/api/v1/internal/debug-wipe"] != "historical" {
		t.Fatalf("unexpected classes: %+v", got)
	}
}
