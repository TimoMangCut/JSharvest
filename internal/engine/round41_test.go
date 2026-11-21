package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"

	"github.com/TimoMangCut/JSharvest/internal/session"
)

func TestRound41ReloginFailureKeepsSnapshotAndStorage(t *testing.T) {
	dir := t.TempDir()
	k := testKeeper(dir)
	if err := k.login.Snapshot.Save(dir); err != nil {
		t.Fatal(err)
	}
	diskBefore, err := os.ReadFile(filepath.Join(dir, session.File))
	if err != nil {
		t.Fatal(err)
	}
	prevSnap := k.login.Snapshot
	k.dirty = true

	// Build a candidate snapshot with new storage on the same origin: must not
	// overwrite prevSnap.Storage via shallow map aliasing.
	cand := k.buildReloginSnapshot(
		prevSnap.Cookies,
		[]*network.Cookie{ck("app.test", "sid", "bad-login")},
		&originStorage{origin: "http://app.test", Storage: session.Storage{Local: map[string]string{"rt": "corrupted-login-page"}}},
	)
	if got := prevSnap.Storage["http://app.test"].Local["rt"]; got != "old" {
		t.Fatalf("buildReloginSnapshot mutated prevSnap.Storage in place: got %q, want \"old\"", got)
	}

	// 1. Verify fails: disk bytes, in-memory snapshot, and dirty flag must stay untouched.
	var sawDuringVerify string
	k.mu.Lock()
	ok, why := k.finishRelogin(cand, func() (bool, string) {
		sawDuringVerify = k.snapCopy().Cookies[0].Value
		return false, "check URL returned 401"
	})
	k.mu.Unlock()
	if ok || why == "" {
		t.Fatalf("expected finishRelogin failure, got ok=%v why=%q", ok, why)
	}
	if sawDuringVerify != "bad-login" {
		t.Fatalf("verify did not see candidate snapshot: saw %q", sawDuringVerify)
	}
	diskAfterFail, err := os.ReadFile(filepath.Join(dir, session.File))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(diskBefore, diskAfterFail) {
		t.Fatalf("failed relogin modified %s on disk", session.File)
	}
	if k.login.Snapshot != prevSnap || !k.dirty || k.stats.Saved {
		t.Fatalf("failed relogin did not restore state: snapSame=%v dirty=%v saved=%v",
			k.login.Snapshot == prevSnap, k.dirty, k.stats.Saved)
	}
	if got := k.snapCopy().Storage["http://app.test"].Local["rt"]; got != "old" {
		t.Fatalf("restored snapshot storage=%q, want \"old\"", got)
	}

	// 2. Verify succeeds: new snapshot is persisted to disk and dirty cleared.
	good := k.buildReloginSnapshot(
		prevSnap.Cookies,
		[]*network.Cookie{ck("app.test", "sid", "verified-good")},
		&originStorage{origin: "http://app.test", Storage: session.Storage{Local: map[string]string{"rt": "verified-rt"}}},
	)
	k.mu.Lock()
	ok, why = k.finishRelogin(good, func() (bool, string) { return true, "" })
	k.mu.Unlock()
	if !ok || why != "" {
		t.Fatalf("expected finishRelogin success, got ok=%v why=%q", ok, why)
	}
	loaded, err := session.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Cookies[0].Value != "verified-good" || loaded.Storage["http://app.test"].Local["rt"] != "verified-rt" {
		t.Fatalf("persisted snapshot mismatch: %+v", loaded)
	}
	if k.dirty || !k.stats.Saved {
		t.Fatalf("expected dirty=false saved=true, got dirty=%v saved=%v", k.dirty, k.stats.Saved)
	}
}

func TestRound41GuardAndSessionLogsMaskTokens(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	dir := t.TempDir()
	k := testKeeper(dir)
	tabCtx, cancel := context.WithCancel(context.Background())
	cancel()
	e := &engine{tab: tabCtx, lane: 1}

	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	pageURL := "https://alice:topSecret@app.test/callback?code=oauth_code_xyz&id_token_hint=" + jwt + "&next=/dashboard#access_token=" + jwt
	_ = k.recover(tabCtx, e, 0, "redirect to login", pageURL)

	logs := buf.String()
	for _, secret := range []string{"topSecret", "alice:", "oauth_code_xyz", "eyJhbGci"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("session slog leaked %q:\n%s", secret, logs)
		}
	}
	if !strings.Contains(logs, "session lost; restoring it") || !strings.Contains(logs, "next=/dashboard") {
		t.Fatalf("unexpected session log output:\n%s", logs)
	}
}

func TestRound41RunSourceCapNoSightingMissing(t *testing.T) {
	const bundle = "fetch('/api/shared');\n//# sourceMappingURL=app.js.map\n"
	srcs := make([]string, 10)
	contents := make([]string, 10)
	for i := range 10 {
		srcs[i] = fmt.Sprintf("src/m_%d.ts", i)
		contents[i] = fmt.Sprintf("export const f%d = () => fetch('/api/m/%d');", i, i)
	}
	mapBytes, err := json.Marshal(map[string]any{
		"version":        3,
		"file":           "app.js",
		"sources":        srcs,
		"sourcesContent": contents,
		"mappings":       "AAAA",
	})
	if err != nil {
		t.Fatal(err)
	}

	var mapHits atomic.Int64
	var hosts []*httptest.Server
	for range 4 {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/app.js":
				w.Header().Set("Content-Type", "application/javascript")
				_, _ = w.Write([]byte(bundle))
			case "/app.js.map":
				mapHits.Add(1)
				time.Sleep(25 * time.Millisecond)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(mapBytes)
			default:
				w.Header().Set("Content-Type", "text/html")
				_, _ = fmt.Fprint(w, `<!doctype html><title>p</title><script src="/app.js"></script>`)
			}
		}))
		defer srv.Close()
		hosts = append(hosts, srv)
	}
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString("<!doctype html><title>seed</title>")
		for _, h := range hosts {
			fmt.Fprintf(&b, `<a href="%s/">h</a>`, h.URL)
		}
		_, _ = w.Write([]byte(b.String()))
	}))
	defer seed.Close()

	target, _ := url.Parse(seed.URL + "/")
	out := t.TempDir()
	rec, err := RunHTTP(context.Background(),
		Config{
			Target:         target,
			OutRoot:        out,
			Role:           "anon",
			ScopeMode:      "fqdn",
			Depth:          1,
			NavTimeout:     5 * time.Second,
			MaxSourceFiles: 3,
		},
		HTTPOptions{Rate: 500, PageWorkers: 4, NoSpecProbe: true, SourceMaps: true},
	)
	if err != nil {
		t.Fatalf("RunHTTP: %v", err)
	}
	if got := mapHits.Load(); got != 1 {
		t.Fatalf("expected map fetched once via singleflight, got %d", got)
	}
	if got := rec.StoreErrors["sighting_missing"]; got != 0 {
		t.Fatalf("expected sighting_missing == 0, got %d (StoreErrors=%v)", got, rec.StoreErrors)
	}
	if rec.Resolver.SourcesCapped != 7 {
		t.Fatalf("expected SourcesCapped == 7 (10 in map - 3 cap), got %d", rec.Resolver.SourcesCapped)
	}

	idx, err := filepath.Glob(filepath.Join(out, "*", "anon", "index.jsonl"))
	if err != nil || len(idx) != 1 {
		t.Fatalf("index.jsonl: %v %v", idx, err)
	}
	f, err := os.Open(idx[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sourceEntries := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e struct {
			Kinds []string `json:"kinds"`
			Pages []string `json:"pages"`
		}
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		for _, k := range e.Kinds {
			if k == "source" {
				sourceEntries++
				if len(e.Pages) != 4 {
					t.Fatalf("stored source entry has %d host sightings, want 4: %v", len(e.Pages), e.Pages)
				}
			}
		}
	}
	if sourceEntries != 3 {
		t.Fatalf("expected exactly 3 stored source entries under MaxSourceFiles=3, got %d", sourceEntries)
	}
}

func TestRound41HTTPStoreBudgetStopsAndWarns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, `<!doctype html><title>app</title><script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script>`)
		case "/a.js", "/b.js", "/c.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = fmt.Fprintf(w, "export const p = %q; // %s\n", r.URL.Path, strings.Repeat("x", 300))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL + "/")
	out := t.TempDir()
	rec, err := RunHTTP(context.Background(),
		Config{
			Target:        target,
			OutRoot:       out,
			Role:          "anon",
			ScopeMode:     "fqdn",
			Depth:         1,
			NavTimeout:    5 * time.Second,
			MaxStoreBytes: 500, // fits 1 script (~340 B), caps before storing the rest
		},
		HTTPOptions{Rate: 500, PageWorkers: 1, NoSpecProbe: true},
	)
	if err != nil {
		t.Fatalf("RunHTTP: %v", err)
	}
	if rec.StoreErrors["write"] != 0 || rec.StoreErrors["store_budget"] == 0 {
		t.Fatalf("unexpected StoreErrors: %v", rec.StoreErrors)
	}
	if rec.HTTP == nil || !strings.Contains(rec.HTTP.Capped, "-max-store-mb") {
		t.Fatalf("expected HTTP.Capped to mention -max-store-mb, got %+v", rec.HTTP)
	}
	joinedWarn := strings.Join(rec.Warnings, "\n")
	if !strings.Contains(joinedWarn, "(-max-store-mb to raise it)") || strings.Contains(joinedWarn, "-resolve-max") {
		t.Fatalf("expected -max-store-mb hint in warnings, got: %v", rec.Warnings)
	}
}
