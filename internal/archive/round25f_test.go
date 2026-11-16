package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/htmlscan"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

// TestResumeCCPartialFailureNoNilMapPanic reproduces the production crash in
// listCC when resuming an archive.json checkpoint whose prior run saw Common
// Crawl fail on every collection (cc.Next populated, cc.Listed empty and
// omitted by json:",omitempty").
func TestResumeCCPartialFailureNoNilMapPanic(t *testing.T) {
	ccSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collinfo.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"id":"CC-MAIN-2026-18"}]`))
		case "/CC-MAIN-2026-18-index":
			if r.URL.Query().Get("showNumPages") == "true" {
				w.Write([]byte(`{"pages": 1, "pageSize": 5, "blocks": 1}`))
				return
			}
			w.Write([]byte(`{"url":"https://a.test/old.js","mime":"application/javascript","status":"200","digest":"AAECAwQFBgcICQoLDA0ODw==","timestamp":"20260401000000","filename":"x","offset":"0","length":"0"}` + "\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ccSrv.Close()

	wbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/web/") {
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`fetch("/api/v1/legacy-orders")`))
			return
		}
		w.Write([]byte("[]"))
	}))
	defer wbSrv.Close()

	root := t.TempDir()
	dir := filepath.Join(root, "a.test", "archive")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	sources := []string{"commoncrawl"}
	// Build the exact checkpoint shape produced when all CC collections return 504:
	// Next is non-empty, Listed is empty (and omitted in JSON!).
	var seed state
	q := queryKey("a.test", sources, since)
	seed.Query = q
	seed.CC.Collections = []string{"CC-MAIN-2026-18"}
	seed.CC.Next = map[string]int{"CC-MAIN-2026-18": 0}
	b, err := json.MarshalIndent(seed, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(`"listed": {`)) {
		t.Fatalf("expected listed to be omitted from JSON checkpoint, got:\n%s", b)
	}
	if err := os.WriteFile(filepath.Join(dir, "archive.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	cl := &Client{HTTP: ccSrv.Client(), Tries: 1}
	sum, err := Run(context.Background(), Options{
		Dir:      dir,
		Root:     root,
		Host:     "a.test",
		InScope:  func(h string) bool { return h == "a.test" },
		Sources:  sources,
		Since:    since,
		MaxFiles: 10,
		MaxBody:  1 << 20,
		Wayback:  &Wayback{Base: wbSrv.URL, Client: cl, Index: &Budget{}, Files: &Budget{}, PageSize: 10},
		CC:       &CommonCrawl{Index: ccSrv.URL, Data: ccSrv.URL, Client: cl, Budget: &Budget{}, Files: &Budget{}, Collections: 1},
		Log:      func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("Run failed on resume: %v", err)
	}
	if sum.Listed["commoncrawl"] != 1 {
		t.Fatalf("expected commoncrawl listed=1, got %+v", sum.Listed)
	}
	var after state
	raw, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatal(err)
	}
	if !after.CC.Done || !after.CC.Listed["CC-MAIN-2026-18"] {
		t.Fatalf("expected CC collection marked listed & done, got %+v", after.CC)
	}
}

func queryKey(host string, sources []string, since time.Time) string {
	q := sha256.Sum256([]byte(fmt.Sprint(stateVersion, "|", host, "|", sources, "|", since.Format(time.DateOnly))))
	return hex.EncodeToString(q[:8])
}

// TestInScriptsLeadingPlaceholderFastAndSemantic verifies both sides of the
// classify() hang fix:
//  1. Leading {}/... wrapper paths match quoted "/..." and "..." paths in JS
//     while rejecting mid-word occurrences ("foo-api/v1/...").
//  2. Scanning 27 {}/api/v1/... endpoints across 10 MB of minified JS finishes
//     in milliseconds rather than 300+ seconds, and honours context cancellation.
func TestInScriptsLeadingPlaceholderFastAndSemantic(t *testing.T) {
	files := [][]byte{[]byte(`
		const a = (m, u) => fetch(base + u, {method: m});
		a("GET", "/api/v1/conversations");
		a("POST", "api/v1/workspaces");
		const tpl = ` + "`${base}/api/v1/conversations/${id}/messages`" + `;
		const bad = "foo-api/v1/not-an-endpoint";
	`)}
	cases := map[string]bool{
		"{}/api/v1/conversations":              true,
		"{}/api/v1/workspaces":                 true,
		"{}/api/v1/conversations/{}/messages":  true,
		"{}/{}/api/v1/conversations":           true,
		"{}/api/v1/not-an-endpoint":            false,
		"{}/api/v1/missing-legacy-route":       false,
		"{}/short":                             false,
	}
	for p, want := range cases {
		if got := inScripts(endpoints.Endpoint{Method: "GET", Path: p}, files); got != want {
			t.Errorf("inScripts(%q) = %v, want %v", p, got, want)
		}
	}

	// Performance gate: 40 x 256 KB = 10 MB of realistic minified JS noise.
	jsDir := t.TempDir()
	chunk := bytes.Repeat([]byte(`function _0x1(e,t){return e.call(this,"/v2/items",t.id+12345)}var k={a:"alpha/beta/gamma",b:99};`), 2700)
	for i := 0; i < 40; i++ {
		if err := os.WriteFile(filepath.Join(jsDir, fmt.Sprintf("bundle-%02d.js", i)), chunk, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var archived []endpoints.Endpoint
	for i := 0; i < 27; i++ {
		archived = append(archived, endpoints.Endpoint{
			Method: "GET",
			Path:   fmt.Sprintf("{}/api/v1/legacy-resource-%02d/{}/details", i),
			Kind:   "wrapper",
		})
	}
	cur := &current{jsDirs: []string{jsDir}}
	start := time.Now()
	lines, _, err := classifyCtx(context.Background(), archived, cur, func(string) (store.Entry, bool) {
		return store.Entry{}, false
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("classifyCtx error: %v", err)
	}
	if len(lines) != 27 {
		t.Fatalf("expected 27 lines, got %d", len(lines))
	}
	if elapsed > 5*time.Second {
		t.Fatalf("classifyCtx took %v on 27 {}/... endpoints x 10 MB (regression to unanchored NFA scan)", elapsed)
	}

	// Context cancellation must abort immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := classifyCtx(ctx, archived, cur, func(string) (store.Entry, bool) { return store.Entry{}, false }); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestChallengePageCloudflare1xxx(t *testing.T) {
	cf1006 := htmlscan.Scan([]byte(`<!DOCTYPE html><html><head><title>Access denied | admin.example.vn used Cloudflare to restrict access | admin.example.vn | Cloudflare</title></head><body></body></html>`), "https://admin.example.vn/")
	if !challengePage(cf1006) {
		t.Error("expected archived Cloudflare 1006 page to be treated as challenge/block page")
	}
	app403 := htmlscan.Scan([]byte(`<!DOCTYPE html><html><head><title>Access Denied</title></head><body><script src="/app.js"></script></body></html>`), "https://admin.example.vn/")
	if challengePage(app403) {
		t.Error("origin app Access Denied page must not be treated as challenge/block page")
	}
}
