package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

// R40-B3: run.json keeps the HTTP run's own counters intact while populating a
// totals block aggregating Escalated/SPABoot Chrome runs and setting
// unique_scripts = st.Len() + sum(er.NewScripts), matching index.jsonl.
func TestRound40RunJSONTotalsAfterEscalateAndSPABoot(t *testing.T) {
	const spaShell = `<!doctype html><html><head><title>App</title><script src="/app.js"></script></head><body><div id="root">SPA</div></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `console.log("boot");`)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, spaShell)
	}))
	defer srv.Close()
	targetURL, _ := url.Parse(srv.URL + "/")

	// 1. Baseline HTTP-only run (no Escalated / SPABoot): no totals block.
	baseOut := t.TempDir()
	baseRec, err := RunHTTP(context.Background(), Config{
		Target:     targetURL,
		OutRoot:    baseOut,
		Role:       "anon",
		ScopeMode:  "fqdn",
		Depth:      1,
		NavTimeout: 5 * time.Second,
	}, HTTPOptions{Rate: 200, NoSpecProbe: true})
	if err != nil {
		t.Fatalf("baseline RunHTTP: %v", err)
	}
	if baseRec.Totals != nil {
		t.Fatalf("baseline HTTP-only run should have nil Totals, got %+v", baseRec.Totals)
	}
	baseRunPath := filepath.Join(baseOut, scope.TargetDir(targetURL), "anon", "run.json")
	if b, err := os.ReadFile(baseRunPath); err != nil || strings.Contains(string(b), `"totals"`) {
		t.Fatalf("baseline run.json should omit totals (err=%v): %s", err, b)
	}

	// 2. HTTP run with SPABoot writing 2 new scripts to the same role dir.
	outDir := t.TempDir()
	roleDir := filepath.Join(outDir, scope.TargetDir(targetURL), "anon")
	rec, err := RunHTTP(context.Background(), Config{
		Target:     targetURL,
		OutRoot:    outDir,
		Role:       "anon",
		ScopeMode:  "fqdn",
		Depth:      1,
		NavTimeout: 5 * time.Second,
	}, HTTPOptions{
		Rate:        200,
		NoSpecProbe: true,
		SPABoot: func(ctx context.Context, origins []string) []EscalatedRun {
			st, err := store.Open(roleDir, store.Options{MaxBody: 4 << 20})
			if err != nil {
				t.Errorf("open store in SPABoot: %v", err)
				return nil
			}
			newCnt := 0
			for i := 1; i <= 2; i++ {
				if _, isNew, err := st.Put(store.Record{
					Body:   []byte(fmt.Sprintf(`fetch("/api/v1/boot-%d");`, i)),
					URL:    fmt.Sprintf("%s/lazy-%d.js", srv.URL, i),
					Kind:   "file",
					Via:    "spa-boot",
					Source: "live",
				}); err != nil {
					t.Errorf("store.Put %d: %v", i, err)
				} else if isNew {
					newCnt++
				}
			}
			_ = st.Flush()
			return []EscalatedRun{{
				Host:             targetURL.Hostname(),
				Target:           targetURL.String(),
				RunID:            "chrome-spaboot-1",
				Pages:            1,
				Requests:         7,
				PageRequests:     5,
				InternalRequests: 2,
				NewScripts:       newCnt,
			}}
		},
	})
	if err != nil {
		t.Fatalf("SPABoot RunHTTP: %v", err)
	}

	// HTTP run's own counters must remain identical to baseline.
	if rec.Requests != baseRec.Requests || rec.PageRequests != baseRec.PageRequests ||
		rec.InternalRequests != baseRec.InternalRequests || rec.NewScripts != baseRec.NewScripts ||
		!slices.Equal(rec.Scripts, baseRec.Scripts) {
		t.Fatalf("HTTP run own counters changed:\n got  req=%d page=%d int=%d new=%d scripts=%v\n want req=%d page=%d int=%d new=%d scripts=%v",
			rec.Requests, rec.PageRequests, rec.InternalRequests, rec.NewScripts, rec.Scripts,
			baseRec.Requests, baseRec.PageRequests, baseRec.InternalRequests, baseRec.NewScripts, baseRec.Scripts)
	}

	// Totals must aggregate HTTP + Chrome accurately.
	if rec.Totals == nil {
		t.Fatal("expected non-nil Totals after SPABoot")
	}
	if rec.Totals.Requests != baseRec.Requests+7 ||
		rec.Totals.PageRequests != baseRec.PageRequests+5 ||
		rec.Totals.InternalRequests != baseRec.InternalRequests+2 ||
		rec.Totals.NewScripts != baseRec.NewScripts+2 ||
		!slices.Equal(rec.Totals.Runs, []string{"chrome-spaboot-1"}) {
		t.Fatalf("unexpected Totals: %+v", rec.Totals)
	}
	if rec.Totals.PageRequests+rec.Totals.InternalRequests != rec.Totals.Requests {
		t.Fatalf("totals invariant broken: %d + %d != %d", rec.Totals.PageRequests, rec.Totals.InternalRequests, rec.Totals.Requests)
	}

	// unique_scripts must match the exact number of distinct SHAs in index.jsonl.
	f, err := os.Open(filepath.Join(roleDir, "index.jsonl"))
	if err != nil {
		t.Fatalf("open index.jsonl: %v", err)
	}
	defer f.Close()
	shas := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var row struct {
			SHA256 string `json:"sha256"`
		}
		if json.Unmarshal(sc.Bytes(), &row) == nil && row.SHA256 != "" {
			shas[row.SHA256] = true
		}
	}
	if rec.UniqueScripts != len(shas) {
		t.Fatalf("unique_scripts=%d, index.jsonl distinct SHAs=%d", rec.UniqueScripts, len(shas))
	}

	// Verify run.json on disk persisted Totals and UniqueScripts.
	b, err := os.ReadFile(filepath.Join(roleDir, "run.json"))
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	var disk Record
	if err := json.Unmarshal(b, &disk); err != nil {
		t.Fatalf("unmarshal run.json: %v", err)
	}
	if disk.Totals == nil || disk.Totals.Requests != rec.Totals.Requests || disk.UniqueScripts != len(shas) {
		t.Fatalf("run.json on disk mismatch: totals=%+v unique=%d (want %d)", disk.Totals, disk.UniqueScripts, len(shas))
	}
}

// R40-B1 (CDP engine): specFilesWithHeaders probes OriginSpecPaths only for
// in-scope origins, keeping out-of-scope cross-origin roots to SpecPaths only.
func TestRound40CDPSpecFilesOriginSpecPathsInScopeOnly(t *testing.T) {
	var mu sync.Mutex
	var gotPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPaths = append(gotPaths, r.URL.Path)
		mu.Unlock()
		http.NotFound(w, r)
	}))
	defer srv.Close()

	srvURL, _ := url.Parse(srv.URL + "/")
	c := &crawl{}
	defer c.closeSpecClient()

	// Out-of-scope origin: must NOT send OriginSpecPaths.
	eOut := &engine{
		runState: &runState{
			cfg: Config{
				Target:  srvURL,
				InScope: func(string) bool { return false },
			},
			privOff: true,
		},
	}
	eOut.specFilesWithHeaders(context.Background(), c, srv.URL, srv.URL+"/", nil, map[string]bool{}, nil)

	mu.Lock()
	outHits := slices.Clone(gotPaths)
	gotPaths = nil
	mu.Unlock()
	if !slices.Contains(outHits, "/openapi.json") {
		t.Fatalf("expected D2 SpecPaths probe on out-of-scope root, got %v", outHits)
	}
	for _, p := range frontier.OriginSpecPaths {
		if slices.Contains(outHits, p) {
			t.Fatalf("out-of-scope CDP root should not probe OriginSpecPath %q (got %v)", p, outHits)
		}
	}

	// In-scope origin: MUST send OriginSpecPaths too.
	eIn := &engine{
		runState: &runState{
			cfg: Config{
				Target:  srvURL,
				InScope: func(string) bool { return true },
			},
			privOff: true,
		},
	}
	eIn.specFilesWithHeaders(context.Background(), c, srv.URL, srv.URL+"/", nil, map[string]bool{}, nil)

	mu.Lock()
	inHits := slices.Clone(gotPaths)
	mu.Unlock()
	if !slices.Contains(inHits, "/swagger.json") {
		t.Fatalf("in-scope CDP root should probe OriginSpecPaths (/swagger.json), got %v", inHits)
	}
}
