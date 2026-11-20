package verify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
)

const round40SPAShell = `<!doctype html><html><head><title>Portal SPA</title><script src="/assets/app.js"></script></head><body><div id="root">Portal App</div></body></html>`

// R40-A3: Load reads http.spa_origins from run.json; relative API calls
// (wrapper/client) pinned to a SPA origin try intel.Bases when SPA origin
// returns its HTML shell, while kind="navigation" stays pinned to SPA origin.
func TestRound40DecoupledSPAVerifiesAgainstIntelBases(t *testing.T) {
	spaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, round40SPAShell)
	}))
	defer spaSrv.Close()

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/gw-private/"):
			// Opaque Kong-like gateway prefix: returns 401 for every path including canary.
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"message":"unauthorized"}`)
		case r.URL.Path == "/gw-pub/health":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not_found"}`)
		}
	}))
	defer apiSrv.Close()

	dir := t.TempDir()
	epLines := []endpoints.Endpoint{
		{Method: "GET", Origin: spaSrv.URL, Path: "/gw-private/orders", Kind: "wrapper", Confidence: "code"},
		{Method: "GET", Origin: spaSrv.URL, Path: "/gw-pub/health", Kind: "client", Confidence: "code"},
		{Method: "GET", Origin: spaSrv.URL, Path: "/dashboard/overview", Kind: "navigation", Confidence: "code"},
	}
	var epBuf strings.Builder
	for _, e := range epLines {
		b, _ := json.Marshal(e)
		epBuf.Write(b)
		epBuf.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, endpoints.File), []byte(epBuf.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	intelBytes, _ := json.Marshal(endpoints.Intel{Bases: []string{apiSrv.URL}})
	if err := os.WriteFile(filepath.Join(dir, endpoints.IntelFile), intelBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	runBytes, _ := json.Marshal(map[string]any{
		"http": map[string]any{"spa_origins": []string{spaSrv.URL}},
	})
	if err := os.WriteFile(filepath.Join(dir, "run.json"), runBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	in, err := Load(dir, "", false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(in.SPAOrigins) != 1 || in.SPAOrigins[0] != strings.ToLower(spaSrv.URL) {
		t.Fatalf("SPAOrigins = %v, want [%s]", in.SPAOrigins, strings.ToLower(spaSrv.URL))
	}
	in.InScope = func(string) bool { return true }

	drafts := Drafts(in)
	for _, d := range drafts {
		if d.Path == "/dashboard/overview" {
			if d.URL != spaSrv.URL+"/dashboard/overview" || len(d.Candidates) != 0 {
				t.Fatalf("navigation route should stay pinned to SPA origin, got URL=%q Candidates=%v", d.URL, d.Candidates)
			}
		}
		if d.Path == "/gw-private/orders" || d.Path == "/gw-pub/health" {
			if len(d.Candidates) != 2 || d.CandidateBases[0] != spaSrv.URL || d.CandidateBases[1] != apiSrv.URL {
				t.Fatalf("%s expected [spa, api] candidates, got bases=%v cands=%v", d.Path, d.CandidateBases, d.Candidates)
			}
		}
	}

	rep := runVerify(t, drafts, 1, 1, 0)
	byPath := map[string]Result{}
	for _, r := range rep.Results {
		byPath[r.Path] = r
	}
	if got := byPath["/gw-private/orders"]; got.Verdict != AuthWall || !strings.HasPrefix(got.URL, apiSrv.URL) {
		t.Fatalf("/gw-private/orders = %+v, want verdict=%s url on %s", got, AuthWall, apiSrv.URL)
	}
	if got := byPath["/gw-pub/health"]; got.Verdict != Alive || got.VerifiedBase != apiSrv.URL {
		t.Fatalf("/gw-pub/health = %+v, want verdict=%s verified_base=%s", got, Alive, apiSrv.URL)
	}
	if got := byPath["/dashboard/overview"]; got.Verdict != DeadOrFP {
		t.Fatalf("/dashboard/overview = %+v, want %s", got, DeadOrFP)
	}
}

// R40-A3: on a reverse-proxy SPA where /api/local lives on the SPA origin
// itself while an external intel.Base returns a distinct JSON 404 (different
// from its canary), keeping the SPA origin first locks onto the SPA origin.
func TestRound40ReverseProxySPAPreservesSameOrigin(t *testing.T) {
	spaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/local" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"local":true}`)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, round40SPAShell)
	}))
	defer spaSrv.Close()

	// External API host returns a distinct JSON 404 for /api/local vs HTML 404
	// for unknown canary paths (which would look like Resource404 if tried first!).
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/local" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"item_not_found","resource":"local"}`)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "404 page not found")
	}))
	defer apiSrv.Close()

	in := Inputs{
		Catalog: []endpoints.Endpoint{
			{Method: "GET", Origin: spaSrv.URL, Path: "/api/local", Kind: "wrapper", Confidence: "code"},
		},
		Intel:      endpoints.Intel{Bases: []string{apiSrv.URL}},
		SPAOrigins: []string{spaSrv.URL},
		InScope:    func(string) bool { return true },
	}
	drafts := Drafts(in)
	rep := runVerify(t, drafts, 1, 1, 0)
	if len(rep.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(rep.Results))
	}
	got := rep.Results[0]
	if got.Verdict != Alive || got.VerifiedBase != spaSrv.URL || !strings.HasPrefix(got.URL, spaSrv.URL) {
		t.Fatalf("reverse-proxy SPA route misrouted: %+v (want Alive on %s)", got, spaSrv.URL)
	}
}

// R40-A3: across 20 decoupled API drafts on a SPA origin, the SPA origin is
// pruned after 16 distinct dead paths (specBasePruneAfter) so subsequent drafts
// go directly to the external API host without wasting probes on the SPA shell.
func TestRound40SPAOriginPrunedAfter16DeadPaths(t *testing.T) {
	var spaDraftHits atomic.Int64
	spaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/svc-") {
			spaDraftHits.Add(1)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, round40SPAShell)
	}))
	defer spaSrv.Close()

	var apiDraftHits atomic.Int64
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/svc-") {
			apiDraftHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"not_found"}`)
	}))
	defer apiSrv.Close()

	var cat []endpoints.Endpoint
	for i := 1; i <= 20; i++ {
		cat = append(cat, endpoints.Endpoint{
			Method:     "GET",
			Origin:     spaSrv.URL,
			Path:       fmt.Sprintf("/v1/svc-%02d", i),
			Kind:       "wrapper",
			Confidence: "code",
		})
	}
	in := Inputs{
		Catalog:    cat,
		Intel:      endpoints.Intel{Bases: []string{apiSrv.URL}},
		SPAOrigins: []string{spaSrv.URL},
		InScope:    func(string) bool { return true },
	}
	drafts := Drafts(in)
	rep := runVerify(t, drafts, 1, 1, 0)

	aliveCount := 0
	for _, r := range rep.Results {
		if r.Verdict == Alive && r.VerifiedBase == apiSrv.URL {
			aliveCount++
		}
	}
	if aliveCount != 20 {
		t.Fatalf("expected all 20 decoupled drafts Alive on %s, got %d", apiSrv.URL, aliveCount)
	}
	if got := spaDraftHits.Load(); got > specBasePruneAfter {
		t.Fatalf("SPA origin received %d draft probes across 20 drafts, want <= %d (pruned)", got, specBasePruneAfter)
	}
	if got := apiDraftHits.Load(); got != 20 {
		t.Fatalf("API host received %d draft probes, want 20", got)
	}
}
