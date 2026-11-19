package verify

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/replay"
)

// R39-A2: when a prefix's 404 canary returns an HTML site shell (status 404)
// and a read-only GET probe (e.g. for POST {}/upload or a stale path) answers
// with Soft-200 carrying that exact same HTML shell and word scale, verify must
// not report verified_alive. Genuine 200 HTML endpoints with a distinct shell
// remain Alive.
func TestRound39VerifySoft200Matching404CanaryShell(t *testing.T) {
	filler := strings.Repeat("word ", 200)
	siteShell := `<!doctype html><html><head><title>Storefront Portal</title><script src="/assets/vendor.js"></script><script src="/assets/app.js"></script></head><body>` + filler + `</body></html>`
	distinctDoc := `<!doctype html><html><head><title>API Console</title><script src="/swagger-ui.js"></script></head><body>Swagger Documentation</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/upload", "/legacy-route":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, siteShell)
		case "/api-console":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, distinctDoc)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, siteShell)
		}
	}))
	defer srv.Close()

	drafts := []Draft{
		{
			ID:         "POST_UPLOAD",
			Source:     "historical",
			Method:     "POST",
			Path:       "{}/upload",
			URL:        srv.URL + "/upload",
			Confidence: "code",
			Tier:       Parameterized,
		},
		{
			ID:         "BARE_ROUTE",
			Source:     "static",
			Method:     "",
			Path:       "/legacy-route",
			URL:        srv.URL + "/legacy-route",
			Confidence: "string",
			Tier:       Ready,
		},
		{
			ID:         "DISTINCT_DOC",
			Source:     "static",
			Method:     "GET",
			Path:       "/api-console",
			URL:        srv.URL + "/api-console",
			Confidence: "code",
			Tier:       Ready,
		},
	}

	s, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Concurrency: 4, OnBlock: replay.OnBlockSkip})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rep, err := Run(context.Background(), Options{
		Target:         "127.0.0.1",
		Role:           "anon",
		Drafts:         drafts,
		Sender:         s,
		InScope:        func(string) bool { return true },
		IncludeStrings: true,
		Concurrency:    4,
		HostInFlight:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Result{}
	for _, r := range rep.Results {
		byID[r.ID] = r
	}
	if got := byID["POST_UPLOAD"]; got.Verdict != DeadOrFP || got.VerifiedMethod != "" || got.VerifiedBase != "" {
		t.Fatalf("POST_UPLOAD = %+v, want verdict=%q with empty VerifiedMethod/VerifiedBase", got, DeadOrFP)
	}
	if got := byID["BARE_ROUTE"]; got.Verdict != ClientRoute {
		t.Fatalf("BARE_ROUTE verdict = %q, want %q", got.Verdict, ClientRoute)
	}
	if got := byID["DISTINCT_DOC"]; got.Verdict != Alive {
		t.Fatalf("DISTINCT_DOC verdict = %q, want %q", got.Verdict, Alive)
	}
}
