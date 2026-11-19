package verify

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// T1 (round 38): when rejudgeShells demotes a multi-candidate draft whose first
// candidate answered 200 HTML matching a late-learned global canary shell (*),
// VerifiedBase must be cleared alongside VerifiedMethod.
func TestRound38RejudgeClearsVerifiedBase(t *testing.T) {
	const waf = `<html><head><title>Access Policy</title></head><body>This request was blocked by the gateway security policy. Reference 88.</body></html>`
	slowWAF := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(350 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, waf)
	})
	a, b := httptest.NewServer(slowWAF), httptest.NewServer(slowWAF)
	defer a.Close()
	defer b.Close()

	c := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gw1/items" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, waf)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"not found"}`)
	}))
	defer c.Close()

	drafts := []Draft{
		{ID: "A", Source: "static", Method: "GET", Path: "/svc/a/x", URL: a.URL + "/svc/a/x", Confidence: "code", Tier: Ready},
		{ID: "B", Source: "static", Method: "GET", Path: "/svc/b/x", URL: b.URL + "/svc/b/x", Confidence: "code", Tier: Ready},
		{
			ID:             "CAND",
			Source:         "static",
			Method:         "GET",
			Path:           "/items",
			Candidates:     []string{c.URL + "/gw1/items", c.URL + "/gw2/items"},
			CandidateBases: []string{c.URL + "/gw1", c.URL + "/gw2"},
			Confidence:     "code",
			Tier:           Incomplete,
		},
	}

	rep := runVerify(t, drafts, 8, 1, 0)
	var cand *Result
	for i := range rep.Results {
		if rep.Results[i].ID == "CAND" {
			cand = &rep.Results[i]
			break
		}
	}
	if cand == nil {
		t.Fatal("missing result for CAND")
	}
	if cand.Verdict != DeadOrFP {
		t.Fatalf("CAND verdict = %q, want %q", cand.Verdict, DeadOrFP)
	}
	if cand.VerifiedMethod != "" || cand.VerifiedBase != "" {
		t.Fatalf("CAND kept VerifiedMethod=%q VerifiedBase=%q after demotion, want both empty", cand.VerifiedMethod, cand.VerifiedBase)
	}
}
