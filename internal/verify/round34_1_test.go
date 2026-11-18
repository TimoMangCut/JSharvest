package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/replay"
)

func TestHTMLShellRequiresExactShellAndTwoHostsBeforeGlobalPromotion(t *testing.T) {
	// Empty <title></title> with no scripts must NOT hash to a non-empty Shell.
	emptySig := SigOf(200, map[string]string{"content-type": "text/html"}, []byte(`<html><head><title>   </title></head><body>short text here</body></html>`))
	if emptySig.Shell != "" {
		t.Fatalf("expected empty <title> without scripts to have empty Shell, got %q", emptySig.Shell)
	}

	// Host A's canary returns a 16-word HTML shell (<title>Portal A</title>).
	// Host B's endpoint /api/v1/health-page returns a 16-word genuine HTML status
	// page with a DIFFERENT <title>Service Health OK</title> (while Host B's canary returns 404 JSON).
	// Host B's endpoint MUST be Alive (neither word-count fallthrough nor single-host "*" promotion may kill it!).
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`<html><head><title>Portal A</title></head><body>Welcome to the single page portal fallback shell</body></html>`))
	}))
	defer srvA.Close()

	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health-page" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<html><head><title>Service Health OK</title></head><body>All database and queue nodes are healthy now</body></html>`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":"not_found"}`))
	}))
	defer srvB.Close()

	sender, err := replay.NewSender(replay.SenderOptions{
		AllowPrivate: true,
		OnBlock:      replay.OnBlockSkip,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	// Run sequentially (Concurrency: 1) so Host A's canary runs before Host B's probe.
	rep, err := Run(context.Background(), Options{
		Target: "127.0.0.1",
		Role:   "anon",
		Drafts: []Draft{
			{ID: "A1", Source: "static", Method: "GET", Path: "/api/v1/ghost", URL: srvA.URL + "/api/v1/ghost", Confidence: "code", Tier: Ready},
			{ID: "B1", Source: "static", Method: "GET", Path: "/api/v1/health-page", URL: srvB.URL + "/api/v1/health-page", Confidence: "code", Tier: Ready},
		},
		Sender:      sender,
		InScope:     func(string) bool { return true },
		Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("verify.Run: %v", err)
	}
	verdicts := map[string]string{}
	for _, r := range rep.Results {
		verdicts[r.ID] = r.Verdict
	}
	if verdicts["A1"] != DeadOrFP {
		t.Errorf("Host A catch-all shell endpoint A1 = %q, want %q", verdicts["A1"], DeadOrFP)
	}
	if verdicts["B1"] != Alive {
		t.Errorf("Host B genuine HTML endpoint with different <title> B1 = %q, want %q", verdicts["B1"], Alive)
	}

	// Now verify 2-host corporate shell promotion: once 2 distinct hosts' canaries
	// return the exact same HTML shell (<title>Corp Gateway Denied</title>), a 3rd host
	// returning that exact shell on a sub-route (even when its own canary returns 404 JSON)
	// IS recognized via "*"!
	corpShell := []byte(`<html><head><title>Corp Gateway Denied</title></head><body>Access denied by corporate edge gateway policy</body></html>`)
	srvC1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write(corpShell)
	}))
	defer srvC1.Close()
	srvC2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write(corpShell)
	}))
	defer srvC2.Close()
	srvC3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/corp-blocked" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			_, _ = w.Write(corpShell)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":"not_found"}`))
	}))
	defer srvC3.Close()

	sender2, err := replay.NewSender(replay.SenderOptions{
		AllowPrivate: true,
		OnBlock:      replay.OnBlockSkip,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sender2.Close()

	rep2, err := Run(context.Background(), Options{
		Target: "127.0.0.1",
		Role:   "anon",
		Drafts: []Draft{
			{ID: "C1", Source: "static", Method: "GET", Path: "/api/v1/x", URL: srvC1.URL + "/api/v1/x", Confidence: "code", Tier: Ready},
			{ID: "C2", Source: "static", Method: "GET", Path: "/api/v1/y", URL: srvC2.URL + "/api/v1/y", Confidence: "code", Tier: Ready},
			{ID: "C3", Source: "static", Method: "GET", Path: "/api/v1/corp-blocked", URL: srvC3.URL + "/api/v1/corp-blocked", Confidence: "code", Tier: Ready},
		},
		Sender:      sender2,
		InScope:     func(string) bool { return true },
		Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("verify.Run 2: %v", err)
	}
	for _, r := range rep2.Results {
		if r.ID == "C3" && r.Verdict != DeadOrFP {
			t.Errorf("2-host shared corporate HTML shell on Host 3 got %q, want %q", r.Verdict, DeadOrFP)
		}
	}
}
