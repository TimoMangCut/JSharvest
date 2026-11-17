package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/replay"
)

func TestJoinDeduplicatesVersionedAPIRootPrefix(t *testing.T) {
	cases := []struct {
		base, path, want string
	}{
		{"https://mta.example.test/api/v1/admin/users", "/api/v1/application-checklists", "https://mta.example.test/api/v1/application-checklists"},
		{"https://mta.example.test/api/v1/events", "/api/v1/admin/users", "https://mta.example.test/api/v1/admin/users"},
		{"https://mta.example.test/v2/orders", "/v2/audit-logs", "https://mta.example.test/v2/audit-logs"},
		// Gateway base prefix distinct from /api/v1 must still wrap /api/v1!
		{"https://gw.example.test/api-gateway", "/api/v1/users", "https://gw.example.test/api-gateway/api/v1/users"},
		{"https://gw.example.test/hub", "/hub/auth/token", "https://gw.example.test/hub/auth/token"},
	}
	for _, c := range cases {
		if got := join(c.base, c.path); got != c.want {
			t.Errorf("join(%q, %q) = %q, want %q", c.base, c.path, got, c.want)
		}
	}
}

func TestVerifyRejectsF5AndSubPathAdminWAFHTMLShells(t *testing.T) {
	// Simulates a gateway where:
	// - /api/applications/<unknown> returns 404 application/json
	// - /api/applications/search returns 200 application/json (genuine alive!)
	// - /api/applications/admin/* returns a custom 200 text/html proxy block shell
	// - /api/v1/f5-admin returns F5 BIG-IP ASM 200 "Request Rejected" HTML
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/f5-admin":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.<br><br>Your support ID is: 1234567890</body></html>`))
		case strings.HasPrefix(r.URL.Path, "/api/applications/admin/"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<html><head><title>Corporate Proxy Policy</title></head><body>Access to administrative URI segment is restricted by gateway policy.</body></html>`))
		case r.URL.Path == "/api/applications/search":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"items":[],"total":0}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"code":"404","message":"not found"}`))
		}
	}))
	defer srv.Close()

	sender, err := replay.NewSender(replay.SenderOptions{
		AllowPrivate: true,
		OnBlock:      replay.OnBlockSkip,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	drafts := []Draft{
		{ID: "0001", Source: "historical", Method: "GET", Path: "/api/applications/search", URL: srv.URL + "/api/applications/search", Confidence: "code", Tier: Ready},
		{ID: "0002", Source: "historical", Method: "GET", Path: "/api/applications/admin/export/all", URL: srv.URL + "/api/applications/admin/export/all", Confidence: "code", Tier: Ready},
		{ID: "0003", Source: "historical", Method: "GET", Path: "/api/applications/admin/drilldown", URL: srv.URL + "/api/applications/admin/drilldown", Confidence: "code", Tier: Ready},
		{ID: "0004", Source: "historical", Method: "GET", Path: "/api/v1/f5-admin", URL: srv.URL + "/api/v1/f5-admin", Confidence: "code", Tier: Ready},
	}

	rep, err := Run(context.Background(), Options{
		Target:      "127.0.0.1",
		Role:        "anon",
		Drafts:      drafts,
		Sender:      sender,
		InScope:     func(string) bool { return true },
		Concurrency: 2,
	})
	if err != nil {
		t.Fatalf("verify.Run: %v", err)
	}

	verdictByID := map[string]string{}
	for _, r := range rep.Results {
		verdictByID[r.ID] = r.Verdict
	}
	if verdictByID["0001"] != Alive {
		t.Errorf("genuine JSON endpoint 0001 got %q, want %q", verdictByID["0001"], Alive)
	}
	if verdictByID["0002"] != DeadOrFP || verdictByID["0003"] != DeadOrFP {
		t.Errorf("custom /admin HTML block endpoints got 0002=%q 0003=%q, want both %q", verdictByID["0002"], verdictByID["0003"], DeadOrFP)
	}
	if verdictByID["0004"] != WAFBlocked {
		t.Errorf("F5 ASM Request Rejected endpoint 0004 got %q, want %q", verdictByID["0004"], WAFBlocked)
	}
}
