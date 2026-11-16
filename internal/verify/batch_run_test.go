package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/replay"
)

// Drafts of one endpoint's operations are the same request: verify sends
// it once, and each draft is listed with the same verdict.
func TestRunSendsOneRequestForDraftsOfOperations(t *testing.T) {
	run := func(ops ...string) (int, *Report) {
		var mu sync.Mutex
		n := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			n++
			mu.Unlock()
			if r.URL.Path == "/api/items" {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"items":[]}`))
				return
			}
			w.WriteHeader(404)
			w.Write([]byte(`{"code":"NO_ROUTE"}`))
		}))
		defer srv.Close()
		in := Inputs{InScope: func(string) bool { return true },
			Catalog: []endpoints.Endpoint{{Method: "GET", Path: "/api/items", Bases: []string{srv.URL}, Confidence: "code", Kind: "fetch", Operations: ops}}}
		s, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 100})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		rep, err := Run(context.Background(), Options{Target: "t", Role: "anon", Drafts: Drafts(in), Sender: s, InScope: in.InScope})
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		return n, rep
	}
	one, _ := run("query A")
	three, rep := run("query A", "query B", "mutation C")
	if three != one {
		t.Fatalf("3 operations sent %d requests, one operation %d", three, one)
	}
	if len(rep.Results) != 3 {
		t.Fatalf("%d results, want 3", len(rep.Results))
	}
	for i, op := range []string{"op=A", "op=B", "op=C"} {
		r := rep.Results[i]
		if r.Operation != op || r.Verdict != rep.Results[0].Verdict || r.Verdict != Alive {
			t.Errorf("result %d: %+v", i, r)
		}
	}
	if rep.Verdicts[Alive] != 3 {
		t.Errorf("%v", rep.Verdicts)
	}
}
