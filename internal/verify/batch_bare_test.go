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

// A draft with no operation is the same request as one with an operation
// when nothing else differs: it is not sent again.
func TestRunBareDraftIsNotSentAgain(t *testing.T) {
	count := func(mk func(d Draft) []Draft) int {
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
			Catalog: []endpoints.Endpoint{{Method: "GET", Path: "/api/items", Bases: []string{srv.URL}, Confidence: "code", Kind: "fetch"}}}
		base := Drafts(in)[0]
		s, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 100})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if _, err := Run(context.Background(), Options{Target: "t", Role: "anon", Drafts: mk(base), Sender: s, InScope: in.InScope}); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		return n
	}
	one := count(func(d Draft) []Draft { return []Draft{d} })
	two := count(func(d Draft) []Draft {
		e := d
		e.ID, e.Operation = "0002", "op=A"
		return []Draft{d, e}
	})
	if one != two {
		t.Fatalf("a bare draft and one of an operation sent %d requests, one draft %d", two, one)
	}
}
