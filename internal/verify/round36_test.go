package verify

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/replay"
)

func TestRound36SpeculativeBasePruningPreservesLiveBase(t *testing.T) {
	var totalReqs atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalReqs.Add(1)
		if r.URL.Path == "/real-gw/v1/item24" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized","code":"AUTH_REQUIRED"}`))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>Portal</title></head><body><div id="app-root">loading...</div></body></html>`))
	}))
	defer srv.Close()

	specBases := []string{
		srv.URL + "/dead-svc-1",
		srv.URL + "/dead-svc-2",
		srv.URL + "/dead-svc-3",
		srv.URL + "/dead-svc-4",
		srv.URL + "/real-gw",
	}
	var cat []endpoints.Endpoint
	for i := 0; i < 30; i++ {
		cat = append(cat, endpoints.Endpoint{
			Method:     "GET",
			Path:       fmt.Sprintf("{}/v1/item%02d", i),
			Bases:      specBases,
			Confidence: "code",
			Kind:       "client",
		})
	}

	in := Inputs{
		InScope: func(string) bool { return true },
		Intel:   endpoints.Intel{Bases: specBases},
		Catalog: cat,
	}
	drafts := Drafts(in)
	snd, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	defer snd.Close()
	rep, err := Run(context.Background(), Options{
		Target:      srv.URL,
		Role:        "anon",
		InScope:     func(string) bool { return true },
		Drafts:      drafts,
		Sender:      snd,
		Concurrency: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Naive Cartesian probing would send 5 canaries + 30*5 = 155+ requests.
	// With speculative base pruning after 16 dead paths, dead bases stop being probed
	// for drafts 16..29, cutting requests down while STILL finding /real-gw/v1/item24!
	if got := totalReqs.Load(); got >= 120 {
		t.Errorf("expected speculative base pruning to keep requests < 120, got %d", got)
	}
	var aliveItem24 *Result
	for i := range rep.Results {
		if strings.HasSuffix(rep.Results[i].Path, "/v1/item24") {
			aliveItem24 = &rep.Results[i]
		}
	}
	if aliveItem24 == nil || aliveItem24.Verdict != Alive || aliveItem24.VerifiedBase != srv.URL+"/real-gw" {
		t.Fatalf("expected item24 to be verified_alive on /real-gw, got %+v", aliveItem24)
	}
}
