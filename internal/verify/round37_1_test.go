package verify

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/replay"
)

const spaShell = `<!doctype html><html><head><title>Portal App</title><script src="/main.js"></script></head><body><div id="root">Welcome to the portal single page application shell</div></body></html>`

func runVerify(t *testing.T, drafts []Draft, conc, hif, gateAfter int) *Report {
	t.Helper()
	s, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Concurrency: max(conc, hif), OnBlock: replay.OnBlockSkip})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rep, err := Run(context.Background(), Options{Target: "127.0.0.1", Role: "anon", Drafts: drafts, Sender: s,
		InScope: func(string) bool { return true }, Concurrency: conc, HostInFlight: hif, GateAfter: gateAfter})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func verdicts(rep *Report) map[string]string {
	out := map[string]string{}
	for _, r := range rep.Results {
		out[r.ID] = r.Verdict
	}
	return out
}

// C2: the origin's root canary is asked at every -host-inflight, so an SPA
// fallback under a prefix whose own canary is JSON is a catch-all at
// -host-inflight 1 too (round 37 only asked it above 1).
func TestRound371RootCanaryAtEveryConcurrency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2/missing-route":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, spaShell)
		case r.URL.Path == "/api/applications/search":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"items":[]}`)
		case strings.HasPrefix(r.URL.Path, "/api/"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			fmt.Fprint(w, `{"code":"404"}`)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, spaShell)
		}
	}))
	defer srv.Close()
	drafts := []Draft{
		{ID: "0001", Source: "static", Method: "GET", Path: "/api/applications/search", URL: srv.URL + "/api/applications/search", Confidence: "code", Tier: Ready},
		{ID: "0006", Source: "static", Method: "GET", Path: "/api/v2/missing-route", URL: srv.URL + "/api/v2/missing-route", Confidence: "code", Tier: Ready},
	}
	for _, c := range []struct{ conc, hif int }{{1, 1}, {8, 1}, {8, 4}} {
		v := verdicts(runVerify(t, drafts, c.conc, c.hif, 0))
		if v["0001"] != Alive || v["0006"] != DeadOrFP {
			t.Errorf("-concurrency %d -host-inflight %d: 0001=%q 0006=%q, want alive and dead_or_fp", c.conc, c.hif, v["0001"], v["0006"])
		}
	}
}

// C1: a shell two hosts' canaries show (promoted to every host) judges a
// third host's probe the same whether those canaries answered before the
// probe or after it: here always after (they are slow), so only the
// re-judge with every canary known can tell the catch-all.
func TestRound371RejudgeWithEveryCanaryKnown(t *testing.T) {
	const waf = `<html><head><title>Access Policy</title></head><body>This request was blocked by the gateway security policy. Reference 77.</body></html>`
	slowWAF := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, waf)
	})
	a, b := httptest.NewServer(slowWAF), httptest.NewServer(slowWAF)
	defer a.Close()
	defer b.Close()
	c := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/x" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, waf)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		fmt.Fprint(w, `{"error":"no route"}`)
	}))
	defer c.Close()
	drafts := []Draft{
		{ID: "A", Source: "static", Method: "GET", Path: "/svc/a/x", URL: a.URL + "/svc/a/x", Confidence: "code", Tier: Ready},
		{ID: "B", Source: "static", Method: "GET", Path: "/svc/b/x", URL: b.URL + "/svc/b/x", Confidence: "code", Tier: Ready},
		{ID: "C", Source: "static", Method: "GET", Path: "/api/x", URL: c.URL + "/api/x", Confidence: "code", Tier: Ready},
	}
	for range 3 {
		v := verdicts(runVerify(t, drafts, 8, 1, 0))
		if v["C"] != DeadOrFP {
			t.Fatalf("C (the WAF page two other hosts' canaries show) = %q, want %q", v["C"], DeadOrFP)
		}
	}
}

// C4: on a gateway with a 401 wall under one prefix and open routes under
// another, the gate's one-at-a-time ends with the first answer that is not
// the wall: -host-inflight is back for the rest of the run.
func TestRound371GateSerialEndsWhenTheHostIsNotGated(t *testing.T) {
	// Only requests that start after an open route has answered count:
	// before that the gate may legitimately hold the host to one.
	var inflight, peak atomic.Int32
	var opened atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		if opened.Load() {
			n := inflight.Add(1)
			defer inflight.Add(-1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
		}
		defer func() {
			if strings.HasPrefix(r.URL.Path, "/public/items/item") {
				opened.Store(true)
			}
		}()
		time.Sleep(120 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/public/items/item") {
			fmt.Fprint(w, `{"id":1}`)
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, `{"error":"no route"}`)
	}))
	defer srv.Close()
	drafts := []Draft{{ID: "w", Source: "static", Method: "GET", Path: "/api/v1/me", URL: srv.URL + "/api/v1/me", Confidence: "code", Tier: Ready}}
	for i := range 16 {
		p := fmt.Sprintf("/public/items/item%d", i)
		drafts = append(drafts, Draft{ID: fmt.Sprint(i), Source: "static", Method: "GET", Path: p, URL: srv.URL + p, Confidence: "code", Tier: Ready})
	}
	rep := runVerify(t, drafts, 8, 4, 3)
	if peak.Load() < 3 {
		t.Errorf("after the first open route answered, %d in flight at most: the gate's one-at-a-time never ended", peak.Load())
	}
	if len(rep.HostsGated) != 0 {
		t.Errorf("host gated: %v", rep.HostsGated)
	}
}

func TestRound371GateSerialPool(t *testing.T) {
	p := newHostSlotPool(4)
	p.setGateSerial(true)
	rel, ok := p.acquire(context.Background())
	if !ok {
		t.Fatal("first slot refused")
	}
	got := make(chan bool, 1)
	go func() {
		r2, ok := p.acquire(context.Background())
		if ok {
			r2()
		}
		got <- ok
	}()
	select {
	case <-got:
		t.Fatal("a second probe ran while the gate was counted")
	case <-time.After(50 * time.Millisecond):
	}
	p.setGateSerial(false)
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("waiter refused")
		}
	case <-time.After(time.Second):
		t.Fatal("ending the gate's one-at-a-time did not wake the waiting probe")
	}
	rel()
}
