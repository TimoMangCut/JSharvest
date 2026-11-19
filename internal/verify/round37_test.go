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

func TestRound37HostInFlightPreservesSubCanaryAndRootShellRejection(t *testing.T) {
	// Validates both B2 (subCanary singleflight race on /api/applications/admin/*)
	// and B3 (cross-prefix root HTML shell learning when /api/v2/<canary> returns 404 JSON
	// while /api/v2/missing-page falls back to the origin's 200 SPA HTML shell)
	// across repeated concurrent runs with Concurrency=8, HostInFlight=4.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/f5-admin":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.<br><br>Your support ID is: 1234567890</body></html>`))
		case strings.HasPrefix(r.URL.Path, "/api/applications/admin/"):
			// Delay the sub-canary slightly so concurrent /admin probes definitely hit the ready wait!
			if !strings.HasSuffix(r.URL.Path, "/all") && !strings.HasSuffix(r.URL.Path, "/drilldown") && !strings.HasSuffix(r.URL.Path, "/audit") {
				time.Sleep(25 * time.Millisecond)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<html><head><title>Corporate Proxy Policy</title></head><body>Access to administrative URI segment is restricted by gateway policy across all endpoints.</body></html>`))
		case r.URL.Path == "/api/applications/search":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"items":[],"total":0}`))
		case strings.HasPrefix(r.URL.Path, "/api/v2/"):
			if r.URL.Path == "/api/v2/missing-route" {
				// Falls back to root SPA shell even though /api/v2/<canary> returned 404 JSON!
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`<!doctype html><html><head><title>Portal App</title><script src="/main.js"></script></head><body><div id="root">Welcome to the portal single page application shell</div></body></html>`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"code":"404","message":"v2 not found"}`))
		case strings.HasPrefix(r.URL.Path, "/api/"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"code":"404","message":"not found"}`))
		default:
			// Root /<canary> returns the SPA HTML shell after 30ms.
			time.Sleep(30 * time.Millisecond)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>Portal App</title><script src="/main.js"></script></head><body><div id="root">Welcome to the portal single page application shell</div></body></html>`))
		}
	}))
	defer srv.Close()

	for iter := range 5 {
		sender, err := replay.NewSender(replay.SenderOptions{
			AllowPrivate: true,
			Concurrency:  8,
			OnBlock:      replay.OnBlockSkip,
		})
		if err != nil {
			t.Fatal(err)
		}
		drafts := []Draft{
			{ID: "0001", Source: "static", Method: "GET", Path: "/api/applications/search", URL: srv.URL + "/api/applications/search", Confidence: "code", Tier: Ready},
			{ID: "0002", Source: "static", Method: "GET", Path: "/api/applications/admin/export/all", URL: srv.URL + "/api/applications/admin/export/all", Confidence: "code", Tier: Ready},
			{ID: "0003", Source: "static", Method: "GET", Path: "/api/applications/admin/drilldown", URL: srv.URL + "/api/applications/admin/drilldown", Confidence: "code", Tier: Ready},
			{ID: "0004", Source: "static", Method: "GET", Path: "/api/applications/admin/audit", URL: srv.URL + "/api/applications/admin/audit", Confidence: "code", Tier: Ready},
			{ID: "0005", Source: "static", Method: "GET", Path: "/api/v1/f5-admin", URL: srv.URL + "/api/v1/f5-admin", Confidence: "code", Tier: Ready},
			{ID: "0006", Source: "static", Method: "GET", Path: "/api/v2/missing-route", URL: srv.URL + "/api/v2/missing-route", Confidence: "code", Tier: Ready},
		}
		rep, err := Run(context.Background(), Options{
			Target:       "127.0.0.1",
			Role:         "anon",
			Drafts:       drafts,
			Sender:       sender,
			InScope:      func(string) bool { return true },
			Concurrency:  8,
			HostInFlight: 4,
		})
		_ = sender.Close()
		if err != nil {
			t.Fatalf("iter %d verify.Run: %v", iter, err)
		}
		got := map[string]string{}
		for _, r := range rep.Results {
			got[r.ID] = r.Verdict
		}
		if got["0001"] != Alive {
			t.Fatalf("iter %d: 0001 got %q, want %q", iter, got["0001"], Alive)
		}
		for _, id := range []string{"0002", "0003", "0004"} {
			if got[id] != DeadOrFP {
				t.Fatalf("iter %d: sub-canary admin block %s got %q, want %q", iter, id, got[id], DeadOrFP)
			}
		}
		if got["0005"] != WAFBlocked {
			t.Fatalf("iter %d: 0005 got %q, want %q", iter, got["0005"], WAFBlocked)
		}
		if got["0006"] != DeadOrFP {
			t.Fatalf("iter %d: cross-prefix SPA shell 0006 got %q, want %q", iter, got["0006"], DeadOrFP)
		}
	}
}

func TestRound37HostInFlightSpeedupAnd429AutoStepDown(t *testing.T) {
	var inFlight atomic.Int32
	var peakInFlight atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := inFlight.Add(1)
		for {
			prev := peakInFlight.Load()
			if cur <= prev || peakInFlight.CompareAndSwap(prev, cur) {
				break
			}
		}
		defer inFlight.Add(-1)
		time.Sleep(60 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/api/v1/live-") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"err":"missing"}`))
	}))
	defer srv.Close()

	var drafts []Draft
	for i := range 12 {
		p := fmt.Sprintf("/api/v1/live-%02d", i)
		drafts = append(drafts, Draft{ID: fmt.Sprintf("d%02d", i), Source: "static", Method: "GET", Path: p, URL: srv.URL + p, Confidence: "code", Tier: Ready})
	}

	sender, err := replay.NewSender(replay.SenderOptions{
		AllowPrivate: true,
		Concurrency:  4,
		Rate:         time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	start := time.Now()
	rep, err := Run(context.Background(), Options{
		Target:       "127.0.0.1",
		Role:         "anon",
		Drafts:       drafts,
		Sender:       sender,
		InScope:      func(string) bool { return true },
		Concurrency:  4,
		HostInFlight: 4,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if peakInFlight.Load() < 3 {
		t.Fatalf("expected >=3 concurrent requests on single host with HostInFlight=4, got peak=%d", peakInFlight.Load())
	}
	// 1 canary (60ms) + 12 probes / 4 in-flight (3 * 60ms = 180ms) = ~240ms vs 13*60ms = 780ms sequential!
	if elapsed > 600*time.Millisecond {
		t.Fatalf("expected parallel single-host verify <600ms, took %v", elapsed)
	}
	if rep.Verdicts[Alive] != 12 {
		t.Fatalf("expected all 12 endpoints verified_alive, got %v", rep.Verdicts)
	}

	// Verify auto-stepdown to 1 after first 429!
	var sent429 atomic.Bool
	var postStepPeak atomic.Int32
	var cur429 atomic.Int32
	srv429 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sent429.Swap(true) {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		c := cur429.Add(1)
		for {
			prev := postStepPeak.Load()
			if c <= prev || postStepPeak.CompareAndSwap(prev, c) {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
		cur429.Add(-1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv429.Close()

	var d429 []Draft
	for i := range 8 {
		p := fmt.Sprintf("/api/v1/item-%02d", i)
		d429 = append(d429, Draft{ID: fmt.Sprintf("r%02d", i), Source: "static", Method: "GET", Path: p, URL: srv429.URL + p, Confidence: "code", Tier: Ready})
	}
	sender2, _ := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Concurrency: 4, Rate: time.Millisecond, OnBlock: replay.OnBlockSkip})
	defer sender2.Close()
	v := &verifier{
		o: Options{
			Target:       "127.0.0.1",
			Role:         "anon",
			Drafts:       d429,
			Sender:       sender2,
			InScope:      func(string) bool { return true },
			Concurrency:  4,
			HostInFlight: 4,
		},
		rep:          &Report{Verdicts: map[string]int{}, Tiers: map[string]int{}, Confidence: map[string]int{}},
		canaries:     map[string]*Canary{},
		htmlShells:   map[string][]Sig{},
		shellHosts:   map[string]map[string]bool{},
		perOrigin:    map[string]int{},
		gates:        map[string]*gate{},
		parents:      map[string]int{},
		hostPrefixes: map[string]int{},
		hostPools:    map[string]*hostSlotPool{},
		specBases:    map[string]*specBaseStat{},
	}
	sender2.Allow(map[string]bool{hostOf(srv429.URL): true}, nil)
	order := v.probeOrder(d429)
	resSlice := make([]*Result, len(d429))
	v.byHost(context.Background(), order, resSlice)
	p := v.poolForHost(hostOf(srv429.URL))
	p.mu.Lock()
	throttled := p.throttled
	p.mu.Unlock()
	if !throttled {
		t.Fatal("expected host pool to latch throttled=true upon first 429")
	}
}
