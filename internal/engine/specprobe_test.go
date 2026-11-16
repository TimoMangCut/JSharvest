package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/browser"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

func TestSpecFilesPhase2CrossOriginNoCORSAndPolicyReuse(t *testing.T) {
	var mu sync.Mutex
	var optionsHits int
	var docHits int

	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.Method == http.MethodOptions {
			optionsHits++
		}
		mu.Unlock()
		if r.Method == http.MethodOptions {
			http.Error(w, "CORS preflight forbidden", http.StatusForbidden)
			return
		}
		// Intentionally omit Access-Control-Allow-Origin while requiring custom client_id header.
		if r.Header.Get("client_id") != "PORTAL_WEB" {
			http.Error(w, "missing client_id", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/orders/v2/api-docs" {
			mu.Lock()
			docHits++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"swagger":"2.0","info":{"title":"Orders","version":"1.0"},"paths":{"/v1/orders":{"get":{"operationId":"listOrders"}}}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer gwSrv.Close()
	gwURL, _ := url.Parse(gwSrv.URL)

	dir := t.TempDir()
	st, err := store.Open(dir, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Flush()

	hostRules := fmt.Sprintf("MAP app.example.com 127.0.0.1, MAP api.example.com %s", gwURL.Host)
	rules, err := netsafe.ParseHostRules(hostRules)
	if err != nil {
		t.Fatal(err)
	}
	targetURL, _ := url.Parse("http://app.example.com/")
	inScope, err := scope.New("app.example.com", "rdn")
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Target:  targetURL,
		InScope: inScope,
		Browser: browser.Options{HostRules: hostRules},
	}
	e := &engine{
		runState: &runState{
			cfg:       cfg,
			st:        st,
			privRules: rules,
			privOff:   true,
			scripts:   map[string]bool{},
		},
	}
	c := &crawl{seedOrigin: "http://app.example.com"}
	r := jsapi.Extract([]byte(fmt.Sprintf(`
const api = axios.create({
  baseURL: "http://api.example.com:%s",
  headers: { "client_id": "PORTAL_WEB" }
});
api.get("/orders/v1/list");
`, gwURL.Port())))
	c.specCtx.AddScript(r, "http://app.example.com/dashboard", "http://app.example.com/app.js")

	p1 := c.getSpecPolicy(cfg)
	p2 := c.getSpecPolicy(cfg)
	if p1 != p2 {
		t.Fatal("expected getSpecPolicy to reuse a single cached *resolve.Policy instance")
	}

	e.specFilesPhase2(context.Background(), c, "http://app.example.com/dashboard")
	c.closeSpecClient()

	mu.Lock()
	defer mu.Unlock()
	if optionsHits != 0 {
		t.Fatalf("cross-origin spec probe sent %d CORS OPTIONS preflights, want 0", optionsHits)
	}
	if docHits != 1 || st.Len() != 1 {
		t.Fatalf("expected cross-origin OpenAPI spec to be stored without CORS (docHits=%d, store=%d)", docHits, st.Len())
	}
}

func TestSpecProbeDirectUsesProxyAndAutoBrakesOnNetErr(t *testing.T) {
	// 1. Verify directSpecFetch honors Browser.Proxy for public cross-origin hosts.
	var mu sync.Mutex
	var proxiedURLs []string
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		proxiedURLs = append(proxiedURLs, r.RequestURI)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"openapi":"3.0.0","info":{"title":"ViaProxy","version":"1.0"},"paths":{}}`)
	}))
	defer proxySrv.Close()

	dir := t.TempDir()
	st, err := store.Open(dir, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	targetURL, _ := url.Parse("http://app.public-example.org/")
	inScope, _ := scope.New("app.public-example.org", "rdn")
	cfg := Config{
		Target:  targetURL,
		InScope: inScope,
		Browser: browser.Options{Proxy: proxySrv.URL},
	}
	e := &engine{
		runState: &runState{
			cfg:     cfg,
			st:      st,
			privOff: false,
			scripts: map[string]bool{},
		},
	}
	c := &crawl{seedOrigin: "http://app.public-example.org"}
	res, err := e.specProbeFetch(context.Background(), c, "http://api.public-example.org/openapi.json", map[string]string{"client_id": "WEB"})
	c.closeSpecClient()
	if err != nil || res.Status != http.StatusOK {
		t.Fatalf("specProbeFetch via proxy failed: status=%d err=%v", res.Status, err)
	}
	mu.Lock()
	gotProxied := len(proxiedURLs)
	mu.Unlock()
	if gotProxied != 1 {
		t.Fatalf("expected request to traverse configured proxy once, got %d (%v)", gotProxied, proxiedURLs)
	}

	// 2. Verify D3 auto-brake trips after 2 consecutive neterr failures on an unreachable gateway.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close() // closed port -> immediate connection refused (Status = -1)

	var dialAttempts int
	cDead := &crawl{seedOrigin: "http://app.example.com"}
	deadRules, _ := netsafe.ParseHostRules("MAP dead-gw.example.com " + deadAddr)
	eDead := &engine{
		runState: &runState{
			cfg: Config{
				Target:  targetURL,
				InScope: func(string) bool { return true },
				Browser: browser.Options{HostRules: "MAP dead-gw.example.com " + deadAddr},
			},
			st:        st,
			privRules: deadRules,
			privOff:   true,
			scripts:   map[string]bool{},
		},
	}
	// Inject custom counting transport over closed port to count exact service probe attempts.
	dialer := &netsafe.Dialer{
		HostRules:    deadRules,
		AllowPrivate: true,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialAttempts++
			mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	cDead.specTr = &http.Transport{DialContext: dialer.DialContext}
	cDead.specHTTP = &http.Client{Transport: cDead.specTr}

	r := jsapi.Extract([]byte(`
fetch("http://dead-gw.example.com/svc1/v1/a");
fetch("http://dead-gw.example.com/svc2/v1/a");
fetch("http://dead-gw.example.com/svc3/v1/a");
fetch("http://dead-gw.example.com/svc4/v1/a");
fetch("http://dead-gw.example.com/svc5/v1/a");
`))
	cDead.specCtx.AddScript(r, "http://app.example.com/", "http://app.example.com/app.js")
	eDead.specFilesPhase2(context.Background(), cDead, "http://app.example.com/")
	cDead.closeSpecClient()

	mu.Lock()
	gotDials := dialAttempts
	mu.Unlock()
	// Plan.Bases is empty (only origin-level services svc1..svc5 -> 10 potential probes).
	// With neterr D3 auto-brake, it must stop right after 2 failed probes!
	if gotDials != 2 {
		t.Fatalf("expected D3 neterr auto-brake to stop after 2 failed probes, got %d dial attempts", gotDials)
	}
}
