package httpcrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/scope"
)

func TestSpecProbeThirdPartyChallengeIsolatesPerHostAndXHTMLGuard(t *testing.T) {
	var mu sync.Mutex
	var thirdPartyHits int

	thirdParty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		thirdPartyHits++
		mu.Unlock()
		w.Header().Set("Cf-Mitigated", "challenge")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<!DOCTYPE html><html><title>Just a moment...</title></html>"))
	}))
	defer thirdParty.Close()
	thirdURL, _ := url.Parse(thirdParty.URL)

	appSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<!doctype html><html><head><script src="/app.js"></script><script src="/xhtml-404.js"></script></head><body>ok</body></html>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `
				fetch("http://ext.unrelated.test:%s/v1/videos");
				const client = axios.create({ baseURL: "/api-gw" });
				client.get("orders/v1/list");
			`, thirdURL.Port())
		case "/xhtml-404.js":
			// 200 OK soft-404 XHTML page whose <html tag appears past byte 512,
			// with ambiguous Content-Type.
			w.Header().Set("Content-Type", "application/octet-stream")
			pad := strings.Repeat("<!-- xml header comment padding -->\n", 20)
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">` + "\n" + pad + `<html xmlns="http://www.w3.org/1999/xhtml"><body>Not Found</body></html>`))
		case "/api-gw/orders/v3/api-docs":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"openapi":"3.0.1","info":{"title":"Orders","version":"1.0"},"paths":{"/orders/v1/export":{"post":{"responses":{"200":{"description":"ok"}}}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer appSrv.Close()
	appURL, _ := url.Parse(appSrv.URL)

	targetURL, _ := url.Parse("http://admin.example.test:" + appURL.Port() + "/")
	inScope, err := scope.New("admin.example.test", "rdn")
	if err != nil {
		t.Fatal(err)
	}
	hostRules := fmt.Sprintf("MAP admin.example.test %s, MAP ext.unrelated.test %s", appURL.Hostname(), thirdURL.Hostname())

	var scripts []string
	var specsFound bool
	res, err := Crawl(context.Background(), Options{
		Target:       targetURL,
		InScope:      inScope,
		HostRules:    hostRules,
		AllowPrivate: true,
		NoDNS:        true,
		Probe:        true,
		Rate:         500,
		Timeout:      5 * time.Second,
		Script: func(s Script) {
			mu.Lock()
			defer mu.Unlock()
			scripts = append(scripts, s.URL)
			if slices.Contains(s.Tags, "openapi") && strings.HasSuffix(s.URL, "/api-gw/orders/v3/api-docs") {
				specsFound = true
			}
		},
	})
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}
	if res.Stats.Stopped != "" {
		t.Errorf("3rd-party challenge must not mark crawl Stopped (reason=%q)", res.Stats.Stopped)
	}
	mu.Lock()
	gotThirdHits := thirdPartyHits
	gotSpecs := specsFound
	gotScripts := slices.Clone(scripts)
	mu.Unlock()

	if gotThirdHits == 0 {
		t.Errorf("expected 3rd-party API origin to still be probed")
	}
	if !gotSpecs {
		t.Errorf("expected Phase 2 spec probe to discover /api-gw/orders/v3/api-docs despite 3rd-party 403 challenge; scripts=%v", gotScripts)
	}
	for _, u := range gotScripts {
		if strings.HasSuffix(u, "/xhtml-404.js") {
			t.Errorf("XHTML soft-404 response was stored as a script: %s", u)
		}
	}
	if res.Stats.NotScript == 0 {
		t.Errorf("expected NotScript > 0 for XHTML soft-404 response")
	}
}
