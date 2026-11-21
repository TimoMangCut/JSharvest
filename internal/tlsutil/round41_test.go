package tlsutil

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/marker"
)

func TestRound41AIASendsChromeUA(t *testing.T) {
	root := newCert(t, "Root", nil, true, "")
	inter := newCert(t, "Intermediate", root, true, "")

	var mu sync.Mutex
	var gotUAs []string
	var gotSecCH []string
	aiaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotUAs = append(gotUAs, r.Header.Get("User-Agent"))
		gotSecCH = append(gotSecCH, r.Header.Get("Sec-CH-UA"))
		mu.Unlock()
		_, _ = w.Write(inter.der)
	}))
	defer aiaSrv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(root.cert)

	// 1. Default UA falls back to marker.FallbackUA, never Go-http-client.
	leaf1 := newCert(t, "leaf1", inter, false, aiaSrv.URL+"/inter1.crt")
	srv1 := leafServer(t, leaf1)
	a1 := New()
	a1.Roots, a1.AllowPrivate = roots, true
	if err := get(a1, srv1.URL); err != nil {
		t.Fatalf("default UA AIA fetch failed: %v", err)
	}

	// 2. Explicit UA (as wired from httpcrawl/replay) is sent verbatim without Sec-CH-UA.
	const customUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
	leaf2 := newCert(t, "leaf2", inter, false, aiaSrv.URL+"/inter2.crt")
	srv2 := leafServer(t, leaf2)
	a2 := New()
	a2.UA = customUA
	a2.Roots, a2.AllowPrivate = roots, true
	if err := get(a2, srv2.URL); err != nil {
		t.Fatalf("custom UA AIA fetch failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(gotUAs) != 2 {
		t.Fatalf("expected 2 AIA fetches, got %d (%v)", len(gotUAs), gotUAs)
	}
	if gotUAs[0] != marker.FallbackUA || strings.Contains(gotUAs[0], "Go-http-client") {
		t.Fatalf("default AIA UA = %q, want %q", gotUAs[0], marker.FallbackUA)
	}
	if gotUAs[1] != customUA {
		t.Fatalf("custom AIA UA = %q, want %q", gotUAs[1], customUA)
	}
	if gotSecCH[0] != "" || gotSecCH[1] != "" {
		t.Fatalf("AIA fetch must not send Sec-CH-UA, got %v", gotSecCH)
	}
}
