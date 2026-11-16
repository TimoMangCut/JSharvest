package httpcrawl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Round 25K: the HTTP engine sends a secure origin the client hints a
// Chrome with its User-Agent sends, and nothing of them over plain http.
func TestClientHintsOnSecureOrigins(t *testing.T) {
	var mu sync.Mutex
	var got []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Proto+" "+r.Header.Get("Sec-CH-UA")+" "+r.Header.Get("Sec-CH-UA-Platform"))
		mu.Unlock()
	})
	tlsSrv := httptest.NewUnstartedServer(h)
	tlsSrv.EnableHTTP2 = true
	tlsSrv.StartTLS()
	defer tlsSrv.Close()
	plain := httptest.NewServer(h)
	defer plain.Close()
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
	c, err := newClient(Options{UserAgent: ua, Insecure: true, Rate: 100, AllowPrivate: true}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.get(context.Background(), tlsSrv.URL+"/a", "", document)
	c.get(context.Background(), plain.URL+"/b", "", document)
	mu.Lock()
	defer mu.Unlock()
	want := []string{`HTTP/2.0 "Google Chrome";v="155", "Chromium";v="155", "Not)A;Brand";v="24" "Windows"`, "HTTP/1.1  "}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %q, want %q", got, want)
	}
}
