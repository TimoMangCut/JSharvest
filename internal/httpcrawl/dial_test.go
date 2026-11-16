package httpcrawl

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

func fetch(t *testing.T, o Options, raw string) answer {
	t.Helper()
	o.Rate, o.MaxBody = 100, 1<<20
	c, err := newClient(o, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.get(context.Background(), raw, "", document)
}

// P2.1: the client never dials a private address of a public target (not
// the metadata address, not a name that rebinds), and is not told twice.
func TestClientNetsafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hi")) }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	// A name that resolves to the metadata address.
	meta := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	if a := fetch(t, Options{Resolver: meta}, "http://meta.example/x"); !errors.Is(a.Err, netsafe.ErrPrivate) {
		t.Fatalf("metadata: %v", a.Err)
	}
	// DNS failure refuses.
	nx := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nx") }
	if a := fetch(t, Options{Resolver: nx}, "http://nx.example/x"); a.Err == nil {
		t.Fatal("a DNS failure was not a refusal")
	}
	// A public target's loopback is refused; an internal target's is allowed.
	if a := fetch(t, Options{}, srv.URL+"/x"); !errors.Is(a.Err, netsafe.ErrPrivate) && !errors.Is(a.Err, netsafe.ErrLiteral) {
		t.Fatalf("loopback of a public target: %v", a.Err)
	}
	if a := fetch(t, Options{AllowPrivate: true}, srv.URL+"/x"); a.Err != nil || a.Status != 200 {
		t.Fatalf("internal target: %v %d", a.Err, a.Status)
	}
	// -host-resolver-rules: the mapped host is trusted, even a public target;
	// the resolver is not asked.
	var looked int32
	count := func(context.Context, string) ([]netip.Addr, error) {
		atomic.AddInt32(&looked, 1)
		return nil, errors.New("nx")
	}
	if a := fetch(t, Options{HostRules: "MAP *.jsh.test 127.0.0.1", Resolver: count}, "http://app.jsh.test:"+port+"/x"); a.Err != nil || a.Status != 200 || looked != 0 {
		t.Fatalf("host rules: %v %d looked %d", a.Err, a.Status, looked)
	}
	// A proxy on loopback is reached (the proxy's own address is exempt),
	// the target's name is the proxy's to resolve.
	px := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("via proxy")) }))
	defer px.Close()
	pu, _ := url.Parse(px.URL)
	if a := fetch(t, Options{Proxy: pu, Resolver: nx}, "http://anything.example/x"); a.Err != nil || string(a.Body) != "via proxy" {
		t.Fatalf("proxy: %v %q", a.Err, a.Body)
	}
}

// P2.2: through a proxy a redirect to a private host in a number form is
// refused (the proxy would resolve it), and so is a first request to one.
func TestClientProxyRefusesLiteralRedirect(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	px := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Host)
		mu.Unlock()
		if r.Host == "public.example" {
			http.Redirect(w, r, "http://0x7f.1/admin", http.StatusFound)
			return
		}
		w.Write([]byte("proxied"))
	}))
	defer px.Close()
	pu, _ := url.Parse(px.URL)
	a := fetch(t, Options{Proxy: pu, Timeout: 3 * time.Second}, "http://public.example/")
	if a.Status == 200 || (a.Err == nil && a.Status != http.StatusFound) {
		t.Fatalf("the redirect was followed: %d %v", a.Status, a.Err)
	}
	for _, h := range []string{"2130706433", "localhost", "[::ffff:7f00:1]", "LOCALHOST."} {
		if a := fetch(t, Options{Proxy: pu}, "http://"+h+"/"); a.Err == nil || !errors.Is(a.Err, netsafe.ErrLiteral) {
			t.Errorf("%s: %+v", h, a)
		}
	}
	mu.Lock()
	for _, h := range seen {
		if h != "public.example" {
			t.Errorf("the proxy was asked for %q", h)
		}
	}
	mu.Unlock()
	// An internal target is not held to it: a private literal goes through
	// the proxy (loopback never does, as Chrome's <-loopback>).
	if a := fetch(t, Options{Proxy: pu, AllowPrivate: true}, "http://10.0.0.5/"); a.Err != nil || a.Status != 200 {
		t.Fatalf("internal: %+v", a)
	}
}
