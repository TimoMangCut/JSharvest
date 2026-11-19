package httpcrawl

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// crawlOne runs a depth-1 crawl of seed, recording pages and requests.
func crawlOne(t *testing.T, seed string, timeout time.Duration) (pages []Page, reqs []traffic.Entry, res *Result, took time.Duration) {
	t.Helper()
	u, _ := url.Parse(seed)
	var mu sync.Mutex
	began := time.Now()
	res, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Depth: 1, Rate: 200, MaxPages: 500,
		Timeout: timeout, NoSpecProbe: true,
		Script: func(Script) {},
		Page: func(p Page) {
			mu.Lock()
			pages = append(pages, p)
			mu.Unlock()
		},
		Request: func(e traffic.Entry) {
			mu.Lock()
			reqs = append(reqs, e)
			mu.Unlock()
		},
		Log: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	return pages, reqs, res, time.Since(began)
}

// A1: an origin that only ever answers 404 (slowly) is settled by its first
// answer: its pages then run at the crawl's page concurrency instead of one
// at a time for ever.
func TestRound371SlowNotFoundOriginSettlesAndRunsConcurrently(t *testing.T) {
	var inflight, peak atomic.Int32
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inflight.Add(1)
		defer inflight.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(400 * time.Millisecond)
		http.NotFound(w, r)
	}))
	defer slow.Close()
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString("<!doctype html><title>seed</title>")
		for i := range 12 {
			fmt.Fprintf(&b, `<a href="%s/admin%d">x</a>`, slow.URL, i)
		}
		w.Write([]byte(b.String()))
	}))
	defer seed.Close()
	_, _, _, took := crawlOne(t, seed.URL+"/", 10*time.Second)
	if peak.Load() < 2 {
		t.Errorf("the 404 origin never had two pages in flight (peak %d): it stayed unsettled", peak.Load())
	}
	if took > 3*time.Second {
		t.Errorf("12 slow 404 pages took %s: serialized (one at a time would be ~4.8s)", took)
	}
}

// A1: a 3xx page with an HTML body (nginx's "302 Found") is no shell: no
// print, no SPA check on its origin; its Location is followed.
func TestRound371RedirectPageIsNoShellAndLocationIsFollowed(t *testing.T) {
	var slugAsked atomic.Int32
	var targetHit atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><title>seed</title><a href="/go">go</a>`)
		case r.URL.Path == "/go":
			// A Location with no matching link in the body.
			w.Header().Set("Location", "/landing")
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusFound)
			fmt.Fprint(w, `<html><head><title>302 Found</title></head><body><h1>302 Found</h1></body></html>`)
		case r.URL.Path == "/landing":
			targetHit.Add(1)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><title>landing</title>`)
		default:
			slugAsked.Add(1)
			http.NotFound(w, r)
		}
	})
	// The seed's origin settles with a shell; the redirect page must not
	// replace or add one. Depth 2 so that /landing (found at depth 1) is
	// visited.
	u, _ := url.Parse(srv.URL + "/")
	var pages []Page
	var mu sync.Mutex
	if _, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Depth: 2, Rate: 200, MaxPages: 50, NoSpecProbe: true,
		Script: func(Script) {}, Page: func(p Page) { mu.Lock(); pages = append(pages, p); mu.Unlock() }, Log: func(string, ...any) {}}); err != nil {
		t.Fatal(err)
	}
	if targetHit.Load() != 1 {
		t.Errorf("the redirect's Location /landing was not followed (hits %d): %+v", targetHit.Load(), pages)
	}
	for _, p := range pages {
		if p.URL == srv.URL+"/go" && p.Shell {
			t.Errorf("the 302 page was taken for the shell: %+v", p)
		}
	}
}

// blackholeAddr is a listening socket whose accept queue is full: dials to
// it time out, as to a firewalled port.
func blackholeAddr(t *testing.T) (string, func()) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skip(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Skip(err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Skip(err)
	}
	sa, _ := syscall.Getsockname(fd)
	addr := fmt.Sprintf("127.0.0.1:%d", sa.(*syscall.SockaddrInet4).Port)
	var fill []net.Conn
	for range 8 {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			break
		}
		fill = append(fill, c)
	}
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		c.Close()
		t.Skip("cannot make a blackhole port here")
	}
	return addr, func() {
		for _, c := range fill {
			c.Close()
		}
		syscall.Close(fd)
	}
}

// F4: pages the dial breaker holds are not visits and leave no line in
// requests.jsonl; only the dials that were made are logged.
func TestRound371DialBreakerHeldPagesAreNotRequestsOrVisits(t *testing.T) {
	addr, done := blackholeAddr(t)
	defer done()
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString("<!doctype html><title>seed</title>")
		for i := range 9 {
			fmt.Fprintf(&b, `<a href="http://%s/admin%d">x</a>`, addr, i)
		}
		w.Write([]byte(b.String()))
	}))
	defer seed.Close()
	pages, reqs, res, took := crawlOne(t, seed.URL+"/", time.Second)
	var held, logged int
	for _, p := range pages {
		if p.Reason == OriginUnreachable {
			held++
			if p.Visited {
				t.Errorf("a held page counted as visited: %+v", p)
			}
		}
	}
	for _, e := range reqs {
		if strings.Contains(e.URL, addr) {
			logged++
			if strings.Contains(e.Outcome, "breaker") {
				t.Errorf("a held request was logged as sent: %+v", e)
			}
		}
	}
	if held < 5 || logged > 4 || logged+held != 9 {
		t.Errorf("held %d, logged %d of 9 dead links (want the breaker to hold most, and every link either sent or held)", held, logged)
	}
	if res.Stats.HeldByBreaker < held {
		t.Errorf("Stats.HeldByBreaker %d < held pages %d", res.Stats.HeldByBreaker, held)
	}
	if res.Listed[OriginUnreachable] != held {
		t.Errorf("Listed[%s] = %d, want %d", OriginUnreachable, res.Listed[OriginUnreachable], held)
	}
	if took > 8*time.Second {
		t.Errorf("9 dead links took %s", took)
	}
}

// A3: an origin that accepts TCP but never finishes TLS is held after three
// handshake timeouts; the rest of its links fail at once.
func TestRound371OriginBreakerHoldsTLSHangAfterThreeFailures(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var conns sync.Map
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Store(c, true) // held open, never answered
		}
	}()
	defer conns.Range(func(k, _ any) bool { k.(net.Conn).Close(); return true })
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString("<!doctype html><title>seed</title>")
		for i := range 8 {
			fmt.Fprintf(&b, `<a href="https://%s/p%d">x</a>`, ln.Addr().String(), i)
		}
		w.Write([]byte(b.String()))
	}))
	defer seed.Close()
	pages, reqs, _, took := crawlOne(t, seed.URL+"/", time.Second)
	held, sent := 0, 0
	for _, p := range pages {
		if p.Reason == OriginUnreachable {
			held++
		}
	}
	for _, e := range reqs {
		if strings.Contains(e.URL, ln.Addr().String()) {
			sent++
		}
	}
	if sent != originFailThreshold || held != 8-originFailThreshold {
		t.Errorf("sent %d, held %d of 8 (want %d sent, the rest held)", sent, held, originFailThreshold)
	}
	if took > 6*time.Second {
		t.Errorf("took %s", took)
	}
}

// headerTimeout is net/http's "timeout awaiting response headers": a
// net.Error whose Timeout is true, after the connection was made.
type headerTimeout struct{}

func (headerTimeout) Error() string   { return "net/http: timeout awaiting response headers" }
func (headerTimeout) Timeout() bool   { return true }
func (headerTimeout) Temporary() bool { return true }

// A3: an origin that has answered is never held for later timeouts, and
// one host's port says nothing of another's.
func TestRound371OriginHealthKeyedByOriginAndProvenOriginsNeverHeld(t *testing.T) {
	cr := &crawler{origins: map[string]*originHealth{}}
	ctx := context.Background()
	timeout := answer{Err: &url.Error{Op: "Get", URL: "x", Err: headerTimeout{}}}
	// https://h:443 answers once, then times out three times: never held.
	for i := 0; i < 4; i++ {
		turn, err := cr.originEnter(ctx, "https://h/a")
		if err != nil {
			t.Fatalf("proven origin held: %v", err)
		}
		a := timeout
		if i == 0 {
			a = answer{Status: 200}
		}
		cr.originLeave(ctx, turn, a)
	}
	// https://h:8443 never answers: held after three failures.
	for i := 0; i < originFailThreshold; i++ {
		turn, err := cr.originEnter(ctx, "https://h:8443/a")
		if err != nil {
			t.Fatalf("held too early at %d: %v", i, err)
		}
		cr.originLeave(ctx, turn, timeout)
	}
	if _, err := cr.originEnter(ctx, "https://h:8443/b"); !heldByBreaker(err) {
		t.Fatalf("https://h:8443 not held after %d failures: %v", originFailThreshold, err)
	}
	if turn, err := cr.originEnter(ctx, "https://h/b"); err != nil {
		t.Fatalf("https://h held because of :8443: %v", err)
	} else {
		cr.originLeave(ctx, turn, answer{Status: 200})
	}
}
