package replay

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// cfPage is a Cloudflare 1xxx page as Cloudflare serves it.
func cfPage(w http.ResponseWriter, status int, code, title string) {
	w.Header().Set("Server", "cloudflare")
	w.Header().Set("CF-Ray", "99aabbccddeeff00-SIN")
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	io.WriteString(w, `<!DOCTYPE html><html><head><title>`+title+`</title></head><body><div id="cf-error-details"><h1>Access denied</h1><span class="cf-error-code">`+code+`</span><p>Error `+code+`</p><a href="https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-`+code+`/">Cloudflare</a></div></body></html>`)
}

const cfDenied = "Access denied | t.test used Cloudflare to restrict access"

func TestClassifyBlock(t *testing.T) {
	cf := map[string]string{"server": "cloudflare", "cf-ray": "1-SIN", "content-type": "text/html"}
	page := func(code, title string) []byte {
		return []byte(`<html><head><title>` + title + `</title></head><body><div id="cf-error-details"><p>Error ` + code + `</p></div></body></html>`)
	}
	with := func(h map[string]string, kv ...string) map[string]string {
		out := map[string]string{}
		for k, v := range h {
			out[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			out[kv[i]] = kv[i+1]
		}
		return out
	}
	for _, c := range []struct {
		name   string
		status int
		hdr    map[string]string
		body   []byte
		kind   BlockKind
		code   string
		wait   time.Duration
	}{
		{"app 403 json behind cloudflare", 403, with(cf, "content-type", "application/json"), []byte(`{"error":"forbidden","message":"Access Denied"}`), "", "", 0},
		{"app 403 html behind cloudflare", 403, cf, []byte(`<html><head><title>Access Denied</title></head><body>403</body></html>`), "", "", 0},
		{"app 200", 200, cf, []byte(`{"ok":true}`), "", "", 0},
		{"cloudflare 1006", 403, cf, page("1006", cfDenied), BlockClient, "1006", 0},
		{"cloudflare 1009 country", 403, cf, page("1009", cfDenied), BlockClient, "1009", 0},
		{"cloudflare 1010 signature", 403, cf, page("1010", cfDenied), BlockSignature, "1010", 0},
		{"cloudflare 1020 rule", 403, cf, page("1020", cfDenied), BlockRequest, "1020", 0},
		{"cloudflare 1015 rate", 429, with(cf, "retry-after", "2"), page("1015", "Rate limited | Cloudflare"), BlockRate, "1015", 2 * time.Second},
		{"plain 429", 429, map[string]string{}, nil, BlockRate, "", 0},
		{"503 retry-after", 503, map[string]string{"retry-after": "7"}, nil, BlockRate, "", 7 * time.Second},
		{"cf-mitigated", 403, with(cf, "cf-mitigated", "challenge"), []byte(`<html></html>`), BlockChallenge, "", 0},
		{"just a moment", 403, cf, []byte(`<html><head><title>Just a moment...</title></head><body>_cf_chl_opt</body></html>`), BlockChallenge, "", 0},
		{"cloudflare 1006 plain text (an API client)", 403, with(cf, "content-type", "text/plain; charset=UTF-8"), []byte("error code: 1006\n"), BlockClient, "1006", 0},
		{"cloudflare 1020 plain text", 403, with(cf, "content-type", "text/plain"), []byte("error code: 1020"), BlockRequest, "1020", 0},
		{"app text 'error code' without cloudflare", 403, map[string]string{"content-type": "text/plain"}, []byte("error code: 1006"), "", "", 0},
		{"cloudflare WAF block page (not a challenge)", 403, cf, []byte(`<html><head><title>Attention Required! | Cloudflare</title></head><body><h1>Sorry, you have been blocked</h1><h2>You are unable to access x.test</h2><script src="/cdn-cgi/challenge-platform/h/g/scripts/jsd/abc/main.js"></script></body></html>`), BlockRequest, "", 0},
		{"akamai deny", 403, map[string]string{"server": "AkamaiGHost", "content-type": "text/html"}, []byte(`<html><head><title>Access Denied</title></head><body>Reference #18.1</body></html>`), BlockRequest, "", 0},
	} {
		b := ClassifyBlock(c.status, c.hdr, c.body)
		switch {
		case c.kind == "" && b != nil:
			t.Errorf("%s: an application's answer read as %s", c.name, b)
		case c.kind != "" && b == nil:
			t.Errorf("%s: no block read, want %s", c.name, c.kind)
		case b != nil && (b.Kind != c.kind || b.Code != c.code || b.RetryAfter != c.wait):
			t.Errorf("%s: %+v, want kind %s code %q wait %s", c.name, b, c.kind, c.code, c.wait)
		}
	}
}

// blockServer answers 200, Cloudflare 1020 for the paths of rule, and
// Cloudflare 1006 to everything once banned is set.
type blockServer struct {
	mu     sync.Mutex
	hits   []string
	uas    []string
	banned atomic.Bool
	rule   string
	srv    *httptest.Server
}

func newBlockServer(t *testing.T, rule string) *blockServer {
	bs := &blockServer{rule: rule}
	bs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bs.mu.Lock()
		bs.hits = append(bs.hits, r.URL.Path)
		bs.uas = append(bs.uas, r.UserAgent())
		bs.mu.Unlock()
		switch {
		case bs.banned.Load():
			cfPage(w, 403, "1006", cfDenied)
		case bs.rule != "" && strings.HasPrefix(r.URL.Path, bs.rule):
			cfPage(w, 403, "1020", cfDenied)
		default:
			w.Header().Set("Server", "cloudflare")
			io.WriteString(w, `{"ok":true}`)
		}
	}))
	t.Cleanup(bs.srv.Close)
	return bs
}

func (bs *blockServer) host() string { return strings.TrimPrefix(bs.srv.URL, "http://") }

func (bs *blockServer) Hits() []string {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return slices.Clone(bs.hits)
}

func get(host, path string) []byte {
	return []byte("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: jsh-test-ua\r\n\r\n")
}

// A rule on one request (1020) marks that answer; the host still answers
// its control, so the run goes on. A ban (1006) on the host gives it up,
// and it alone: the other host is still sent to.
func TestSenderBlockPerRequestThenHost(t *testing.T) {
	a, b := newBlockServer(t, "/rule"), newBlockServer(t, "")
	s, err := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{a.host(): true, b.host(): true}, Max: 50})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	send := func(host, path string) (Answer, error) {
		return s.Send(ctx, get(host, path), "http", "probe", "anon", path, nil)
	}
	if ans, err := send(a.host(), "/ok"); err != nil || ans.Block != nil || ans.Status != 200 {
		t.Fatalf("/ok: %+v %v", ans, err)
	}
	ans, err := send(a.host(), "/rule/x")
	if err != nil || ans.Block == nil || ans.Block.Kind != BlockRequest || ans.Block.Code != "1020" {
		t.Fatalf("/rule/x: %+v %v", ans, err)
	}
	if j := Judge(Case{Trial: ans}); j.Verdict != Blocked {
		t.Fatalf("a 1020 judged %+v", j)
	}
	if s.Stopped() != "" || len(s.BlockedHosts()) != 0 {
		t.Fatalf("a rule on one request stopped the run (%q) or gave the host up (%v)", s.Stopped(), s.BlockedHosts())
	}
	if want := []string{"/ok", "/rule/x", "/ok"}; !slices.Equal(a.Hits(), want) {
		t.Fatalf("hits %v, want %v (the control is the read answered before)", a.Hits(), want)
	}
	if ans, err := send(a.host(), "/after-rule"); err != nil || ans.Status != 200 {
		t.Fatalf("after the rule: %+v %v", ans, err)
	}

	a.banned.Store(true)
	ans, err = send(a.host(), "/banned")
	if err != nil || ans.Block == nil || ans.Block.Kind != BlockClient {
		t.Fatalf("/banned: %+v %v", ans, err)
	}
	why := s.BlockedHosts()[a.host()]
	if !strings.Contains(why, "1006") || !strings.Contains(why, "control") {
		t.Fatalf("host not given up after its control was blocked too: %v", s.BlockedHosts())
	}
	if s.Stopped() != "" {
		t.Fatalf("the run stopped (%q) while another host answers", s.Stopped())
	}
	n := len(a.Hits())
	if _, err := send(a.host(), "/never"); !errors.Is(err, ErrHostBlocked) || !errors.Is(err, errStopped) {
		t.Fatalf("a request to the host given up: %v", err)
	}
	if len(a.Hits()) != n {
		t.Fatal("a request reached the host given up")
	}
	if ans, err := send(b.host(), "/still"); err != nil || ans.Status != 200 {
		t.Fatalf("the other host: %+v %v", ans, err)
	}
}

// The last host given up stops the run. With no read answered before, the
// control is GET / with the request's User-Agent and nothing else.
func TestSenderLastHostStopsRun(t *testing.T) {
	a := newBlockServer(t, "")
	a.banned.Store(true)
	s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{a.host(): true}, Max: 50})
	defer s.Close()
	ans, err := s.Send(context.Background(), get(a.host(), "/api/x"), "http", "probe", "anon", "x", nil)
	if err != nil || ans.Block == nil {
		t.Fatalf("%+v %v", ans, err)
	}
	if !strings.Contains(s.Stopped(), "every host is blocked") {
		t.Fatalf("stopped %q", s.Stopped())
	}
	if want := []string{"/api/x", "/"}; !slices.Equal(a.Hits(), want) {
		t.Fatalf("hits %v, want %v", a.Hits(), want)
	}
	if a.uas[1] != "jsh-test-ua" {
		t.Fatalf("the control's User-Agent %q", a.uas[1])
	}
}

// Many blocks at once ask one control, not one each.
func TestSenderOneControlForConcurrentBlocks(t *testing.T) {
	a, b := newBlockServer(t, ""), newBlockServer(t, "")
	a.banned.Store(true)
	s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{a.host(): true, b.host(): true}, Max: 50, Concurrency: 4})
	defer s.Close()
	var wg sync.WaitGroup
	for _, p := range []string{"/a", "/b", "/c", "/d"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Send(context.Background(), get(a.host(), p), "http", "probe", "anon", p, nil)
		}()
	}
	wg.Wait()
	if c := slices.Index(a.Hits(), "/"); c < 0 || slices.Index(a.Hits()[c+1:], "/") >= 0 {
		t.Fatalf("controls in %v, want exactly one GET /", a.Hits())
	}
	if s.BlockedHosts()[a.host()] == "" {
		t.Fatal("host not given up")
	}
}

// Blocks in a row after a control found the host answering ask again
// every recheckEvery blocks, not at each.
func TestSenderRechecksEveryFewBlocks(t *testing.T) {
	a := newBlockServer(t, "/rule")
	s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{a.host(): true}, Max: 50})
	defer s.Close()
	ctx := context.Background()
	s.Send(ctx, get(a.host(), "/ok"), "http", "probe", "anon", "", nil)
	for range 6 {
		s.Send(ctx, get(a.host(), "/rule/x"), "http", "probe", "anon", "", nil)
	}
	controls := 0
	for _, h := range a.Hits()[1:] {
		if h == "/ok" {
			controls++
		}
	}
	if controls != 2 {
		t.Fatalf("%d controls in %v, want 2 (the first block, the fifth in a row)", controls, a.Hits())
	}
}

// A rate answer to a read waits its Retry-After and asks again; the run
// goes on. A write is not asked again.
func TestSenderRateRetry(t *testing.T) {
	var n atomic.Int32
	var hits []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if n.Add(1) == 1 || r.Method == "POST" {
			w.Header().Set("Retry-After", "1")
			cfPage(w, 429, "1015", "Rate limited | Cloudflare")
			return
		}
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{host: true}, Max: 50})
	defer s.Close()
	began := time.Now()
	ans, err := s.Send(context.Background(), get(host, "/r"), "http", "probe", "anon", "", nil)
	if err != nil || ans.Status != 200 || ans.Block != nil {
		t.Fatalf("%+v %v", ans, err)
	}
	if d := time.Since(began); d < 900*time.Millisecond {
		t.Fatalf("asked again after %s, before its Retry-After", d)
	}
	post := []byte("POST /w HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 2\r\n\r\n{}")
	ans, err = s.Send(context.Background(), post, "http", "probe", "anon", "", nil)
	if err != nil || ans.Block == nil || ans.Block.Kind != BlockRate {
		t.Fatalf("POST: %+v %v", ans, err)
	}
	if j := Judge(Case{Trial: ans, Write: true}); j.Verdict != Unclear {
		t.Fatalf("a rate answer judged %+v", j)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"GET /r", "GET /r", "POST /w"}; !slices.Equal(hits, want) {
		t.Fatalf("hits %v, want %v", hits, want)
	}
	if s.Stopped() != "" || len(s.BlockedHosts()) != 0 {
		t.Fatalf("stopped %q, given up %v", s.Stopped(), s.BlockedHosts())
	}
}

func TestSenderOnBlockModes(t *testing.T) {
	t.Run("stop", func(t *testing.T) {
		a := newBlockServer(t, "/rule")
		s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{a.host(): true}, Max: 50, OnBlock: OnBlockStop})
		defer s.Close()
		s.Send(context.Background(), get(a.host(), "/rule/x"), "http", "probe", "anon", "", nil)
		if !strings.Contains(s.Stopped(), "1020") {
			t.Fatalf("stopped %q", s.Stopped())
		}
		if _, err := s.Send(context.Background(), get(a.host(), "/ok"), "http", "probe", "anon", "", nil); !errors.Is(err, errStopped) {
			t.Fatalf("sent after the stop: %v", err)
		}
		if len(a.Hits()) != 1 {
			t.Fatalf("hits %v", a.Hits())
		}
	})
	t.Run("skip", func(t *testing.T) {
		a := newBlockServer(t, "")
		a.banned.Store(true)
		s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{a.host(): true}, Max: 50, OnBlock: OnBlockSkip})
		defer s.Close()
		for _, p := range []string{"/a", "/b", "/c"} {
			if ans, err := s.Send(context.Background(), get(a.host(), p), "http", "probe", "anon", "", nil); err != nil || ans.Block == nil {
				t.Fatalf("%s: %+v %v", p, ans, err)
			}
		}
		if want := []string{"/a", "/b", "/c"}; !slices.Equal(a.Hits(), want) || s.Stopped() != "" || len(s.BlockedHosts()) != 0 {
			t.Fatalf("hits %v (no control wanted), stopped %q, given up %v", a.Hits(), s.Stopped(), s.BlockedHosts())
		}
	})
	if _, err := ParseOnBlock("ignore"); err == nil {
		t.Fatal("-on-block ignore taken")
	}
}

// Round 25I review: the control request carries no identity: the read
// kept as the host's control is sent again without its Cookie or
// Authorization.
func TestSenderControlCarriesNoCredential(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path+" cookie="+r.Header.Get("Cookie")+" auth="+r.Header.Get("Authorization"))
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/rule") {
			cfPage(w, 403, "1020", cfDenied)
			return
		}
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{host: true}, Max: 20})
	defer s.Close()
	ctx := context.Background()
	withID := func(p string) []byte {
		return []byte("GET " + p + " HTTP/1.1\r\nHost: " + host + "\r\nCookie: sid=admin1\r\nAuthorization: Bearer adm1n\r\n\r\n")
	}
	s.Send(ctx, withID("/ok"), "http", "trial", "admin", "", nil)
	s.Send(ctx, withID("/rule/x"), "http", "trial", "anon", "", nil)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 || seen[2] != "/ok cookie= auth=" {
		t.Fatalf("requests %q: the control (third) must go bare", seen)
	}
}

// Round 25I review: five network errors in a row give that host up, not
// the run: the other host is still sent to.
func TestSenderErrorsPerHost(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadHost := strings.TrimPrefix(dead.URL, "http://")
	dead.Close() // connections refused from now on
	live := newBlockServer(t, "")
	s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{deadHost: true, live.host(): true}, Max: 50, Timeout: 2 * time.Second})
	defer s.Close()
	ctx := context.Background()
	for range 5 {
		s.Send(ctx, get(deadHost, "/x"), "http", "probe", "anon", "", nil)
	}
	if s.BlockedHosts()[deadHost] == "" || s.Stopped() != "" {
		t.Fatalf("given up %v, stopped %q: the dead host alone should be given up", s.BlockedHosts(), s.Stopped())
	}
	if ans, err := s.Send(ctx, get(live.host(), "/y"), "http", "probe", "anon", "", nil); err != nil || ans.Status != 200 {
		t.Fatalf("the live host: %+v %v", ans, err)
	}
}

// Round 25I review: sent.jsonl logs the User-Agent the Sender adds.
func TestSenderLogsAddedUserAgent(t *testing.T) {
	a := newBlockServer(t, "")
	log := t.TempDir() + "/sent.jsonl"
	s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{a.host(): true}, Max: 5, Log: log, UserAgent: "Mozilla/5.0 test-browser"})
	s.Send(context.Background(), []byte("GET /z HTTP/1.1\r\nHost: "+a.host()+"\r\n\r\n"), "http", "probe", "anon", "", nil)
	s.Close()
	b, _ := os.ReadFile(log)
	if !strings.Contains(string(b), `User-Agent: Mozilla/5.0 test-browser`) || a.uas[0] != "Mozilla/5.0 test-browser" {
		t.Fatalf("log %s; sent UA %q", b, a.uas[0])
	}
}

// Round 25J: a control request answered 429 holds the host back by its
// Retry-After, as any rate answer does.
func TestSenderControlRateAnswerPausesHost(t *testing.T) {
	var okHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/rule"):
			cfPage(w, 403, "1020", cfDenied)
		case r.URL.Path == "/ok" && okHits.Add(1) == 2: // the control
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
		default:
			io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{host: true}, Max: 20})
	defer s.Close()
	ctx := context.Background()
	s.Send(ctx, get(host, "/ok"), "http", "probe", "anon", "", nil)
	s.Send(ctx, get(host, "/rule/x"), "http", "probe", "anon", "", nil)
	began := time.Now()
	if ans, err := s.Send(ctx, get(host, "/next"), "http", "probe", "anon", "", nil); err != nil || ans.Status != 200 {
		t.Fatalf("%+v %v", ans, err)
	}
	if d := time.Since(began); d < 800*time.Millisecond {
		t.Fatalf("the next request went after %s: the control's Retry-After was not kept", d)
	}
	if len(s.BlockedHosts()) != 0 || s.Stopped() != "" {
		t.Fatalf("given up %v, stopped %q", s.BlockedHosts(), s.Stopped())
	}
}

// Round 25K: what goes on the wire is the browser's: the run's
// User-Agent, the client hints it sends a secure origin, HTTP/2, no
// hop-by-hop header; and sent.jsonl logs that.
func TestSenderWireIsTheBrowsers(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Proto+"|"+r.UserAgent()+"|"+r.Header.Get("Sec-CH-UA-Platform")+"|"+r.Header.Get("Keep-Alive"))
		mu.Unlock()
		io.WriteString(w, `{"ok":true}`)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	log := t.TempDir() + "/sent.jsonl"
	const ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
	s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{host: true}, Max: 5, Insecure: true, Log: log, UserAgent: ua})
	raw := []byte("GET /a HTTP/1.1\r\nHost: " + host + "\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\r\n")
	if ans, err := s.Send(context.Background(), raw, "https", "probe", "anon", "", nil); err != nil || ans.Status != 200 {
		t.Fatalf("%+v %v", ans, err)
	}
	s.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "HTTP/2.0|"+ua+`|"Linux"|` {
		t.Fatalf("the server saw %q", got)
	}
	b, _ := os.ReadFile(log)
	if !strings.Contains(string(b), `Sec-CH-UA-Platform: \"Linux\"`) || strings.Contains(string(b), "Keep-Alive") {
		t.Fatalf("sent.jsonl: %s", b)
	}
}

// Round 25K: a host's CDN cookies go back with the next requests of the
// role that got them, never another role's, never with a control; the
// session's own cookies are left to the identity.
func TestSenderCDNCookiesPerRole(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("Cookie")
		mu.Unlock()
		if r.URL.Path == "/first" {
			http.SetCookie(w, &http.Cookie{Name: "__cf_bm", Value: "bm1", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "app", Path: "/"})
		}
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{host: true}, Max: 10})
	defer s.Close()
	ctx := context.Background()
	send := func(path, role, cookie string) {
		raw := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n"
		if cookie != "" {
			raw += "Cookie: " + cookie + "\r\n"
		}
		s.Send(ctx, []byte(raw+"\r\n"), "http", "probe", role, "", nil)
	}
	send("/first", "user", "")
	send("/again", "user", "sid=mine; __cf_bm=old")
	send("/other", "admin", "")
	send("/control", "", "")
	mu.Lock()
	defer mu.Unlock()
	if seen["/again"] != "sid=mine; __cf_bm=bm1" {
		t.Errorf("the role's next request: %q (the fresher __cf_bm, its own sid)", seen["/again"])
	}
	if seen["/other"] != "" || seen["/control"] != "" {
		t.Errorf("another role %q, a control %q: neither gets the role's CDN cookies", seen["/other"], seen["/control"])
	}
	id := NewIdentity("user", nil, nil, time.Now())
	u, _ := url.Parse(srv.URL + "/")
	gone, turned := updateJar(id, u, Answer{Header: map[string]string{"set-cookie": "__cf_bm=bm2; Path=/"}})
	if gone != "" || turned || len(id.Jar.Cookies(u)) != 0 {
		t.Errorf("updateJar took a CDN cookie for the session's: gone %q turned %v jar %v", gone, turned, id.Jar.Cookies(u))
	}
}

// Round 25L review: an identity takes no CDN cookie, from the login's
// snapshot or from its traffic: an old __cf_bm or cf_clearance is the
// browser's, not the session's; the Sender keeps the run's own.
func TestIdentityLeavesCDNCookies(t *testing.T) {
	snap := &session.Snapshot{Cookies: []*network.Cookie{
		{Name: "sid", Value: "s1", Domain: "app.x.test", Path: "/"},
		{Name: "cf_clearance", Value: "old", Domain: ".x.test", Path: "/"},
	}}
	u, _ := url.Parse("http://app.x.test/")
	got := func(id *Identity) []string {
		var n []string
		for _, c := range id.Jar.Cookies(u) {
			n = append(n, c.Name)
		}
		return n
	}
	if n := got(NewIdentity("user", snap, nil, time.Now())); !slices.Equal(n, []string{"sid"}) {
		t.Errorf("from the snapshot: %v", n)
	}
	entries := []traffic.Entry{{URL: "http://app.x.test/api", Headers: map[string]string{"cookie": "sid=s2; __cf_bm=old"}}}
	if n := got(NewIdentity("user", nil, entries, time.Now())); !slices.Equal(n, []string{"sid"}) {
		t.Errorf("from the traffic: %v", n)
	}
}
