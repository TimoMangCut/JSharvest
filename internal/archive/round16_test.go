package archive

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/replay"
	"github.com/TimoMangCut/JSharvest/internal/store"
)

// Reviewer round 16 (ARC-01 → ARC-09).

// ARC-01: the Wayback keeps http://; today's server sends it on to https.
func TestLiveUpgrade(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/static/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, "fetch('/api/x')")
			return
		}
		http.NotFound(w, r)
	}))
	defer tlsSrv.Close()
	tu, _ := url.Parse(tlsSrv.URL)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/static/app.js", "/static/gone.js":
			w.Header().Set("Location", "https://"+tu.Host+r.URL.RequestURI())
		default: // elsewhere: a login page is no copy of the script
			w.Header().Set("Location", "https://"+tu.Host+"/login")
		}
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer plain.Close()
	pu, _ := url.Parse(plain.URL)
	hosts := map[string]bool{pu.Host: true, tu.Host: true}
	s, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Hosts: hosts, Insecure: true, Max: 20})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := &runner{o: Options{Sender: s, LiveHosts: hosts}}
	ctx := context.Background()
	alive, body, at := r.liveCheck(ctx, plain.URL+"/static/app.js")
	if alive == nil || !*alive || string(body) != "fetch('/api/x')" || at != tlsSrv.URL+"/static/app.js" {
		t.Fatalf("upgraded: %v %q %s", alive, body, at)
	}
	for _, p := range []string{"/static/gone.js", "/static/moved.js"} {
		if alive, _, _ := r.liveCheck(ctx, plain.URL+p); alive == nil || *alive {
			t.Errorf("%s: %v", p, alive)
		}
	}
	// A host neither crawled nor the target: not asked.
	r.o.LiveHosts = map[string]bool{"other.test": true}
	if alive, _, _ := r.liveCheck(ctx, plain.URL+"/static/app.js"); alive != nil {
		t.Fatalf("asked a host not allowed: %v", *alive)
	}
	// No answer on port 80 at all: https is asked; a port named is kept.
	u, _ := url.Parse("http://app.test/a.js")
	if up := upgrade(u, replay.Answer{Err: "connection refused"}, nil); up == nil || up.String() != "https://app.test/a.js" {
		t.Fatalf("refused: %v", up)
	}
	u, _ = url.Parse("http://app.test:8080/a.js")
	if up := upgrade(u, replay.Answer{Err: "connection refused"}, nil); up != nil {
		t.Fatalf("a port named: %v", up)
	}
	u, _ = url.Parse("http://app.test/a.js?v=1")
	if up := upgrade(u, replay.Answer{Status: 301, Header: map[string]string{"location": "https://app.test/a.js"}}, nil); up != nil {
		t.Fatalf("the query dropped: %v", up)
	}
}

// ARC-02: OTX answers a subdomain under hostname, an IP under IPv4.
func TestOTXSection(t *testing.T) {
	for host, want := range map[string]string{
		"example.vn": "domain", "admin.example.vn": "hostname", "example.co.uk": "domain", "www.example.co.uk": "hostname",
		"127.0.0.1": "IPv4", "[::1]": "IPv6",
	} {
		if got := otxSection(host); got != want {
			t.Errorf("%s: %s, want %s", host, got, want)
		}
	}
	var asked string
	var askedMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		askedMu.Lock()
		asked = r.URL.Path
		askedMu.Unlock()
		io.WriteString(w, `{"url_list":[{"url":"https://a.b.test/x.js","date":"2024-01-02T03:04:05","httpcode":200}],"has_next":false}`)
	}))
	defer srv.Close()
	o := &OTX{Base: srv.URL, Client: newClient(), Budget: &Budget{}}
	caps, more, err := o.Page(context.Background(), "a.b.test", 1)
	if err != nil || more || len(caps) != 1 || asked != "/api/v1/indicators/hostname/a.b.test/url_list" {
		t.Fatalf("%v %v %v %s", caps, more, err, asked)
	}
}

// ARC-05: the CDX server's "Temporarily Offline" page, as a 200 and as a
// 502, is waited out.
func TestWaybackOffline(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			io.WriteString(w, "<html><head><title>Internet Archive: Temporarily Offline</title></head></html>")
		case 2:
			w.WriteHeader(502)
			io.WriteString(w, "<html>Bad Gateway</html>")
		default:
			io.WriteString(w, `[["timestamp","original","mimetype","statuscode","digest"],["20240101000000","https://a.test/x.js","application/javascript","200","D"]]`)
		}
	}))
	defer srv.Close()
	c := newClient()
	c.Wait = time.Millisecond
	w := &Wayback{Base: srv.URL, Client: c, Index: &Budget{}, PageSize: 10}
	caps, _, err := w.Page(context.Background(), "a.test", "")
	if err != nil || len(caps) != 1 || n.Load() != 3 {
		t.Fatalf("%v %v %d", caps, err, n.Load())
	}
	// Offline every time: unavailable, not a parse error.
	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html>Temporarily Offline</html>")
	}))
	defer off.Close()
	w.Base = off.URL
	if _, _, err := w.Page(context.Background(), "a.test", ""); err == nil || !strings.Contains(err.Error(), ErrUnavailable.Error()) {
		t.Fatalf("offline: %v", err)
	}
}

func testRunner(t *testing.T, o Options) *runner {
	t.Helper()
	o.Dir = t.TempDir()
	if o.InScope == nil {
		o.InScope = func(string) bool { return true }
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	r := &runner{o: o, done: map[string]bool{}, cred: map[string]bool{}, namedURLs: map[string]bool{}}
	r.st.Summary.Listed, r.st.Summary.Skipped = map[string]int{}, map[string]int{}
	var err error
	if r.urls, err = appendFile(filepath.Join(o.Dir, "urls.jsonl")); err != nil {
		t.Fatal(err)
	}
	if r.js, err = appendFile(filepath.Join(o.Dir, "js.jsonl")); err != nil {
		t.Fatal(err)
	}
	if r.html, err = appendFile(filepath.Join(o.Dir, "html.jsonl")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.urls.Close(); r.js.Close(); r.html.Close() })
	return r
}

// ARC-05: one source down; the others list, and the next run lists it on.
func TestListGoesOn(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer down.Close()
	otx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"url_list":[{"url":"https://a.test/x.js","date":"2024-01-02T03:04:05","httpcode":200},{"url":"https://a.test/x.js","date":"2024-01-03T03:04:05","httpcode":200}],"has_next":false}`)
	}))
	defer otx.Close()
	c := newClient()
	c.Wait = time.Millisecond
	r := testRunner(t, Options{Host: "a.test", Sources: []string{"wayback", "otx"},
		Wayback: &Wayback{Base: down.URL, Client: c, Index: &Budget{}, PageSize: 10},
		OTX:     &OTX{Base: otx.URL, Client: c, Budget: &Budget{}}})
	if err := r.list(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.st.Summary.Listed["otx"] != 2 || !r.partial || r.st.Wayback.Done || len(r.st.Summary.Notes) != 1 {
		t.Fatalf("listed %v, partial %v, notes %v", r.st.Summary.Listed, r.partial, r.st.Summary.Notes)
	}
	// ARC-06: a URL listed twice is one URL.
	r.urls.Sync()
	if n := distinctURLs(filepath.Join(r.o.Dir, "urls.jsonl")); n != 1 {
		t.Fatalf("%d URLs", n)
	}
}

// ARC-03: since -since, only revisits of a script: it is fetched at the
// newest revisit. ARC-04: a URL without a digest is dropped only when the
// CDX's group of it is fetched.
func TestGroupsRevisitOnly(t *testing.T) {
	r := testRunner(t, Options{})
	at := func(ts string) time.Time { t, _ := time.Parse(tsLayout, ts); return t }
	enc := json.NewEncoder(r.js)
	for _, c := range []Capture{
		{URL: "https://a.test/old.js", Timestamp: "20230101000000", Time: at("20230101000000"), MIME: "warc/revisit", Status: "-", Digest: "R", Source: "wayback"},
		{URL: "https://a.test/old.js", Timestamp: "20240101000000", Time: at("20240101000000"), MIME: "warc/revisit", Status: "-", Digest: "R", Source: "wayback"},
		{URL: "https://a.test/old.js", Source: "otx"},
		{URL: "https://a.test/new.js", Source: fromHTML, Timestamp: "20240201000000", Time: at("20240201000000")},
	} {
		enc.Encode(c)
	}
	gs, err := r.groups()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, g := range gs {
		got = append(got, g.key+" "+g.latest.Timestamp)
	}
	slices.Sort(got)
	want := []string{"R 20240101000000", "url:https://a.test/new.js 20240201000000"}
	if !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
}

// ARC-07, ARC-08, ARC-09.
func TestClassifyRound16(t *testing.T) {
	cur := &current{catalogs: [][]endpoints.Endpoint{{
		{Method: "GET", Path: "/v2.0/scooters/{}"},
		{Method: "GET", Path: "/v2/users"},
	}}}
	dir := t.TempDir()
	today := []byte(`const r={invoice:` + "`billing/v1.0/invoices/${id}`" + `};`)
	os.WriteFile(filepath.Join(dir, "a.js"), today, 0o600)
	cur.jsDirs = []string{dir}
	archived := []endpoints.Endpoint{
		{Method: "GET", Path: "/v1.0/scooters/{}"},
		{Method: "GET", Path: "/v1/users"},
		{Method: "POST", Path: "/legacy/v1.0/export", Bases: []string{"/api-gateway"}, Body: []string{"from"}},
		{Method: "GET", Path: "/billing/v1.0/invoices/{}", Bases: []string{"/api-gateway"}},
	}
	lines, inCode := classify(archived, cur, func(string) (store.Entry, bool) { return store.Entry{}, false })
	var got []string
	for _, l := range lines {
		got = append(got, l.Class+" "+l.Path+" "+strings.Join(l.Bases, ","))
	}
	want := []string{"version_changed /v1.0/scooters/{} ", "version_changed /v1/users ", "historical /legacy/v1.0/export /api-gateway",
		"in_current_code /billing/v1.0/invoices/{} /api-gateway"}
	if !slices.Equal(got, want) || inCode != 1 {
		t.Fatalf("%v %d", got, inCode)
	}
}

func TestInScriptsRelative(t *testing.T) {
	files := [][]byte{[]byte(`get("system-user/v1.0/admin/roles/"+id);put(` + "`system-user/v1.0/admin/roles/${id}/status`" + `);x="foo-billing/v1.0/plans"`)}
	for p, want := range map[string]bool{
		"/system-user/v1.0/admin/roles/{}/status": true,  // after the quote, without its slash
		"/billing/v1.0/plans":                     false, // inside another word: no
		"/api-gateway/system-user/v1.0/admin":     false,
	} {
		if got := inScripts(endpoints.Endpoint{Path: p}, files); got != want {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
}
