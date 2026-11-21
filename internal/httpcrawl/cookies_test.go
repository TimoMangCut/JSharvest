package httpcrawl

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// Round 25L: the crawl hands its escalation the application's cookies it
// holds at the end: not a CDN's, not one deleted since, each with its
// attributes (host-only by its URL, a domain cookie by its Domain).
func TestCrawlCookies(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "region", Value: "vn", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: "__cf_bm", Value: "bm", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "gone", Value: "x", Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!doctype html><title>home</title><script src="/a.js"></script>`))
	})
	mux.HandleFunc("/a.js", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "gone", Value: "", Path: "/", MaxAge: -1})
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`console.log(1)`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/")
	res, err := Crawl(context.Background(), Options{Target: u, InScope: func(string) bool { return true }, Rate: 1000, NoDNS: true,
		Script: func(Script) {}, Page: func(Page) {}, Log: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range res.Cookies {
		names = append(names, c.Name)
	}
	if !slices.Equal(names, []string{"region"}) {
		t.Fatalf("cookies %v, want [region] (not __cf_bm, not the deleted one)", names)
	}
	c := res.Cookies[0]
	if c.Domain != "" || c.URL != srv.URL+"/" || !c.HTTPOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("%+v", c)
	}
}

// Round 25N (review of 25M): a cookie set with no Path from a nested URL
// lives at that URL's directory (RFC 6265 default-path), and is kept;
// a domain cookie two hosts set is one cookie; a Domain the setting host
// is not under (the jar refuses it) is never handed on.
func TestCrawlCookiesPathsAndDomains(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, port, _ := strings.Cut(r.Host, ":")
		w.Write([]byte(`<!doctype html><title>home</title><a href="/app/login">in</a><script src="http://b.x.test:` + port + `/b.js"></script>`))
	})
	mux.HandleFunc("/app/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sid=abc")                           // no Path: /app
		w.Header().Add("Set-Cookie", "consent=1; Domain=x.test; Path=/")  // a domain cookie
		w.Header().Add("Set-Cookie", "evil=1; Domain=other.test; Path=/") // refused by the jar
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!doctype html><title>login</title>`))
	})
	var bHit atomic.Bool
	mux.HandleFunc("/b.js", func(w http.ResponseWriter, r *http.Request) {
		bHit.Store(true)
		w.Header().Add("Set-Cookie", "consent=1; Domain=x.test; Path=/")
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`console.log(1)`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	_, port, _ := strings.Cut(host, ":")
	u, _ := url.Parse("http://a.x.test:" + port + "/")
	res, err := Crawl(context.Background(), Options{Target: u, InScope: func(h string) bool { return strings.HasSuffix(h, "x.test") }, Depth: 1, Rate: 1000, NoDNS: true,
		HostRules: "MAP *.x.test 127.0.0.1", Resolver: nxResolver,
		Script: func(Script) {}, Page: func(Page) {}, Log: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	if !bHit.Load() {
		t.Fatal("b.x.test's script was not fetched: the domain cookie two hosts set is not tested")
	}
	got := map[string]Cookie{}
	var names []string
	for _, c := range res.Cookies {
		got[c.Name] = c
		names = append(names, c.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"consent", "sid"}) {
		t.Fatalf("cookies %v, want [consent sid] (one consent, no evil)", names)
	}
	if c := got["sid"]; c.Path != "/app" || c.Domain != "" || c.URL != "http://a.x.test:"+port+"/app" {
		t.Errorf("sid: %+v", c)
	}
	if c := got["consent"]; c.Domain != ".x.test" || c.Path != "/" || c.URL != "" {
		t.Errorf("consent: %+v", c)
	}
}

// Round 25N review: an IP address has no subdomains. Its own address as the
// Domain is a host-only cookie (net/http/cookiejar, browsers), never
// ".127.0.0.1"; another address is refused.
func TestRecJarIPDomain(t *testing.T) {
	base, _ := cookiejar.New(nil)
	j := &recJar{CookieJar: base}
	u, _ := url.Parse("http://127.0.0.1:8080/app/login")
	j.SetCookies(u, []*http.Cookie{
		{Name: "own", Value: "1", Domain: "127.0.0.1"},
		{Name: "other", Value: "2", Domain: "10.0.0.1"},
	})
	got := j.cookies(func(string) bool { return true })
	if len(got) != 1 || got[0].Name != "own" {
		t.Fatalf("cookies %+v, want only own", got)
	}
	if c := got[0]; c.Domain != "" || c.URL != "http://127.0.0.1:8080/app" || c.Path != "/app" {
		t.Errorf("own: %+v, want host-only at /app", c)
	}
}
