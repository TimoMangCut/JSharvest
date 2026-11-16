package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type rtEnv struct {
	t    *testing.T
	app  *refreshApp
	srv  *httptest.Server
	clk  time.Time
	mu   sync.Mutex
	logs []string
}

func newRTEnv(t *testing.T) *rtEnv {
	e := &rtEnv{t: t, clk: time.Unix(1_000_000, 0)}
	e.app = newRefreshApp(8 * time.Second)
	e.app.now = func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.clk }
	e.app.logf = func(f string, a ...any) { e.mu.Lock(); e.logs = append(e.logs, fmt.Sprintf(f, a...)); e.mu.Unlock() }
	dist := filepath.Join("..", "..", "apps", "refresh-app", "dist")
	e.srv = httptest.NewServer(e.app.handler(dist, http.NotFoundHandler()))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *rtEnv) advance(d time.Duration) { e.mu.Lock(); e.clk = e.clk.Add(d); e.mu.Unlock() }

func (e *rtEnv) do(req *http.Request) (int, map[string]any, *http.Response) {
	e.t.Helper()
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	m := map[string]any{}
	json.Unmarshal(b, &m)
	return resp.StatusCode, m, resp
}

func (e *rtEnv) post(p, ctype, body string, cookies ...*http.Cookie) (int, map[string]any, *http.Response) {
	req, _ := http.NewRequest("POST", e.srv.URL+p, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return e.do(req)
}

func (e *rtEnv) data(at string, cookies ...*http.Cookie) (int, map[string]any) {
	req, _ := http.NewRequest("GET", e.srv.URL+"/rt/api/data?page=1", nil)
	if at != "" {
		req.Header.Set("Authorization", "Bearer "+at)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	s, m, _ := e.do(req)
	return s, m
}

func (e *rtEnv) login(kind string) (map[string]any, *http.Response) {
	s, m, r := e.post("/rt/login", "application/x-www-form-urlencoded",
		url.Values{"email": {"a@b.test"}, "password": {"hunter22"}, "kind": {kind}}.Encode())
	if s != 200 {
		e.t.Fatalf("login: %d %v", s, m)
	}
	return m, r
}

func (e *rtEnv) stats() map[string]any {
	_, m, _ := e.do(mustReq(e.srv.URL + "/rt/_stats"))
	return m
}

func mustReq(u string) *http.Request { r, _ := http.NewRequest("GET", u, nil); return r }

func num(m map[string]any, k string) int { f, _ := m[k].(float64); return int(f) }

func (e *rtEnv) revokedLogs() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, l := range e.logs {
		if strings.HasPrefix(l, "REVOKED family=") && strings.Contains(l, "reason=reuse") {
			n++
		}
	}
	return n
}

func TestBadLogin(t *testing.T) {
	e := newRTEnv(t)
	s, _, _ := e.post("/rt/login", "application/x-www-form-urlencoded", "email=a@b.test&password=nope")
	if s != 401 {
		t.Fatalf("status %d", s)
	}
}

func TestAccessTokenExpires(t *testing.T) {
	e := newRTEnv(t)
	m, _ := e.login("oauth")
	at := m["access_token"].(string)
	if s, _ := e.data(at); s != 200 {
		t.Fatalf("fresh token: %d", s)
	}
	e.advance(7 * time.Second)
	if s, _ := e.data(at); s != 200 {
		t.Fatalf("token at 7s: %d", s)
	}
	e.advance(2 * time.Second)
	s, b := e.data(at)
	if s != 401 || b["why"] != "expired" {
		t.Fatalf("token at 9s: %d %v", s, b)
	}
	if s, _ := e.data(""); s != 401 {
		t.Fatalf("no token: %d", s)
	}
	st := e.stats()
	if num(st, "data_ok") != 2 || num(st, "data_401") != 2 || num(st, "data_401_expired") != 1 || num(st, "data_401_none") != 1 {
		t.Fatalf("stats %v", st)
	}
}

func TestOAuthThreeForms(t *testing.T) {
	for _, mode := range []string{"form", "json", "query"} {
		t.Run(mode, func(t *testing.T) {
			e := newRTEnv(t)
			m, _ := e.login("oauth")
			rt := m["refresh_token"].(string)
			var s int
			var r map[string]any
			switch mode {
			case "form":
				s, r, _ = e.post("/rt/oauth/token", "application/x-www-form-urlencoded",
					url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}.Encode())
			case "json":
				s, r, _ = e.post("/rt/oauth/token", "application/json",
					fmt.Sprintf(`{"grant_type":"refresh_token","refresh_token":%q}`, rt))
			case "query":
				s, r, _ = e.post("/rt/oauth/token?grant_type=refresh_token&refresh_token="+rt, "", "")
			}
			if s != 200 || r["access_token"] == nil || r["refresh_token"] == nil || r["refresh_token"] == rt {
				t.Fatalf("%d %v", s, r)
			}
			if c, _ := e.data(r["access_token"].(string)); c != 200 {
				t.Fatalf("new access token: %d", c)
			}
			if st := e.stats(); num(st, "refresh_ok") != 1 {
				t.Fatalf("stats %v", st)
			}
		})
	}
}

func TestOAuthWrongGrant(t *testing.T) {
	e := newRTEnv(t)
	s, _, _ := e.post("/rt/oauth/token", "application/x-www-form-urlencoded", "grant_type=password")
	if s != 400 {
		t.Fatalf("status %d", s)
	}
}

func TestReuseRevokesFamily(t *testing.T) {
	e := newRTEnv(t)
	other, _ := e.login("oauth") // a second family must stay alive
	m, _ := e.login("oauth")
	rt1 := m["refresh_token"].(string)
	form := func(rt string) (int, map[string]any) {
		s, r, _ := e.post("/rt/oauth/token", "application/x-www-form-urlencoded",
			url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}.Encode())
		return s, r
	}
	s, r := form(rt1)
	if s != 200 {
		t.Fatalf("first use: %d", s)
	}
	at2, rt2 := r["access_token"].(string), r["refresh_token"].(string)
	if c, _ := e.data(at2); c != 200 {
		t.Fatalf("at2: %d", c)
	}
	if s, _ := form(rt1); s != 401 { // the old one again
		t.Fatalf("reuse: %d", s)
	}
	if e.revokedLogs() != 1 {
		t.Fatalf("REVOKED lines: %v", e.logs)
	}
	// the whole family: the access token of the new pair and its refresh token
	if c, b := e.data(at2); c != 401 || b["why"] != "revoked" {
		t.Fatalf("at2 after revoke: %d %v", c, b)
	}
	if s, _ := form(rt2); s != 401 {
		t.Fatalf("rt2 after revoke: %d", s)
	}
	if c, _ := e.data(other["access_token"].(string)); c != 200 {
		t.Fatalf("other family hit: %d", c)
	}
	st := e.stats()
	if num(st, "refresh_ok") != 1 || num(st, "refresh_reuse") != 1 || num(st, "refresh_revoked") != 1 ||
		num(st, "revoked") != 1 || num(st, "families") != 2 || num(st, "alive_families") != 1 {
		t.Fatalf("stats %v", st)
	}
	if e.revokedLogs() != 1 { // a token of a revoked family is not a second revocation
		t.Fatalf("REVOKED lines: %v", e.logs)
	}
}

func TestUnknownAndExpiredRefresh(t *testing.T) {
	e := newRTEnv(t)
	if s, _, _ := e.post("/rt/oauth/token", "application/x-www-form-urlencoded", "grant_type=refresh_token&refresh_token=rt_nope"); s != 401 {
		t.Fatalf("unknown: %d", s)
	}
	m, _ := e.login("oauth")
	e.advance(2 * time.Hour)
	if s, _, _ := e.post("/rt/oauth/token?grant_type=refresh_token&refresh_token="+m["refresh_token"].(string), "", ""); s != 401 {
		t.Fatalf("expired: %d", s)
	}
	if e.revokedLogs() != 0 || num(e.stats(), "refresh_unknown") != 2 {
		t.Fatalf("stats %v logs %v", e.stats(), e.logs)
	}
}

func cookieNamed(r *http.Response, n string) *http.Cookie {
	for _, c := range r.Cookies() {
		if c.Name == n {
			return c
		}
	}
	return nil
}

func TestBFFRotatesCookies(t *testing.T) {
	e := newRTEnv(t)
	_, r := e.login("bff")
	ses, ref := cookieNamed(r, "rt_session"), cookieNamed(r, "rt_refresh")
	if ses == nil || ref == nil || !ses.HttpOnly || !ref.HttpOnly {
		t.Fatalf("cookies %v", r.Cookies())
	}
	if s, _ := e.data("", ses); s != 200 {
		t.Fatalf("data with cookie: %d", s)
	}
	e.advance(9 * time.Second)
	if s, _ := e.data("", ses); s != 401 {
		t.Fatalf("expired cookie: %d", s)
	}
	s, b, r2 := e.post("/rt/api/auth/refresh", "", "", ref)
	if s != 200 || b["ok"] != true {
		t.Fatalf("refresh: %d %v", s, b)
	}
	ses2, ref2 := cookieNamed(r2, "rt_session"), cookieNamed(r2, "rt_refresh")
	if ses2 == nil || ref2 == nil || ses2.Value == ses.Value || ref2.Value == ref.Value {
		t.Fatalf("not turned over: %v", r2.Cookies())
	}
	if s, _ := e.data("", ses2); s != 200 {
		t.Fatalf("new cookie: %d", s)
	}
	// the old refresh cookie again: revoked, the new session with it
	if s, _, _ := e.post("/rt/api/auth/refresh", "", "", ref); s != 401 {
		t.Fatalf("reuse: %d", s)
	}
	if s, _ := e.data("", ses2); s != 401 {
		t.Fatalf("session after revoke: %d", s)
	}
	if e.revokedLogs() != 1 {
		t.Fatalf("logs %v", e.logs)
	}
	if s, _, _ := e.post("/rt/api/auth/refresh", "", ""); s != 401 { // no cookie
		t.Fatalf("no cookie: %d", s)
	}
}

func TestClientLogAndStats(t *testing.T) {
	e := newRTEnv(t)
	for _, ev := range []string{"refresh_try", "refresh_try", "refresh_fake"} {
		if s, _, _ := e.do(mustReq(e.srv.URL + "/rt/_clientlog?e=" + ev)); s != 200 {
			t.Fatal(s)
		}
	}
	if s, _, _ := e.do(mustReq(e.srv.URL + "/rt/_clientlog")); s != 400 {
		t.Fatalf("no e: %d", s)
	}
	cl, _ := e.stats()["client"].(map[string]any)
	if num(cl, "refresh_try") != 2 || num(cl, "refresh_fake") != 1 {
		t.Fatalf("client %v", cl)
	}
	if s, _, _ := e.post("/rt/_clientlog?e=x", "", ""); s == 200 { // GET only
		t.Fatal("POST accepted")
	}
}

func TestPagesAndMode(t *testing.T) {
	e := newRTEnv(t)
	get := func(p string) string {
		resp, err := http.Get(e.srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		return string(b)
	}
	if s := get("/rt/?mode=json"); !strings.Contains(s, `data-mode="json"`) || !strings.Contains(s, `href="/rt/a?mode=json"`) {
		t.Fatalf("index: %s", s)
	}
	if s := get("/rt/a?mode=query"); !strings.Contains(s, `data-mode="query"`) {
		t.Fatalf("a: %s", s)
	}
	if s := get("/rt/bff/?kind=bff"); !strings.Contains(s, `data-kind="bff"`) {
		t.Fatalf("bff: %s", s)
	}
	if s := get("/rt/bff/c?kind=bff"); !strings.Contains(s, "rt bff c") {
		t.Fatalf("bff c: %s", s)
	}
	if s := get("/rt/login?kind=bff"); !strings.Contains(s, `value="bff"`) {
		t.Fatalf("login: %s", s)
	}
	if s := get("/rt/app.js"); !strings.Contains(s, "_clientlog") {
		t.Fatal("app.js")
	}
}

func TestRTTTL(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 8 * time.Second, "3": 3 * time.Second, "2.5": 2500 * time.Millisecond, "4s": 4 * time.Second} {
		os.Setenv("RT_TTL", in)
		if got := rtTTL(); got != want {
			t.Errorf("RT_TTL=%q: %v, want %v", in, got, want)
		}
	}
	os.Unsetenv("RT_TTL")
}

func TestRefreshAppForOnlyThatApp(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(418) })
	h := refreshAppFor("testbed/apps/session-app", next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/rt/_stats", nil))
	if rec.Code != 418 {
		t.Fatalf("other app: %d", rec.Code)
	}
	h = refreshAppFor("testbed/apps/refresh-app", next)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/rt/_stats", nil))
	if rec.Code != 200 {
		t.Fatalf("refresh-app: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/other", nil))
	if rec.Code != 418 {
		t.Fatalf("outside /rt/: %d", rec.Code)
	}
}
