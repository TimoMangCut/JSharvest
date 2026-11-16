package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// refreshApp is the server of refresh-app (testbed/apps/refresh-app, plan-28
// 28B(b)): a login with an access token of short life and a refresh token
// that turns over, one use each. A refresh token used a second time is a
// theft to the server: the whole family of the session is revoked (as Auth0
// and Okta do), access tokens included, and "REVOKED family=... reason=reuse"
// is logged. Two kinds of client:
//
//	OAuth  POST /rt/oauth/token, grant_type=refresh_token and refresh_token as
//	       a form, as JSON, or in the query; the tokens live in localStorage.
//	BFF    cookies rt_session and rt_refresh (HttpOnly); POST /rt/api/auth/refresh
//	       with an empty body turns them over.
//
// GET /rt/_stats (linked from nowhere) says what the server saw; the page
// reports what it saw by GET /rt/_clientlog?e=... (a GET, so that a guard that
// holds back writes does not hold the report back).
type refreshApp struct {
	ttl  time.Duration // life of an access token
	rtl  time.Duration // life of a refresh token
	now  func() time.Time
	logf func(format string, args ...any)

	mu       sync.Mutex
	access   map[string]rtAccess   // access token -> its data
	refresh  map[string]*rtRefresh // refresh token -> its data
	revoked  map[string]bool       // family -> revoked
	families int
	st       rtStats
	client   map[string]int
}

type rtAccess struct {
	family string
	exp    time.Time
}

type rtRefresh struct {
	family string
	used   bool
	exp    time.Time
}

type rtStats struct {
	Logins         int `json:"logins"`
	RefreshOK      int `json:"refresh_ok"`
	RefreshReuse   int `json:"refresh_reuse"`   // a used token again: the family revoked
	RefreshRevoked int `json:"refresh_revoked"` // a token of a family already revoked
	RefreshUnknown int `json:"refresh_unknown"`
	Revoked        int `json:"revoked"` // families revoked
	DataOK         int `json:"data_ok"`
	Data401        int `json:"data_401"`
	Data401Expired int `json:"data_401_expired"`
	Data401Revoked int `json:"data_401_revoked"`
	Data401None    int `json:"data_401_none"`
}

func newRefreshApp(ttl time.Duration) *refreshApp {
	return &refreshApp{
		ttl: ttl, rtl: time.Hour, now: time.Now, logf: log.Printf,
		access: map[string]rtAccess{}, refresh: map[string]*rtRefresh{},
		revoked: map[string]bool{}, client: map[string]int{},
	}
}

// rtTTL reads RT_TTL: seconds ("8", "2.5") or a duration ("8s"); 8 s if unset.
func rtTTL() time.Duration {
	v := os.Getenv("RT_TTL")
	if v == "" {
		return 8 * time.Second
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
		return time.Duration(f * float64(time.Second))
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	log.Fatalf("RT_TTL=%q: seconds or a duration", v)
	return 0
}

// issue gives a family a new pair of tokens. a.mu held.
func (a *refreshApp) issue(family string) (at, rt string, ttl time.Duration) {
	at, rt = "at_"+token(), "rt_"+token()
	a.access[at] = rtAccess{family: family, exp: a.now().Add(a.ttl)}
	a.refresh[rt] = &rtRefresh{family: family, exp: a.now().Add(a.rtl)}
	return at, rt, a.ttl
}

// login starts a family.
func (a *refreshApp) login() (at, rt string, ttl time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.families++
	a.st.Logins++
	return a.issue(fmt.Sprintf("f%d", a.families))
}

// rotate is a refresh: the token turns over once; a token used before revokes
// its family. err is the OAuth error, status the HTTP status.
func (a *refreshApp) rotate(rt string) (at, newRT string, ttl time.Duration, status int, errCode string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.refresh[rt]
	switch {
	case !ok:
		a.st.RefreshUnknown++
		return "", "", 0, http.StatusUnauthorized, "invalid_grant"
	case a.revoked[r.family]:
		a.st.RefreshRevoked++
		return "", "", 0, http.StatusUnauthorized, "invalid_grant"
	case r.used:
		a.st.RefreshReuse++
		a.st.Revoked++
		a.revoked[r.family] = true
		a.logf("REVOKED family=%s reason=reuse", r.family)
		return "", "", 0, http.StatusUnauthorized, "invalid_grant"
	case !a.now().Before(r.exp):
		a.st.RefreshUnknown++
		return "", "", 0, http.StatusUnauthorized, "invalid_grant"
	}
	r.used = true
	a.st.RefreshOK++
	at, newRT, ttl = a.issue(r.family)
	return at, newRT, ttl, http.StatusOK, ""
}

// check judges an access token: "" if good, else why not.
func (a *refreshApp) check(at string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.access[at]
	switch {
	case at == "" || !ok:
		a.st.Data401++
		a.st.Data401None++
		return "none"
	case a.revoked[t.family]:
		a.st.Data401++
		a.st.Data401Revoked++
		return "revoked"
	case !a.now().Before(t.exp):
		a.st.Data401++
		a.st.Data401Expired++
		return "expired"
	}
	a.st.DataOK++
	return ""
}

func (a *refreshApp) stats() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	alive := a.families - a.st.Revoked
	cl := map[string]int{}
	for k, v := range a.client {
		cl[k] = v
	}
	b, _ := json.Marshal(a.st)
	m := map[string]any{}
	json.Unmarshal(b, &m)
	m["families"] = a.families
	m["alive_families"] = alive
	m["client"] = cl
	return m
}

func rtJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// tokenParams reads grant_type and refresh_token from the query, then from a
// JSON body or a form body.
func tokenParams(r *http.Request) (grant, rt string) {
	q := r.URL.Query()
	grant, rt = q.Get("grant_type"), q.Get("refresh_token")
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var b struct {
			Grant string `json:"grant_type"`
			RT    string `json:"refresh_token"`
		}
		if json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<16)).Decode(&b) == nil {
			if b.Grant != "" {
				grant = b.Grant
			}
			if b.RT != "" {
				rt = b.RT
			}
		}
		return grant, rt
	}
	if r.ParseForm() == nil {
		if v := r.PostForm.Get("grant_type"); v != "" {
			grant = v
		}
		if v := r.PostForm.Get("refresh_token"); v != "" {
			rt = v
		}
	}
	return grant, rt
}

func bearer(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("rt_session"); err == nil {
		return c.Value
	}
	return ""
}

func (a *refreshApp) setCookies(w http.ResponseWriter, at, rt string) {
	http.SetCookie(w, &http.Cookie{Name: "rt_session", Value: at, Path: "/rt", HttpOnly: true, MaxAge: 3600})
	http.SetCookie(w, &http.Cookie{Name: "rt_refresh", Value: rt, Path: "/rt/api/auth", HttpOnly: true, MaxAge: 3600})
}

// handler answers /rt/ ; the rest goes to next. dist is the app's dist
// directory (HTML with {{MODE}} replaced by the page's ?mode=).
func (a *refreshApp) handler(dist string, next http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /rt/login", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("email") == "" || r.FormValue("password") != "hunter22" {
			rtJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad credentials"})
			return
		}
		at, rt, ttl := a.login()
		if r.FormValue("kind") == "bff" {
			a.setCookies(w, at, rt)
			rtJSON(w, http.StatusOK, map[string]any{"ok": true, "expires_in": ttl.Seconds()})
			return
		}
		rtJSON(w, http.StatusOK, map[string]any{"access_token": at, "refresh_token": rt, "expires_in": ttl.Seconds()})
	})
	mux.HandleFunc("POST /rt/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		grant, rt := tokenParams(r)
		if grant != "refresh_token" {
			rtJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
			return
		}
		at, nrt, ttl, status, e := a.rotate(rt)
		if status != http.StatusOK {
			rtJSON(w, status, map[string]string{"error": e})
			return
		}
		rtJSON(w, http.StatusOK, map[string]any{"access_token": at, "refresh_token": nrt, "expires_in": ttl.Seconds(), "token_type": "Bearer"})
	})
	mux.HandleFunc("POST /rt/api/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("rt_refresh")
		if err != nil {
			a.mu.Lock()
			a.st.RefreshUnknown++
			a.mu.Unlock()
			rtJSON(w, http.StatusUnauthorized, map[string]string{"error": "no refresh cookie"})
			return
		}
		at, nrt, ttl, status, e := a.rotate(c.Value)
		if status != http.StatusOK {
			rtJSON(w, status, map[string]string{"error": e})
			return
		}
		a.setCookies(w, at, nrt)
		rtJSON(w, http.StatusOK, map[string]any{"ok": true, "expires_in": ttl.Seconds()})
	})
	// The data: ?hold=MS keeps the answer back (up to 5 s), so that a page
	// has a request in flight for as long as the crawl should take.
	mux.HandleFunc("GET /rt/api/data", func(w http.ResponseWriter, r *http.Request) {
		if ms, _ := strconv.Atoi(r.URL.Query().Get("hold")); ms > 0 {
			if ms > 5000 {
				ms = 5000
			}
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
		if why := a.check(bearer(r)); why != "" {
			rtJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "why": why})
			return
		}
		rtJSON(w, http.StatusOK, map[string]any{"page": r.URL.Query().Get("page"), "items": []int{1, 2, 3}})
	})
	mux.HandleFunc("GET /rt/_clientlog", func(w http.ResponseWriter, r *http.Request) {
		e := r.URL.Query().Get("e")
		if e == "" || len(e) > 64 {
			http.Error(w, "e", http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		a.client[e]++
		a.mu.Unlock()
		rtJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /rt/_stats", func(w http.ResponseWriter, r *http.Request) {
		rtJSON(w, http.StatusOK, a.stats())
	})
	mux.HandleFunc("GET /rt/", func(w http.ResponseWriter, r *http.Request) {
		a.page(w, r, dist)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/rt/") || r.URL.Path == "/rt" {
			mux.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// page serves dist/rt/<path>, or <path>.html, or <path>/index.html; HTML gets
// {{MODE}} and {{KIND}} filled in.
func (a *refreshApp) page(w http.ResponseWriter, r *http.Request, dist string) {
	rel := path.Clean(r.URL.Path)
	mode := r.URL.Query().Get("mode")
	switch mode {
	case "form", "json", "query":
	default:
		mode = "form"
	}
	kind := r.URL.Query().Get("kind")
	if kind != "bff" {
		kind = "oauth"
	}
	for _, c := range []string{filepath.Join(dist, rel), filepath.Join(dist, rel+".html"), filepath.Join(dist, rel, "index.html")} {
		st, err := os.Stat(c)
		if err != nil || st.IsDir() {
			continue
		}
		if strings.HasSuffix(c, ".html") {
			b, err := os.ReadFile(c)
			if err != nil {
				break
			}
			s := strings.NewReplacer("{{MODE}}", mode, "{{KIND}}", kind).Replace(string(b))
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprint(w, s)
			return
		}
		serveFile(w, r, c)
		return
	}
	http.NotFound(w, r)
}

// refreshAppFor serves refresh-app (testbed/apps/refresh-app); any other
// app is left to next.
func refreshAppFor(app string, next http.Handler) http.Handler {
	if filepath.Base(filepath.Clean(app)) != "refresh-app" {
		return next
	}
	return newRefreshApp(rtTTL()).handler(filepath.Join(app, "dist"), next)
}
