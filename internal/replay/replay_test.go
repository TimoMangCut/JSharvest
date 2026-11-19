package replay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"

	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func TestPatch(t *testing.T) {
	raw := []byte("POST /api/notes/note_1/x?q=a%20b HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\n" +
		"X-Csrf-Token: old\r\nContent-Length: 15\r\n\r\n{\"name\":\"Bo\"}  ")
	for _, c := range []struct{ at, v, want string }{
		{"header:x-csrf-token", "n3w.t0k", "X-Csrf-Token: n3w.t0k\r\n"},
		{"path:3", "note 2/x", "POST /api/notes/note%202%2Fx/x?"},
		{"query:q", "a&b c", "?q=a%26b+c HTTP/1.1"},
		{"body:$.name", "B\"o\n", `{"name":"B\"o\n"}`},
	} {
		got, err := Patch(raw, c.at, c.v)
		if err != nil || !strings.Contains(string(got), c.want) {
			t.Errorf("%s: %q (%v), want %q in it", c.at, got, err, c.want)
			continue
		}
		q, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(got)))
		if err != nil {
			t.Errorf("%s: %v", c.at, err)
			continue
		}
		body, _ := io.ReadAll(q.Body)
		if int64(len(body)) != q.ContentLength || !bytes.HasSuffix(got, body) {
			t.Errorf("%s: length %d, body %q", c.at, q.ContentLength, body)
		}
	}
	// A number's place: a number goes in bare, anything else as a string.
	num := []byte("POST /n HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"id\":7,\"ok\":true}")
	for v, want := range map[string]string{"42": `{"id":42,"ok":true}`, "abc": `{"id":"abc","ok":true}`, "null": `{"id":null,"ok":true}`} {
		got, err := Patch(num, "body:$.id", v)
		if err != nil || !bytes.HasSuffix(got, []byte(want)) {
			t.Errorf("%s: %q %v", v, got, err)
		}
	}
	if got := dropCredential(num, "body:$.id"); !bytes.HasSuffix(got, []byte(`{"id":null,"ok":true}`)) {
		t.Errorf("drop a number: %q", got)
	}
	if _, err := Patch(raw, "header:x-csrf-token", "a\r\nX-Evil: 1"); err == nil {
		t.Error("a line break went into a header")
	}
	if _, err := Patch(raw, "query:nope", "x"); err == nil {
		t.Error("a place the request does not have")
	}
	if got := SetLength([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n")); strings.Contains(string(got), "Content-Length") {
		t.Errorf("%q", got)
	}
}

func TestPolicy(t *testing.T) {
	p := Policy{ReadAllow: regexp.MustCompile(`/api/search$`)}
	j := map[string]string{"content-type": "application/json"}
	f := map[string]string{"content-type": "application/x-www-form-urlencoded"}
	for _, c := range []struct {
		e    traffic.Entry
		held bool
		want Kind
	}{
		{traffic.Entry{Method: "GET", URL: "http://a/api/ra/admin/stats"}, false, Read},
		{traffic.Entry{Method: "GET", URL: "http://a/api/items?refresh=1"}, false, Read},
		{traffic.Entry{Method: "GET", URL: "http://a/api/authors"}, false, Read},
		{traffic.Entry{Method: "GET", URL: "http://a/api/ra/rpc?action=list"}, false, Read},
		{traffic.Entry{Method: "GET", URL: "http://a/api/ra/rpc?action=purge"}, false, Destructive},
		{traffic.Entry{Method: "GET", URL: "http://a/api/rpc?action=approve"}, false, Write},
		{traffic.Entry{Method: "GET", URL: "http://a/api/orders/7/approve"}, false, Write},
		{traffic.Entry{Method: "GET", URL: "http://a/api/x"}, true, Write},
		{traffic.Entry{Method: "POST", URL: "http://a/api/ra/admin/invite", Body: traffic.Body{Body: "email=x@y.z"}}, false, Write},
		{traffic.Entry{Method: "POST", URL: "http://a/api/search", Headers: j, Body: traffic.Body{Body: `{"q":"x"}`}}, false, Read},
		{traffic.Entry{Method: "DELETE", URL: "http://a/api/ra/admin/users/7"}, false, Destructive},
		{traffic.Entry{Method: "POST", URL: "http://a/api/items/7", Headers: map[string]string{"x-http-method-override": "DELETE"}}, false, Destructive},
		{traffic.Entry{Method: "POST", URL: "http://a/api/items/7", Headers: f, Body: traffic.Body{Body: "_method=DELETE"}}, false, Destructive},
		{traffic.Entry{Method: "POST", URL: "http://a/rpc", Headers: j, Body: traffic.Body{Body: `{"jsonrpc":"2.0","method":"user.remove","params":[7]}`}}, false, Destructive},
		// GraphQL: a query reads; a mutation writes; its root fields and
		// every operation of a batch count; a persisted query is unknown.
		{traffic.Entry{Method: "POST", URL: "http://a/graphql", Headers: j, Body: traffic.Body{Body: `{"query":"query News { news { id } }"}`}}, false, Read},
		{traffic.Entry{Method: "POST", URL: "http://a/graphql", Headers: j, Body: traffic.Body{Body: `{"query":"mutation Save { saveThing(id: 1) { id } }"}`}}, false, Write},
		{traffic.Entry{Method: "POST", URL: "http://a/graphql", Headers: j, Body: traffic.Body{Body: `{"operationName":"SaveThing","query":"mutation SaveThing { deleteUser(id: 7) }"}`}}, false, Destructive},
		{traffic.Entry{Method: "POST", URL: "http://a/graphql", Headers: j, Body: traffic.Body{Body: `[{"query":"query A { a }"},{"query":"mutation { purgeUsers }"}]`}}, false, Destructive},
		{traffic.Entry{Method: "POST", URL: "http://a/graphql", Headers: j, Body: traffic.Body{Body: `{"operationName":"PurgeUsers","query":"mutation PurgeUsers { purgeUsers }"}`}}, false, Destructive},
		{traffic.Entry{Method: "POST", URL: "http://a/graphql", Headers: j, Body: traffic.Body{Body: `{"operationName":"X","extensions":{"persistedQuery":{"sha256Hash":"ab"}}}`}}, false, Destructive},
		{traffic.Entry{Method: "GET", URL: "http://a/graphql?query=query%20Me%20%7B%20me%20%7B%20id%20%7D%20%7D"}, false, Read},
		// Never: a session's end, a login flow, a response that cleared
		// the site's data.
		{traffic.Entry{Method: "GET", URL: "http://a/account/logout"}, false, Never},
		{traffic.Entry{Method: "POST", URL: "http://a/account/expire"}, false, Never},
		{traffic.Entry{Method: "POST", URL: "http://a/api/login", Body: traffic.Body{Body: "email=a"}}, false, Never},
		{traffic.Entry{Method: "POST", URL: "http://a/oauth/token"}, false, Never},
		{traffic.Entry{Method: "GET", URL: "http://a/api/x", Response: &traffic.Response{Headers: map[string]string{"Clear-Site-Data": `"cookies"`}}}, false, Never},
		{traffic.Entry{Method: "OPTIONS", URL: "http://a/api/x"}, false, Excluded},
	} {
		if got := p.Classify(c.e, c.held); got.Kind != c.want {
			t.Errorf("%s %s %q: %s (%s), want %s", c.e.Method, c.e.URL, c.e.Body.Body, got.Kind, got.Reason, c.want)
		}
	}
	if !slices.Equal(rootFields("mutation SaveThing($id: ID!) { a: deleteUser(id: $id) { id ok } other(x: \"}\") }"), []string{"a", "deleteUser", "other"}) {
		t.Errorf("%v", rootFields("mutation SaveThing($id: ID!) { a: deleteUser(id: $id) { id ok } other(x: \"}\") }"))
	}
}

func TestJudge(t *testing.T) {
	js := map[string]string{"content-type": "application/json"}
	a := func(s int, body string) Answer { return Answer{Status: s, Header: js, Body: []byte(body)} }
	login := func(l string) bool { return strings.Contains(l, "/login") }
	admin := `{"users":[{"id":1,"email":"a@x"},{"id":2,"email":"b@x"}],"ts":1793773780458}`
	admin2 := `{"users":[{"id":1,"email":"a@x"},{"id":2,"email":"b@x"}],"ts":1793773799999}`
	for _, c := range []struct {
		name string
		c    Case
		want Verdict
	}{
		{"same answer, a time stamp aside", Case{Trial: a(200, `{"users":[{"id":1,"email":"a@x"},{"id":2,"email":"b@x"}],"ts":1}`), Controls: []Answer{a(200, admin), a(200, admin2)}}, Bypass},
		{"no identity gets it too", Case{Trial: a(200, admin), Controls: []Answer{a(200, admin), a(200, admin)}, NoIdentity: &Answer{Status: 200, Header: js, Body: []byte(admin)}}, Unauthenticated},
		{"no identity refused", Case{Trial: a(200, admin), Controls: []Answer{a(200, admin), a(200, admin)}, NoIdentity: &Answer{Status: 401, Header: js}}, Bypass},
		{"a filtered list", Case{Trial: a(200, `{"users":[{"id":1,"email":"a@x"}],"ts":5}`), Controls: []Answer{a(200, admin), a(200, admin2)}}, NeedsReview},
		{"its own object", Case{Trial: a(200, `{"id":9,"email":"me@x","name":"Me"}`), Controls: []Answer{a(200, `{"id":1,"email":"a@x","name":"Admin"}`)}}, NeedsReview},
		{"one field differs", Case{Trial: a(200, `{"a":1,"b":2,"c":3,"d":4,"e":5,"f":"user"}`), Controls: []Answer{a(200, `{"a":1,"b":2,"c":3,"d":4,"e":5,"f":"admin"}`)}}, Likely},
		{"an error in a 200", Case{Trial: a(200, `{"error":"forbidden"}`), Controls: []Answer{a(200, admin)}}, NeedsReview},
		{"an SPA fallback", Case{Trial: Answer{Status: 200, Header: map[string]string{"content-type": "text/html"}, Body: []byte("<!doctype html><div id=app>")}, Controls: []Answer{a(200, admin)}}, Unclear},
		{"refused", Case{Trial: a(403, `{"error":"Forbidden"}`), Controls: []Answer{a(200, admin)}}, Enforced},
		{"refused, its CSRF token stale", Case{Trial: a(403, `{"error":"csrf"}`), Controls: []Answer{a(200, admin)}, Stale: true}, Unclear},
		{"419", Case{Trial: a(419, ``), Controls: []Answer{a(200, admin)}}, Unclear},
		{"to the login", Case{Trial: Answer{Status: 302, Header: map[string]string{"location": "/login?next=/x"}}, Controls: []Answer{a(200, admin)}, IsLogin: login}, Enforced},
		{"elsewhere", Case{Trial: Answer{Status: 302, Header: map[string]string{"location": "/home"}}, Controls: []Answer{a(200, admin)}, IsLogin: login}, Unclear},
		{"404 where the control has it", Case{Trial: a(404, ``), Controls: []Answer{a(200, admin)}}, Enforced},
		{"the control failed", Case{Trial: a(403, ``), Controls: []Answer{a(401, ``)}}, Unclear},
		{"a WAF", Case{Trial: Answer{Status: 403, Header: map[string]string{"cf-mitigated": "challenge"}}, Controls: []Answer{a(200, admin)}}, Blocked},
		{"from a cache", Case{Trial: Answer{Status: 200, Header: map[string]string{"content-type": "application/json", "cf-cache-status": "HIT"}, Body: []byte(admin)}, Controls: []Answer{a(200, admin)}}, Unclear},
		{"a per-session token: all of it varies", Case{Trial: a(200, `{"csrf":"u1"}`), Controls: []Answer{a(200, `{"csrf":"a1"}`), a(200, `{"csrf":"a2"}`)}}, NeedsReview},
		{"a write accepted", Case{Write: true, Trial: a(201, `{"id":5}`)}, Bypass},
		{"a write refused", Case{Write: true, Trial: a(403, ``)}, Enforced},
		{"a write, 404", Case{Write: true, Trial: a(404, ``)}, Unclear},
		{"500", Case{Trial: a(500, ``), Controls: []Answer{a(200, admin)}}, Unclear},
		{"text, varying", Case{Trial: Answer{Status: 200, Header: map[string]string{"content-type": "text/plain"}, Body: []byte("report 2026-11-04T10:00:00Z ok")}, Controls: []Answer{{Status: 200, Header: map[string]string{"content-type": "text/plain"}, Body: []byte("report 2026-11-04T09:00:00Z ok")}}}, Bypass},
	} {
		if got := Judge(c.c); got.Verdict != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, got.Verdict, got.Reason, c.want)
		}
	}
}

func TestIdentity(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	exp := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1000}`))
	snap := &session.Snapshot{Cookies: []*network.Cookie{
		{Name: "session", Value: "user-sid", Domain: "app.test", Path: "/"},
		{Name: "old", Value: "x", Domain: "app.test", Path: "/", Expires: 1000},
		{Name: "theme", Value: "dark", Domain: ".app.test", Path: "/"},
	}}
	user := []traffic.Entry{
		{URL: "http://app.test/api/a", Headers: map[string]string{"host": "app.test", "authorization": "Bearer user-tok", "x-csrf-token": "user-csrf"}},
		{URL: "http://app.test/api/b", Headers: map[string]string{"host": "app.test", "x-api-key": "REDACTED_ab12cd34"}},
		{URL: "http://app.test/api/c", HeadersProvisional: true, Headers: map[string]string{"authorization": "Bearer held"}},
	}
	id := NewIdentity("user", snap, user, now)
	if id.Creds["authorization"] != "Bearer user-tok" || id.Creds["x-api-key"] != "" || len(id.Notes) != 1 {
		t.Fatalf("%+v %v", id.Creds, id.Notes)
	}
	admin := []byte("GET /api/ra/admin/users HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer admin-tok\r\nX-Api-Key: admin-key\r\n" +
		"X-Csrf-Token: admin-csrf\r\nCookie: session=admin-sid; theme=light\r\nAccept: */*\r\n\r\n")
	out, missing := Apply(admin, id, "http://app.test/api/ra/admin/users", map[string]bool{"x-csrf-token": true})
	s := string(out)
	for _, want := range []string{"Authorization: Bearer user-tok\r\n", "X-Csrf-Token: admin-csrf\r\n", "Accept: */*\r\n", "session=user-sid", "theme=dark"} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q in %q", want, s)
		}
	}
	for _, gone := range []string{"admin-tok", "admin-key", "admin-sid", "old=x"} {
		if strings.Contains(s, gone) {
			t.Errorf("%q left in %q", gone, s)
		}
	}
	if !slices.Equal(missing, []string{"x-api-key"}) {
		t.Errorf("missing %v", missing)
	}
	// No identity: every credential goes, none is missing.
	out, missing = Apply(admin, NoIdentity(), "http://app.test/api/ra/admin/users", nil)
	if strings.Contains(string(out), "admin") && strings.Contains(string(out), "Cookie") || len(missing) != 0 || strings.Contains(string(out), "Authorization") {
		t.Errorf("%q %v", out, missing)
	}
	// An expired JWT is no credential.
	stale := NewIdentity("u", nil, []traffic.Entry{{URL: "http://app.test/", Headers: map[string]string{"host": "app.test", "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9." + exp + ".sig", "cookie": "sid=1"}}}, now)
	if _, ok := stale.Creds["authorization"]; ok || len(stale.Notes) != 1 {
		t.Errorf("%+v", stale)
	}
	if cs := stale.Jar.Cookies(&url.URL{Scheme: "http", Host: "app.test", Path: "/"}); len(cs) != 1 || cs[0].Value != "1" {
		t.Errorf("cookies from traffic: %v", cs)
	}
}

func TestSender(t *testing.T) {
	var hits []string
	var hitsMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsMu.Lock()
		hits = append(hits, r.Method+" "+r.URL.Path+" "+r.Header.Get("Cookie"))
		hitsMu.Unlock()
		if r.URL.Path == "/slow-down" {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	dir := t.TempDir()
	raw := func(path, h string) []byte {
		return []byte("GET " + path + " HTTP/1.1\r\nHost: " + h + "\r\nCookie: s=1\r\n\r\n")
	}
	s, err := NewSender(SenderOptions{Hosts: map[string]bool{host: true}, Max: 4, AllowPrivate: true, Log: dir + "/sent.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if a, err := s.Send(ctx, raw("/a", host), "http", "trial", "user", "x", nil); err != nil || a.Status != 200 || string(a.Body) != `{"ok":true}` {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err := s.Send(ctx, raw("/a", "evil.test"), "http", "trial", "user", "x", nil); !errors.Is(err, ErrScope) {
		t.Fatalf("another host: %v", err)
	}
	if _, err := s.Send(ctx, []byte("GET http://evil.test/a HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), "http", "trial", "user", "x", nil); !errors.Is(err, ErrScope) {
		t.Fatalf("a request line naming another host: %v", err)
	}
	// A 429 to a read is asked again after its Retry-After (round 25H);
	// still 429 after rateTries, the host is given up, and with it the run
	// (its only host).
	s.Send(ctx, raw("/slow-down", host), "http", "trial", "user", "x", nil)
	if !strings.Contains(s.Stopped(), "every host is blocked") || !strings.Contains(s.Stopped(), "429") {
		t.Fatalf("429 three times did not give the host up: %q", s.Stopped())
	}
	if _, err := s.Send(ctx, raw("/b", host), "http", "trial", "user", "x", nil); err == nil {
		t.Fatal("sent after the stop")
	}
	s.Close()
	if len(hits) != 1+rateTries || hits[0] != "GET /a s=1" || hits[rateTries] != "GET /slow-down s=1" {
		t.Fatalf("server saw %v", hits)
	}
	if st, _ := os.Stat(dir + "/sent.jsonl"); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	// A dry run sends nothing, and logs what it would send.
	d, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{host: true}, DryRun: true, Log: dir + "/dry.jsonl"})
	d.Send(ctx, raw("/c", host), "http", "trial", "user", "x", nil)
	d.Close()
	if b, _ := os.ReadFile(dir + "/dry.jsonl"); len(hits) != 1+rateTries || !strings.Contains(string(b), `"dry_run":true`) {
		t.Fatalf("dry run: %v %s", hits, b)
	}
	// The budget.
	b, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{host: true}, Max: 1})
	b.Send(ctx, raw("/d", host), "http", "trial", "user", "x", nil)
	if _, err := b.Send(ctx, raw("/e", host), "http", "trial", "user", "x", nil); !errors.Is(err, ErrBudget) {
		t.Fatalf("budget: %v", err)
	}
}

func TestStrip(t *testing.T) {
	raw := []byte("GET /a?access_token=adm1n&q=1 HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer adm1n\r\nCookie: s=adm1n\r\n\r\n")
	if out := strip(raw, "http://a/a?access_token=adm1n&q=1", nil); bytes.Contains(out, []byte("adm1n")) || !bytes.Contains(out, []byte("q=1")) {
		t.Fatalf("%q", out)
	}
}

func TestDropCredential(t *testing.T) {
	raw := []byte("POST /a?access_token=adm1n HTTP/1.1\r\nHost: a\r\nX-Csrf-Token: admin-token\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"csrf\":\"adm1n2\"}")
	out := dropCredential(raw, "header:x-csrf-token")
	out = dropCredential(out, "query:access_token")
	out = dropCredential(out, "body:$.csrf")
	if bytes.Contains(out, []byte("adm1n")) || bytes.Contains(out, []byte("admin-token")) {
		t.Fatalf("%q", out)
	}
	q, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(out)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(q.Body)
	if string(body) != `{"csrf":""}` || q.ContentLength != int64(len(body)) || q.Header.Get("Content-Type") == "" {
		t.Fatalf("%q", out)
	}
}

func TestSenderConcurrency(t *testing.T) {
	var mu sync.Mutex
	inFlight, most := 0, 0
	var starts []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inFlight++
		most = max(most, inFlight)
		starts = append(starts, time.Now())
		mu.Unlock()
		time.Sleep(60 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	run := func(conc int, rate time.Duration) {
		mu.Lock()
		most, starts = 0, nil
		mu.Unlock()
		s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{host: true}, Concurrency: conc, Rate: rate})
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.Send(context.Background(), []byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), "http", "trial", "u", "x", nil)
			}()
		}
		wg.Wait()
	}
	// Four at once, no rate: four in flight.
	run(4, 0)
	if most != 4 {
		t.Fatalf("in flight %d, want 4", most)
	}
	// Four at once and a rate: the starts keep to it.
	run(4, 30*time.Millisecond)
	// The sender keeps the rate when it sends; the server sees each start
	// after a connection's own handshake, so one pair can come closer
	// under -race. The whole train keeps to it.
	sort.Slice(starts, func(i, j int) bool { return starts[i].Before(starts[j]) })
	if span := starts[len(starts)-1].Sub(starts[0]); span < 6*30*time.Millisecond {
		t.Fatalf("span %v for %d requests, under the rate", span, len(starts))
	}
	// One at a time by default.
	run(0, 0)
	if most != 1 {
		t.Fatalf("default: %d in flight", most)
	}
}

func TestDowngradeByTime(t *testing.T) {
	t0 := time.Now()
	rc := &roleCtx{name: "user", dead: "probe answered 401", goodAt: t0}
	a := &authz{roles: []*roleCtx{rc}, out: &AuthzReport{Items: []AuthzItem{
		{Trials: []Trial{{Role: "user", Judgement: Judgement{Verdict: Enforced}, At: t0.Add(-time.Second)}}}, // before the good probe: stands
		{Trials: []Trial{{Role: "user", Judgement: Judgement{Verdict: Enforced}, At: t0.Add(time.Second)}}},  // after: unclear
		{Trials: []Trial{{Role: "anon", Judgement: Judgement{Verdict: Enforced}, At: t0.Add(time.Second)}}},  // another role
		{Trials: []Trial{{Role: "user", Judgement: Judgement{Verdict: Bypass}, At: t0.Add(time.Second)}}},    // not a refusal
	}}}
	a.downgrade()
	got := []Verdict{}
	for _, it := range a.out.Items {
		got = append(got, it.Trials[0].Verdict)
	}
	if want := []Verdict{Enforced, Unclear, Enforced, Bypass}; !slices.Equal(got, want) {
		t.Fatalf("%v, want %v", got, want)
	}
}

func TestUpdateJarTurned(t *testing.T) {
	id := NoIdentity()
	u, _ := url.Parse("http://app.test/")
	id.Jar.SetCookies(u, []*http.Cookie{{Name: "sid", Value: "a"}})
	if gone, turned := updateJar(id, u, Answer{Header: map[string]string{"set-cookie": "sid=b; Path=/"}}); gone != "" || !turned {
		t.Fatalf("a new value: %q %v", gone, turned)
	}
	if gone, turned := updateJar(id, u, Answer{Header: map[string]string{"set-cookie": "sid=b; Path=/"}}); gone != "" || turned {
		t.Fatalf("the same value: %q %v", gone, turned)
	}
	if gone, _ := updateJar(id, u, Answer{Header: map[string]string{"set-cookie": "sid=; Max-Age=0"}}); gone != "sid" {
		t.Fatalf("deleted: %q", gone)
	}
}
