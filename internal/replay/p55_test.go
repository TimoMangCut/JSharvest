package replay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"

	"github.com/TimoMangCut/JSharvest/internal/export"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// 1: a pure-letter slug of the path, and a signature, are sent values; an
// escaped copy in a leaf is the echo.
func TestReflectionOfPathSlug(t *testing.T) {
	raw := []byte("GET /api/projects/alpha-roadmap?expires=4102444800&sig=9f86d081884c7d65 HTTP/1.1\r\nHost: h\r\n\r\n")
	sent := sentValues(raw, "alpha-roadmap")
	for _, want := range []string{"alpha-roadmap", "9f86d081884c7d65"} {
		if !strings.Contains(strings.Join(sent, "|"), want) {
			t.Errorf("%q not among the sent values %v", want, sent)
		}
	}
	empty := `{"detail":"No items for alpha-roadmap","items":[]}`
	c := peerCase(empty, `{"detail":"Alpha launch plan 2026 is amber","secret":"amber-orbit-99"}`)
	c.Controls = []Answer{*jsAns(200, `{"detail":"No items for alpha-roadmap","items":[]}`), *jsAns(200, `{"detail":"No items for alpha-roadmap","items":[]}`)}
	c.Bogus, c.BogusTried = jsAns(200, `{"detail":"No items for z-k9x2m1q4p8w3","items":[]}`), true
	c.Sent, c.SentBogus = sent, sentValues([]byte("GET /api/projects/z-k9x2m1q4p8w3 HTTP/1.1\r\nHost: h\r\n\r\n"), "alpha-roadmap", "z-k9x2m1q4p8w3")
	if j := settle(c); j.Verdict == Bypass || j.Verdict == Shared {
		t.Errorf("an echoed slug: %s (%s)", j.Verdict, j.Reason)
	}
	if !newReflector([]string{"alpha roadmap"}).hit("see%20alpha%20roadmap") {
		t.Error("an escaped leaf is not read")
	}
}

// 2, 3: text evidence is a line of A's that the trial has.
func TestTextEvidenceNeedsTheTrial(t *testing.T) {
	csv := func(s string) Answer {
		return Answer{Status: 200, Header: map[string]string{"content-type": "text/csv"}, Body: []byte(s)}
	}
	a := "id,secret_hex\n550e8400-e29b-41d4-a716-446655440000,a1b2c3d4e5f60123456789abcdef0123\n"
	b := "id,secret_hex\n99999999-e29b-41d4-a716-999999999999,ffffffffffffffffffffffffffffffff\n"
	c := peerCase(``, ``)
	c.Controls = []Answer{csv(a), csv(a)}
	c.Trial = csv(b)
	c.Bogus, c.BogusTried = &Answer{Status: 404, Header: map[string]string{"content-type": "text/plain"}, Body: []byte("not found")}, true
	if j := settle(c); j.Verdict == Bypass || j.Verdict == Shared || len(j.Evidence) != 0 {
		t.Errorf("B's own export: %s (%s) %v", j.Verdict, j.Reason, j.Evidence)
	}
	// A's own line in the trial is evidence; no identity getting only a
	// header is not "unauthenticated".
	st := "holder,iban\nAlice Moreau,PT50000201231234567890154\n"
	d := peerCase(``, ``)
	d.Controls = []Answer{csv(st), csv(st)}
	d.Trial = csv(st)
	d.Bogus, d.BogusTried = &Answer{Status: 404, Header: map[string]string{"content-type": "text/plain"}}, true
	for _, n := range []string{"holder,iban\n", "login required\n"} {
		x := d
		na := csv(n)
		x.NoIdentity = &na
		if j := JudgePeer(x); j.Verdict != Bypass {
			t.Errorf("no identity got %q: %s (%s)", n, j.Verdict, j.Reason)
		}
	}
	x := d
	na := csv(st)
	x.NoIdentity = &na
	if j := JudgePeer(x); j.Verdict != Unauthenticated {
		t.Errorf("no identity got the line: %s (%s)", j.Verdict, j.Reason)
	}
	// B's and anon's text responses are seen.
	s := NewSeenSet()
	s.AddResponse(map[string]string{"content-type": "text/csv"}, "holder,iban\nBob Quill,DE89370400440532013000\n")
	if !s.Has("Bob Quill,DE89370400440532013000") {
		t.Error("a CSV line of B's is not seen")
	}
}

// 4: a short value is found at its own path.
func TestShortValueExactPath(t *testing.T) {
	c := peerCase(`{"summary":{"tier":1,"seats":1},"benchmarks":[{"tier":4},{"seats":125}]}`, `{"summary":{"tier":4,"seats":125}}`)
	c.Self = jsAns(200, `{"summary":{"tier":1,"seats":5},"benchmarks":[]}`)
	if j := settle(c); j.Verdict == Bypass {
		t.Errorf("short values moved by key name: %s", j.Verdict)
	}
	// A strong value that moved (a filtered list) still counts.
	s := peerCase(`{"items":[{"note":"Alice private: the safe code is 48-17-92"}]}`, `{"items":[{"id":1},{"note":"Alice private: the safe code is 48-17-92"}]}`)
	if j := settle(s); j.Verdict != Bypass {
		t.Errorf("a moved strong value: %s (%s)", j.Verdict, j.Reason)
	}
}

// 5: the probe's word.
func TestPeerAlive(t *testing.T) {
	var body, ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ctype)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	probe := &export.Request{Entry: traffic.Entry{Method: "GET", URL: srv.URL + "/api/me", Headers: map[string]string{"host": host, "cookie": "s=1"}}, Key: "GET " + host + "/api/me"}
	mk := func(max int) (*authz, *roleCtx) {
		s, _ := NewSender(SenderOptions{AllowPrivate: true, Hosts: map[string]bool{host: true}, Max: max, UserAgent: "Mozilla/5.0 Chrome/156"})
		a := &authz{o: AuthzOptions{Sender: s}, peer: true}
		return a, &roleCtx{name: "bob", id: NewIdentity("bob", nil, []traffic.Entry{probe.Entry}, time.Now()), probe: probe, model: &export.Model{}}
	}
	for _, c := range []struct {
		name, ct, body string
		max            int
		alive, known   bool
	}{
		{"fine", "application/json", `{"id":"u"}`, 10, true, true},
		{"an error code in a 200", "application/json", `{"code":40101,"msg":"session expired"}`, 10, false, true},
		{"a login page in a 200", "text/html", `<!doctype html><form>login</form>`, 10, false, true},
		{"the budget spent", "application/json", `{"id":"u"}`, 0, false, false},
	} {
		ctype, body = c.ct, c.body
		a, rc := mk(c.max)
		if c.max == 0 {
			a.o.Sender.o.Max = 1
			a.o.Sender.n = 1
		}
		al, known := a.peerAlive(context.Background(), rc)
		if al != c.alive || known != c.known {
			t.Errorf("%s: alive %v known %v, want %v %v", c.name, al, known, c.alive, c.known)
		}
	}
	// No probe at all: not known. A dead role stays dead.
	a, rc := mk(10)
	rc.probe = nil
	if al, known := a.peerAlive(context.Background(), rc); al || known {
		t.Error("no probe")
	}
	rc.dead = "x"
	if al, known := a.peerAlive(context.Background(), rc); al || !known {
		t.Error("dead")
	}
}

// 6: a refusal read with a token not taken fresh is not enforced.
func TestStaleRefusals(t *testing.T) {
	login := func(l string) bool { return strings.Contains(l, "/login") }
	for _, tr := range []Answer{
		*jsAns(200, `{"errors":[{"message":"CSRF invalid"}],"data":null}`),
		*jsAns(404, `{"error":"nf"}`),
		{Status: 302, Header: map[string]string{"location": "/login"}},
	} {
		c := peerCase(``, aNote)
		c.Trial, c.Stale, c.IsLogin = tr, true, login
		if j := JudgePeer(c); j.Verdict != Unclear {
			t.Errorf("%d stale: %s (%s)", tr.Status, j.Verdict, j.Reason)
		}
		c.Stale, c.Kept = false, true
		if j := JudgePeer(c); j.Verdict != Unclear {
			t.Errorf("%d kept: %s (%s)", tr.Status, j.Verdict, j.Reason)
		}
		c.Kept = false
		if j := JudgePeer(c); j.Verdict != Enforced {
			t.Errorf("%d clean: %s (%s)", tr.Status, j.Verdict, j.Reason)
		}
	}
}

// 8: A's credentials never go under B, in a source request either.
func TestSourceRequestsCarryNoForeignCredential(t *testing.T) {
	f := newBolaFixture(t)
	alice, bob := f.toks["alice"], f.toks["bob"]
	t0 := time.Now().UTC().Add(-time.Hour)
	// alice: a csrf request with her token in the query, then a note with the
	// csrf header it gave; bob: his own me.
	reqs := []rq{{method: "GET", path: "/api/me"},
		{method: "GET", path: "/api/csrf?access_token=" + alice},
		{method: "GET", path: "/api/notes/1101", hdr: map[string]string{"x-csrf-token": "csrf-alice-0123456789"}}}
	links := []flow.Link{{Request: 3, At: "header:x-csrf-token", From: flow.LinkEnd{Request: 2, At: "json:$.csrf"}}}
	recordDir(t, f.srv.URL, filepath.Join(f.root, "alice"), alice, reqs, links)
	recordDir(t, f.srv.URL, filepath.Join(f.root, "bob"), bob, []rq{{method: "GET", path: "/api/me"}}, nil)
	f.app.mu.Lock()
	n := len(f.app.hits)
	f.app.mu.Unlock()
	rep, dest := f.run(t, [2]string{"alice", "bob"}, RelCrossOrg, nil)
	f.app.mu.Lock()
	for _, h := range f.app.hits[n:] {
		if strings.HasPrefix(h, "bob ") && strings.Contains(h, alice) {
			t.Errorf("alice's token in a request sent as bob: %s", h)
		}
	}
	f.app.mu.Unlock()
	checkRun(t, f, rep, dest, false)
	_ = t0
}

func TestForeignParam(t *testing.T) {
	a := &authz{peer: true, secrets: map[string]bool{"sess-value-of-alice": true}}
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"
	raw := []byte("POST /api/lookup?t=" + jwt + "&n=sess-value-of-alice&sig=abc123&page=2&expires=9 HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 70\r\n\r\n" +
		`{"itemId":"vault-alice-01","key":["sk_live_alice"],"nested":{"x":"sess-value-of-alice"}}`)
	got := map[string]bool{}
	for _, p := range export.Params(raw) {
		if a.foreignParam(p) {
			got[p.Name] = true
		}
	}
	for _, want := range []string{"t", "n", "$.key[0]", "$.nested.x"} {
		if !got[want] {
			t.Errorf("%s is a credential", want)
		}
	}
	for _, no := range []string{"sig", "page", "expires", "$.itemId"} {
		if got[no] {
			t.Errorf("%s is no credential", no)
		}
	}
	// stripPeer takes them all off, a request with 200 params is refused.
	out := stripPeer(raw, "http://h/api/lookup", nil, a)
	for _, s := range []string{jwt, "sess-value-of-alice", "sk_live_alice"} {
		if strings.Contains(string(out), s) {
			t.Errorf("%s left in %s", s, out)
		}
	}
	if !strings.Contains(string(out), "sig=abc123") {
		t.Errorf("the URL's signature went: %s", out)
	}
	var big strings.Builder
	big.WriteString("GET /x?")
	for i := range 210 {
		big.WriteString("p" + strings.Repeat("a", i%5) + string(rune('a'+i%26)) + strings.Repeat("b", i/26) + "=1&")
	}
	big.WriteString(" HTTP/1.1\r\nHost: h\r\n\r\n")
	if stripPeer([]byte(big.String()), "http://h/x", nil, a) != nil {
		t.Error("a request with more params than were read was stripped")
	}
}

// 9: an opaque token that the storage does not hold is not used.
func TestOpaqueTokenNotInStorage(t *testing.T) {
	snap := &session.Snapshot{Storage: map[string]session.Storage{"http://h": {Local: map[string]string{
		"access_token": "opq_new_fedcba9876543210fedcba98", "refresh_token": "ref_cur_11223344556677889900aabb"}}}}
	e := []traffic.Entry{{URL: "http://h/api/orders/1", Headers: map[string]string{"host": "h", "x-api-token": "opq_old_0123456789abcdef01234567", "authorization": "Token opq_new_fedcba9876543210fedcba98"}}}
	id := NewIdentity("b", nil, e, time.Now())
	var notes []string
	resolveStorageCreds(id, snap, e, time.Now(), func(s string) { notes = append(notes, s) })
	if _, ok := id.Creds["x-api-token"]; ok {
		t.Errorf("the dead token is kept: %v", id.Creds)
	}
	if id.Creds["authorization"] != "Token opq_new_fedcba9876543210fedcba98" {
		t.Errorf("a token that is in storage under a scheme word: %v", id.Creds)
	}
	if len(notes) == 0 {
		t.Error("no note")
	}
}

// 10: a small Relay inner id is seen only as Type:inner.
func TestRelaySmallInnerNotSeenBare(t *testing.T) {
	s := NewSeenSet()
	s.AddResponse(map[string]string{"content-type": "application/json"}, `{"data":{"used":42,"limit":100}}`)
	if s.Has(EncodeRelay("VaultItem", "42", 0)) {
		t.Error("a count hides a small Relay id")
	}
	s.AddResponse(map[string]string{"content-type": "application/json"}, `{"id":"`+EncodeRelay("VaultItem", "42", 0)+`"}`)
	if !s.Has(EncodeRelay("VaultItem", "42", 1)) {
		t.Error("the same Relay id is not seen")
	}
	u := NewSeenSet()
	u.Add("550e8400-e29b-41d4-a716-446655440000")
	if !u.Has(EncodeRelay("Doc", "550e8400-e29b-41d4-a716-446655440000", 0)) {
		t.Error("a UUID inner is global")
	}
}

// 11: one person's many requests do not push the other's out.
func TestAlignKeepsBothPeers(t *testing.T) {
	var a []*export.Request
	for i := range 320 {
		a = append(a, &export.Request{Entry: traffic.Entry{Method: "GET", URL: "http://h/v1/invoices/inv-" + strings.Repeat("x", 1) + string(rune('a'+i%26)) + "1" + strings.Repeat("z", i/26)}})
	}
	b := &export.Request{Entry: traffic.Entry{Method: "GET", URL: "http://h/v1/invoices/inv-b9"}}
	al := alignWildcards(&export.Model{Requests: a}, &export.Model{Requests: []*export.Request{b}})
	if !al[b][3] {
		t.Error("B's request was dropped from its bucket")
	}
}

// 12: the leaf is the path's; a short slug keeps its shape.
func TestBogusLeafAndSlugShape(t *testing.T) {
	ids := []ParsedID{{In: "path", Start: 20, Kind: IDIntSmall, Value: "2201"}, {In: "query", Start: 40, Kind: IDUUID, Value: "x"}, {In: "header", Start: 90, Kind: IDUUID, Value: "y"}}
	if got := bogusTarget(ids); got.In != "path" {
		t.Errorf("target %s", got.In)
	}
	if got := bogusTarget(ids[1:]); got.In != "query" {
		t.Errorf("without a path id: %s", got.In)
	}
	re := regexp.MustCompile(`^doc-\d{3}$`)
	for range 100 {
		if v := BogusID(ParsedID{Kind: IDSlug, Value: "doc-101"}, nil); !re.MatchString(v) {
			t.Fatalf("%q", v)
		}
	}
}

// 13: more verbs of action.
func TestClassifyPeerMoreVerbs(t *testing.T) {
	p := Policy{}
	for _, c := range []struct {
		body string
		want Kind
	}{
		{`{"operationName":"OTPVerify","query":"query OTPVerify($id: ID!) { OTPVerify(id: $id) { ok } }","variables":{"id":"1101"}}`, Write},
		{`{"operationName":"X","query":"query X { JWTRefresh { ok } }"}`, Write},
		{`{"operationName":"X","query":"query X { APIRegenerate { ok } }"}`, Write},
		{`{"operationName":"ApproveOrder","query":"query ApproveOrder($id: ID!) { approveOrder(id: $id) { status } }"}`, Write},
		{`{"query":"query T { transferFunds { ok } }"}`, Write},
		{`{"query":"fragment F on Note { id }\nmutation Drop($id: ID!) { updateNote(id: $id) { ...F } }"}`, Write},
		{`{"operationName":"GetVaultItem","query":"fragment F on Item { id } query GetVaultItem($id: ID!) { vaultItem(id: $id) { ...F label } }"}`, Read},
	} {
		if d := p.ClassifyPeer(entryFor("POST", "http://a/api/graphql", c.body), false); d.Kind != c.want {
			t.Errorf("%s: %s (%s), want %s", c.body, d.Kind, d.Reason, c.want)
		}
	}
	for _, s := range []string{"OTPVerify", "JWTRefresh", "APIRegenerate", "verify-email", "doEmailVerify"} {
		if !replayWord(s) {
			t.Errorf("%s is a replay verb", s)
		}
	}
	for _, s := range []string{"Verified", "verifiable", "refreshing", "Unverified"} {
		if replayWord(s) {
			t.Errorf("%s is no verb", s)
		}
	}
}

// 14: trial files do not overwrite each other.
func TestTrialFilesAreUnique(t *testing.T) {
	b := &bola{o: BolaOptions{Out: t.TempDir()}}
	k := "GET app.test/api/items"
	f1 := b.trialFile(k, "main", "alice", "bob", []byte("one"))
	f2 := b.trialFile(k, "main", "alice", "bob", []byte("two"))
	f3 := b.trialFile("GET other.test/api/items", "main", "alice", "bob", []byte("three"))
	if f1 == "" || f1 == f2 || f2 == f3 || f1 == f3 {
		t.Fatalf("%s %s %s", f1, f2, f3)
	}
	if b1, _ := os.ReadFile(filepath.Join(b.o.Out, f1)); string(b1) != "one" {
		t.Error("overwritten")
	}
	if !regexp.MustCompile(`-as-[^.]+\.http$`).MatchString(f1) {
		t.Errorf("the scorer reads the identity from the name: %s", f1)
	}
	_ = json.Marshal
	_ = network.Cookie{}
}

// P5.6 (Jellyfin): the token inside a header of parameters, kept in storage
// inside a JSON value, is the current one and stays.
func TestTokenInsideParameterHeader(t *testing.T) {
	tok := "0123456789abcdef0123456789abcdef"
	snap := &session.Snapshot{Storage: map[string]session.Storage{"https://h": {Local: map[string]string{
		"jellyfin_credentials": `{"Servers":[{"Id":"s1","AccessToken":"` + tok + `","UserId":"u1"}]}`}}}}
	auth := `MediaBrowser Client="Jellyfin Web", Device="Chrome", DeviceId="d1", Version="12.4.0", Token="` + tok + `"`
	e := []traffic.Entry{{URL: "https://h/Users/u1", Headers: map[string]string{"host": "h", "authorization": auth}}}
	id := NewIdentity("b", nil, e, time.Now())
	resolveStorageCreds(id, snap, e, time.Now(), func(string) {})
	if id.Creds["authorization"] != auth {
		t.Errorf("the current token inside the header was dropped: %v", id.Creds)
	}
}
