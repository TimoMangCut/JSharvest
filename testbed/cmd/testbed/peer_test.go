package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

type peerEnv struct {
	t    *testing.T
	app  *peerApp
	srv  *httptest.Server
	mu   sync.Mutex
	logs []string
}

func newPeerEnv(t *testing.T) *peerEnv {
	e := &peerEnv{t: t, app: newPeerApp()}
	e.app.logf = func(f string, a ...any) { e.mu.Lock(); e.logs = append(e.logs, fmt.Sprintf(f, a...)); e.mu.Unlock() }
	e.srv = httptest.NewServer(e.app.handler(http.NotFoundHandler()))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *peerEnv) logged(s string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, l := range e.logs {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

type peerClient struct {
	e    *peerEnv
	http *http.Client
}

// client logs name in ("" is anon).
func (e *peerEnv) client(name string) *peerClient {
	jar, _ := cookiejar.New(nil)
	c := &peerClient{e: e, http: &http.Client{Jar: jar}}
	if name != "" {
		resp, err := c.http.PostForm(e.srv.URL+"/api/peer/login", url.Values{"user": {name}, "password": {peerPass}})
		if err != nil || resp.StatusCode != 200 {
			e.t.Fatalf("login %s: %v %v", name, resp, err)
		}
		resp.Body.Close()
	}
	return c
}

func (c *peerClient) do(method, path, body string, hdr map[string]string) (int, map[string]any, string) {
	c.e.t.Helper()
	req, _ := http.NewRequest(method, c.e.srv.URL+path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	m := map[string]any{}
	json.Unmarshal(b, &m)
	return resp.StatusCode, m, string(b)
}

func (c *peerClient) get(path string) (int, map[string]any, string) {
	c.e.t.Helper()
	return c.do("GET", path, "", nil)
}

func peerWantStatus(t *testing.T, who, path string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("%s GET %s: %d, want %d", who, path, got, want)
	}
}

func TestPeerLoginLogout(t *testing.T) {
	e := newPeerEnv(t)
	resp, _ := http.PostForm(e.srv.URL+"/api/peer/login", url.Values{"user": {"alice"}, "password": {"nope"}})
	if resp.StatusCode != 401 {
		t.Errorf("bad password: %d", resp.StatusCode)
	}
	// JSON login; the cookie is HttpOnly, the CSRF one is not.
	resp, _ = http.Post(e.srv.URL+"/api/peer/login", "application/json", strings.NewReader(`{"user":"bob","password":"hunter22"}`))
	if resp.StatusCode != 200 {
		t.Fatalf("json login: %d", resp.StatusCode)
	}
	var sess, csrf *http.Cookie
	for _, c := range resp.Cookies() {
		switch c.Name {
		case "peer_session":
			sess = c
		case "peer_csrf":
			csrf = c
		}
	}
	if sess == nil || !sess.HttpOnly || csrf == nil || csrf.HttpOnly {
		t.Fatalf("cookies: %+v %+v", sess, csrf)
	}
	c := e.client("alice")
	if s, _, _ := c.do("POST", "/api/peer/logout", "", nil); s != 403 {
		t.Errorf("logout without CSRF: %d", s)
	}
	u, _ := url.Parse(e.srv.URL)
	var tok string
	for _, ck := range c.http.Jar.Cookies(u) {
		if ck.Name == "peer_csrf" {
			tok = ck.Value
		}
	}
	if s, _, _ := c.do("POST", "/api/peer/logout", "", map[string]string{"X-CSRF-Token": tok}); s != 200 {
		t.Errorf("logout: %d", s)
	}
	if s, _, _ := c.get("/api/peer/me"); s != 401 {
		t.Errorf("me after logout: %d", s)
	}
}

func TestPeerMeFeedAnon(t *testing.T) {
	e := newPeerEnv(t)
	anon := e.client("")
	if s, _, _ := anon.get("/api/peer/me"); s != 401 {
		t.Errorf("anon me: %d", s)
	}
	s, m, _ := anon.get("/api/peer/feed")
	if s != 200 || len(m["announcements"].([]any)) != 2 {
		t.Errorf("anon feed: %d %v", s, m)
	}
	if s, m, _ := anon.get("/api/peer/announcements/7"); s != 200 || m["title"] == nil {
		t.Errorf("anon announcement: %d %v", s, m)
	}
	_, m, _ = e.client("charlie").get("/api/peer/me")
	if m["org"] != "org-beta" || m["id"] != peerUsers["charlie"].ID {
		t.Errorf("me: %v", m)
	}
}

func TestPeerHome(t *testing.T) {
	e := newPeerEnv(t)
	_, m, _ := e.client("alice").get("/api/peer/home")
	if n := m["notes"].([]any); len(n) != 1 || n[0].(float64) != 1101 {
		t.Errorf("alice notes: %v", m["notes"])
	}
	if v := m["vault"].([]any); len(v) != 1 || v[0] != "VmF1bHRJdGVtOjEwMDE=" {
		t.Errorf("alice vault: %v", m["vault"])
	}
	_, m, _ = e.client("dave").get("/api/peer/home")
	for k, v := range m {
		if len(v.([]any)) != 0 {
			t.Errorf("dave owns %s: %v", k, v)
		}
	}
}

func TestPeerOrgDocs(t *testing.T) {
	e := newPeerEnv(t)
	p := "/api/peer/org-docs/5a1c0d0c-2e4f-4b6a-8c7d-0000a11ce001"
	for who, want := range map[string]int{"alice": 200, "bob": 200, "charlie": 403, "dave": 403, "": 401} {
		s, m, _ := e.client(who).get(p)
		peerWantStatus(t, who, p, s, want)
		if s == 200 {
			if _, has := m["private"]; has || m["visibility"] != nil {
				t.Errorf("an org doc must carry no private flag: %v", m)
			}
		}
	}
}

func TestPeerPrivateNotes(t *testing.T) {
	e := newPeerEnv(t)
	for _, who := range []string{"alice", "bob", "charlie", "dave"} {
		s, m, _ := e.client(who).get("/api/peer/private-notes/1101")
		if s != 200 || m["visibility"] != "private" || !strings.Contains(m["body"].(string), "Alice private") {
			t.Errorf("%s: note 1101: %d %v", who, s, m)
		}
	}
	if s, _, _ := e.client("bob").get("/api/peer/private-notes/987654"); s != 404 {
		t.Errorf("unknown note: %d", s)
	}
	if s, _, _ := e.client("").get("/api/peer/private-notes/1101"); s != 401 {
		t.Errorf("anon note: %d", s)
	}
}

func TestPeerPreferencesIgnoreUserID(t *testing.T) {
	e := newPeerEnv(t)
	alice := peerUsers["alice"].ID
	_, m, raw := e.client("bob").get("/api/peer/preferences?userId=" + alice)
	if m["preferences"].(map[string]any)["theme"] != "contrast" || strings.Contains(raw, "Alice Moreau") {
		t.Errorf("bob asks for alice's: %s", raw)
	}
	_, m, raw = e.client("dave").get("/api/peer/preferences?userId=" + alice)
	if len(m["preferences"].(map[string]any)) != 0 || strings.Contains(raw, "Alice") {
		t.Errorf("dave asks for alice's: %s", raw)
	}
}

func TestPeerLookupEchoes(t *testing.T) {
	e := newPeerEnv(t)
	_, m, _ := e.client("alice").get("/api/peer/lookup?itemId=vault-alice-01")
	if m["found"] != true || len(m["items"].([]any)) != 1 {
		t.Errorf("owner: %v", m)
	}
	for _, who := range []string{"bob", "dave"} {
		_, m, raw := e.client(who).get("/api/peer/lookup?itemId=vault-alice-01")
		if m["found"] != false || m["itemId"] != "vault-alice-01" || len(m["items"].([]any)) != 0 || strings.Contains(raw, "AX-5521") {
			t.Errorf("%s: %s", who, raw)
		}
	}
}

func TestPeerOrders(t *testing.T) {
	e := newPeerEnv(t)
	for id := range peerOrders {
		if len(fmt.Sprint(id)) != 19 {
			t.Errorf("order id %d is not 19 digits", id)
		}
	}
	for _, who := range []string{"alice", "bob", "dave"} {
		s, _, raw := e.client(who).get("/api/peer/orders/1700000000000000001")
		if s != 200 || !strings.Contains(raw, "Harbor Lane") {
			t.Errorf("%s: order of alice: %d %s", who, s, raw)
		}
	}
	if s, _, _ := e.client("dave").get("/api/peer/orders/1700000000000999999"); s != 404 {
		t.Errorf("unknown order: %d", s)
	}
}

func TestPeerFeaturedBogus200(t *testing.T) {
	e := newPeerEnv(t)
	_, m, _ := e.client("alice").get("/api/peer/featured/2201")
	if m["sku"] != "ALC-LAMP-44" {
		t.Errorf("owner: %v", m)
	}
	for _, c := range []struct{ who, id string }{{"bob", "2201"}, {"dave", "2201"}, {"dave", "999999"}} {
		s, m, _ := e.client(c.who).get("/api/peer/featured/" + c.id)
		if s != 200 || m["sku"] != "DEF-9" || m["title"] != "Default Pack" {
			t.Errorf("%s %s: %d %v", c.who, c.id, s, m)
		}
	}
}

func TestPeerProjectsHierarchy(t *testing.T) {
	e := newPeerEnv(t)
	cases := []struct {
		who, path string
		want      int
		leak      bool
	}{
		{"alice", "/api/peer/orgs/org-alpha/projects/proj-aurora", 200, true},
		{"bob", "/api/peer/orgs/org-alpha/projects/proj-aurora", 200, true},      // org-level: shared
		{"charlie", "/api/peer/orgs/org-alpha/projects/proj-aurora", 403, false}, // o is not charlie's
		{"charlie", "/api/peer/orgs/org-beta/projects/proj-aurora", 200, true},   // p's org forgotten
		{"alice", "/api/peer/orgs/org-alpha/projects/proj-cygnus", 200, false},   // charlie's, via alice's o
		{"dave", "/api/peer/orgs/org-beta/projects/nope", 404, false},
	}
	for _, c := range cases {
		s, _, raw := e.client(c.who).get(c.path)
		peerWantStatus(t, c.who, c.path, s, c.want)
		if c.leak && !strings.Contains(raw, "Aurora budget") {
			t.Errorf("%s %s: no project in %s", c.who, c.path, raw)
		}
	}
}

func TestPeerSignedFiles(t *testing.T) {
	e := newPeerEnv(t)
	_, m, _ := e.client("alice").get("/api/peer/file-links")
	files := m["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("links: %v", m)
	}
	u := files[0].(map[string]any)["url"].(string)
	if !regexp.MustCompile(`^/api/peer/files/doc-a1\?expires=4102444800&sig=[0-9a-f]{64}$`).MatchString(u) {
		t.Errorf("url: %s", u)
	}
	// No cookie: still the content of alice's file.
	s, _, raw := e.client("").get(u)
	if s != 200 || !strings.Contains(raw, "Alice tax return") {
		t.Errorf("anon, signed: %d %s", s, raw)
	}
	for _, bad := range []string{
		strings.Replace(u, "sig=", "sig=0", 1),
		strings.Replace(u, "doc-a1", "doc-b1", 1),
		strings.Replace(u, "4102444800", "4102444801", 1),
		"/api/peer/files/doc-a1",
	} {
		if s, _, _ := e.client("alice").get(bad); s != 403 {
			t.Errorf("%s: %d, want 403", bad, s)
		}
	}
	if _, m, _ = e.client("dave").get("/api/peer/file-links"); len(m["files"].([]any)) != 0 {
		t.Errorf("dave's links: %v", m)
	}
}

func TestPeerGraphQL(t *testing.T) {
	e := newPeerEnv(t)
	c := e.client("alice")
	batch := `[{"operationName":"GetViewer","query":"query GetViewer { viewer { id } }"},
	  {"operationName":"GetVaultItem","query":"query GetVaultItem($id: ID!) { vaultItem(id: $id) { id } }","variables":{"id":"` + relayID("VaultItem", 1002) + `"}}]`
	_, _, raw := c.do("POST", "/api/peer/graphql", batch, map[string]string{"Content-Type": "application/json"})
	var out []map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil || len(out) != 2 {
		t.Fatalf("batch answer: %s", raw)
	}
	v := out[0]["data"].(map[string]any)["viewer"].(map[string]any)
	if v["name"] != "alice" {
		t.Errorf("viewer: %v", v)
	}
	// The flaw: bob's vault item, to alice.
	item := out[1]["data"].(map[string]any)["vaultItem"].(map[string]any)
	if item["private"] != true || !strings.Contains(item["secret"].(string), "cobalt") {
		t.Errorf("vault item of bob: %v", item)
	}
	// One operation, not a batch, answers as an object; no such item is null;
	// the name is read from the document when operationName is missing.
	one := `{"query":"query GetVaultItem($id: ID!) { vaultItem(id: $id) { id } }","variables":{"id":"` + relayID("VaultItem", 4242) + `"}}`
	_, m, raw := c.do("POST", "/api/peer/graphql", one, map[string]string{"Content-Type": "application/json"})
	if d, _ := m["data"].(map[string]any); d == nil || d["vaultItem"] != nil {
		t.Errorf("unknown vault item: %s", raw)
	}
	if s, _, _ := e.client("").do("POST", "/api/peer/graphql", one, nil); s != 401 {
		t.Errorf("anon graphql: %d", s)
	}
}

func TestPeerWalletsCodes(t *testing.T) {
	e := newPeerEnv(t)
	code := func(who, path string) (int, map[string]any) {
		_, m, _ := e.client(who).get(path)
		return int(m["code"].(float64)), m
	}
	if c, m := code("alice", "/api/peer/wallets/4501"); c != 20000 || m["data"].(map[string]any)["balance"].(float64) != 750 || m["data"].(map[string]any)["tier"].(float64) != 4 {
		t.Errorf("owner: %v", m)
	}
	for _, who := range []string{"bob", "dave"} {
		c, m := code(who, "/api/peer/wallets/4501")
		if c != 40301 || m["data"] != nil {
			t.Errorf("%s: %v", who, m)
		}
	}
	if c, _ := code("dave", "/api/peer/wallets/999"); c != 40401 {
		t.Errorf("unknown wallet: %d", c)
	}
	// The leaky one: the owner's numbers, to anybody logged in; private flag.
	c, m := code("dave", "/api/peer/wallets-leaky/4501")
	d := m["data"].(map[string]any)
	if c != 20000 || d["balance"].(float64) != 750 || d["tier"].(float64) != 4 || d["private"] != true {
		t.Errorf("leaky: %v", m)
	}
	if c, _ := code("dave", "/api/peer/wallets-leaky/999"); c != 40401 {
		t.Errorf("unknown leaky wallet: %d", c)
	}
	// The short values of the people differ.
	seen := map[string]bool{}
	for _, w := range peerWallets {
		k := fmt.Sprint(w.Bal, "/", w.Tier)
		if seen[k] {
			t.Errorf("two wallets with %s", k)
		}
		seen[k] = true
	}
}

func TestPeerQuotaPhase(t *testing.T) {
	e := newPeerEnv(t)
	alice, bob := e.client("alice"), e.client("bob")
	if _, m, _ := alice.get("/api/peer/quota/5501"); m["code"].(float64) != 20000 {
		t.Errorf("crawl phase, owner: %v", m)
	}
	if _, m, _ := bob.get("/api/peer/quota/5501"); m["code"].(float64) != 40301 {
		t.Errorf("crawl phase, stranger: %v", m)
	}
	if s, _, _ := alice.do("POST", "/api/peer/_phase?p=nonsense", "", nil); s != 400 {
		t.Errorf("bad phase: %d", s)
	}
	if s, m, _ := alice.do("POST", "/api/peer/_phase?p=replay", "", nil); s != 200 || m["phase"] != "replay" {
		t.Errorf("phase: %d %v", s, m)
	}
	for _, c := range []*peerClient{alice, bob} {
		s, m, _ := c.get("/api/peer/quota/5501")
		if s != 200 || m["code"].(float64) != 2001 || m["msg"] != "expired" {
			t.Errorf("replay phase: %d %v", s, m)
		}
	}
	if s, _, _ := e.client("").get("/api/peer/quota/5501"); s != 401 {
		t.Errorf("anon quota: %d", s)
	}
}

func TestPeerNonceOnce(t *testing.T) {
	e := newPeerEnv(t)
	alice := e.client("alice")
	p := "/api/peer/signed-preview/6601"
	h := map[string]string{"X-Req-Nonce": "0123456789abcdef0123456789abcdef"}
	if s, m, _ := alice.do("GET", p, "", h); s != 200 || m["amount"].(float64) != 1250 {
		t.Errorf("first use: %d %v", s, m)
	}
	if s, _, _ := alice.do("GET", p, "", h); s != 401 {
		t.Errorf("the nonce again: %d", s)
	}
	if s, _, _ := alice.get("/api/peer/me"); s != 200 {
		t.Errorf("me after the replay: %d", s)
	}
	if s, _, _ := alice.get(p); s != 401 {
		t.Errorf("no nonce: %d", s)
	}
	if s, _, _ := alice.do("GET", p, "", map[string]string{"X-Req-Nonce": "fresh0000000000000000000000000001"}); s != 200 {
		t.Errorf("a fresh nonce: %d", s)
	}
	// A stranger with a fresh nonce is refused; the nonce is spent all the same.
	bob := e.client("bob")
	h2 := map[string]string{"X-Req-Nonce": "fresh0000000000000000000000000002"}
	if s, _, _ := bob.do("GET", p, "", h2); s != 403 {
		t.Errorf("stranger: %d", s)
	}
	if s, _, _ := alice.do("GET", p, "", h2); s != 401 {
		t.Errorf("spent nonce of a stranger: %d", s)
	}
}

func TestPeerKeysRegenerate(t *testing.T) {
	e := newPeerEnv(t)
	alice := e.client("alice")
	_, m, _ := alice.get("/api/peer/keys/key-alice-1")
	before := m["secret"]
	if e.logged("REGENERATE") {
		t.Fatal("a read logged REGENERATE")
	}
	if s, _, _ := e.client("bob").get("/api/peer/keys/key-alice-1?action=regenerate"); s != 403 {
		t.Errorf("stranger regenerates: %d", s)
	}
	if e.logged("REGENERATE") {
		t.Error("a refused regeneration was logged")
	}
	_, m, _ = alice.get("/api/peer/keys/key-alice-1?action=regenerate")
	if m["secret"] == before || !e.logged("REGENERATE user=alice key=key-alice-1") {
		t.Errorf("owner regenerates: %v, logged %v", m, e.logged("REGENERATE"))
	}
	if _, m, _ = alice.get("/api/peer/_phase"); m["regenerated"].(map[string]any)["key-alice-1"].(float64) != 1 {
		t.Errorf("phase says: %v", m)
	}
}

func TestPeerLogsWhoAsked(t *testing.T) {
	e := newPeerEnv(t)
	e.client("bob").get("/api/peer/private-notes/1101")
	e.client("").get("/api/peer/feed")
	if !e.logged("PEERLOG user=bob method=GET uri=/api/peer/private-notes/1101") || !e.logged("PEERLOG user=- method=GET uri=/api/peer/feed") {
		t.Errorf("log: %v", e.logs)
	}
}

func TestPeerOtherAppsAndPages(t *testing.T) {
	if peerAppFor("testbed/apps/authz-app", http.NotFoundHandler()) == nil {
		t.Fatal("nil")
	}
	h := peerAppFor("testbed/apps/authz-app", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "next") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/peer/me", nil))
	if rec.Body.String() != "next" {
		t.Errorf("another app answers /api/peer/: %q", rec.Body.String())
	}
}

func TestPeerIDsAreOfTheKindsTheTableNames(t *testing.T) {
	uuid4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for n, u := range peerUsers {
		if !uuid4.MatchString(u.ID) {
			t.Errorf("%s: %s is not a UUID v4", n, u.ID)
		}
	}
	for id := range peerDocs {
		if !uuid4.MatchString(id) {
			t.Errorf("doc %s is not a UUID v4", id)
		}
	}
}

// peerSecrets lists the strings of the people's data that must not leak.
func peerSecrets() []string {
	set := map[string]bool{}
	add := func(s ...string) {
		for _, x := range s {
			if len(x) >= 8 {
				set[x] = true
			}
		}
	}
	for _, u := range peerUsers {
		if s, ok := u.Prefs["signature"].(string); ok {
			add(s)
		}
	}
	for _, n := range peerNotes {
		add(n.Body, n.TaxID)
	}
	for _, d := range peerDocs {
		add(d.Body)
	}
	for _, i := range peerItems {
		add(i.Note)
	}
	for _, o := range peerOrders {
		add(o.ShipTo, o.Card)
	}
	for _, p := range peerProjects {
		add(p.Budget)
	}
	for _, f := range peerFiles {
		add(f.Content)
	}
	for _, v := range peerVaults {
		add(v.Secret)
	}
	for _, x := range peerTransfers {
		add(x.Memo, x.To)
	}
	for _, k := range peerKeys {
		add(k.Secret)
	}
	var out []string
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// secrets.txt lists exactly those strings. PEER_WRITE_SECRETS=1 rewrites it.
func TestPeerSecretsFile(t *testing.T) {
	const path = "../../apps/peer-app/secrets.txt"
	want := "# What peerscore looks for in bola.json and bola.md (go test -run TestPeerSecretsFile with PEER_WRITE_SECRETS=1 rewrites this)\n" +
		strings.Join(peerSecrets(), "\n") + "\n"
	if os.Getenv("PEER_WRITE_SECRETS") != "" {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Errorf("%s is not what peerSecrets gives (PEER_WRITE_SECRETS=1 go test -run TestPeerSecretsFile ./testbed/cmd/testbed)", path)
	}
}

// The truth names only endpoints the server has, in the shape of a key.
func TestPeerTruthShape(t *testing.T) {
	var truth peerTruth
	if err := readJSON("../../apps/peer-app/peer.truth.json", &truth); err != nil {
		t.Fatal(err)
	}
	if len(truth.Scenarios) != 5 {
		t.Errorf("%d scenarios", len(truth.Scenarios))
	}
	keyRe := regexp.MustCompile(`^(GET|POST) /api/peer/[a-z/{}-]+( (op|action)=\w+)?$`)
	for name, sc := range truth.Scenarios {
		seen := map[string]bool{}
		for _, it := range sc.Items {
			id := it.Key + it.Direction + it.Mode
			if seen[id] || !keyRe.MatchString(it.Key) || it.Verdict == "" {
				t.Errorf("%s: bad or repeated item %+v", name, it)
			}
			seen[id] = true
		}
	}
}
