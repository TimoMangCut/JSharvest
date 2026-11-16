package replay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/export"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// fakeApp is a small peer-app (testbed/cmd/testbed/peer.go) for the tests of
// authz -peers: people log in by a cookie; each route has its flaw or its care.
type fakeApp struct {
	mu       sync.Mutex
	sessions map[string]string // cookie -> user
	hits     []string
	regen    int
	phase    string          // "" while crawling, "replay" after
	nonces   map[string]bool // X-Req-Nonce values used
}

type fakeUser struct{ org, id string }

var fakeUsers = map[string]fakeUser{
	"alice": {"org-alpha", "3f0a8c1e-5d2b-4c7a-9e11-a11ce0000001"},
	"bob":   {"org-alpha", "7b2d9e44-1a6c-4f08-b3d5-b0b000000002"},
	"carol": {"org-beta", "c5e19a07-8b3f-4d62-a4c8-c4a41e000003"},
	"dave":  {"org-beta", "d4e0f6b2-2c9a-4a71-8f3e-da7e00000004"},
}

const (
	docA = "5a1c0d0c-2e4f-4b6a-8c7d-0000a11ce001"
	docB = "5b0b0d0c-3f5a-4c7b-9d8e-0000b0b00002"
	hmKy = "fake-hmac-key"
)

func fakeSig(id string) string {
	m := hmac.New(sha256.New, []byte(hmKy))
	m.Write([]byte(id))
	return hex.EncodeToString(m.Sum(nil))
}

func (a *fakeApp) login(user string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	tok := "tok-" + user + "-" + strconv.Itoa(len(a.sessions)+1) + "-0123456789abcdef"
	a.sessions[tok] = user
	return tok
}

func (a *fakeApp) restart() {
	a.mu.Lock()
	a.sessions = map[string]string{}
	a.mu.Unlock()
}

func (a *fakeApp) handler() http.Handler {
	mux := http.NewServeMux()
	js := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
	authed := func(h func(w http.ResponseWriter, r *http.Request, u string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie("sess")
			a.mu.Lock()
			u := ""
			if err == nil {
				u = a.sessions[c.Value]
			}
			a.hits = append(a.hits, fmt.Sprintf("%s %s %s", orDash(u), r.Method, r.URL.RequestURI()))
			a.mu.Unlock()
			if u == "" {
				js(w, 401, map[string]string{"error": "unauthenticated"})
				return
			}
			h(w, r, u)
		}
	}
	mux.HandleFunc("GET /api/feed", func(w http.ResponseWriter, r *http.Request) {
		js(w, 200, map[string]any{"announcements": []map[string]any{{"id": 7, "title": "Maintenance window"}, {"id": 8, "title": "New office hours"}}})
	})
	mux.HandleFunc("GET /api/orgs", func(w http.ResponseWriter, r *http.Request) {
		js(w, 200, map[string]any{"orgs": []string{"org-alpha", "org-beta"}})
	})
	mux.HandleFunc("GET /api/csrf", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		js(w, 200, map[string]any{"csrf": "csrf-" + u + "-0123456789"})
	}))
	mux.HandleFunc("GET /api/announcements/{id}", func(w http.ResponseWriter, r *http.Request) {
		js(w, 200, map[string]any{"id": r.PathValue("id"), "title": "Maintenance window", "body": "down on Sunday from 02:00 UTC"})
	})
	mux.HandleFunc("GET /api/me", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		js(w, 200, map[string]any{"id": fakeUsers[u].id, "name": u, "org": fakeUsers[u].org})
	}))
	ownProj := map[string]string{"alice": "proj-aurora", "bob": "proj-borealis", "carol": "proj-cygnus"}
	mux.HandleFunc("GET /api/home", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		ps := []map[string]string{}
		if p, ok := ownProj[u]; ok {
			ps = append(ps, map[string]string{"org": fakeUsers[u].org, "id": p})
		}
		js(w, 200, map[string]any{"projects": ps, "keys": []string{"key-" + u + "-1"}})
	}))
	notes := map[int][3]string{1101: {"alice", "Vault codes", "Alice private: the safe code is 48-17-92 behind the blue ledger"}, 1201: {"bob", "Garage", "Bob private: the spare key hangs under the third crate of hops"}}
	mux.HandleFunc("GET /api/notes/{id}", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		n, ok := notes[id]
		if !ok {
			js(w, 404, map[string]string{"error": "not found"})
			return
		}
		js(w, 200, map[string]any{"id": id, "visibility": "private", "title": n[1], "body": n[2]})
	}))
	docs := map[string][3]string{docA: {"org-alpha", "Alpha roadmap", "Alpha roadmap: ship the amber release after the Lisbon audit"}, docB: {"org-alpha", "Alpha budget", "Alpha budget: reserve 41 percent for the Kestrel migration"}}
	mux.HandleFunc("GET /api/docs/{id}", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		d, ok := docs[r.PathValue("id")]
		switch {
		case !ok:
			js(w, 404, map[string]string{"error": "not found"})
		case d[0] != fakeUsers[u].org:
			js(w, 403, map[string]string{"error": "forbidden"})
		default:
			js(w, 200, map[string]any{"id": r.PathValue("id"), "title": d[1], "body": d[2]})
		}
	}))
	prefs := map[string]map[string]string{"alice": {"theme": "solarized", "signature": "Alice Moreau, 14 Harbor Lane, flat 3B"}, "bob": {"theme": "contrast", "signature": "Robert Quill, 77 Mill Street, unit 9"},
		"carol": {"theme": "forest", "signature": "Carol Vane, 5 Quarry Road"}, "dave": {}}
	mux.HandleFunc("GET /api/prefs", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		js(w, 200, map[string]any{"preferences": prefs[u]})
	}))
	items := map[string][3]string{"vault-alice-01": {"alice", "ALC-77", "the amber ring is insured under policy AX-5521-77"}, "vault-bob-01": {"bob", "BOB-31", "the brass compass sits in locker 12"}}
	mux.HandleFunc("GET /api/lookup", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		id := r.URL.Query().Get("itemId")
		it, ok := items[id]
		if !ok || it[0] != u {
			js(w, 200, map[string]any{"itemId": id, "items": []any{}, "found": false})
			return
		}
		js(w, 200, map[string]any{"itemId": id, "found": true, "items": []map[string]string{{"sku": it[1], "note": it[2]}}})
	}))
	orders := map[int64][2]string{1700000000000000001: {"alice", "Alice Moreau, 14 Harbor Lane, flat 3B"}, 1700000000000004002: {"bob", "Robert Quill, 77 Mill Street, unit 9"}}
	mux.HandleFunc("GET /api/orders/{id}", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		o, ok := orders[id]
		if !ok {
			js(w, 404, map[string]string{"error": "not found"})
			return
		}
		js(w, 200, map[string]any{"id": id, "ownerId": fakeUsers[o[0]].id, "total": 18250, "shipTo": o[1]})
	}))
	feat := map[int][3]string{2201: {"alice", "Alice Pick: the amber lamp", "ALC-LAMP-44"}, 2202: {"bob", "Bob Pick: the brass vice", "BOB-VICE-45"}}
	mux.HandleFunc("GET /api/featured/{id}", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		if f, ok := feat[id]; ok && f[0] == u {
			js(w, 200, map[string]string{"title": f[1], "sku": f[2]})
			return
		}
		js(w, 200, map[string]string{"title": "Default Pack", "sku": "DEF-9"})
	}))
	wallets := map[int][3]any{4501: {"alice", 750, 4}, 4502: {"bob", 120, 2}}
	wallet := func(leaky bool) http.HandlerFunc {
		return authed(func(w http.ResponseWriter, r *http.Request, u string) {
			id, _ := strconv.Atoi(r.PathValue("id"))
			x, ok := wallets[id]
			switch {
			case !ok:
				js(w, 200, map[string]any{"code": 40401, "msg": "not found"})
			case leaky:
				js(w, 200, map[string]any{"code": 20000, "data": map[string]any{"balance": x[1], "tier": x[2], "private": true}})
			case x[0] != u:
				js(w, 200, map[string]any{"code": 40301, "msg": "forbidden"})
			default:
				js(w, 200, map[string]any{"code": 20000, "data": map[string]any{"balance": x[1], "tier": x[2]}})
			}
		})
	}
	mux.HandleFunc("GET /api/wallets/{id}", wallet(false))
	mux.HandleFunc("GET /api/wallets-leaky/{id}", wallet(true))
	projects := map[string][3]string{"proj-aurora": {"org-alpha", "Aurora", "Aurora budget: 912000 for the Kestrel rollout"}, "proj-borealis": {"org-alpha", "Borealis", "Borealis budget: 477500 for the Mill Street refit"},
		"proj-cygnus": {"org-beta", "Cygnus", "Cygnus budget: 265000 for the Fenwick depot closure"}}
	mux.HandleFunc("GET /api/orgs/{o}/projects/{p}", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		if r.PathValue("o") != fakeUsers[u].org {
			js(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		p, ok := projects[r.PathValue("p")]
		if !ok {
			js(w, 404, map[string]string{"error": "not found"})
			return
		}
		js(w, 200, map[string]any{"id": r.PathValue("p"), "name": p[1], "budget": p[2]})
	}))
	files := map[string]string{"doc-a1": "Alice tax return 2025: income 88213 and refund 1904 at account AC-5521-9987", "doc-b1": "Bob lease: Mill Street unit 9, 1450 a month until March 2028"}
	mux.HandleFunc("GET /api/file-links", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		id := "doc-" + u[:1] + "1"
		js(w, 200, map[string]any{"files": []map[string]string{{"id": id, "url": "/api/files/" + id + "?expires=4102444800&sig=" + fakeSig(id)}}})
	}))
	mux.HandleFunc("GET /api/files/{id}", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.hits = append(a.hits, "- GET "+r.URL.RequestURI())
		a.mu.Unlock()
		id := r.PathValue("id")
		if !hmac.Equal([]byte(r.URL.Query().Get("sig")), []byte(fakeSig(id))) {
			js(w, 403, map[string]string{"error": "bad signature"})
			return
		}
		c, ok := files[id]
		if !ok {
			js(w, 404, map[string]string{"error": "not found"})
			return
		}
		js(w, 200, map[string]string{"id": id, "name": id + "-2025.txt", "content": c})
	})
	transfers := map[int]string{6601: "alice", 6602: "bob"}
	mux.HandleFunc("GET /api/transfers/{id}", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		n := r.Header.Get("X-Req-Nonce")
		a.mu.Lock()
		used := n == "" || a.nonces[n]
		a.nonces[n] = true
		a.mu.Unlock()
		if used {
			js(w, 401, map[string]string{"error": "nonce missing or already used"})
			return
		}
		id, _ := strconv.Atoi(r.PathValue("id"))
		if transfers[id] != u {
			js(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		js(w, 200, map[string]any{"id": id, "memo": "invoice 20931 for the amber lamp", "to": "ACC-ALICE-3312"})
	}))
	mux.HandleFunc("GET /api/quota/{id}", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		a.mu.Lock()
		phase := a.phase
		a.mu.Unlock()
		if phase == "replay" {
			js(w, 200, map[string]any{"code": 2001, "msg": "expired"})
			return
		}
		js(w, 200, map[string]any{"code": 20000, "data": map[string]any{"used": 42, "limit": 100}})
	}))
	mux.HandleFunc("GET /api/pins/{id}", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		js(w, 200, map[string]any{"id": r.PathValue("id"), "pin": "4417-2208-9931 held by alice"})
	}))
	mux.HandleFunc("GET /api/keys/{id}", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		if r.URL.Query().Get("action") == "regenerate" {
			a.mu.Lock()
			a.regen++
			a.mu.Unlock()
		}
		js(w, 200, map[string]string{"id": r.PathValue("id"), "secret": "ks_" + u + "_4f9c21d7a0b3"})
	}))
	vault := map[int][3]string{1001: {"alice", "Alice vault entry", "Alice vault secret: seed phrase begins amber orbit velvet"}, 1002: {"bob", "Bob vault entry", "Bob vault secret: seed phrase begins cobalt ember anchor"}}
	mux.HandleFunc("POST /api/graphql", authed(func(w http.ResponseWriter, r *http.Request, u string) {
		b, _ := io.ReadAll(r.Body)
		var els []map[string]any
		if json.Unmarshal(b, &els) != nil {
			js(w, 400, map[string]string{"error": "bad batch"})
			return
		}
		out := make([]map[string]any, len(els))
		for i, el := range els {
			switch el["operationName"] {
			case "GetViewer":
				out[i] = map[string]any{"data": map[string]any{"viewer": map[string]any{"id": fakeUsers[u].id, "name": u}}}
			case "GetVaultItem":
				vars, _ := el["variables"].(map[string]any)
				id, _ := vars["id"].(string)
				_, inner, _, _, ok := DecodeRelay(id)
				n, _ := strconv.Atoi(inner)
				if v, found := vault[n]; ok && found {
					out[i] = map[string]any{"data": map[string]any{"vaultItem": map[string]any{"id": id, "label": v[1], "secret": v[2], "private": true}}}
				} else {
					out[i] = map[string]any{"data": map[string]any{"vaultItem": nil}}
				}
			}
		}
		js(w, 200, out)
	}))
	return mux
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type rq struct {
	method, path, body string
	held               bool
	hdr                map[string]string
}

// recordDir crawls the requests as a user against the server and writes the
// requests.jsonl and flows.jsonl of a role's directory.
func recordDir(t *testing.T, base, dir, tok string, reqs []rq, links []flow.Link) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(base, "http://")
	t0 := time.Now().UTC().Add(-time.Hour)
	var lines []string
	var refs []flow.Ref
	for i, r := range reqs {
		id := i + 1
		h := map[string]string{"host": host, "accept": "*/*"}
		if tok != "" {
			h["cookie"] = "sess=" + tok
		}
		e := traffic.Entry{Run: "R1", ID: id, Time: t0.Add(time.Duration(i) * time.Second), Target: "page", ResourceType: "Fetch", Method: r.method,
			URL: base + r.path, Headers: h, Outcome: "ok"}
		for k, v := range r.hdr {
			h[k] = v
		}
		if r.body != "" {
			h["content-type"] = "application/json"
			e.Body = traffic.Body{Body: r.body}
		}
		if r.held {
			e.Outcome = "held_back:write"
			e.Response = &traffic.Response{Status: 200, MIME: "application/json", Headers: map[string]string{"content-type": "application/json", traffic.GuardHeader: "write"}, Body: traffic.Body{Body: "{}"}}
		} else {
			req, _ := http.NewRequest(r.method, base+r.path, strings.NewReader(r.body))
			if tok != "" {
				req.AddCookie(&http.Cookie{Name: "sess", Value: tok})
			}
			if r.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			for k, v := range r.hdr {
				req.Header.Set(k, v)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			e.Response = &traffic.Response{Status: int64(resp.StatusCode), MIME: "application/json", Source: "network",
				Headers: map[string]string{"content-type": "application/json"}, Body: traffic.Body{Body: string(b)}}
		}
		b, _ := json.Marshal(e)
		lines = append(lines, string(b))
		refs = append(refs, flow.Ref{ID: id})
	}
	if err := os.WriteFile(filepath.Join(dir, "requests.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if filepath.Base(dir) == "anon" {
		return
	}
	f := flow.Flow{Run: "R1", Action: "a1", Kind: "load", Label: "page", Started: t0, Ended: t0.Add(time.Duration(len(reqs)) * time.Second), Requests: refs, DependsOn: links}
	b, _ := json.Marshal(f)
	if err := os.WriteFile(filepath.Join(dir, "flows.jsonl"), append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// userReqs is what a user's page asks for: only ids of its own.
func userReqs(u, tok string) ([]rq, []flow.Link) {
	proj := map[string]string{"alice": "proj-aurora", "bob": "proj-borealis", "carol": "proj-cygnus"}
	notes := map[string]string{"alice": "1101", "bob": "1201"}
	docs := map[string]string{"alice": docA, "bob": docB}
	orders := map[string]string{"alice": "1700000000000000001", "bob": "1700000000000004002"}
	feat := map[string]string{"alice": "2201", "bob": "2202"}
	wal := map[string]string{"alice": "4501", "bob": "4502"}
	transfers := map[string]string{"alice": "6601", "bob": "6602"}
	quota := map[string]string{"alice": "5501", "bob": "5502"}
	items := map[string]string{"alice": "vault-alice-01", "bob": "vault-bob-01"}
	vault := map[string]int{"alice": 1001, "bob": 1002}
	id := fakeUsers[u].id
	reqs := []rq{
		{method: "GET", path: "/api/feed"}, {method: "GET", path: "/api/announcements/7"}, {method: "GET", path: "/api/announcements/8"},
		{method: "GET", path: "/api/me"}, {method: "GET", path: "/api/home"},
		{method: "GET", path: "/api/prefs?userId=" + id},
	}
	var links []flow.Link
	if p, ok := proj[u]; ok {
		reqs = append(reqs, rq{method: "GET", path: "/api/orgs/" + fakeUsers[u].org + "/projects/" + p})
		// The org segment came from the home response.
		links = append(links, flow.Link{Request: len(reqs), At: "path:3", From: flow.LinkEnd{Request: 5, At: "json:$.projects[0].org"}},
			flow.Link{Request: len(reqs), At: "path:5", From: flow.LinkEnd{Request: 5, At: "json:$.projects[0].id"}})
	}
	if n, ok := notes[u]; ok {
		reqs = append(reqs,
			rq{method: "GET", path: "/api/docs/" + docs[u]},
			rq{method: "GET", path: "/api/notes/" + n},
			rq{method: "GET", path: "/api/lookup?itemId=" + items[u]},
			rq{method: "GET", path: "/api/orders/" + orders[u]},
			rq{method: "GET", path: "/api/featured/" + feat[u]},
			rq{method: "GET", path: "/api/wallets/" + wal[u]},
			rq{method: "GET", path: "/api/wallets-leaky/" + wal[u]},
			rq{method: "GET", path: "/api/file-links"},
			rq{method: "GET", path: "/api/transfers/" + transfers[u], hdr: map[string]string{"x-req-nonce": "nonce-" + u + "-0001-4f9c21d7"}},
			rq{method: "GET", path: "/api/quota/" + quota[u]},
			rq{method: "POST", path: "/api/graphql", body: fmt.Sprintf(`[{"operationName":"GetViewer","query":"query GetViewer { viewer { id name } }","variables":{}},`+
				`{"operationName":"GetVaultItem","query":"query GetVaultItem($id: ID!) { vaultItem(id: $id) { id label secret private } }","variables":{"id":%q}}]`,
				EncodeRelay("VaultItem", strconv.Itoa(vault[u]), 0))},
			rq{method: "GET", path: "/api/keys/key-" + u + "-1?action=regenerate", held: true},
		)
		// The key id came from the home answer; the file id from the links'.
		links = append(links, flow.Link{Request: len(reqs), At: "path:3", From: flow.LinkEnd{Request: 5, At: "json:$.keys[0]"}})
		linksID := len(reqs) - 4 // /api/file-links
		fid := "doc-" + u[:1] + "1"
		reqs = append(reqs, rq{method: "GET", path: "/api/files/" + fid + "?expires=4102444800&sig=" + fakeSig(fid)})
		links = append(links, flow.Link{Request: len(reqs), At: "path:3", From: flow.LinkEnd{Request: linksID, At: "json:$.files[0].id"}})
	}
	if u == "alice" {
		// A credential in the query, that nothing refreshes: never sent as bob.
		reqs = append(reqs, rq{method: "GET", path: "/api/pins/3001?access_token=" + tok})
	}
	return reqs, links
}

type bolaFixture struct {
	app     *fakeApp
	srv     *httptest.Server
	root    string // <out>/<host>
	prof    string
	toks    map[string]string
	hostDir string
}

func newBolaFixture(t *testing.T) *bolaFixture {
	t.Helper()
	app := &fakeApp{sessions: map[string]string{}, nonces: map[string]bool{}}
	srv := httptest.NewServer(app.handler())
	t.Cleanup(srv.Close)
	f := &bolaFixture{app: app, srv: srv, toks: map[string]string{}}
	out := t.TempDir()
	f.hostDir = strings.ReplaceAll(strings.TrimPrefix(srv.URL, "http://"), ":", "_")
	f.root = filepath.Join(out, f.hostDir)
	recordDir(t, srv.URL, filepath.Join(f.root, "anon"), "", []rq{{method: "GET", path: "/api/feed"}, {method: "GET", path: "/api/announcements/7"}, {method: "GET", path: "/api/orgs"}}, nil)
	for _, u := range []string{"alice", "bob", "carol", "dave"} {
		tok := app.login(u)
		f.toks[u] = tok
		reqs, links := userReqs(u, tok)
		recordDir(t, srv.URL, filepath.Join(f.root, u), tok, reqs, links)
	}
	// The crawl is over: quota's token expires for everybody.
	app.mu.Lock()
	app.phase = "replay"
	app.mu.Unlock()
	return f
}

func (f *bolaFixture) run(t *testing.T, peers [2]string, rel Relation, mod func(*BolaOptions)) (*BolaReport, string) {
	t.Helper()
	dest := filepath.Join(f.root, "authz")
	os.RemoveAll(dest)
	s, err := NewSender(SenderOptions{AllowPrivate: true, Max: 2000, Log: filepath.Join(dest, "bola.sent.jsonl"), UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	o := BolaOptions{Root: f.root, Peers: peers, Relation: rel, Sender: s, InScope: func(string) bool { return true }, Out: dest}
	if mod != nil {
		mod(&o)
	}
	rep, err := Bola(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if err := rep.Write(dest); err != nil {
		t.Fatal(err)
	}
	return rep, dest
}

var hostRe = regexp.MustCompile(` [^ /]+/`)

// verdicts is a report as "METHOD /path [op] direction mode" -> verdict.
func verdicts(rep *BolaReport) map[string]string {
	out := map[string]string{}
	for _, it := range rep.Items {
		k := hostRe.ReplaceAllString(it.Key, " /")
		k = placeholderAnyRe.ReplaceAllString(k, "{}")
		out[k+" | "+it.Direction+" | "+it.Mode] = string(it.Verdict)
	}
	return out
}

func checkVerdicts(t *testing.T, rep *BolaReport, want map[string]string) {
	t.Helper()
	got := verdicts(rep)
	for k, v := range want {
		if got[k] != v {
			reason := ""
			for _, it := range rep.Items {
				if strings.Contains(k, strings.TrimPrefix(hostRe.ReplaceAllString(it.Key, " /"), "")) && strings.Contains(k, it.Direction) && strings.HasSuffix(k, it.Mode) {
					reason = it.Reason
				}
			}
			t.Errorf("%s: %q, want %q (%s)", k, got[k], v, reason)
		}
	}
	for k, v := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("EXTRA %s: %s", k, v)
		}
	}
	if len(rep.Items) != len(got) {
		t.Errorf("%d items, %d distinct keys: a duplicate", len(rep.Items), len(got))
	}
}

func both(dir1, dir2 string, m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out["GET "+k+" | "+dir1+" | main"] = v
		out["GET "+k+" | "+dir2+" | main"] = v
	}
	return out
}

func TestBolaSameOrg(t *testing.T) {
	f := newBolaFixture(t)
	rep, dest := f.run(t, [2]string{"alice", "bob"}, RelSameOrg, nil)
	want := both("alice->bob", "bob->alice", map[string]string{
		"/api/docs/{}":                   "shared",
		"/api/notes/{}":                  "bypass",
		"/api/prefs":                     "enforced",
		"/api/lookup":                    "enforced",
		"/api/orders/{}":                 "bypass",
		"/api/featured/{}":               "enforced",
		"/api/wallets/{}":                "enforced",
		"/api/wallets-leaky/{}":          "bypass",
		"/api/orgs/{}/projects/{}":       "shared",
		"/api/files/{}":                  "unauthenticated",
		"/api/keys/{} action=regenerate": "skipped",
		"/api/transfers/{}":              "replay_broken",
		"/api/quota/{}":                  "unclear",
	})
	want["GET /api/pins/{} | alice->bob | main"] = "unclear"
	for _, d := range []string{"alice->bob", "bob->alice"} {
		want["POST /api/graphql op=GetVaultItem | "+d+" | main"] = "bypass"
	}
	checkVerdicts(t, rep, want)
	if rep.Summary["bypass"] != 8 || rep.StoppedEndpoints != nil {
		t.Errorf("%v %v", rep.Summary, rep.StoppedEndpoints)
	}
	checkRun(t, f, rep, dest, false)
	for _, it := range rep.Items {
		if (it.Verdict == Bypass || it.Verdict == Shared || it.Verdict == Unauthenticated) && len(it.Evidence) == 0 {
			t.Errorf("%s %s: no evidence", it.Key, it.Direction)
		}
		for _, e := range it.Evidence {
			if !strings.HasPrefix(e.Value, "REDACTED_") || (e.RefVal != "" && !strings.HasPrefix(e.RefVal, "REDACTED_")) {
				t.Errorf("%s: evidence %s not masked: %q", it.Key, e.Path, e.Value)
			}
		}
	}
	// With -private the project is a bypass; with -reveal the values show.
	rep, dest = f.run(t, [2]string{"alice", "bob"}, RelSameOrg, func(o *BolaOptions) {
		o.Private, o.Reveal = regexp.MustCompile(`orgs/.*/projects`), true
	})
	for _, it := range rep.Items {
		if strings.Contains(it.Key, "/projects/") && it.Verdict != Bypass {
			t.Errorf("-private: %s %s", it.Key, it.Verdict)
		}
	}
	if rep.Redacted {
		t.Error("redacted under -reveal")
	}
	b, _ := os.ReadFile(filepath.Join(dest, "bola.json"))
	if !bytes.Contains(b, []byte("TAX-ALICE")) && !bytes.Contains(b, []byte("Alice private")) {
		t.Error("the evidence's values are not shown under -reveal")
	}
}

// checkRun checks what every run keeps to: nobody's credential under another
// identity, no regeneration or login, the files 0600 in 0700, the server saw
// what the log says.
func checkRun(t *testing.T, f *bolaFixture, rep *BolaReport, dest string, restarted bool) {
	t.Helper()
	// Credentials: a request sent as X carries no other person's token.
	sent, err := os.ReadFile(filepath.Join(dest, "bola.sent.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, l := range bytes.Split(bytes.TrimSpace(sent), []byte("\n")) {
		var s struct{ Role, Request string }
		if err := json.Unmarshal(l, &s); err != nil {
			t.Fatal(err)
		}
		n++
		for u, tok := range f.toks {
			if u != s.Role && strings.Contains(s.Request, tok) {
				t.Errorf("a request sent as %s carries %s's session", s.Role, u)
			}
		}
		if s.Role == "(none)" && strings.Contains(s.Request, "sess=") {
			t.Errorf("a request with no identity carries a cookie")
		}
	}
	if n != rep.Sent {
		t.Errorf("sent.jsonl has %d lines, the report says %d", n, rep.Sent)
	}
	files, _ := filepath.Glob(filepath.Join(dest, "trials", "*.http"))
	for _, p := range files {
		b, _ := os.ReadFile(p)
		m := regexp.MustCompile(`-as-([^.]+)\.http$`).FindStringSubmatch(p)
		for u, tok := range f.toks {
			if m != nil && u != m[1] && bytes.Contains(b, []byte(tok)) {
				t.Errorf("%s carries %s's session", filepath.Base(p), u)
			}
		}
	}
	if len(files) == 0 && !restarted {
		t.Error("no trial files")
	}
	for _, p := range append(files, filepath.Join(dest, "bola.json"), filepath.Join(dest, "bola.md"), filepath.Join(dest, "bola.sent.jsonl")) {
		if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", p, err, st)
		}
	}
	if st, err := os.Stat(dest); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("%s: %v", dest, err)
	}
	f.app.mu.Lock()
	defer f.app.mu.Unlock()
	if f.app.regen != 0 {
		t.Errorf("the server regenerated a key %d times", f.app.regen)
	}
	for _, h := range f.app.hits {
		if strings.Contains(h, "action=regenerate") {
			t.Errorf("the server saw %s", h)
		}
	}
}

func TestBolaCrossOrg(t *testing.T) {
	f := newBolaFixture(t)
	// carol, of org-beta, has an own project and preferences; dave nothing.
	rep, dest := f.run(t, [2]string{"alice", "dave"}, RelCrossOrg, nil)
	want := map[string]string{}
	for k, v := range both("alice->dave", "x", map[string]string{
		"/api/docs/{}":                   "enforced",
		"/api/notes/{}":                  "bypass",
		"/api/prefs":                     "enforced",
		"/api/lookup":                    "enforced",
		"/api/orders/{}":                 "bypass",
		"/api/featured/{}":               "enforced",
		"/api/wallets/{}":                "enforced",
		"/api/wallets-leaky/{}":          "bypass",
		"/api/orgs/{}/projects/{}":       "enforced-parent",
		"/api/files/{}":                  "unauthenticated",
		"/api/keys/{} action=regenerate": "skipped",
		"/api/transfers/{}":              "replay_broken",
		"/api/quota/{}":                  "unclear",
	}) {
		if !strings.Contains(k, "| x |") {
			want[k] = v
		}
	}
	want["POST /api/graphql op=GetVaultItem | alice->dave | main"] = "bypass"
	want["GET /api/prefs | dave->alice | main"] = "enforced"
	want["GET /api/pins/{} | alice->dave | main"] = "unclear"
	checkVerdicts(t, rep, want)
	checkRun(t, f, rep, dest, false)
	// The Bogus ids are far from the real ones.
	sent, _ := os.ReadFile(filepath.Join(dest, "bola.sent.jsonl"))
	bogus := 0
	for _, l := range bytes.Split(bytes.TrimSpace(sent), []byte("\n")) {
		var s struct{ Purpose, Request string }
		json.Unmarshal(l, &s)
		if s.Purpose == "bogus" {
			bogus++
		}
	}
	if bogus == 0 {
		t.Error("no Bogus sent")
	}
	for _, it := range rep.Items {
		for _, id := range it.IDs {
			if id.Bogus == "" {
				continue
			}
			if id.Bogus == id.Value || near(id.Bogus, id.Value, id.Kind) || strings.HasPrefix(id.Bogus, "-") || id.Bogus == "0" {
				t.Errorf("%s: bogus %q of %q", it.Key, id.Bogus, id.Value)
			}
		}
	}

	// -substitute: carol has a project of her own, the other id of the
	// request is the parent that she has: the leaf is the flaw.
	rep, dest = f.run(t, [2]string{"alice", "carol"}, RelCrossOrg, func(o *BolaOptions) { o.Substitute = true })
	got := verdicts(rep)
	for k, v := range map[string]string{
		"GET /api/orgs/{}/projects/{} | alice->carol | main":              "enforced-parent",
		"GET /api/orgs/{}/projects/{} | alice->carol | substitute:path:3": "enforced",
		"GET /api/orgs/{}/projects/{} | alice->carol | substitute:path:5": "bypass",
		"GET /api/prefs | alice->carol | main":                            "enforced",
	} {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	checkRun(t, f, rep, dest, false)
	// Without -substitute only the main trial is sent.
	rep, _ = f.run(t, [2]string{"alice", "carol"}, RelCrossOrg, nil)
	for k := range verdicts(rep) {
		if strings.Contains(k, "substitute") {
			t.Errorf("a substitute trial without -substitute: %s", k)
		}
	}
}

func TestBolaDeadSessions(t *testing.T) {
	f := newBolaFixture(t)
	f.app.restart() // every session gone
	rep, dest := f.run(t, [2]string{"alice", "bob"}, RelSameOrg, nil)
	if len(rep.Items) == 0 {
		t.Fatal("no items")
	}
	for _, it := range rep.Items {
		if it.Verdict != Unclear && it.Verdict != Skipped {
			t.Errorf("%s %s: %s (%s) with every session dead", it.Key, it.Direction, it.Verdict, it.Reason)
		}
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "session is dead") {
		t.Errorf("notes: %q", notes)
	}
	checkRun(t, f, rep, dest, true)
}

func TestBolaPeerSessionDiesDuringTheRun(t *testing.T) {
	// B's session is revoked after the first requests: what it is refused
	// afterwards is not enforced.
	f := newBolaFixture(t)
	var n int
	var mu sync.Mutex
	var died time.Time
	inner := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		if n == 40 {
			died = time.Now()
			f.app.mu.Lock()
			delete(f.app.sessions, f.toks["bob"])
			f.app.mu.Unlock()
		}
		mu.Unlock()
		inner.ServeHTTP(w, r)
	})
	rep, _ := f.run(t, [2]string{"alice", "bob"}, RelSameOrg, nil)
	mu.Lock()
	defer mu.Unlock()
	if died.IsZero() {
		t.Fatal("the session was never revoked")
	}
	after, dead := 0, false
	for _, it := range rep.Items {
		if it.As != "bob" || it.At.Before(died) {
			continue
		}
		after++
		if it.Verdict == Enforced || it.Verdict == EnforcedParent {
			t.Errorf("%s %s: %s after B's session died (%s)", it.Key, it.Direction, it.Verdict, it.Reason)
		}
		dead = dead || strings.Contains(it.Reason, "dead")
	}
	if after == 0 || !dead {
		t.Errorf("%d items after the death, one says dead: %v: %v", after, dead, rep.Summary)
	}
}

func mustModel(t *testing.T, dir string) *export.Model {
	t.Helper()
	m, err := export.Load(export.Options{Dir: dir, Run: "all"})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAlignWildcards(t *testing.T) {
	f := newBolaFixture(t)
	a := mustModel(t, filepath.Join(f.root, "alice"))
	b := mustModel(t, filepath.Join(f.root, "bob"))
	al := alignWildcards(a, b)
	found := false
	for r, pos := range al {
		if strings.Contains(r.Entry.URL, "/api/notes/") && pos[3] {
			found = true
		}
		if pos[1] || pos[2] {
			t.Errorf("a constant segment taken as an id: %s %v", r.Entry.URL, pos)
		}
	}
	if !found {
		t.Error("the note id was not found to vary")
	}
}

func TestBolaDryRun(t *testing.T) {
	f := newBolaFixture(t)
	f.app.mu.Lock()
	before := len(f.app.hits)
	f.app.mu.Unlock()
	rep, _ := f.run(t, [2]string{"alice", "bob"}, RelSameOrg, func(o *BolaOptions) {
		s, err := NewSender(SenderOptions{AllowPrivate: true, DryRun: true, Max: 500, Log: filepath.Join(o.Out, "bola.sent.jsonl")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		o.Sender = s
	})
	f.app.mu.Lock()
	defer f.app.mu.Unlock()
	if len(f.app.hits) != before {
		t.Errorf("a dry run sent %d requests", len(f.app.hits)-before)
	}
	for _, it := range rep.Items {
		// A request that still carries a credential of A's is not sent in a
		// dry run either: unclear, with its reason.
		if it.Verdict != Skipped && !(it.Verdict == Unclear && strings.Contains(it.Reason, "credential of A")) {
			t.Errorf("%s %s: %s in a dry run", it.Key, it.Direction, it.Verdict)
		}
	}
	if len(rep.Items) == 0 {
		t.Error("no items")
	}
}

func TestBolaBudget(t *testing.T) {
	f := newBolaFixture(t)
	rep, _ := f.run(t, [2]string{"alice", "bob"}, RelSameOrg, func(o *BolaOptions) {
		s, err := NewSender(SenderOptions{AllowPrivate: true, Max: 25, Log: filepath.Join(o.Out, "bola.sent.jsonl")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		o.Sender = s
	})
	if rep.Sent > 25 {
		t.Errorf("%d sent, the budget 25", rep.Sent)
	}
	spent := 0
	for _, it := range rep.Items {
		if it.Verdict == Skipped && strings.Contains(it.Reason, "budget") {
			spent++
		}
		// What was not finished is never a finding built on a half.
		if (it.Verdict == Enforced || it.Verdict == EnforcedParent) && it.Trial == nil {
			t.Errorf("%s: enforced without a trial", it.Key)
		}
	}
	if spent == 0 && rep.Stopped == "" {
		t.Errorf("the budget spent, no item says so: %v", rep.Summary)
	}
}

func TestHasIdentityFor(t *testing.T) {
	id := NewIdentity("p", nil, []traffic.Entry{{URL: "http://a.test/x", Headers: map[string]string{"host": "a.test", "cookie": "s=1"}}}, time.Now())
	p := &peerCtx{roleCtx: &roleCtx{id: id}}
	if !hasIdentityFor(p, "http://a.test/y") {
		t.Error("the host it has a cookie for")
	}
	if hasIdentityFor(p, "http://b.test/y") {
		t.Error("another host: no cookie, no header credential")
	}
	id.Creds["authorization"] = "Bearer x"
	if !hasIdentityFor(p, "http://b.test/y") {
		t.Error("a header credential goes to every host")
	}
}
