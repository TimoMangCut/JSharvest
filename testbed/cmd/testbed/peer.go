package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// peerApp is the server of peer-app (testbed/apps/peer-app, plan-28 6, P5.3):
// the fixture of authz -peers (docs/gd7-bola-design.md 6.1-6.2). Four people
// log in at POST /api/peer/login: alice and bob (org-alpha), charlie and dave
// (org-beta; dave owns nothing). Every route under /api/peer/ answers as the
// table of 6.2 says, each with its own flaw or its own care:
//
//	/me, /home            the caller's own profile and the ids of what it owns
//	/feed, /announcements shared, open to anon
//	/org-docs/{uuid}      org check only: shared inside an org, 403 outside
//	/private-notes/{id}   login only, no owner check: the BOLA (visibility private)
//	/preferences?userId=  userId ignored: the caller's own
//	/lookup?itemId=       a stranger gets the id echoed and nothing else
//	/orders/{snowflake}   no owner check; an unknown id is 404
//	/featured/{id}        owner or the default pack (200), never an error
//	/orgs/{o}/projects/{p} o checked against the caller; p's own org forgotten
//	/file-links, /files/{id}?expires=&sig=  HMAC capability URL, no cookie
//	/graphql              a batch; GetViewer by session, GetVaultItem (Relay id) no owner check
//	/wallets/{id}         numeric codes: 20000 owner, 40301 stranger, 40401 unknown
//	/wallets-leaky/{id}   the same, owner check forgotten
//	/quota/{id}           after POST /_phase?p=replay: 200 {"code":2001} for all
//	/signed-preview/{id}  X-Req-Nonce, once: a repeat is 401
//	/keys/{id}[?action=regenerate]  owner only; regenerate rotates and logs REGENERATE
//
// PEERLOG user=... lines in the server log say who asked (the log of
// logRequests has the status, method and URI only). All the data is fixed, so
// that apps/peer-app/secrets.txt can list what must never leak.
type peerApp struct {
	logf func(format string, args ...any)
	now  func() time.Time

	mu       sync.Mutex
	sessions map[string]*peerSession // token -> session
	nonces   map[string]bool         // X-Req-Nonce values used
	phase    string                  // "crawl" or "replay"
	regen    map[string]int          // key id -> regenerations
	keys     map[string]*peerKey     // peerKeys, as this server's regenerations changed them
}

type peerSession struct {
	user *peerUser
	csrf string
}

type peerUser struct {
	Name, Org, ID, Pass string
	Prefs               map[string]any
}

type peerNote struct {
	Owner, Title, Body, TaxID string
}
type peerDoc struct{ Org, Owner, Title, Body string }
type peerItem struct{ Owner, SKU, Note string }
type peerOrder struct {
	Owner, ShipTo, Card string
	Total               int
}
type peerFeatured struct{ Owner, Title, SKU string }
type peerProject struct{ Org, Owner, Name, Budget string }
type peerFile struct{ Owner, Name, Content string }
type peerVault struct{ Owner, Label, Secret string }
type peerWallet struct {
	Owner string
	Bal   int
	Tier  int
}
type peerQuota struct {
	Owner       string
	Used, Limit int
}
type peerTransfer struct {
	Owner, Memo, To string
	Amount          int
}
type peerKey struct{ Owner, Label, Secret string }

const (
	peerPass      = "hunter22" // a test password, not a secret
	peerHMACKey   = "peer-app-test-hmac-key"
	peerFarFuture = 4102444800 // 2100-01-01: an URL that does not expire in a gate
)

// The people. IDs are UUID v4.
var peerUsers = map[string]*peerUser{
	"alice": {Name: "alice", Org: "org-alpha", ID: "3f0a8c1e-5d2b-4c7a-9e11-a11ce0000001", Pass: peerPass,
		Prefs: map[string]any{"theme": "solarized", "signature": "Alice Moreau, 14 Harbor Lane, flat 3B, Port Arden"}},
	"bob": {Name: "bob", Org: "org-alpha", ID: "7b2d9e44-1a6c-4f08-b3d5-b0b000000002", Pass: peerPass,
		Prefs: map[string]any{"theme": "contrast", "signature": "Robert Quill, 77 Mill Street, unit 9, Port Arden"}},
	"charlie": {Name: "charlie", Org: "org-beta", ID: "c5e19a07-8b3f-4d62-a4c8-c4a41e000003", Pass: peerPass,
		Prefs: map[string]any{"theme": "forest", "signature": "Charles Vane, 5 Quarry Road, Fenwick Bay"}},
	"dave": {Name: "dave", Org: "org-beta", ID: "d4e0f6b2-2c9a-4a71-8f3e-da7e00000004", Pass: peerPass,
		Prefs: map[string]any{}},
}

var peerNotes = map[int]peerNote{
	1101: {"alice", "Vault codes", "Alice private: the safe code is 48-17-92 behind the blue ledger", "TAX-ALICE-7731-QX9"},
	1201: {"bob", "Garage", "Bob private: the spare key hangs under the third crate of hops", "TAX-BOB-5520-ZK4"},
	1301: {"charlie", "Harbor", "Charlie private: the ferry ledger is kept in the ice locker", "TAX-CHARLIE-9904-MV2"},
}

var peerDocs = map[string]peerDoc{
	"5a1c0d0c-2e4f-4b6a-8c7d-0000a11ce001": {"org-alpha", "alice", "Alpha roadmap", "Alpha roadmap: ship the amber release after the Lisbon audit"},
	"5b0b0d0c-3f5a-4c7b-9d8e-0000b0b00002": {"org-alpha", "bob", "Alpha budget", "Alpha budget: reserve 41 percent for the Kestrel migration"},
	"5c4a0d0c-4a6b-4d8c-ae9f-0000c4a10003": {"org-beta", "charlie", "Beta plan", "Beta plan: close the Fenwick depot in the second quarter"},
}

var peerItems = map[string]peerItem{
	"vault-alice-01":   {"alice", "ALC-77", "Alice item note: the amber ring is insured under policy AX-5521-77"},
	"vault-bob-01":     {"bob", "BOB-31", "Bob item note: the brass compass sits in locker 12 of the pier house"},
	"vault-charlie-01": {"charlie", "CHA-18", "Charlie item note: the slate map is sealed in the harbor office"},
}

var peerOrders = map[int64]peerOrder{
	1700000000000000001: {"alice", "Alice Moreau, 14 Harbor Lane, flat 3B, Port Arden", "card ending 4417 held by Alice", 18250},
	1700000000000004002: {"bob", "Robert Quill, 77 Mill Street, unit 9, Port Arden", "card ending 9081 held by Bob", 6420},
	1700000000000008003: {"charlie", "Charles Vane, 5 Quarry Road, Fenwick Bay", "card ending 2236 held by Charlie", 33100},
}

var peerFeaturedItems = map[int]peerFeatured{
	2201: {"alice", "Alice Pick: the amber lamp", "ALC-LAMP-44"},
	2202: {"bob", "Bob Pick: the brass vice", "BOB-VICE-45"},
	2203: {"charlie", "Charlie Pick: the slate clock", "CHA-CLOCK-46"},
}

var peerDefaultFeatured = map[string]string{"title": "Default Pack", "sku": "DEF-9"}

var peerProjects = map[string]peerProject{
	"proj-aurora":   {"org-alpha", "alice", "Aurora", "Aurora budget: 912000 for the Kestrel rollout, owner Alice Moreau"},
	"proj-borealis": {"org-alpha", "bob", "Borealis", "Borealis budget: 477500 for the Mill Street refit, owner Robert Quill"},
	"proj-cygnus":   {"org-beta", "charlie", "Cygnus", "Cygnus budget: 265000 for the Fenwick depot closure, owner Charles Vane"},
}

var peerFiles = map[string]peerFile{
	"doc-a1": {"alice", "tax-2025.txt", "Alice tax return 2025: income 88213 and refund 1904 at account AC-5521-9987"},
	"doc-b1": {"bob", "lease.txt", "Bob lease: Mill Street unit 9, 1450 a month until March 2028"},
	"doc-c1": {"charlie", "audit.txt", "Charlie audit memo: the Fenwick depot overstated stock by 12 percent"},
}

var peerVaults = map[int]peerVault{
	1001: {"alice", "Alice vault entry", "Alice vault secret: seed phrase begins amber orbit velvet"},
	1002: {"bob", "Bob vault entry", "Bob vault secret: seed phrase begins cobalt ember anchor"},
	1003: {"charlie", "Charlie vault entry", "Charlie vault secret: seed phrase begins slate marble quill"},
}

var peerWallets = map[int]peerWallet{
	4501: {"alice", 750, 4},
	4502: {"bob", 120, 2},
	4503: {"charlie", 9300, 7},
}

var peerQuotas = map[int]peerQuota{
	5501: {"alice", 42, 100},
	5502: {"bob", 17, 50},
	5503: {"charlie", 88, 200},
}

var peerTransfers = map[int]peerTransfer{
	6601: {"alice", "Alice transfer memo: invoice 20931 for the amber lamp", "ACC-ALICE-3312", 1250},
	6602: {"bob", "Bob transfer memo: invoice 20977 for the brass vice", "ACC-BOB-7740", 480},
	6603: {"charlie", "Charlie transfer memo: invoice 21004 for the slate clock", "ACC-CHARLIE-1155", 2210},
}

// peerKeys is the start of every server's keys (the secrets rotate in a copy).
var peerKeys = map[string]*peerKey{
	"key-alice-1":   {"alice", "Alice API key", "ks_alice_4f9c21d7a0b3"},
	"key-bob-1":     {"bob", "Bob API key", "ks_bob_71e3a5c9d204"},
	"key-charlie-1": {"charlie", "Charlie API key", "ks_charlie_a92b60f1e7c8"},
}

var peerAnnouncements = []struct {
	ID    int
	Title string
	Body  string
}{
	{7, "Maintenance window", "The service is down on Sunday from 02:00 to 03:00 UTC"},
	{8, "New office hours", "Support answers from 08:00 to 18:00 on weekdays"},
}

func newPeerApp() *peerApp {
	a := &peerApp{
		logf: log.Printf, now: time.Now,
		sessions: map[string]*peerSession{}, nonces: map[string]bool{},
		phase: "crawl", regen: map[string]int{}, keys: map[string]*peerKey{},
	}
	for id, k := range peerKeys {
		c := *k
		a.keys[id] = &c
	}
	if p := strings.TrimSpace(strings.ToLower(os.Getenv("PEER_PHASE"))); p == "replay" {
		a.phase = "replay"
	}
	return a
}

func peerJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func peerErr(w http.ResponseWriter, status int, msg string) {
	peerJSON(w, status, map[string]string{"error": msg})
}

// user is the person of the request's session cookie, nil if none.
func (a *peerApp) user(r *http.Request) *peerUser {
	if s := a.session(r); s != nil {
		return s.user
	}
	return nil
}

func (a *peerApp) session(r *http.Request) *peerSession {
	c, err := r.Cookie("peer_session")
	if err != nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessions[c.Value]
}

// authed wraps a handler that needs a login.
func (a *peerApp) authed(h func(w http.ResponseWriter, r *http.Request, u *peerUser)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := a.user(r)
		if u == nil {
			peerErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		h(w, r, u)
	}
}

func peerSig(id string, expires int64) string {
	m := hmac.New(sha256.New, []byte(peerHMACKey))
	fmt.Fprintf(m, "%s:%d", id, expires)
	return hex.EncodeToString(m.Sum(nil))
}

func relayID(typ string, n int) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%d", typ, n)))
}

var gqlNameRe = regexp.MustCompile(`(?:query|mutation)\s+([_A-Za-z]\w*)`)

// credentials reads the login: a form (user, password) or JSON.
func peerCredentials(r *http.Request) (user, pass string) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var b struct {
			User     string `json:"user"`
			Password string `json:"password"`
		}
		json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<16)).Decode(&b)
		return b.User, b.Password
	}
	return r.FormValue("user"), r.FormValue("password")
}

// graphql answers one element of a batch (or a single request).
func (a *peerApp) gqlOne(u *peerUser, el map[string]any) map[string]any {
	name, _ := el["operationName"].(string)
	if q, _ := el["query"].(string); name == "" {
		if m := gqlNameRe.FindStringSubmatch(q); m != nil {
			name = m[1]
		}
	}
	vars, _ := el["variables"].(map[string]any)
	switch name {
	case "GetViewer":
		return map[string]any{"data": map[string]any{"viewer": map[string]any{"id": u.ID, "name": u.Name, "org": u.Org}}}
	case "GetVaultItem":
		id, _ := vars["id"].(string)
		raw, err := base64.StdEncoding.DecodeString(id)
		typ, num, ok := strings.Cut(string(raw), ":")
		n, _ := strconv.Atoi(num)
		v, found := peerVaults[n]
		if err != nil || !ok || typ != "VaultItem" || !found {
			return map[string]any{"data": map[string]any{"vaultItem": nil}}
		}
		// No check that v belongs to the caller: the flaw.
		return map[string]any{"data": map[string]any{"vaultItem": map[string]any{
			"id": id, "label": v.Label, "secret": v.Secret, "private": true}}}
	}
	return map[string]any{"errors": []map[string]string{{"message": "unknown operation"}}}
}

// handler answers /api/peer/ ; the rest goes to next.
func (a *peerApp) handler(next http.Handler) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/peer/login", func(w http.ResponseWriter, r *http.Request) {
		name, pass := peerCredentials(r)
		u := peerUsers[strings.ToLower(name)]
		if u == nil || pass != u.Pass {
			peerErr(w, http.StatusUnauthorized, "bad credentials")
			return
		}
		s := &peerSession{user: u, csrf: token()}
		t := token() + token()
		a.mu.Lock()
		a.sessions[t] = s
		a.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "peer_session", Value: t, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: "peer_csrf", Value: s.csrf, Path: "/", SameSite: http.SameSiteLaxMode})
		peerJSON(w, http.StatusOK, map[string]any{"ok": true, "user": u.Name})
	})
	// The logout wants the CSRF token (double submit) as well as the session.
	mux.HandleFunc("POST /api/peer/logout", func(w http.ResponseWriter, r *http.Request) {
		s := a.session(r)
		if s == nil {
			peerErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		if r.Header.Get("X-CSRF-Token") != s.csrf {
			peerErr(w, http.StatusForbidden, "csrf")
			return
		}
		c, _ := r.Cookie("peer_session")
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
		for _, n := range []string{"peer_session", "peer_csrf"} {
			http.SetCookie(w, &http.Cookie{Name: n, Value: "", Path: "/", MaxAge: -1})
		}
		peerJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	// The gate says the crawl is over: quota's token expires for everybody.
	mux.HandleFunc("/api/peer/_phase", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			switch p := r.URL.Query().Get("p"); p {
			case "crawl", "replay":
				a.mu.Lock()
				a.phase = p
				a.mu.Unlock()
			default:
				peerErr(w, http.StatusBadRequest, "p: crawl or replay")
				return
			}
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		peerJSON(w, http.StatusOK, map[string]any{"phase": a.phase, "regenerated": a.regen})
	})

	mux.HandleFunc("GET /api/peer/me", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		peerJSON(w, http.StatusOK, map[string]any{"id": u.ID, "name": u.Name, "org": u.Org, "role": "member"})
	}))

	// home: the ids of what the caller owns, as an API gives them to a page
	// (the page's later requests derive from it).
	mux.HandleFunc("GET /api/peer/home", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		h := map[string][]any{"notes": {}, "docs": {}, "items": {}, "orders": {}, "featured": {}, "projects": {},
			"wallets": {}, "quotas": {}, "transfers": {}, "keys": {}, "vault": {}}
		for id, n := range peerNotes {
			if n.Owner == u.Name {
				h["notes"] = append(h["notes"], id)
			}
		}
		for id, d := range peerDocs {
			if d.Owner == u.Name {
				h["docs"] = append(h["docs"], id)
			}
		}
		for id, it := range peerItems {
			if it.Owner == u.Name {
				h["items"] = append(h["items"], id)
			}
		}
		for id, o := range peerOrders {
			if o.Owner == u.Name {
				h["orders"] = append(h["orders"], strconv.FormatInt(id, 10)) // a string: a 19-digit id is past what a JS number keeps
			}
		}
		for id, f := range peerFeaturedItems {
			if f.Owner == u.Name {
				h["featured"] = append(h["featured"], id)
			}
		}
		for id, p := range peerProjects {
			if p.Owner == u.Name {
				h["projects"] = append(h["projects"], map[string]string{"org": p.Org, "id": id})
			}
		}
		for id, x := range peerWallets {
			if x.Owner == u.Name {
				h["wallets"] = append(h["wallets"], id)
			}
		}
		for id, x := range peerQuotas {
			if x.Owner == u.Name {
				h["quotas"] = append(h["quotas"], id)
			}
		}
		for id, x := range peerTransfers {
			if x.Owner == u.Name {
				h["transfers"] = append(h["transfers"], id)
			}
		}
		for id, k := range peerKeys {
			if k.Owner == u.Name {
				h["keys"] = append(h["keys"], id)
			}
		}
		for id, v := range peerVaults {
			if v.Owner == u.Name {
				h["vault"] = append(h["vault"], relayID("VaultItem", id))
			}
		}
		peerJSON(w, http.StatusOK, h)
	}))

	// Shared and open, to anon too.
	mux.HandleFunc("GET /api/peer/feed", func(w http.ResponseWriter, r *http.Request) {
		var l []map[string]any
		for _, an := range peerAnnouncements {
			l = append(l, map[string]any{"id": an.ID, "title": an.Title})
		}
		peerJSON(w, http.StatusOK, map[string]any{"announcements": l})
	})
	mux.HandleFunc("GET /api/peer/announcements/{id}", func(w http.ResponseWriter, r *http.Request) {
		for _, an := range peerAnnouncements {
			if strconv.Itoa(an.ID) == r.PathValue("id") {
				peerJSON(w, http.StatusOK, map[string]any{"id": an.ID, "title": an.Title, "body": an.Body})
				return
			}
		}
		peerErr(w, http.StatusNotFound, "not found")
	})

	// 2b: the org's own; no private flag.
	mux.HandleFunc("GET /api/peer/org-docs/{id}", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		d, ok := peerDocs[r.PathValue("id")]
		if !ok {
			peerErr(w, http.StatusNotFound, "not found")
			return
		}
		if d.Org != u.Org {
			peerErr(w, http.StatusForbidden, "forbidden")
			return
		}
		peerJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("id"), "title": d.Title, "body": d.Body})
	}))

	// 2c: the flaw. Login only.
	mux.HandleFunc("GET /api/peer/private-notes/{id}", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		n, ok := peerNotes[id]
		if !ok {
			peerErr(w, http.StatusNotFound, "not found")
			return
		}
		peerJSON(w, http.StatusOK, map[string]any{"id": id, "visibility": "private", "title": n.Title, "body": n.Body, "taxId": n.TaxID})
	}))

	// 3: userId is ignored; the caller's own.
	mux.HandleFunc("GET /api/peer/preferences", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		peerJSON(w, http.StatusOK, map[string]any{"preferences": u.Prefs})
	}))

	// 4: a stranger gets the id back and nothing else.
	mux.HandleFunc("GET /api/peer/lookup", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		id := r.URL.Query().Get("itemId")
		it, ok := peerItems[id]
		if !ok || it.Owner != u.Name {
			peerJSON(w, http.StatusOK, map[string]any{"itemId": id, "items": []any{}, "found": false})
			return
		}
		peerJSON(w, http.StatusOK, map[string]any{"itemId": id, "found": true,
			"items": []map[string]string{{"sku": it.SKU, "note": it.Note}}})
	}))

	// 5a: no owner check; unknown is 404.
	mux.HandleFunc("GET /api/peer/orders/{id}", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		o, ok := peerOrders[id]
		if !ok {
			peerErr(w, http.StatusNotFound, "not found")
			return
		}
		// ownerId: the owner's user id, the marker by which -relation
		// same-org tells a private object from one an org shares (gd7 8 Q2).
		owner := ""
		if pu := peerUsers[o.Owner]; pu != nil {
			owner = pu.ID
		}
		peerJSON(w, http.StatusOK, map[string]any{"id": id, "ownerId": owner, "total": o.Total, "shipTo": o.ShipTo, "payment": o.Card})
	}))

	// 5b: the owner has its own; every other id (a stranger's too) the default.
	mux.HandleFunc("GET /api/peer/featured/{id}", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		if f, ok := peerFeaturedItems[id]; ok && f.Owner == u.Name {
			peerJSON(w, http.StatusOK, map[string]string{"title": f.Title, "sku": f.SKU})
			return
		}
		peerJSON(w, http.StatusOK, peerDefaultFeatured)
	}))

	// 6: o is checked against the caller; p's own org is not checked against o.
	mux.HandleFunc("GET /api/peer/orgs/{o}/projects/{p}", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		if r.PathValue("o") != u.Org {
			peerErr(w, http.StatusForbidden, "forbidden")
			return
		}
		p, ok := peerProjects[r.PathValue("p")]
		if !ok {
			peerErr(w, http.StatusNotFound, "not found")
			return
		}
		peerJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("p"), "name": p.Name, "budget": p.Budget})
	}))

	// 7: the links an API hands out, and the capability URL: no cookie.
	mux.HandleFunc("GET /api/peer/file-links", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		var l []map[string]string
		for id, f := range peerFiles {
			if f.Owner == u.Name {
				l = append(l, map[string]string{"id": id, "name": f.Name,
					"url": fmt.Sprintf("/api/peer/files/%s?expires=%d&sig=%s", id, int64(peerFarFuture), peerSig(id, peerFarFuture))})
			}
		}
		if l == nil {
			l = []map[string]string{}
		}
		peerJSON(w, http.StatusOK, map[string]any{"files": l})
	}))
	mux.HandleFunc("GET /api/peer/files/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		exp, _ := strconv.ParseInt(r.URL.Query().Get("expires"), 10, 64)
		sig := r.URL.Query().Get("sig")
		if exp == 0 || exp < a.now().Unix() || !hmac.Equal([]byte(sig), []byte(peerSig(id, exp))) {
			peerErr(w, http.StatusForbidden, "bad signature")
			return
		}
		f, ok := peerFiles[id]
		if !ok {
			peerErr(w, http.StatusNotFound, "not found")
			return
		}
		peerJSON(w, http.StatusOK, map[string]any{"id": id, "name": f.Name, "content": f.Content})
	})

	// 8: a batch or one operation. GetViewer by session, GetVaultItem by id.
	mux.HandleFunc("POST /api/peer/graphql", func(w http.ResponseWriter, r *http.Request) {
		u := a.user(r)
		if u == nil {
			peerJSON(w, http.StatusUnauthorized, map[string]any{"errors": []map[string]string{{"message": "unauthenticated"}}})
			return
		}
		b, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		body := strings.TrimSpace(string(b))
		if strings.HasPrefix(body, "[") {
			var els []map[string]any
			if json.Unmarshal(b, &els) != nil || len(els) == 0 {
				peerErr(w, http.StatusBadRequest, "bad batch")
				return
			}
			out := make([]map[string]any, len(els))
			for i, el := range els {
				out[i] = a.gqlOne(u, el)
			}
			peerJSON(w, http.StatusOK, out)
			return
		}
		var el map[string]any
		if json.Unmarshal(b, &el) != nil {
			peerErr(w, http.StatusBadRequest, "bad body")
			return
		}
		peerJSON(w, http.StatusOK, a.gqlOne(u, el))
	})

	// 9a: numeric codes in a 200.
	wallet := func(leaky bool) http.HandlerFunc {
		return a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
			id, _ := strconv.Atoi(r.PathValue("id"))
			x, ok := peerWallets[id]
			switch {
			case !ok:
				peerJSON(w, http.StatusOK, map[string]any{"code": 40401, "msg": "not found"})
			case leaky:
				peerJSON(w, http.StatusOK, map[string]any{"code": 20000, "data": map[string]any{"balance": x.Bal, "tier": x.Tier, "private": true}})
			case x.Owner != u.Name:
				peerJSON(w, http.StatusOK, map[string]any{"code": 40301, "msg": "cấm"})
			default:
				peerJSON(w, http.StatusOK, map[string]any{"code": 20000, "data": map[string]any{"balance": x.Bal, "tier": x.Tier}})
			}
		})
	}
	mux.HandleFunc("GET /api/peer/wallets/{id}", wallet(false))
	mux.HandleFunc("GET /api/peer/wallets-leaky/{id}", wallet(true))

	// 9b: after the crawl the token is gone for everybody, the owner too.
	mux.HandleFunc("GET /api/peer/quota/{id}", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		a.mu.Lock()
		phase := a.phase
		a.mu.Unlock()
		if phase == "replay" {
			peerJSON(w, http.StatusOK, map[string]any{"code": 2001, "msg": "expired"})
			return
		}
		id, _ := strconv.Atoi(r.PathValue("id"))
		x, ok := peerQuotas[id]
		if !ok || x.Owner != u.Name {
			peerJSON(w, http.StatusOK, map[string]any{"code": 40301, "msg": "forbidden"})
			return
		}
		peerJSON(w, http.StatusOK, map[string]any{"code": 20000, "data": map[string]any{"used": x.Used, "limit": x.Limit}})
	}))

	// 10: a nonce that serves once. The session stays good (/me is 200).
	mux.HandleFunc("GET /api/peer/signed-preview/{id}", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		n := r.Header.Get("X-Req-Nonce")
		a.mu.Lock()
		used := n == "" || a.nonces[n]
		if n != "" {
			a.nonces[n] = true
		}
		a.mu.Unlock()
		if used {
			peerErr(w, http.StatusUnauthorized, "nonce missing or already used")
			return
		}
		id, _ := strconv.Atoi(r.PathValue("id"))
		t, ok := peerTransfers[id]
		if !ok || t.Owner != u.Name {
			peerErr(w, http.StatusForbidden, "forbidden")
			return
		}
		peerJSON(w, http.StatusOK, map[string]any{"id": id, "memo": t.Memo, "to": t.To, "amount": t.Amount})
	}))

	// 11: owner only. ?action=regenerate rotates the secret: the verb a replay
	// must never send.
	mux.HandleFunc("GET /api/peer/keys/{id}", a.authed(func(w http.ResponseWriter, r *http.Request, u *peerUser) {
		k, ok := a.keys[r.PathValue("id")]
		if !ok {
			peerErr(w, http.StatusNotFound, "not found")
			return
		}
		if k.Owner != u.Name {
			peerErr(w, http.StatusForbidden, "forbidden")
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if r.URL.Query().Get("action") == "regenerate" {
			a.regen[r.PathValue("id")]++
			k.Secret = fmt.Sprintf("ks_%s_r%d", u.Name, a.regen[r.PathValue("id")])
			a.logf("REGENERATE user=%s key=%s", u.Name, r.PathValue("id"))
		}
		peerJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("id"), "label": k.Label, "secret": k.Secret})
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/peer/") {
			who := "-"
			if u := a.user(r); u != nil {
				who = u.Name
			}
			a.logf("PEERLOG user=%s method=%s uri=%s", who, r.Method, r.URL.RequestURI())
			mux.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// peerAppFor serves peer-app (testbed/apps/peer-app); any other app is left
// to next.
func peerAppFor(app string, next http.Handler) http.Handler {
	if filepath.Base(filepath.Clean(app)) != "peer-app" {
		return next
	}
	return newPeerApp().handler(next)
}
