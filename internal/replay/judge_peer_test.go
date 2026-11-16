package replay

import (
	"strings"
	"testing"
	"time"
)

func jsAns(status int, body string) *Answer {
	return &Answer{Status: status, Header: map[string]string{"content-type": "application/json"}, Body: []byte(body)}
}

func ans(a *Answer) Answer { return *a }

// peerCase is a read trial whose controls are control (twice), with the
// pieces a test replaces.
func peerCase(trial, control string) PeerCase {
	return PeerCase{
		Relation: RelCrossOrg, Mode: "main", IDCount: 1,
		Trial:    ans(jsAns(200, trial)),
		Controls: []Answer{ans(jsAns(200, control)), ans(jsAns(200, control))},
		Seen:     NewSeenSet(), AliveA: true, RecordedOK: true,
		OwnerIDs: []string{"owner-id-aaaa"}, PeerIDs: []string{"peer-id-bbbb"},
	}
}

// settle gives the answers a judge asks for (no identity: refused) and
// judges again, as the caller does.
func settle(c PeerCase) PeerJudgement {
	for range 4 {
		j := JudgePeer(c)
		switch {
		case j.NeedNoID && c.NoIdentity == nil:
			c.NoIdentity = &Answer{Status: 401, Header: map[string]string{"content-type": "application/json"}, Body: []byte(`{"error":"login"}`)}
		case j.NeedBogus && !c.BogusTried:
			c.BogusTried = true
		default:
			return j
		}
	}
	return JudgePeer(c)
}

const aNote = `{"id":1101,"title":"Vault codes","body":"Alice private: the safe code is 48-17-92 behind the blue ledger","taxId":"TAX-ALICE-7731-QX9"}`

func TestJudgePeer(t *testing.T) {
	for _, c := range []struct {
		name string
		mk   func() PeerCase
		want Verdict
		in   string // what the reason holds
	}{
		{"the request echoed, exactly: no evidence", func() PeerCase {
			c := peerCase(`{"itemId":"vault-alice-01","items":[],"found":false}`, `{"itemId":"vault-alice-01","found":true,"items":[{"sku":"ALC-77","note":"the amber ring is insured under AX-5521-77"}]}`)
			c.Sent = []string{"vault-alice-01"}
			c.Self = jsAns(200, `{"itemId":"vault-bob-01","found":true,"items":[{"sku":"BOB-31","note":"the brass compass"}]}`)
			return c
		}, Enforced, "nothing of A's"},
		{"the request echoed as a part of a longer value", func() PeerCase {
			c := peerCase(`{"self":"https://h/api/users/4242","message":"No items for alpha-roadmap"}`, `{"self":"https://h/api/users/4242","message":"No items for alpha-roadmap"}`)
			c.Sent = []string{"4242", "alpha-roadmap"}
			return c
		}, Enforced, ""},
		{"an id of the request echoed in a url, upper case", func() PeerCase {
			c := peerCase(`{"link":"HTTPS://H/API/DOC-A1/READ"}`, `{"link":"HTTPS://H/API/DOC-A1/READ"}`)
			c.Sent = []string{"doc-a1"}
			return c
		}, Enforced, ""},
		{"a number inside a longer number is no echo", func() PeerCase {
			c := peerCase(`{"account":"AC-5521-9987","ref":"order 91101234"}`, `{"account":"AC-5521-9987","ref":"order 91101234"}`)
			c.Sent = []string{"1101"}
			return c
		}, Bypass, ""},
		{"shared data: what B shows already", func() PeerCase {
			c := peerCase(`{"title":"Quarterly handbook 2026","body":"Rules of the house 2026"}`, `{"title":"Quarterly handbook 2026","body":"Rules of the house 2026"}`)
			c.Seen.AddResponse(nil, `{"docs":[{"title":"Quarterly handbook 2026","body":"Rules of the house 2026"}]}`)
			return c
		}, Enforced, ""},
		{"B's own object: the server ignores the id", func() PeerCase {
			c := peerCase(`{"preferences":{"theme":"contrast","signature":"Robert Quill, 77 Mill Street"}}`, `{"preferences":{"theme":"solarized","signature":"Alice Moreau, 14 Harbor Lane"}}`)
			c.Self = jsAns(200, `{"preferences":{"theme":"contrast","signature":"Robert Quill, 77 Mill Street"}}`)
			return c
		}, Enforced, "B's own object"},
		{"B empty, Bogus 404, A's private data in the trial", func() PeerCase {
			c := peerCase(aNote, aNote)
			c.Bogus, c.BogusTried = jsAns(404, `{"error":"not found"}`), true
			return c
		}, Bypass, ""},
		{"B empty, no Bogus yet: asks for no identity first", func() PeerCase {
			return peerCase(aNote, aNote)
		}, Bypass, ""},
		{"Bogus 200 with data, the trial another: stop", func() PeerCase {
			c := peerCase(`{"title":"Alice Pick: the amber lamp","sku":"ALC-LAMP-44"}`, `{"title":"Alice Pick: the amber lamp","sku":"ALC-LAMP-44"}`)
			c.Bogus, c.BogusTried = jsAns(200, `{"title":"Default Pack","sku":"DEF-9"}`), true
			return c
		}, Unclear, "answers any id"},
		{"the trial is what Bogus is: enforced before the fuse", func() PeerCase {
			c := peerCase(`{"title":"Default Pack","sku":"DEF-9"}`, `{"title":"Alice Pick: the amber lamp","sku":"ALC-LAMP-44"}`)
			c.Bogus, c.BogusTried = jsAns(200, `{"title":"Default Pack","sku":"DEF-9"}`), true
			return c
		}, Enforced, "names nothing"},
		{"a default answer, B has its own: asks Bogus, then enforced", func() PeerCase {
			c := peerCase(`{"title":"Default Pack","sku":"DEF-9"}`, `{"title":"Alice Pick: the amber lamp","sku":"ALC-LAMP-44"}`)
			c.Self = jsAns(200, `{"title":"Bob Pick: the brass vice","sku":"BOB-VICE-45"}`)
			c.BogusTried = false
			return c
		}, NeedsReview, ""}, // settle's Bogus is not an answer: review
		{"Control failed with the session alive, recorded 2xx", func() PeerCase {
			c := peerCase(aNote, aNote)
			c.Controls = []Answer{ans(jsAns(401, `{"error":"nonce used"}`))}
			c.Trial = ans(jsAns(401, `{"error":"nonce used"}`))
			return c
		}, ReplayBroken, ""},
		{"Control failed, A's session dead", func() PeerCase {
			c := peerCase(aNote, aNote)
			c.Controls = []Answer{ans(jsAns(401, `{}`))}
			c.AliveA = false
			return c
		}, Unclear, "dead"},
		{"Control failed, not recorded clean", func() PeerCase {
			c := peerCase(aNote, aNote)
			c.Controls = []Answer{ans(jsAns(403, `{}`))}
			c.RecordedOK = false
			return c
		}, Unclear, ""},
		{"Control with an error code in a 200", func() PeerCase {
			c := peerCase(`{"code":2001,"msg":"expired"}`, `{"code":2001,"msg":"expired"}`)
			return c
		}, Unclear, "error in its body"},
		{"one short value of A's: no bypass", func() PeerCase {
			c := peerCase(`{"code":20000,"data":{"tier":"gold"}}`, `{"code":20000,"data":{"tier":"gold"}}`)
			c.Self = jsAns(200, `{"code":20000,"data":{"tier":"silver"}}`)
			return c
		}, NeedsReview, ""},
		{"two short values, one of three characters: bypass", func() PeerCase {
			c := peerCase(`{"code":20000,"data":{"balance":750,"tier":4}}`, `{"code":20000,"data":{"balance":750,"tier":4}}`)
			c.Self = jsAns(200, `{"code":20000,"data":{"balance":120,"tier":2}}`)
			return c
		}, Bypass, ""},
		{"two values of one or two characters: not enough", func() PeerCase {
			c := peerCase(`{"data":{"a":42,"b":7}}`, `{"data":{"a":42,"b":7}}`)
			c.Self = jsAns(200, `{"data":{"a":1,"b":2}}`)
			return c
		}, NeedsReview, ""},
		{"three values of one or two characters", func() PeerCase {
			c := peerCase(`{"data":{"a":42,"b":7,"c":13}}`, `{"data":{"a":42,"b":7,"c":13}}`)
			c.Self = jsAns(200, `{"data":{"a":1,"b":2,"c":3}}`)
			return c
		}, Bypass, ""},
		{"default values never count: 0, 1, true, a currency, active", func() PeerCase {
			c := peerCase(`{"data":{"n":0,"m":1,"ok2":true,"cur":"USD","state":"active"}}`, `{"data":{"n":0,"m":1,"ok2":true,"cur":"USD","state":"active"}}`)
			c.Self = jsAns(200, `{"data":{"n":5,"m":6,"ok2":false,"cur":"EUR","state":"gone"}}`)
			return c
		}, Enforced, ""},
		{"two weak pairs, the reference not 2xx: three wanted", func() PeerCase {
			c := peerCase(`{"data":{"balance":750,"tier":4}}`, `{"data":{"balance":750,"tier":4}}`)
			c.Bogus, c.BogusTried = jsAns(404, `{"error":"not found"}`), true
			return c
		}, NeedsReview, ""},
		{"an enum name is no proof alone", func() PeerCase {
			c := peerCase(`{"role":"ROLE_ACCOUNTANT","zone":"Europe/Lisbon"}`, `{"role":"ROLE_ACCOUNTANT","zone":"Europe/Lisbon"}`)
			c.Self = jsAns(200, `{"role":"ROLE_USER","zone":"Europe/Lisbon"}`)
			return c
		}, NeedsReview, ""},
		{"a key of bodyErrors' meta set is data: a note's title", func() PeerCase {
			c := peerCase(`{"title":"The tax return of Alice Moreau 2025","description":"income 88213 refund 1904"}`, `{"title":"The tax return of Alice Moreau 2025","description":"income 88213 refund 1904"}`)
			c.Self = jsAns(200, `{"title":"Lease of Robert Quill","description":"rent 1450"}`)
			return c
		}, Bypass, ""},
		{"a code, a message, a trace id are not data", func() PeerCase {
			c := peerCase(`{"code":20000,"message":"all went well today for owner","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","status":"success-ok-1234"}`,
				`{"code":20000,"message":"all went well today for owner","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","status":"success-ok-1234"}`)
			c.Self = jsAns(200, `{"code":20000,"message":"nothing","trace_id":"x"}`)
			return c
		}, Enforced, ""},
		{"same-org, nothing private: shared", func() PeerCase {
			c := peerCase(`{"id":"d1","title":"Alpha roadmap","body":"ship the amber release after the Lisbon audit 2026"}`, `{"id":"d1","title":"Alpha roadmap","body":"ship the amber release after the Lisbon audit 2026"}`)
			c.Relation = RelSameOrg
			c.Self = jsAns(200, `{"id":"d2","title":"Alpha budget","body":"reserve 41 percent for the Kestrel migration"}`)
			return c
		}, Shared, ""},
		{"same-org, the object is A's by its owner id", func() PeerCase {
			o := `{"id":9,"ownerId":"owner-id-aaaa","total":18250,"shipTo":"Alice Moreau, 14 Harbor Lane, flat 3B"}`
			c := peerCase(o, o)
			c.Relation = RelSameOrg
			return c
		}, Bypass, "A's own"},
		{"same-org, an owner that is B's own is no marker", func() PeerCase {
			o := `{"id":9,"ownerId":"peer-id-bbbb","total":18250,"shipTo":"Bob Quill, 77 Mill Street, unit 9"}`
			c := peerCase(o, o)
			c.Relation = RelSameOrg
			return c
		}, Shared, ""},
		{"same-org, a private flag", func() PeerCase {
			o := `{"data":{"label":"Alice vault entry","secret":"seed phrase begins amber orbit velvet","private":true}}`
			c := peerCase(o, o)
			c.Relation = RelSameOrg
			return c
		}, Bypass, "private"},
		{"same-org, visibility private", func() PeerCase {
			c := peerCase(aNote[:len(aNote)-1]+`,"visibility":"private"}`, aNote[:len(aNote)-1]+`,"visibility":"private"}`)
			c.Relation = RelSameOrg
			return c
		}, Bypass, ""},
		{"same-org, -private matched", func() PeerCase {
			c := peerCase(`{"name":"Aurora","budget":"Aurora budget: 912000 for the Kestrel rollout"}`, `{"name":"Aurora","budget":"Aurora budget: 912000 for the Kestrel rollout"}`)
			c.Relation, c.Private = RelSameOrg, true
			return c
		}, Bypass, ""},
		{"a capability URL: no identity gets it too", func() PeerCase {
			c := peerCase(`{"name":"tax-2025.txt","content":"Alice tax return 2025: income 88213 and refund 1904"}`, `{"name":"tax-2025.txt","content":"Alice tax return 2025: income 88213 and refund 1904"}`)
			c.NoIdentity = jsAns(200, `{"name":"tax-2025.txt","content":"Alice tax return 2025: income 88213 and refund 1904"}`)
			return c
		}, Unauthenticated, ""},
		{"no identity gets a 200 with nothing of A's", func() PeerCase {
			c := peerCase(aNote, aNote)
			c.NoIdentity = jsAns(200, `{"error":"","note":"log in to see this"}`)
			return c
		}, Bypass, ""},
		{"a refusal at the parent, two ids: only the parent", func() PeerCase {
			c := peerCase(`{"error":"forbidden"}`, aNote)
			c.Trial = ans(jsAns(403, `{"error":"forbidden"}`))
			c.IDCount = 2
			return c
		}, EnforcedParent, "-substitute"},
		{"a refusal of one id alone (substitute): enforced", func() PeerCase {
			c := peerCase(`{}`, aNote)
			c.Trial = ans(jsAns(403, `{"error":"forbidden"}`))
			c.IDCount, c.Mode = 2, "substitute:path:4"
			return c
		}, Enforced, ""},
		{"404 where A gets it", func() PeerCase {
			c := peerCase(``, aNote)
			c.Trial = ans(jsAns(404, `{"error":"not found"}`))
			return c
		}, Enforced, ""},
		{"a 200 whose code says refused", func() PeerCase {
			c := peerCase(`{"code":40301,"msg":"forbidden"}`, `{"code":20000,"data":{"balance":750,"tier":4}}`)
			return c
		}, Enforced, ""},
		{"401 with a credential not replaced", func() PeerCase {
			c := peerCase(``, aNote)
			c.Trial = ans(jsAns(401, `{}`))
			c.Kept = true
			return c
		}, Unclear, ""},
		{"a shared cache", func() PeerCase {
			c := peerCase(aNote, aNote)
			c.Trial.Header["x-cache"] = "HIT"
			return c
		}, Unclear, "cache"},
		{"a WAF", func() PeerCase {
			c := peerCase(aNote, aNote)
			c.Trial = Answer{Status: 403, Header: map[string]string{"cf-mitigated": "challenge"}}
			return c
		}, Blocked, ""},
		{"a SPA fallback", func() PeerCase {
			c := peerCase(aNote, aNote)
			c.Trial = Answer{Status: 200, Header: map[string]string{"content-type": "text/html"}, Body: []byte("<!doctype html><div id=app>")}
			return c
		}, Unclear, ""},
		{"a write accepted: a blind write", func() PeerCase {
			c := peerCase(`{"ok":true}`, ``)
			c.Write, c.Controls = true, nil
			return c
		}, NeedsReview, "blind-write"},
		{"a write refused", func() PeerCase {
			c := peerCase(``, ``)
			c.Write, c.Controls = true, nil
			c.Trial = ans(jsAns(403, `{}`))
			return c
		}, Enforced, ""},
		{"text: the same lines, B's differ", func() PeerCase {
			txt := func(s string) Answer {
				return Answer{Status: 200, Header: map[string]string{"content-type": "text/csv"}, Body: []byte(s)}
			}
			c := peerCase(``, ``)
			c.Trial = txt("name,iban\nAlice Moreau,GB82WEST12345698765432\n")
			c.Controls = []Answer{txt("name,iban\nAlice Moreau,GB82WEST12345698765432\n"), txt("name,iban\nAlice Moreau,GB82WEST12345698765432\n")}
			c.Self = &Answer{Status: 200, Header: map[string]string{"content-type": "text/csv"}, Body: []byte("name,iban\nBob Quill,DE89370400440532013000\n")}
			return c
		}, Bypass, ""},
	} {
		j := settle(c.mk())
		if j.Verdict != c.want || !strings.Contains(j.Reason, c.in) {
			t.Errorf("%s: %s (%s), want %s with %q", c.name, j.Verdict, j.Reason, c.want, c.in)
		}
		if (j.Verdict == Bypass || j.Verdict == Shared || j.Verdict == Unauthenticated) && len(j.Evidence) == 0 {
			t.Errorf("%s: %s without evidence", c.name, j.Verdict)
		}
	}
}

func TestJudgePeerStopsTheEndpoint(t *testing.T) {
	c := peerCase(`{"title":"Alice Pick: the amber lamp","sku":"ALC-LAMP-44"}`, `{"title":"Alice Pick: the amber lamp","sku":"ALC-LAMP-44"}`)
	c.Bogus, c.BogusTried = jsAns(200, `{"title":"Default Pack","sku":"DEF-9"}`), true
	if j := JudgePeer(c); !j.StopEndpoint || j.Verdict != Unclear {
		t.Fatalf("%+v", j)
	}
}

func TestJudgePeerAsksFirst(t *testing.T) {
	c := peerCase(aNote, aNote)
	j := JudgePeer(c)
	if !j.NeedNoID || len(j.Evidence) == 0 {
		t.Fatalf("%+v", j)
	}
	// A default answer next to B's own different one: a Bogus is asked for.
	d := peerCase(`{"title":"Default Pack","sku":"DEF-9"}`, `{"title":"Alice Pick: the amber lamp","sku":"ALC-LAMP-44"}`)
	d.Self = jsAns(200, `{"title":"Bob Pick: the brass vice","sku":"BOB-VICE-45"}`)
	if j := JudgePeer(d); !j.NeedBogus {
		t.Fatalf("%+v", j)
	}
	d.Bogus, d.BogusTried = jsAns(200, `{"title":"Default Pack","sku":"DEF-9"}`), true
	if j := JudgePeer(d); j.Verdict != Enforced {
		t.Fatalf("%+v", j)
	}
}

func TestPrivateMarker(t *testing.T) {
	a, b := []string{"u-a"}, []string{"u-b"}
	for _, c := range []struct {
		body string
		want bool
	}{
		{`{"private":true}`, true}, {`{"isPrivate":true}`, true}, {`{"is_private":false}`, false},
		{`{"data":{"visibility":"Private"}}`, true}, {`{"access":"only_me"}`, true}, {`{"scope":"public"}`, false},
		{`{"ownerId":"u-a"}`, true}, {`{"owner":{"id":"u-a"}}`, true}, {`{"createdBy":"u-a"}`, true},
		{`{"ownerId":"u-b"}`, false}, {`{"ownerId":"u-c"}`, false}, {`{"authorName":"u-a"}`, false}, {`not json`, false},
	} {
		if got := privateMarker([]byte(c.body), a, b) != ""; got != c.want {
			t.Errorf("%s: %v", c.body, got)
		}
	}
	// An identifier both people share marks nothing.
	if privateMarker([]byte(`{"ownerId":"u-x"}`), []string{"u-x"}, []string{"u-x"}) != "" {
		t.Error("shared id")
	}
}

func TestClassifyPeer(t *testing.T) {
	p := Policy{ReadAllow: nil}
	read := func(m, u, body string) Decision {
		e := entryFor(m, u, body)
		return p.ClassifyPeer(e, false)
	}
	for _, c := range []struct {
		m, u, body string
		want       Kind
	}{
		{"GET", "http://a/api/keys/k1?action=regenerate", "", Write},
		{"GET", "http://a/api/users/7/verify-email", "", Write},
		{"GET", "http://a/api/magic-link/3", "", Write},
		{"GET", "http://a/api/previews/3?refresh=1", "", Write},
		{"POST", "http://a/graphql", `{"operationName":"RegenerateKey","query":"query RegenerateKey { regenerateKey { id } }"}`, Write},
		{"POST", "http://a/graphql", `{"operationName":"GetVaultItem","query":"query GetVaultItem($id: ID!) { vaultItem(id: $id) { id } }","variables":{"id":"x"}}`, Read},
		{"POST", "http://a/graphql", `[{"operationName":"GetViewer","query":"query GetViewer { viewer { id } }"},{"query":"query Q { magicLink }"}]`, Write},
		{"GET", "http://a/api/orders/7", "", Read},
		{"GET", "http://a/api/verified-badges/7", "", Read},
		{"GET", "http://a/api/users/7/logout", "", Never},
		{"DELETE", "http://a/api/users/7", "", Destructive},
	} {
		if got := read(c.m, c.u, c.body); got.Kind != c.want {
			t.Errorf("%s %s %s: %s (%s), want %s", c.m, c.u, c.body, got.Kind, got.Reason, c.want)
		}
	}
	// -read-allow does not make a POST a read here.
	pa := Policy{ReadAllow: regexpMust(`/api/search$`)}
	e := entryFor("POST", "http://a/api/search", `{"q":"x"}`)
	if d := pa.ClassifyPeer(e, false); d.Kind != Write {
		t.Errorf("-read-allow honoured: %s", d.Kind)
	}
	// ...and does not lift the action list of a query named by it either.
	e = entryFor("POST", "http://a/api/search", `{"query":"query R { regenerate }"}`)
	if d := pa.ClassifyPeer(e, false); d.Kind != Write {
		t.Errorf("%s", d.Kind)
	}
	// The vertical policy is as it was.
	if d := pa.Classify(entryFor("POST", "http://a/api/search", `{"q":"x"}`), false); d.Kind != Read {
		t.Errorf("Classify changed: %s", d.Kind)
	}
	if d := p.Classify(entryFor("GET", "http://a/api/keys/k1?action=regenerate", ""), false); d.Kind != Read {
		t.Errorf("Classify changed for regenerate: %s", d.Kind)
	}
}

func TestSentValues(t *testing.T) {
	relay := EncodeRelay("VaultItem", "1001", 0)
	raw := []byte("POST /api/orgs/org-alpha/projects/proj-aurora/items/1101?itemId=vault-alice-01&access_token=s3cr3tvalue&page=2 HTTP/1.1\r\nHost: h\r\n" +
		"Content-Type: application/json\r\nCookie: sess=cookievalue123\r\nAuthorization: Bearer tokenvalue456\r\nX-Req-Nonce: n0nc3v4lu3\r\nContent-Length: 62\r\n\r\n" +
		`{"id":"` + relay + `","csrf_token":"c5rfvalue789","note":"hello there"}`)
	got := strings.Join(sentValues(raw), "|")
	for _, want := range []string{"1101", "vault-alice-01", "n0nc3v4lu3", relay, "VaultItem:1001", "1001", "hello there"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in %s", want, got)
		}
	}
	for _, no := range []string{"api", "projects", "s3cr3tvalue", "cookievalue123", "tokenvalue456", "c5rfvalue789"} {
		for _, v := range strings.Split(got, "|") {
			if v == no {
				t.Errorf("%q is sent as a value", no)
			}
		}
	}
}

func TestReflectorBoundedUnescape(t *testing.T) {
	r := newReflector([]string{"alpha/beta", "987654"})
	// 1-layer and 2-layer URL-encoded echoes still match.
	if !r.hit("path=alpha%2Fbeta") {
		t.Fatal("1-layer URL-encoded echo did not match")
	}
	if !r.hit("path=alpha%252Fbeta") {
		t.Fatal("2-layer URL-encoded echo did not match")
	}
	if !r.hit("id%3D987654") || r.hit("id=1987654") {
		t.Fatal("whole-number digit boundary broken")
	}

	// Deeply nested %2525... leaf (50,000 layers ~ 100 KB) must run in O(1) passes (< 10 ms)
	// without unbounded recursion or O(N^2) allocations.
	deep := "%" + strings.Repeat("25", 50000) + "41"
	start := time.Now()
	_ = r.hit(deep)
	if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
		t.Fatalf("reflector.hit on 100 KB multi-encoded leaf took %v (> 10ms quadratic blowup)", elapsed)
	}
}
