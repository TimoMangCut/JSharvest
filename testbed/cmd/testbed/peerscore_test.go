package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const peerTruthPath = "../../apps/peer-app/peer.truth.json"

type fakeBola struct {
	t   *testing.T
	dir string
	rep map[string]any
}

// newFakeBola writes, by hand, the files an authz -peers run would for a
// scenario of the truth, all right: each item with the truth's verdict, an
// evidence (redacted) on each bypass and shared, a sent log and a trial file
// that carry each their own identity's credential.
func newFakeBola(t *testing.T, scenario string, reveal bool) *fakeBola {
	var truth peerTruth
	if err := readJSON(peerTruthPath, &truth); err != nil {
		t.Fatal(err)
	}
	sc := truth.Scenarios[scenario]
	var items []map[string]any
	stopped := map[string]string{}
	for _, it := range sc.Items {
		i := map[string]any{
			"key": "127.0.0.1" + strings.TrimPrefix(it.Key, strings.SplitN(it.Key, " ", 2)[0]+" "), "direction": it.Direction,
			"mode": it.Mode, "verdict": it.Verdict, "reason": "by hand",
		}
		i["key"] = strings.SplitN(it.Key, " ", 2)[0] + " 127.0.0.1" + strings.SplitN(strings.SplitN(it.Key, " ", 2)[1], " ", 2)[0]
		if parts := strings.SplitN(it.Key, " ", 3); len(parts) == 3 {
			i["key"] = i["key"].(string) + " " + parts[2]
		}
		if it.Verdict == "bypass" || it.Verdict == "shared" {
			v := "REDACTED_0a1b2c3d"
			if reveal {
				v = "Alice private: the safe code is 48-17-92 behind the blue ledger"
			}
			i["evidence"] = []map[string]any{{"path": "$.body", "value": v, "ref_value": v}}
		}
		if it.Stopped {
			stopped[it.Key+" "+it.Direction] = "Bogus answers 200 like the trial"
		}
		items = append(items, i)
	}
	f := &fakeBola{t: t, dir: t.TempDir(), rep: map[string]any{
		"host": "127.0.0.1", "peers": sc.Peers, "relation": sc.Relation, "redacted": !reveal, "items": items,
	}}
	if len(stopped) > 0 {
		f.rep["stopped_endpoints"] = stopped
	}
	f.write()
	os.WriteFile(filepath.Join(f.dir, "bola.md"), []byte("# bola\nbypass: REDACTED_0a1b2c3d\n"), 0o600)
	sent := `{"n":1,"purpose":"trial","role":"bob","request":"GET http://127.0.0.1/x","headers":{"Cookie":"peer_session=bobsession00000001"}}` + "\n" +
		`{"n":2,"purpose":"control","role":"alice","request":"GET http://127.0.0.1/x","headers":{"Cookie":"peer_session=alicesession0000001","X-CSRF-Token":"alicecsrf00000001"}}` + "\n" +
		`{"n":3,"purpose":"no-identity","role":"(none)","request":"GET http://127.0.0.1/files/doc-a1?expires=1&sig=abc"}` + "\n"
	os.WriteFile(filepath.Join(f.dir, "bola.sent.jsonl"), []byte(sent), 0o600)
	os.MkdirAll(filepath.Join(f.dir, "trials"), 0o700)
	os.WriteFile(filepath.Join(f.dir, "trials", "bola.notes.alice-as-bob.http"), []byte("GET /api/peer/private-notes/1101\nCookie: peer_session=bobsession00000001\n"), 0o600)
	return f
}

func (f *fakeBola) write() {
	b, _ := json.Marshal(f.rep)
	if err := os.WriteFile(filepath.Join(f.dir, "bola.json"), b, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeBola) items() []map[string]any { return f.rep["items"].([]map[string]any) }

func (f *fakeBola) drop(key string) {
	var keep []map[string]any
	for _, i := range f.items() {
		if !strings.Contains(i["key"].(string), key) {
			keep = append(keep, i)
		}
	}
	f.rep["items"] = keep
	f.write()
}

func writeSecretsAndCreds(t *testing.T) (secrets, creds string) {
	d := t.TempDir()
	secrets = filepath.Join(d, "secrets.txt")
	creds = filepath.Join(d, "creds.txt")
	os.WriteFile(secrets, []byte("# secrets\nAlice private: the safe code is 48-17-92 behind the blue ledger\nTAX-ALICE-7731-QX9\nshort\n"), 0o600)
	os.WriteFile(creds, []byte("alice\talicesession0000001\nalice\talicecsrf00000001\nbob\tbobsession00000001\n"), 0o600)
	return
}

func (f *fakeBola) score(scenario string, reveal bool) (peerResult, string, error) {
	f.t.Helper()
	secrets, creds := writeSecretsAndCreds(f.t)
	var out bytes.Buffer
	r, err := peerScore(peerTruthPath, f.dir, scenario, secrets, creds, reveal, &out)
	return r, out.String(), err
}

func wantFail(t *testing.T, f *fakeBola, scenario string, reveal bool, want ...string) {
	t.Helper()
	r, out, err := f.score(scenario, reveal)
	if err != nil {
		t.Fatal(err)
	}
	if r.bad == 0 {
		t.Fatalf("no failure; wanted %v\n%s", want, out)
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("no %q in:\n%s", w, out)
		}
	}
}

func TestPeerScoreRightPasses(t *testing.T) {
	var truth peerTruth
	if err := readJSON(peerTruthPath, &truth); err != nil {
		t.Fatal(err)
	}
	for name, sc := range truth.Scenarios {
		f := newFakeBola(t, name, false)
		r, out, err := f.score(name, false)
		if err != nil || r.bad != 0 || r.ok != len(sc.Items) {
			t.Errorf("%s: %d right %d wrong, %v\n%s", name, r.ok, r.bad, err, out)
		}
	}
	f := newFakeBola(t, "alice-bob-same-org", true)
	if r, out, err := f.score("alice-bob-same-org", true); err != nil || r.bad != 0 {
		t.Errorf("-reveal: %v\n%s", err, out)
	}
}

func TestPeerScoreMissingAndWrong(t *testing.T) {
	f := newFakeBola(t, "alice-bob-same-org", false)
	f.drop("private-notes")
	wantFail(t, f, "alice-bob-same-org", false, "MISSING GET /api/peer/private-notes/{} alice->bob (main), want bypass", "MISSING GET /api/peer/private-notes/{} bob->alice")

	f = newFakeBola(t, "alice-bob-same-org", false)
	for _, i := range f.items() {
		if strings.Contains(i["key"].(string), "org-docs") && i["direction"] == "alice->bob" {
			i["verdict"] = "bypass"
		}
	}
	f.write()
	wantFail(t, f, "alice-bob-same-org", false, "WRONG GET /api/peer/org-docs/{} alice->bob (main): bypass", "want shared")
}

func TestPeerScoreExtraAndExcluded(t *testing.T) {
	f := newFakeBola(t, "alice-bob-same-org", false)
	f.rep["items"] = append(f.items(), map[string]any{"key": "GET 127.0.0.1/api/peer/me", "direction": "alice->bob", "mode": "main", "verdict": "enforced"},
		map[string]any{"key": "GET 127.0.0.1/api/peer/unknown/1", "direction": "alice->bob", "mode": "main", "verdict": "enforced"},
		f.items()[0])
	f.write()
	wantFail(t, f, "alice-bob-same-org", false, "EXTRA GET /api/peer/me alice->bob (main): an excluded", "EXTRA GET /api/peer/unknown/1", "DUPLICATE")
}

func TestPeerScoreModeAndRelation(t *testing.T) {
	f := newFakeBola(t, "alice-charlie-cross-org-substitute", false)
	for _, i := range f.items() {
		if i["mode"] == "substitute:path:6" {
			i["mode"] = "substitute:path:5"
		}
	}
	f.rep["relation"] = "same-org"
	f.write()
	wantFail(t, f, "alice-charlie-cross-org-substitute", false, "WRONG relation", "MISSING GET /api/peer/orgs/{}/projects/{} alice->charlie (substitute:path:6)", "EXTRA GET /api/peer/orgs/{}/projects/{} alice->charlie (substitute:path:5)")
}

// No scenario of the truth stops an endpoint any more (the dave scenario's
// featured answers the same for a Bogus id as for the trial: enforced, gd7 8
// #5); the scorer still checks a truth that says so.
func TestPeerScoreStopped(t *testing.T) {
	var truth map[string]any
	if err := readJSON(peerTruthPath, &truth); err != nil {
		t.Fatal(err)
	}
	for _, it := range truth["scenarios"].(map[string]any)["alice-dave-cross-org"].(map[string]any)["items"].([]any) {
		if m := it.(map[string]any); m["key"] == "GET /api/peer/featured/{}" {
			m["stopped"], m["verdict"] = true, "unclear"
		}
	}
	b, _ := json.Marshal(truth)
	path := filepath.Join(t.TempDir(), "truth.json")
	os.WriteFile(path, b, 0o600)
	f := newFakeBola(t, "alice-dave-cross-org", false)
	for _, i := range f.items() {
		if strings.Contains(i["key"].(string), "/featured/") {
			i["verdict"] = "unclear"
		}
	}
	f.write()
	var out bytes.Buffer
	r, err := peerScore(path, f.dir, "alice-dave-cross-org", "", "", false, &out)
	if err != nil || r.bad == 0 || !strings.Contains(out.String(), "NOT STOPPED GET /api/peer/featured/{}") {
		t.Fatalf("%v %d\n%s", err, r.bad, out.String())
	}
	f.rep["stopped_endpoints"] = map[string]string{"GET 127.0.0.1/api/peer/featured/{}": "Bogus answers 200"}
	f.write()
	out.Reset()
	if r, err := peerScore(path, f.dir, "alice-dave-cross-org", "", "", false, &out); err != nil || r.bad != 0 {
		t.Fatalf("%v %d\n%s", err, r.bad, out.String())
	}
}

func TestPeerScoreEvidenceAndRedaction(t *testing.T) {
	// A bypass without evidence.
	f := newFakeBola(t, "alice-bob-same-org", false)
	for _, i := range f.items() {
		if strings.Contains(i["key"].(string), "private-notes") {
			delete(i, "evidence")
		}
	}
	f.write()
	wantFail(t, f, "alice-bob-same-org", false, "NO EVIDENCE GET /api/peer/private-notes/{} alice->bob")

	// Evidence in the clear without -reveal; and the secret in bola.json, bola.md.
	f = newFakeBola(t, "alice-bob-same-org", false)
	for _, i := range f.items() {
		if e, ok := i["evidence"].([]map[string]any); ok {
			e[0]["value"] = "TAX-ALICE-7731-QX9"
		}
	}
	f.rep["redacted"] = false
	f.write()
	os.WriteFile(filepath.Join(f.dir, "bola.md"), []byte("the safe code is: Alice private: the safe code is 48-17-92 behind the blue ledger"), 0o600)
	wantFail(t, f, "alice-bob-same-org", false, "UNREDACTED", "redacted: false", "LEAK bola.json carries the secret", "LEAK bola.md carries the secret")

	// Under -reveal the secrets may be there, but the report must say so.
	f = newFakeBola(t, "alice-bob-same-org", true)
	f.rep["redacted"] = true
	f.write()
	wantFail(t, f, "alice-bob-same-org", true, "redacted: true under -reveal")
}

func TestPeerScoreForeignCredentials(t *testing.T) {
	// bob's request carries alice's cookie.
	f := newFakeBola(t, "alice-bob-same-org", false)
	b, _ := os.ReadFile(filepath.Join(f.dir, "bola.sent.jsonl"))
	b = append(b, []byte(`{"n":4,"purpose":"trial","role":"bob","request":"GET http://127.0.0.1/y","headers":{"Cookie":"peer_session=alicesession0000001"}}`+"\n")...)
	os.WriteFile(filepath.Join(f.dir, "bola.sent.jsonl"), b, 0o600)
	wantFail(t, f, "alice-bob-same-org", false, "LEAK bola.sent.jsonl line 4 (trial), sent as bob, carries alice's credential")

	// The CSRF token of alice in a request without identity.
	f = newFakeBola(t, "alice-bob-same-org", false)
	b, _ = os.ReadFile(filepath.Join(f.dir, "bola.sent.jsonl"))
	b = append(b, []byte(`{"n":4,"purpose":"no-identity","role":"(none)","headers":{"X-CSRF-Token":"alicecsrf00000001"}}`+"\n")...)
	os.WriteFile(filepath.Join(f.dir, "bola.sent.jsonl"), b, 0o600)
	wantFail(t, f, "alice-bob-same-org", false, "sent as (none), carries alice's credential")

	// A reproduction file of a trial as bob that holds alice's cookie; one as
	// alice that holds her own is fine.
	f = newFakeBola(t, "alice-bob-same-org", false)
	os.WriteFile(filepath.Join(f.dir, "trials", "bola.x.alice-as-bob.http"), []byte("Cookie: peer_session=alicesession0000001\n"), 0o600)
	os.WriteFile(filepath.Join(f.dir, "trials", "bola.x.bob-as-alice.http"), []byte("Cookie: peer_session=alicesession0000001\n"), 0o600)
	r, out, _ := f.score("alice-bob-same-org", false)
	if r.bad != 1 || !strings.Contains(out, "trials/bola.x.alice-as-bob.http, sent as bob") {
		t.Errorf("trial files: %d wrong\n%s", r.bad, out)
	}
}

func TestPeerScoreNoScenarioNoBola(t *testing.T) {
	var out bytes.Buffer
	if _, err := peerScore(peerTruthPath, t.TempDir(), "alice-bob-same-org", "", "", false, &out); err == nil {
		t.Error("no bola.json: no error")
	}
	f := newFakeBola(t, "alice-bob-same-org", false)
	if _, err := peerScore(peerTruthPath, f.dir, "nobody", "", "", false, &out); err == nil || !strings.Contains(err.Error(), "no scenario") {
		t.Errorf("unknown scenario: %v", err)
	}
}

func TestPeerCanon(t *testing.T) {
	for in, want := range map[string]string{
		"GET 127.0.0.1:8770/api/peer/org-docs/{uuid}": "GET /api/peer/org-docs/{}",
		"GET host/api/peer/orgs/{o}/projects/{id}":    "GET /api/peer/orgs/{}/projects/{}",
		"POST host/api/peer/graphql op=GetVaultItem":  "POST /api/peer/graphql op=GetVaultItem",
		"GET /api/peer/keys/{} action=regenerate":     "GET /api/peer/keys/{} action=regenerate",
	} {
		if got := peerCanon(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
