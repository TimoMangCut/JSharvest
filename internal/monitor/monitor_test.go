package monitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ep(method, path string, code, traffic bool, ok, refused int, scripts ...string) *Endpoint {
	return &Endpoint{Method: method, Host: "app.test", Path: path, Code: code, Traffic: traffic, OK: ok, Refused: refused,
		Params: map[string]bool{}, Scripts: scripts}
}

func content(scripts map[string][]string, eps ...*Endpoint) *Content {
	return &Content{Scripts: scripts, Endpoints: eps, Hosts: map[string]bool{"app.test": true}}
}

func find(cs []Change, kind, key string) *Change {
	for i := range cs {
		if cs[i].Kind == kind && strings.Contains(cs[i].Key, key) {
			return &cs[i]
		}
	}
	return nil
}

func TestCompareRole(t *testing.T) {
	scripts := map[string][]string{"app.test/app.js": {"a1"}, "app.test/vendor.[h].js": {"v1"}}
	base := content(scripts,
		ep("GET", "/api/items/{}", true, true, 2, 0, "app.test/app.js"),
		ep("GET", "/api/old", true, false, 0, 0, "app.test/app.js"),
		ep("GET", "/api/gone-chunk", true, false, 0, 0, "app.test/lazy.js"),
		ep("GET", "/api/polled", false, true, 3, 0),
		ep("GET", "/api/report", false, true, 0, 2),
	)
	cur := content(map[string][]string{"app.test/app.js": {"a2"}, "app.test/vendor.[h].js": {"v2"}},
		ep("GET", "/api/items/{}", true, true, 1, 0, "app.test/app.js"),
		ep("POST", "/api/admin/export", true, false, 0, 0, "app.test/app.js"),
		ep("GET", "/api/news", true, true, 1, 0, "app.test/app.js"),
		ep("GET", "/api/report", false, true, 2, 0),
	)
	cur.Endpoints[0].Params["include_deleted"] = true
	rc := &roleCompare{role: "anon", cur: cur, base: base, known: []*Content{base}}
	cs := compareRole(rc)
	for _, w := range []struct{ kind, key, sev string }{
		{"endpoint_new", "/api/admin/export", High},
		{"endpoint_new", "/api/news", Medium},
		{"param_new", "include_deleted", High},
		{"status_changed", "/api/report", High},
		{"endpoint_gone", "/api/old", Medium},      // its script is there, without it
		{"endpoint_gone", "/api/gone-chunk", Info}, // its script was not seen
		{"endpoint_gone", "/api/polled", Info},     // traffic only
		{"script_changed", "app.test/app.js", Low},
	} {
		c := find(cs, w.kind, w.key)
		if c == nil || c.Severity != w.sev {
			t.Errorf("%s %s: %+v, want %s", w.kind, w.key, c, w.sev)
		}
	}
	if find(cs, "script_changed", "vendor") != nil {
		t.Error("a rebuilt hashed bundle reported")
	}

	// Not comparable: what is gone is info.
	rc.partial = "the crawl hit its page limit"
	if c := find(compareRole(rc), "endpoint_gone", "/api/old"); c == nil || c.Severity != Info {
		t.Errorf("partial: %+v", c)
	}
	// Known from an earlier snapshot: not new again.
	rc.partial = ""
	rc.known = append(rc.known, content(nil, ep("GET", "/api/news", true, false, 0, 0)))
	if find(compareRole(rc), "endpoint_new", "/api/news") != nil {
		t.Error("an endpoint an earlier snapshot knew reported new")
	}
}

func TestStatusChange(t *testing.T) {
	for _, c := range []struct {
		b, a    *Endpoint
		session bool
		want    string
	}{
		{ep("GET", "/x", false, true, 0, 2), ep("GET", "/x", false, true, 1, 0), false, High},
		{ep("GET", "/x", false, true, 0, 1), ep("GET", "/x", false, true, 1, 0), false, Medium}, // refused once only
		{ep("GET", "/x", false, true, 0, 2), ep("GET", "/x", false, true, 1, 1), false, Low},    // mixed now
		{ep("GET", "/x", false, true, 2, 0), ep("GET", "/x", false, true, 0, 2), false, Low},
		{ep("GET", "/x", false, true, 0, 2), ep("GET", "/x", false, true, 2, 0), true, Info},
	} {
		ch, ok := statusChange(c.b, c.a, c.session)
		if !ok || ch.Severity != c.want {
			t.Errorf("%s→%s session %v: %v %+v, want %s", fares(c.b), fares(c.a), c.session, ok, ch, c.want)
		}
	}
}

func TestMergeRoles(t *testing.T) {
	all := []Change{
		{Kind: "endpoint_new", Severity: Medium, Layer: "endpoint", Key: "GET a/x", Roles: []string{"anon"}},
		{Kind: "endpoint_new", Severity: High, Layer: "endpoint", Key: "GET a/x", Roles: []string{"admin"}},
		{Kind: "endpoint_new", Severity: Medium, Layer: "endpoint", Key: "GET a/x", Roles: []string{"user"}},
	}
	got := merge(all)
	if len(got) != 1 || got[0].Severity != High || strings.Join(got[0].Roles, ",") != "anon,admin,user" {
		t.Fatalf("%+v", got)
	}
}

func TestRuns(t *testing.T) {
	if (run{Mode: "watch", Scripts: []string{}}).eligible() || (run{Mode: "launch", ExitCode: 3, Scripts: []string{}}).eligible() ||
		(run{Mode: "launch"}).eligible() || !(run{Mode: "launch", Scripts: []string{}}).eligible() {
		t.Fatal("eligible")
	}
	base := &RoleSnap{Targets: []string{"http://a/"}, Config: json.RawMessage(`{"depth":1}`), Pages: 10}
	if comparable(&RoleSnap{Targets: []string{"http://a/", "http://a/x"}, Config: json.RawMessage(`{"depth":1}`), Pages: 20}, base) == "" {
		t.Fatal("a batch compared with a crawl")
	}
	if w := comparable(&RoleSnap{Targets: []string{"http://a/"}, Config: json.RawMessage(`{"depth": 1}`), Pages: 9}, base); w != "" {
		t.Fatal(w)
	}
	if comparable(&RoleSnap{Targets: []string{"http://a/"}, Config: json.RawMessage(`{"depth":2}`), Pages: 10}, base) == "" ||
		comparable(&RoleSnap{Targets: []string{"http://a/"}, Config: json.RawMessage(`{"depth":1}`), Pages: 5}, base) == "" {
		t.Fatal("not comparable")
	}
}

func TestWebhook(t *testing.T) {
	var got []Payload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		var p Payload
		json.NewDecoder(r.Body).Decode(&p)
		got = append(got, p)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	r := &Result{Snapshot: &Snapshot{ID: "s1"}, Changes: []Change{
		{Kind: "endpoint_new", Severity: High, Key: "POST app.test/api/admin/<!here>@channel", Roles: []string{"anon"}},
		{Kind: "script_new", Severity: Low, Key: "app.test/x.js"},
	}}
	p := NewPayload(r, "app.test", "/out/latest.md", Medium, false)
	if p.Counts[High] != 1 || p.Counts[Low] != 0 || len(p.Changes) != 0 || strings.Contains(p.Text, "admin") {
		t.Fatalf("counts only: %+v", p)
	}
	k := NewPayload(r, "app.test", "/out/latest.md", Medium, true)
	if len(k.Changes) != 1 || strings.Contains(k.Text, "<!here>") || strings.Contains(k.Text, "@channel") {
		t.Fatalf("keys: %q", k.Text)
	}
	if err := Send(context.Background(), srv.URL+"/hook", p); err != nil || len(got) != 1 || got[0].ID != p.ID {
		t.Fatalf("%v %+v", err, got)
	}
	if err := Send(context.Background(), srv.URL+"/moved", p); err == nil || len(got) != 1 {
		t.Fatalf("a redirect was followed: %v", err)
	}
	if err := Send(context.Background(), "http://example.test/hook", p); err != ErrInsecure {
		t.Fatalf("http to a host: %v", err)
	}
	err := Send(context.Background(), "http://127.0.0.1:1/T0KEN-secret", p)
	if err == nil || strings.Contains(err.Error(), "T0KEN") {
		t.Fatalf("the URL in the error: %v", err)
	}
}
