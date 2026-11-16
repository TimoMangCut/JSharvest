package export

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// mixedDir is a batch of an anonymous query, GetA and GetB (whose csrf
// variable an earlier response gave).
func mixedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().UTC()
	h := map[string]string{"content-type": "text/plain;charset=UTF-8", "host": "app.test", "cookie": "s=1"}
	batch := `[{"query":"{ me { id } }"},{"operationName":"GetA","query":"query GetA { a }"},` +
		`{"operationName":"GetB","query":"query GetB($c: String) { b(c: $c) }","variables":{"csrf":"tok1"}}]`
	es := []traffic.Entry{
		{Run: "R1", ID: 1, Method: "POST", URL: "http://app.test/graphql", ResourceType: "Fetch", Outcome: "ok", Time: now.Add(time.Second),
			Headers: h, Body: traffic.Body{Body: batch}, Response: &traffic.Response{Status: 200, Body: traffic.Body{Body: "[]"}}},
		{Run: "R1", ID: 2, Method: "GET", URL: "http://app.test/api/token", ResourceType: "Fetch", Outcome: "ok", Time: now,
			Headers: map[string]string{"host": "app.test"}, Response: &traffic.Response{Status: 200, MIME: "application/json",
				Headers: map[string]string{"content-type": "application/json"}, Body: traffic.Body{Body: `{"token":"tok1"}`}}},
	}
	var s string
	for _, e := range es {
		b, _ := json.Marshal(e)
		s += string(b) + "\n"
	}
	os.WriteFile(filepath.Join(dir, "requests.jsonl"), []byte(s), 0o600)
	f := flow.Flow{Run: "R1", Action: "a1", Kind: "click", Label: "go", Started: now, Ended: now.Add(2 * time.Second),
		Requests:  []flow.Ref{{ID: 2}, {ID: 1}},
		DependsOn: []flow.Link{{Request: 1, At: "body:$[2].variables.csrf", From: flow.LinkEnd{Request: 2, At: "json:$.token"}}}}
	b, _ := json.Marshal(f)
	os.WriteFile(filepath.Join(dir, "flows.jsonl"), append(b, '\n'), 0o600)
	return dir
}

func TestExportBatchDerivedFollowsTheElement(t *testing.T) {
	dir := mixedDir(t)
	m, err := Load(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	var a, b *Request
	for _, r := range m.Requests {
		switch {
		case strings.HasSuffix(r.Key, "op=GetA"):
			a = r
		case strings.HasSuffix(r.Key, "op=GetB"):
			b = r
		}
	}
	if a == nil || b == nil {
		t.Fatal("no request of GetA or GetB")
	}
	if _, ok := b.Derived["body:$[0].variables.csrf"]; !ok || len(b.Derived) != 1 {
		t.Errorf("GetB derived %v", b.Derived)
	}
	if len(a.Derived) != 0 {
		t.Errorf("GetA derived %v", a.Derived)
	}
	// The whole batch keeps the places it was recorded with.
	if _, ok := m.Request("R1", 1).Derived["body:$[2].variables.csrf"]; !ok {
		t.Errorf("batch derived %v", m.Request("R1", 1).Derived)
	}
	// params.jsonl says where the value came from.
	if _, err := Export(Options{Dir: dir, Dest: filepath.Join(dir, "out")}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "out", "params.jsonl"))
	found := false
	for _, ln := range bytes.Split(raw, []byte("\n")) {
		var l ParamLine
		if json.Unmarshal(ln, &l) == nil && strings.HasSuffix(l.Endpoint, "op=GetB") && l.Name == "$[0].variables.csrf" {
			found = l.DerivedFrom != nil && l.DerivedFrom.At == "json:$.token"
		}
	}
	if !found {
		t.Errorf("no derived_from on GetB's csrf:\n%s", raw)
	}
}

// An anonymous operation of a mixed batch is the endpoint without one.
func TestExportBatchAnonymousOperation(t *testing.T) {
	dir := mixedDir(t)
	man, err := Export(Options{Dir: dir, Dest: filepath.Join(dir, "out")})
	if err != nil {
		t.Fatal(err)
	}
	keys := strings.Join(keysOf(man), "|")
	for _, k := range []string{"POST app.test/graphql|", "POST app.test/graphql op=GetA", "POST app.test/graphql op=GetB"} {
		if !strings.Contains(keys+"|", k) {
			t.Errorf("no key %q in %s", k, keys)
		}
	}
}

func TestValueTypeOfBatchQuery(t *testing.T) {
	for _, n := range []string{"$.query", "$[0].query", "$[12].query"} {
		if got := valueType("query GetA { a }", ParamLine{In: "json", Name: n}); got != "graphql" {
			t.Errorf("%s: %s", n, got)
		}
	}
	if got := valueType("query GetA { a }", ParamLine{In: "json", Name: "$[x].query"}); got == "graphql" {
		t.Errorf("$[x].query: %s", got)
	}
}
