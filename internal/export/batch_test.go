package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

const (
	elemA  = `{"operationName":"GetA","query":"query GetA($id: ID) { a(id: $id) }","variables":{"id":"7"},"extensions":{"persisted":1}}`
	elemB  = `{"operationName":"GetB","query":"query GetB { b }","variables":{}}`
	batch2 = "[" + elemA + "," + elemB + "]"
)

// batchDir writes a run with a GraphQL batch of two operations and a flow
// that has it.
func batchDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().UTC()
	h := map[string]string{"content-type": "application/json", "content-length": "999", "host": "app.test", "cookie": "s=1"}
	es := []traffic.Entry{
		{Run: "R1", ID: 1, Method: "POST", URL: "http://app.test/graphql", ResourceType: "Fetch", Outcome: "ok", Time: now,
			Headers: h, Body: traffic.Body{Body: batch2}, Response: &traffic.Response{Status: 200, Body: traffic.Body{Body: "[]"}}},
		{Run: "R1", ID: 2, Method: "POST", URL: "http://app.test/graphql", ResourceType: "Fetch", Outcome: "ok", Time: now.Add(time.Second),
			Headers: h, Body: traffic.Body{Body: elemA}, Response: &traffic.Response{Status: 200, Body: traffic.Body{Body: "{}"}}},
	}
	var s string
	for _, e := range es {
		b, _ := json.Marshal(e)
		s += string(b) + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "requests.jsonl"), []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	f := flow.Flow{Run: "R1", Action: "a1", Kind: "click", Label: "go", Started: now, Ended: now.Add(2 * time.Second),
		Requests: []flow.Ref{{ID: 1}, {ID: 2}}}
	b, _ := json.Marshal(f)
	if err := os.WriteFile(filepath.Join(dir, "flows.jsonl"), append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func keysOf(m *Manifest) []string {
	var out []string
	for _, e := range m.Endpoints {
		out = append(out, e.Key)
	}
	return out
}

// Each operation of a batch is an endpoint of its own: its representative
// is a request of that operation alone, in an array, with its own length.
func TestExportBatchOneKeyPerOperation(t *testing.T) {
	dir := batchDir(t)
	man, err := Export(Options{Dir: dir, Dest: filepath.Join(dir, "out")})
	if err != nil {
		t.Fatal(err)
	}
	keys := strings.Join(keysOf(man), "|")
	if !strings.Contains(keys, "POST app.test/graphql op=GetA") || !strings.Contains(keys, "POST app.test/graphql op=GetB") {
		t.Fatalf("keys: %s", keys)
	}
	if strings.Contains(keys, "GetA+GetB") || strings.Contains(keys, "graphql|") || strings.HasSuffix(keys, "graphql") {
		t.Fatalf("a key for the batch as a whole: %s", keys)
	}
	var fileB string
	for _, e := range man.Endpoints {
		if strings.HasSuffix(e.Key, "op=GetB") {
			fileB = e.File
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "out", fileB))
	if err != nil {
		t.Fatal(err)
	}
	want := "[" + elemB + "]"
	if !strings.HasSuffix(string(raw), "\r\n\r\n"+want) || !strings.Contains(string(raw), "Content-Length: "+itoa(len(want))+"\r\n") {
		t.Fatalf("%q", raw)
	}
	// The flow keeps the request as it was sent.
	m, err := Load(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.Request("R1", 1).Raw()
	if err != nil || !strings.HasSuffix(string(r), batch2) {
		t.Fatalf("%q %v", r, err)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// Params are those of the representative's own body: the byte offsets
// land on the values of the one operation, which is element 0.
func TestExportBatchParamsOffsets(t *testing.T) {
	dir := batchDir(t)
	m, err := Load(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, r := range m.Requests {
		op := r.Key[strings.LastIndex(r.Key, " ")+1:]
		raw, _ := r.Raw()
		for _, p := range r.Params() {
			if p.In != "json" {
				continue
			}
			if strings.HasPrefix(p.Name, "$[1]") {
				t.Fatalf("%s: %s: the batch's second element in a request of one", r.Key, p.Name)
			}
			if strings.HasSuffix(p.Name, "variables.id") {
				if got := strings.Trim(string(raw[p.Start:p.End]), `"`); got != "7" {
					t.Fatalf("%s: %s at %d:%d is %q", r.Key, p.Name, p.Start, p.End, got)
				}
				found[op] = true
			}
		}
	}
	if !found["op=GetA"] {
		t.Fatalf("no variables.id of op=GetA: %v", found)
	}
	var b *Request
	for _, r := range m.Requests {
		if strings.HasSuffix(r.Key, "op=GetB") {
			b = r
		}
	}
	if b == nil {
		t.Fatal("no request of op=GetB in the model")
	}
	raw, _ := b.Raw()
	if strings.Contains(string(raw), "GetA") || !strings.HasSuffix(string(raw), "["+elemB+"]") {
		t.Fatalf("%q", raw)
	}
}
