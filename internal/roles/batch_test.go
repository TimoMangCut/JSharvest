package roles

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func writeReqs(t *testing.T, dir string, es ...traffic.Entry) {
	t.Helper()
	os.MkdirAll(dir, 0o700)
	var s string
	for _, e := range es {
		b, _ := json.Marshal(e)
		s += string(b) + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "requests.jsonl"), []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A role's batch is a call of each of its operations: what anon sent as
// one operation and user sent among others is the same endpoint.
func TestCompareBatchOperations(t *testing.T) {
	root := t.TempDir()
	h := map[string]string{"content-type": "application/json"}
	ok := &traffic.Response{Status: 200}
	elemA := `{"operationName":"GetA","query":"query GetA { a }"}`
	elemB := `{"operationName":"GetB","query":"query GetB { b }"}`
	req := func(id int, body string) traffic.Entry {
		return traffic.Entry{Run: "R1", ID: id, Method: "POST", URL: "http://app.test/graphql", ResourceType: "Fetch", Outcome: "ok",
			Headers: h, Body: traffic.Body{Body: body}, Response: ok}
	}
	writeReqs(t, filepath.Join(root, "anon"), req(1, elemA))
	writeReqs(t, filepath.Join(root, "user"), req(1, "["+elemA+","+elemB+"]"))
	rep, err := Compare(Options{Root: root, Roles: []string{"anon", "user"}, All: true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Item{}
	for _, it := range rep.Items {
		if it.Layer == "endpoint" {
			got[it.Key] = it
		}
	}
	a, okA := got["POST app.test/graphql op=GetA"]
	b, okB := got["POST app.test/graphql op=GetB"]
	if !okA || !okB || len(got) != 2 {
		var keys []string
		for k := range got {
			keys = append(keys, k)
		}
		t.Fatalf("endpoint items %v", keys)
	}
	if a.Class != Same {
		t.Errorf("GetA: %s, want %s", a.Class, Same)
	}
	if b.Class != HigherOnly {
		t.Errorf("GetB: %s, want %s", b.Class, HigherOnly)
	}
}
