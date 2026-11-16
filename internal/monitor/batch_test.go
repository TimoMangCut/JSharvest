package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// A GraphQL batch the role sent is an endpoint for each operation, with the
// params of that operation's own element.
func TestBuildBatchOneEndpointPerOperation(t *testing.T) {
	dir := t.TempDir()
	h := map[string]string{"content-type": "application/json"}
	body := `[{"operationName":"GetA","query":"query GetA { a }","variables":{"pa":1}},{"operationName":"GetB","query":"query GetB { b }","variables":{"pb":1}}]`
	var s string
	for id := 1; id <= 2; id++ { // twice: a param seen once is no sign
		e := traffic.Entry{Run: "R1", ID: id, Method: "POST", URL: "http://app.test/graphql", ResourceType: "Fetch", Outcome: "ok",
			Headers: h, Body: traffic.Body{Body: body}, Response: &traffic.Response{Status: 200}}
		b, _ := json.Marshal(e)
		s += string(b) + "\n"
	}
	os.WriteFile(filepath.Join(dir, "requests.jsonl"), []byte(s), 0o600)
	c, err := build(dir, []string{"R1"}, "http://app.test/", func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*Endpoint{}
	for _, e := range c.Endpoints {
		got[e.Key()] = e
	}
	a, b := got["POST app.test/graphql op=GetA"], got["POST app.test/graphql op=GetB"]
	if a == nil || b == nil || len(got) != 2 {
		var keys []string
		for k := range got {
			keys = append(keys, k)
		}
		t.Fatalf("endpoints %v", keys)
	}
	if a.OK != 2 || b.OK != 2 {
		t.Fatalf("ok %d %d", a.OK, b.OK)
	}
	if !a.Params["json:$.variables.pa"] && !hasSuffixKey(a.Params, "pa") || hasSuffixKey(a.Params, "pb") {
		t.Fatalf("a params %v", a.Params)
	}
	if !hasSuffixKey(b.Params, "pb") || hasSuffixKey(b.Params, "pa") {
		t.Fatalf("b params %v", b.Params)
	}
}

func hasSuffixKey(m map[string]bool, suf string) bool {
	for k := range m {
		if len(k) >= len(suf) && k[len(k)-len(suf):] == suf {
			return true
		}
	}
	return false
}
