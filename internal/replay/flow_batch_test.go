package replay

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/export"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// replay -flow sends a GraphQL batch as recorded: the export lists it as
// its operations, but a flow's later steps may read $[i] of its answer.
func TestReplayFlowSendsTheBatchWhole(t *testing.T) {
	const batch = `[{"operationName":"GetA","query":"query GetA { a }"},{"operationName":"GetB","query":"query GetB { b }"}]`
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[{"data":{}},{"data":{}}]`)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	dir := t.TempDir()
	now := time.Now().UTC()
	e := traffic.Entry{Run: "R1", ID: 1, Method: "POST", URL: srv.URL + "/graphql", ResourceType: "Fetch", Outcome: "ok", Time: now,
		Headers: map[string]string{"content-type": "application/json", "host": host, "cookie": "s=1"}, Body: traffic.Body{Body: batch},
		Response: &traffic.Response{Status: 200, Body: traffic.Body{Body: "[]"}}}
	b, _ := json.Marshal(e)
	os.WriteFile(filepath.Join(dir, "requests.jsonl"), append(b, '\n'), 0o600)
	f := flow.Flow{Run: "R1", Action: "a1", Kind: "click", Label: "go", Started: now, Ended: now, Requests: []flow.Ref{{ID: 1}}}
	b, _ = json.Marshal(f)
	os.WriteFile(filepath.Join(dir, "flows.jsonl"), append(b, '\n'), 0o600)

	m, err := export.Load(export.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSender(SenderOptions{Hosts: map[string]bool{host: true}, Max: 5, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	res, err := ReplayFlow(context.Background(), FlowOptions{Model: m, Action: "a1", As: NoIdentity(), Owner: "(none)", Sender: s,
		InScope: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 1 || !res.Steps[0].Sent {
		t.Fatalf("%+v", res.Steps)
	}
	if len(bodies) != 1 || bodies[0] != batch {
		t.Fatalf("the server saw %q, want the batch as recorded", bodies)
	}
}
