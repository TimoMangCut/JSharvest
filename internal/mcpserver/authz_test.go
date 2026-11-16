package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// get_authz (P6.2b): bola.json read from <host>/authz, its evidence masked
// unless -reveal, filtered by verdict, inside the untrusted envelope.
func TestGetAuthzPeers(t *testing.T) {
	root := t.TempDir()
	w := newWatch(t, root)
	w.snapshot()
	authz := filepath.Join(filepath.Dir(w.dir), "authz")
	secret := "TAX-ID 4417-ALICE-9921"

	cs := connect(t, Options{Root: root})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_authz"})
	if err != nil || !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "jsharvest authz") {
		t.Fatalf("missing authz: want a tool error naming jsharvest authz, got %v %+v", err, res)
	}

	rep := map[string]any{"host": "app.test", "peers": []string{"alice", "bob"}, "relation": "same-org", "summary": map[string]int{"bypass": 1, "enforced": 1},
		"items": []any{
			map[string]any{"key": "GET app.test/api/notes/{}", "direction": "alice->bob", "owner": "alice", "as": "bob", "verdict": "bypass", "reason": "values only A had",
				"evidence": []any{map[string]any{"path": "$.body", "value": secret}}, "ids": []any{map[string]any{"at": "path:3", "kind": "int_small", "value": "1101"}}},
			map[string]any{"key": "GET app.test/api/prefs", "direction": "bob->charlie", "owner": "bob", "as": "charlie", "verdict": "enforced", "reason": "the trial is B's own"},
		}}
	os.MkdirAll(authz, 0o700)
	b, _ := json.Marshal(rep)
	if err := os.WriteFile(filepath.Join(authz, "bola.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	text := func(cs *mcp.ClientSession, args map[string]any) string {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_authz", Arguments: args})
		if err != nil || res.IsError {
			t.Fatalf("get_authz %v: %v %+v", args, err, res)
		}
		return res.Content[0].(*mcp.TextContent).Text
	}
	masked := text(cs, map[string]any{})
	var out struct {
		Untrusted string           `json:"untrusted"`
		Mode      string           `json:"mode"`
		Total     int              `json:"total"`
		Items     []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(masked), &out); err != nil {
		t.Fatal(err)
	}
	if out.Untrusted != "target" || out.Mode != "peers" || out.Total != 2 {
		t.Fatalf("envelope/mode/total: %+v", out)
	}
	if strings.Contains(masked, secret) || !strings.Contains(masked, "REDACTED_") {
		t.Fatalf("evidence not masked: %s", masked)
	}
	if strings.Contains(masked, `"value":"1101"`) {
		t.Fatalf("id value not masked: %s", masked)
	}
	only := text(cs, map[string]any{"verdict": "bypass"})
	if err := json.Unmarshal([]byte(only), &out); err != nil || out.Total != 1 || len(out.Items) != 1 {
		t.Fatalf("verdict filter: %s", only)
	}
	byDir := text(cs, map[string]any{"direction": "bob->charlie"})
	if err := json.Unmarshal([]byte(byDir), &out); err != nil || out.Total != 1 || len(out.Items) != 1 || out.Items[0]["key"] != "GET app.test/api/prefs" {
		t.Fatalf("direction filter: %s", byDir)
	}
	byRole := text(cs, map[string]any{"role": "charlie"})
	if err := json.Unmarshal([]byte(byRole), &out); err != nil || out.Total != 1 || len(out.Items) != 1 {
		t.Fatalf("role filter: %s", byRole)
	}
	revealed := text(connect(t, Options{Root: root, Reveal: true}), map[string]any{"mode": "peers"})
	if !strings.Contains(revealed, secret) {
		t.Fatalf("-reveal: the evidence should be shown: %s", revealed)
	}
	listed, _ := cs.ListTools(context.Background(), nil)
	found := false
	for _, tl := range listed.Tools {
		if tl.Name == "get_authz" && strings.Contains(tl.Description, untrustedNote) {
			found = true
		}
	}
	if !found {
		t.Fatal("get_authz not listed with the untrusted note")
	}
}
