package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/TimoMangCut/JSharvest/internal/results"
)

// --- get_authz (plan-28 P6.2b) ---

type getAuthzIn struct {
	Mode        string `json:"mode,omitempty" jsonschema:"peers (authz -peers: bola.json) or roles (authz between roles: authz.json); default: peers when there is a bola.json"`
	Verdict     string `json:"verdict,omitempty" jsonschema:"only items with this verdict (bypass, unauthenticated, shared, likely, needs-review, enforced, enforced-parent, replay_broken, unclear, skipped, blocked)"`
	Direction   string `json:"direction,omitempty" jsonschema:"only peer items in this direction (e.g. userA->userB)"`
	Role        string `json:"role,omitempty" jsonschema:"only items involving this role or peer (owner/as in peers mode, trial/sample_role in roles mode)"`
	KeyContains string `json:"key_contains,omitempty" jsonschema:"only items whose endpoint key contains this text"`
	Limit       int    `json:"limit,omitempty" jsonschema:"at most this many items (default 50, at most 500)"`
	Offset      int    `json:"offset,omitempty" jsonschema:"skip this many of the matching items"`
}

type getAuthzOut struct {
	Dir    string         `json:"dir"`
	Mode   string         `json:"mode"`
	File   string         `json:"file"`
	Report map[string]any `json:"report"` // the file's fields but items, masked unless -reveal
	Total  int            `json:"total"`
	Offset int            `json:"offset,omitempty"`
	Items  []any          `json:"items"`
}

// valueKeys hold a value read from a response or sent in a request (the
// proof of a bypass, an id): masked as REDACTED_<hash> unless -reveal, the
// same value giving the same mask, as authz itself writes them.
var valueKeys = map[string]bool{"value": true, "ref_value": true, "bogus": true, "relay_id": true}

func (s *server) getAuthz(ctx context.Context, _ *mcp.CallToolRequest, in getAuthzIn) (*mcp.CallToolResult, any, error) {
	d, err := s.dir()
	if err != nil {
		return nil, nil, err
	}
	authzDir := filepath.Join(filepath.Dir(d.Path), "authz")
	mode := in.Mode
	if mode == "" {
		mode = "roles"
		if _, err := os.Stat(filepath.Join(authzDir, "bola.json")); err == nil {
			mode = "peers"
		}
	}
	var name string
	switch mode {
	case "peers":
		name = "bola.json"
	case "roles":
		name = "authz.json"
	default:
		return nil, nil, fmt.Errorf("unknown mode %q: want peers or roles", in.Mode)
	}
	file := filepath.Join(authzDir, name)
	b, err := os.ReadFile(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			host, _ := results.HostRole(d.Path)
			if mode == "peers" {
				return nil, nil, fmt.Errorf("no %s: run `jsharvest authz -target %s -peers A,B -relation same-org|cross-org` first", file, host)
			}
			return nil, nil, fmt.Errorf("no %s: run `jsharvest authz -target %s` first", file, host)
		}
		return nil, nil, err
	}
	var rep map[string]any
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}
	items, _ := rep["items"].([]any)
	delete(rep, "items")
	limit := clamp(in.Limit, 50, 500)
	out := getAuthzOut{Dir: authzDir, Mode: mode, File: name, Offset: in.Offset, Items: []any{}}
	for _, it := range items {
		m, _ := it.(map[string]any)
		if m == nil {
			continue
		}
		if in.Verdict != "" && !verdictMatches(m, in.Verdict) {
			continue
		}
		if in.Direction != "" && fmt.Sprint(m["direction"]) != in.Direction {
			continue
		}
		if in.Role != "" && !roleMatches(m, in.Role) {
			continue
		}
		if in.KeyContains != "" && !strings.Contains(fmt.Sprint(m["key"]), in.KeyContains) {
			continue
		}
		out.Total++
		if out.Total <= in.Offset || len(out.Items) >= limit {
			continue
		}
		out.Items = append(out.Items, s.maskAuthz(m, ""))
	}
	out.Report, _ = s.maskAuthz(rep, "").(map[string]any)
	return reply(out)
}

func verdictMatches(m map[string]any, want string) bool {
	if verdictOf(m) == want {
		return true
	}
	if trials, ok := m["trials"].([]any); ok {
		for _, t := range trials {
			if tm, ok := t.(map[string]any); ok && verdictOf(tm) == want {
				return true
			}
		}
	}
	return false
}

func roleMatches(m map[string]any, want string) bool {
	for _, k := range []string{"owner", "as", "role", "sample_role"} {
		if s, ok := m[k].(string); ok && s == want {
			return true
		}
	}
	if dir, ok := m["direction"].(string); ok {
		if a, b, ok := strings.Cut(dir, "->"); ok && (a == want || b == want) {
			return true
		}
	}
	if trials, ok := m["trials"].([]any); ok {
		for _, t := range trials {
			if tm, ok := t.(map[string]any); ok {
				if r, _ := tm["role"].(string); r == want {
					return true
				}
			}
		}
	}
	return false
}

// verdictOf reads an item's verdict: a top-level "verdict", or one nested
// in a judgement ({"judgement":{"verdict":…}}) as authz.json has it.
func verdictOf(m map[string]any) string {
	if v, ok := m["verdict"].(string); ok {
		return v
	}
	for _, k := range []string{"judgement", "result"} {
		if j, ok := m[k].(map[string]any); ok {
			if v, ok := j["verdict"].(string); ok {
				return v
			}
		}
	}
	return ""
}

// maskAuthz walks a decoded report: values under valueKeys are masked
// (REDACTED_<hash>), every other string goes through the credential
// redactor; with -reveal it is returned as it is.
func (s *server) maskAuthz(v any, key string) any {
	if s.red == nil {
		return v
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out[k] = s.maskAuthz(x[k], k)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = s.maskAuthz(e, key)
		}
		return out
	case string:
		if valueKeys[key] && x != "" {
			return s.red.Value(x)
		}
		return s.text(x)
	}
	return v
}
