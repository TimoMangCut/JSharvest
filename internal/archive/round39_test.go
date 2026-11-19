package archive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRound39CrawlHostsIncludesInScopeAuthFlowRedirectHost(t *testing.T) {
	root := t.TempDir()
	roleDir := filepath.Join(root, "portal.example.test", "anon")
	if err := os.MkdirAll(roleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	intelJSON := `{
		"auth_flows": [
			{"provider": "entra_id", "redirect_uri": "https://sso-cb.example.test/oauth/callback"},
			{"provider": "okta", "redirect_uri": "https://outside.other.test/cb"}
		]
	}`
	if err := os.WriteFile(filepath.Join(roleDir, "intel.json"), []byte(intelJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	inScope := func(h string) bool {
		return h == "example.test" || strings.HasSuffix(h, ".example.test")
	}
	hosts, _ := CrawlHosts(root, inScope)
	if !hosts["sso-cb.example.test"] {
		t.Fatalf("expected in-scope redirect_uri host sso-cb.example.test in CrawlHosts, got %v", hosts)
	}
	if hosts["outside.other.test"] {
		t.Fatalf("unexpected out-of-scope redirect_uri host in CrawlHosts: %v", hosts)
	}
}
