package endpoints

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// R39-C: SaveIntel extracts OAuth2/OIDC SSO flows from HTML links recorded in
// pages.jsonl (where requests.jsonl omits HTML bodies), promotes clean in-scope
// redirect_uri paths into intel.Routes without query secrets, and fingerprints
// backend frameworks from Set-Cookie names without ever storing cookie values.
func TestRound39HTMLPageAuthFlowsAndCookieServerHints(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	const cookieSecret = "eyJpdiI6IlNFQ1JFVF9sYXJhdmVsX3ZhbHVlXzk5ODg3NyJ9"
	reqs := `{"url":"https://portal.example.test/login","response":{"status":200,"headers":{"server":"cloudflare","set-cookie":"XSRF-TOKEN=xsrf_tok_val\nlaravel_session=` + cookieSecret + `; path=/; httponly"}}}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "requests.jsonl"), []byte(reqs), 0o600); err != nil {
		t.Fatal(err)
	}

	pages := `{"url":"https://portal.example.test/login","visited":true,"status":200}
{"url":"https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/authorize?client_id=750019d9-aaaa-bbbb-cccc-dce01c1c31c0&response_type=code&redirect_uri=https://auth-cb.example.test/callback?secret_tok=NO_LEAK&scope=https://graph.microsoft.com/.default&state=st123","visited":false,"from":"https://portal.example.test/login","how":"link","reason":"scope"}
{"url":"https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/oauth2/v2.0/authorize?client_id=ignore-out-of-scope&response_type=code&redirect_uri=https://evil.other.test/cb","visited":false,"from":"https://thirdparty.other.test/login","how":"link","reason":"scope"}
`
	if err := os.WriteFile(filepath.Join(dir, "pages.jsonl"), []byte(pages), 0o600); err != nil {
		t.Fatal(err)
	}

	inScope := func(h string) bool {
		return h == "portal.example.test" || strings.HasSuffix(h, ".example.test")
	}
	in, err := SaveIntel(dir, inScope, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(in.AuthFlows) != 1 {
		t.Fatalf("got %d auth_flows, want 1: %+v", len(in.AuthFlows), in.AuthFlows)
	}
	af := in.AuthFlows[0]
	if af.Provider != "entra_id" || af.TenantID != "11111111-2222-3333-4444-555555555555" || af.ClientID != "750019d9-aaaa-bbbb-cccc-dce01c1c31c0" {
		t.Fatalf("unexpected auth_flow: %+v", af)
	}

	var routePaths []string
	for _, r := range in.Routes {
		routePaths = append(routePaths, r.Path)
	}
	if !slices.Equal(routePaths, []string{"/callback"}) {
		t.Fatalf("routes = %v, want [/callback] (clean path without query secrets)", routePaths)
	}

	var hintNames []string
	for _, h := range in.ServerHints {
		hintNames = append(hintNames, h.Name)
	}
	if !slices.Equal(hintNames, []string{"Laravel", "cloudflare"}) {
		t.Fatalf("server_hints = %v, want [Laravel cloudflare]", hintNames)
	}

	rawIntel, err := os.ReadFile(filepath.Join(dir, IntelFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawIntel), cookieSecret) || strings.Contains(string(rawIntel), "xsrf_tok_val") {
		t.Fatalf("cookie value leaked into intel.json:\n%s", rawIntel)
	}
}
