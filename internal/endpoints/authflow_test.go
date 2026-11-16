package endpoints

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestExtractAuthFlowsProviders(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		headers map[string]string
		body    string
		want    AuthFlow
	}{
		{
			name:   "entra_id_json_escaped",
			status: 200,
			body:   `{"code":0,"data":{"ssoUrl":"https:\/\/login.microsoftonline.com\/11111111-2222-3333-4444-555555555555\/oauth2\/v2.0\/authorize?client_id=00001111-aaaa-2222-bbbb-3333cccc4444\u0026response_type=code\u0026redirect_uri=https%3A%2F%2Fadmin.example.com%2Fauth%2Fcallback\u0026scope=openid+profile+email\u0026state=rnd123"}}`,
			want: AuthFlow{
				Provider:              "entra_id",
				AuthorizationEndpoint: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/authorize",
				TenantID:              "11111111-2222-3333-4444-555555555555",
				ClientID:              "00001111-aaaa-2222-bbbb-3333cccc4444",
				RedirectURI:           "https://admin.example.com/auth/callback",
				ResponseType:          "code",
				Scope:                 "openid profile email",
				SourceURL:             "https://admin.example.com/api/v1/sso/url",
			},
		},
		{
			name:   "keycloak_location_302",
			status: 302,
			headers: map[string]string{
				"location": "https://sso.example.com/realms/corp-admin/protocol/openid-connect/auth?client_id=portal-web&redirect_uri=https%3A%2F%2Fadmin.example.com%2Fcb&response_type=code&scope=openid",
			},
			want: AuthFlow{
				Provider:              "keycloak",
				AuthorizationEndpoint: "https://sso.example.com/realms/corp-admin/protocol/openid-connect/auth",
				TenantID:              "corp-admin",
				ClientID:              "portal-web",
				RedirectURI:           "https://admin.example.com/cb",
				ResponseType:          "code",
				Scope:                 "openid",
				SourceURL:             "https://admin.example.com/api/v1/sso/url",
			},
		},
		{
			name:   "cognito_hosted_ui",
			status: 200,
			body:   `{"login":"https://portal-pool.auth.ap-southeast-1.amazoncognito.com/oauth2/authorize?client_id=4exampleclientid&response_type=code&scope=email+openid&redirect_uri=https://admin.example.com/cb"}`,
			want: AuthFlow{
				Provider:              "cognito",
				AuthorizationEndpoint: "https://portal-pool.auth.ap-southeast-1.amazoncognito.com/oauth2/authorize",
				ClientID:              "4exampleclientid",
				RedirectURI:           "https://admin.example.com/cb",
				ResponseType:          "code",
				Scope:                 "email openid",
				SourceURL:             "https://admin.example.com/api/v1/sso/url",
			},
		},
		{
			name:   "auth0_authorize",
			status: 200,
			body:   `{"url":"https://acme-prod.us.auth0.com/authorize?client_id=Auth0ClientXYZ&response_type=code&redirect_uri=https://admin.example.com/callback&scope=openid%20profile"}`,
			want: AuthFlow{
				Provider:              "auth0",
				AuthorizationEndpoint: "https://acme-prod.us.auth0.com/authorize",
				ClientID:              "Auth0ClientXYZ",
				RedirectURI:           "https://admin.example.com/callback",
				ResponseType:          "code",
				Scope:                 "openid profile",
				SourceURL:             "https://admin.example.com/api/v1/sso/url",
			},
		},
		{
			name:   "okta_oauth2",
			status: 307,
			headers: map[string]string{
				"Location": "https://acme.okta.com/oauth2/default/v1/authorize?client_id=0oa1example&response_type=code&scope=openid&redirect_uri=https://admin.example.com/login/callback",
			},
			want: AuthFlow{
				Provider:              "okta",
				AuthorizationEndpoint: "https://acme.okta.com/oauth2/default/v1/authorize",
				ClientID:              "0oa1example",
				RedirectURI:           "https://admin.example.com/login/callback",
				ResponseType:          "code",
				Scope:                 "openid",
				SourceURL:             "https://admin.example.com/api/v1/sso/url",
			},
		},
		{
			name:   "google_oauth2",
			status: 200,
			body:   `{"google":"https://accounts.google.com/o/oauth2/v2/auth?client_id=123456.apps.googleusercontent.com&redirect_uri=https://admin.example.com/google/cb&response_type=code&scope=openid%20email"}`,
			want: AuthFlow{
				Provider:              "google",
				AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
				ClientID:              "123456.apps.googleusercontent.com",
				RedirectURI:           "https://admin.example.com/google/cb",
				ResponseType:          "code",
				Scope:                 "openid email",
				SourceURL:             "https://admin.example.com/api/v1/sso/url",
			},
		},
		{
			name:   "oidc_generic_connect",
			status: 200,
			body:   `{"idp":"https://id.example.org/connect/authorize?client_id=web-spa&response_type=code&redirect_uri=https://admin.example.com/cb"}`,
			want: AuthFlow{
				Provider:              "oidc_generic",
				AuthorizationEndpoint: "https://id.example.org/connect/authorize",
				ClientID:              "web-spa",
				RedirectURI:           "https://admin.example.com/cb",
				ResponseType:          "code",
				SourceURL:             "https://admin.example.com/api/v1/sso/url",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows, notes := ExtractAuthFlows("https://admin.example.com/api/v1/sso/url", tc.status, tc.headers, []byte(tc.body))
			if len(flows) != 1 || flows[0] != tc.want {
				t.Fatalf("got flows=%+v, want [%+v]", flows, tc.want)
			}
			if len(notes) != 0 {
				t.Fatalf("unexpected security notes: %v", notes)
			}
		})
	}
}

func TestExtractAuthFlowsSecurityNotesAndGuards(t *testing.T) {
	// Implicit token + non-loopback HTTP redirect_uri -> both notes.
	flows, notes := ExtractAuthFlows(
		"https://admin.example.com/auth/init",
		200,
		nil,
		[]byte(`{"url":"https://acme.auth0.com/authorize?client_id=c1&response_type=id_token+token&redirect_uri=http://admin.example.com/callback"}`),
	)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	wantNotes := []string{"oauth_http_redirect_uri", "oauth_implicit_flow"}
	if !slices.Equal(notes, wantNotes) {
		t.Fatalf("notes = %v, want %v", notes, wantNotes)
	}

	// Hybrid flow leaking access token ("code token") -> oauth_implicit_flow;
	// Loopback HTTP redirect_uri (localhost, 127.0.0.1, [::1]) -> NO oauth_http_redirect_uri.
	for _, loop := range []string{
		"http://localhost:3000/cb",
		"http://127.0.0.1:8080/cb",
		"http://[::1]:5173/cb",
	} {
		_, ns := ExtractAuthFlows(
			"https://admin.example.com/auth/dev",
			302,
			map[string]string{"location": "https://acme.auth0.com/authorize?client_id=c1&response_type=code+token&redirect_uri=" + loop},
			nil,
		)
		if !slices.Equal(ns, []string{"oauth_implicit_flow"}) {
			t.Fatalf("loopback %s: notes = %v, want [oauth_implicit_flow]", loop, ns)
		}
	}

	// id_token without code -> oauth_implicit_flow.
	_, ns := ExtractAuthFlows(
		"https://admin.example.com/auth/implicit-id",
		200,
		nil,
		[]byte(`{"u":"https://acme.auth0.com/authorize?client_id=c1&response_type=id_token&redirect_uri=https://admin.example.com/cb"}`),
	)
	if !slices.Equal(ns, []string{"oauth_implicit_flow"}) {
		t.Fatalf("id_token alone: notes = %v, want [oauth_implicit_flow]", ns)
	}

	// Guards: 4xx/5xx ignored; >256KB body ignored; discovery doc without client_id ignored.
	if fs, _ := ExtractAuthFlows("https://admin.example.com/x", 401, map[string]string{
		"location": "https://acme.auth0.com/authorize?client_id=c1&response_type=code",
	}, nil); len(fs) != 0 {
		t.Fatalf("401 should be ignored, got %+v", fs)
	}
	big := `{"u":"https://acme.auth0.com/authorize?client_id=c1&response_type=code"}` + strings.Repeat(" ", (256<<10)+10)
	if fs, _ := ExtractAuthFlows("https://admin.example.com/x", 200, nil, []byte(big)); len(fs) != 0 {
		t.Fatalf(">256KB body should be ignored, got %+v", fs)
	}
	if fs, _ := ExtractAuthFlows("https://admin.example.com/.well-known/openid-configuration", 200, nil,
		[]byte(`{"authorization_endpoint":"https://login.microsoftonline.com/common/oauth2/v2.0/authorize"}`)); len(fs) != 0 {
		t.Fatalf("bare discovery endpoint without client_id should be ignored, got %+v", fs)
	}
}

func TestSaveIntelAuthFlowsCrossDomainIdP(t *testing.T) {
	dir := t.TempDir()
	// Empty index.jsonl so Load(dir) succeeds with 0 scripts; intel comes purely from requests.jsonl!
	if err := os.WriteFile(filepath.Join(dir, "index.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	reqs := `{"url":"https://admin.example.com/api-gateway/auth/v1/sso/url","response":{"status":200,"headers":{"content-type":"application/json"},"body":"{\"url\":\"https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/oauth2/v2.0/authorize?client_id=app-123\\u0026response_type=token\\u0026redirect_uri=http://admin.example.com/sso/cb\\u0026scope=openid\\u0026state=s1\"}"}}
{"url":"https://admin.example.com/api-gateway/auth/v1/sso/url","response":{"status":200,"headers":{"content-type":"application/json"},"body":"{\"url\":\"https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/oauth2/v2.0/authorize?client_id=app-123\\u0026response_type=token\\u0026redirect_uri=http://admin.example.com/sso/cb\\u0026scope=openid\\u0026state=s2\"}"}}
{"url":"https://tracker.thirdparty.example/sso","response":{"status":302,"headers":{"location":"https://evil.auth0.com/authorize?client_id=ignore&response_type=code"}}}
`
	if err := os.WriteFile(filepath.Join(dir, "requests.jsonl"), []byte(reqs), 0o600); err != nil {
		t.Fatal(err)
	}
	inScope := func(h string) bool { return h == "admin.example.com" }
	in, err := SaveIntel(dir, inScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.AuthFlows) != 1 {
		t.Fatalf("got %d auth_flows, want 1 (deduplicated): %+v", len(in.AuthFlows), in.AuthFlows)
	}
	got := in.AuthFlows[0]
	if got.Provider != "entra_id" || got.TenantID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" || got.ClientID != "app-123" {
		t.Fatalf("unexpected auth_flow: %+v", got)
	}
	var noteKinds []string
	for _, n := range in.SecurityNotes {
		noteKinds = append(noteKinds, n.Kind)
	}
	if !slices.Equal(noteKinds, []string{"oauth_http_redirect_uri", "oauth_implicit_flow"}) {
		t.Fatalf("security_notes = %v, want [oauth_http_redirect_uri oauth_implicit_flow]", noteKinds)
	}
	raw, err := os.ReadFile(filepath.Join(dir, IntelFile))
	if err != nil {
		t.Fatal(err)
	}
	var disk Intel
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(disk.AuthFlows, in.AuthFlows) {
		t.Fatalf("disk auth_flows = %+v, want %+v", disk.AuthFlows, in.AuthFlows)
	}
}
