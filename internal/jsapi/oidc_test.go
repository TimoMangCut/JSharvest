package jsapi

import "testing"

func TestOIDC(t *testing.T) {
	doc := []byte(`{"issuer":"https://id.x","authorization_endpoint":"https://id.x/auth","token_endpoint":"https://id.x/token",
"userinfo_endpoint":"https://id.x/me","revocation_endpoint":"https://id.x/revoke","jwks_uri":"javascript:alert(1)","end_session_endpoint":"https://id.x/logout"}`)
	if !IsOIDC(doc) || IsOIDC([]byte(`{"openapi":"3.0.0","paths":{}}`)) || IsOIDC([]byte(`{"issuer":"x"}`)) {
		t.Fatal("IsOIDC")
	}
	got := map[string]string{}
	for _, e := range ExtractOIDC(doc).Endpoints {
		got[e.URL] = e.Method
		if e.Kind != "openapi" {
			t.Errorf("%s: kind %s", e.URL, e.Kind)
		}
	}
	want := map[string]string{"https://id.x/auth": "GET", "https://id.x/token": "POST", "https://id.x/me": "GET", "https://id.x/revoke": "POST",
		"https://id.x/logout": "GET"}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for u, m := range want {
		if got[u] != m {
			t.Errorf("%s: %q, want %q", u, got[u], m)
		}
	}
}
