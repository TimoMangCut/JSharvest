package traffic

import (
	"reflect"
	"strings"
	"testing"
)

func TestRound41LogURLMasksTokens(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "oidc logout keeps order and raw slash",
			in:   "https://idp.example/logout?id_token_hint=" + jwt + "&post_logout_redirect_uri=/x",
			want: "https://idp.example/logout?id_token_hint=…&post_logout_redirect_uri=/x",
		},
		{
			name: "userinfo stripped",
			in:   "https://user:p%40ss@host.example/p?page=2",
			want: "https://host.example/p?page=2",
		},
		{
			name: "token in userinfo stripped",
			in:   "https://ghp_1234567890abcdefghijklmnopqrstuvwx1234@host.example/repo.git",
			want: "https://host.example/repo.git",
		},
		{
			name: "fragment stripped",
			in:   "https://app.example/cb?page=1#access_token=" + jwt,
			want: "https://app.example/cb?page=1",
		},
		{
			name: "semicolon delimiter preserved",
			in:   "https://app.example/s?a=1;code=oauth_code_123;b=2",
			want: "https://app.example/s?a=1;code=…;b=2",
		},
		{
			name: "malformed percent escape masked fail-closed",
			in:   "https://app.example/s?x=%ZZsecret&page=3",
			want: "https://app.example/s?x=…&page=3",
		},
		{
			name: "token-shaped value under benign param name",
			in:   "https://app.example/s?state=0123456789abcdef01234567&slug=international_electronics_store",
			want: "https://app.example/s?state=…&slug=international_electronics_store",
		},
		{
			name: "content-hashed script filename in path preserved",
			in:   "https://cdn.example/assets/index-0123456789abcdef0123456789abcdef.js",
			want: "https://cdn.example/assets/index-0123456789abcdef0123456789abcdef.js",
		},
		{
			name: "about blank preserved without query or fragment",
			in:   "about:blank?token=secret#frag",
			want: "about:blank",
		},
		{
			name: "blob nested url scrubbed",
			in:   "blob:https://user:secret@app.example/1234-5678?api_key=abc",
			want: "blob:https://app.example/1234-5678?api_key=…",
		},
		{
			name: "missing scheme unparsable",
			in:   "host.example/path?token=secret",
			want: "(unparsable)",
		},
		{
			name: "empty stays empty",
			in:   "",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LogURL(tc.in)
			if got != tc.want {
				t.Fatalf("LogURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for _, leak := range []string{"eyJhbGci", "p%40ss", "ghp_", "oauth_code_123", "secret"} {
				if strings.Contains(got, leak) {
					t.Fatalf("LogURL(%q) leaked %q in %q", tc.in, leak, got)
				}
			}
		})
	}

	gotLabels := LogBundleLabels([]string{
		"a1b2c3d4e5f6",
		"https://cdn.example/app.js?token=supersecret",
	})
	wantLabels := []string{
		"a1b2c3d4e5f6",
		"https://cdn.example/app.js?token=…",
	}
	if !reflect.DeepEqual(gotLabels, wantLabels) {
		t.Fatalf("LogBundleLabels = %#v, want %#v", gotLabels, wantLabels)
	}
}
