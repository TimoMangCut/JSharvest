package traffic

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestRound41AppendOpenIsolatesTruncatedLine(t *testing.T) {
	dir := t.TempDir()
	reqPath := filepath.Join(dir, "requests.jsonl")

	// 1. Existing 0-byte file: Create/AppendOpen must NOT write a leading '\n'.
	if err := os.WriteFile(reqPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w1, err := Create(dir, "r1", nil)
	if err != nil {
		t.Fatal(err)
	}
	w1.Write(Entry{Method: "GET", URL: "https://app.example/one", Outcome: "ok"})
	if err := w1.Close(); err != nil {
		t.Fatal(err)
	}
	b0, err := os.ReadFile(reqPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(b0) == 0 || b0[0] == '\n' {
		t.Fatalf("0-byte file got unexpected leading newline: %q", string(b0))
	}

	// 2. Append a truncated half-JSON line (simulating SIGKILL mid-write without '\n').
	raw, err := os.OpenFile(reqPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = raw.WriteString(`{"run":"r2","id":1,"method":"POST","url":"https://app.example/crashed`)
	_ = raw.Close()

	// 3. Next run uses Create -> AppendOpen: inserts '\n' before writing r3's first entry.
	w3, err := Create(dir, "r3", nil)
	if err != nil {
		t.Fatal(err)
	}
	w3.Write(Entry{Method: "GET", URL: "https://app.example/three", Outcome: "ok"})
	if err := w3.Close(); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(reqPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(after), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 physical lines (r1, truncated r2, clean r3), got %d:\n%s", len(lines), string(after))
	}
	var e1, e3 Entry
	if err := json.Unmarshal([]byte(lines[0]), &e1); err != nil || e1.URL != "https://app.example/one" {
		t.Fatalf("line 0 corrupted: %v (%q)", err, lines[0])
	}
	if err := json.Unmarshal([]byte(lines[2]), &e3); err != nil || e3.Run != "r3" || e3.URL != "https://app.example/three" {
		t.Fatalf("line 2 was not isolated onto its own clean JSON line: %v (%q)", err, lines[2])
	}
}

func TestRound41RedactorURLPercentEncodedAndTokenUserinfo(t *testing.T) {
	r := NewRedactor()

	u1 := r.URL("https://admin:p%40ss%3A1@example.test/p")
	if strings.Contains(u1, "p%40ss") || strings.Contains(u1, "p@ss") {
		t.Fatalf("Redactor.URL leaked percent-encoded password: %q", u1)
	}
	if !strings.HasPrefix(u1, "https://admin:REDACTED_") {
		t.Fatalf("Redactor.URL unexpected format for user:pass: %q", u1)
	}

	u2 := r.URL("https://custom_pat_token_12345@example.test/p")
	if strings.Contains(u2, "custom_pat_token_12345") {
		t.Fatalf("Redactor.URL leaked single-token userinfo: %q", u2)
	}

	u3 := r.URL(`302 -> https://admin:p%40ss@idp.example.test/cb?code=secret_code_9`)
	if strings.Contains(u3, "p%40ss") || strings.Contains(u3, "secret_code_9") {
		t.Fatalf("Redactor.URL leaked embedded URL secret in reason text: %q", u3)
	}

	// Ensure /@user path is NOT treated as userinfo.
	u4 := r.URL("https://example.test/@alice/profile")
	if u4 != "https://example.test/@alice/profile" {
		t.Fatalf("Redactor.URL corrupted @path segment: %q", u4)
	}

	l1 := LogURL("https://example.test/cb?next=https%3A%2F%2Fuser%3Ap%2540ss%40internal.example.test%2F")
	if strings.Contains(l1, "user") || strings.Contains(l1, "p%40ss") || strings.Contains(l1, "p%2540ss") {
		t.Fatalf("LogURL leaked nested userinfo in query param: %q", l1)
	}

	// Standard base64 token starting with '/' and ending with '=' padding must be masked, while '/assets/main.js' stays.
	l2 := LogURL("https://example.test/cb?sig=/9j/4AAQSkZJRgABAQEAYABgAA==&asset=/assets/app_bundle_1234567890.js")
	if strings.Contains(l2, "4AAQSkZJRg") {
		t.Fatalf("LogURL missed /-prefixed padded base64 token: %q", l2)
	}
	if !strings.Contains(l2, "asset=/assets/app_bundle_1234567890.js") {
		t.Fatalf("LogURL masked normal asset path: %q", l2)
	}
}
