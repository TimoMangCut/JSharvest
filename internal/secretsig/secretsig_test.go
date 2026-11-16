package secretsig

import (
	"strings"
	"testing"
)

func TestFindAllVendorSignatures(t *testing.T) {
	cases := []struct {
		name string
		in   string
		kind string
		val  string
	}{
		{
			name: "google_api_key",
			in:   "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
			kind: "google_api_key",
			val:  "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
		},
		{
			name: "aws_access_key_id_akia",
			in:   "AKIA8F92KL39QP71MX42",
			kind: "aws_access_key_id",
			val:  "AKIA8F92KL39QP71MX42",
		},
		{
			name: "aws_access_key_id_asia",
			in:   "ASIA9G83LM40RQ82NY53",
			kind: "aws_access_key_id",
			val:  "ASIA9G83LM40RQ82NY53",
		},
		{
			name: "stripe_pk_live",
			in:   "pk_live_51N1A2B3C4D5E6F7G8H9I0J1K",
			kind: "stripe_key",
			val:  "pk_live_51N1A2B3C4D5E6F7G8H9I0J1K",
		},
		{
			name: "stripe_rk_test",
			in:   "rk_test_51N1A2B3C4D5E6F7G8H9I0J1K",
			kind: "stripe_key",
			val:  "rk_test_51N1A2B3C4D5E6F7G8H9I0J1K",
		},
		{
			name: "github_classic_pat",
			in:   "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
			kind: "github_token",
			val:  "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
		},
		{
			name: "github_fine_grained_pat",
			in:   "github_pat_11ABCDEFG0a1B2c3D4e5F6_g7H8i9J0k1L2m3N4",
			kind: "github_token",
			val:  "github_pat_11ABCDEFG0a1B2c3D4e5F6_g7H8i9J0k1L2m3N4",
		},
		{
			name: "slack_bot_token",
			// Split synthetic prefixes in source to avoid false positives from repo secret scanners.
			in:   "xoxb" + "-123456789012-987654321098-a1B2c3D4e5F6g7H8",
			kind: "slack_token",
			val:  "xoxb" + "-123456789012-987654321098-a1B2c3D4e5F6g7H8",
		},
		{
			name: "sendgrid_key",
			in:   "SG" + ".a1B2c3D4e5F6g7H8i9J0k1." + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V",
			kind: "sendgrid_key",
			val:  "SG" + ".a1B2c3D4e5F6g7H8i9J0k1." + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V",
		},
		{
			name: "mapbox_public_token",
			in:   "pk.eyJ1IjoiZGVtb3VzZXIiLCJhIjoiY2x4MTIzNDUifQ.a1B2c3D4e5F6g7H8i9J0k1",
			kind: "mapbox_token",
			val:  "pk.eyJ1IjoiZGVtb3VzZXIiLCJhIjoiY2x4MTIzNDUifQ.a1B2c3D4e5F6g7H8i9J0k1",
		},
		{
			name: "sentry_dsn_regional",
			in:   "https://a1b2c3d4e5f60718293a4b5c6d7e8f90@o450123.ingest.us.sentry.io/450999",
			kind: "sentry_dsn",
			val:  "https://a1b2c3d4e5f60718293a4b5c6d7e8f90@o450123.ingest.us.sentry.io/450999",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := `{"cfg": "` + tc.in + `"}`
			got := FindAll(wrapped)
			if len(got) != 1 || got[0].Kind != tc.kind || got[0].Value != tc.val {
				t.Fatalf("FindAll(%q) = %+v, want [{Kind:%s Value:%s}]", wrapped, got, tc.kind, tc.val)
			}
		})
	}
}

func TestBoundariesAndPlaceholders(t *testing.T) {
	// Strict boundary checks: flanked tokens, wrong lengths, base64/SVG/hashes must NOT match.
	negatives := []string{
		"AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6",       // 38 chars (too short)
		"AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6QX",     // 40 chars (flanked right)
		"x-AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",    // flanked left by '-'
		"AKIA8F92KL39QP71MX4",                          // 19 chars
		"AKIA8F92KL39QP71MX429",                        // 21 chars
		"ZAKIA8F92KL39QP71MX42",                        // flanked left by [A-Z]
		"wJalrXUtnFEMIK7MDENGbPxRfiCYAKIA8F92KL39QP71MX42xyz", // embedded in base64
		"pk_live_short123",                             // too short (<16 after prefix)
		"ghp_short1234567890",                          // too short (<36 after prefix)
		"M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z",          // SVG path
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", // plain JWT, not mapbox
	}
	for _, s := range negatives {
		if got := FindAll(s); len(got) != 0 {
			t.Errorf("FindAll(%q) = %+v, want nil", s, got)
		}
	}

	// Documentation placeholders: rejected by FindAll, but STILL masked by ReplaceAllFunc!
	placeholders := []string{
		"AIzaSyDUMMY0000000000000000000000000000",
		"AIzaSyEXAMPLE1234567890abcdefghijklmnop",
		"AIzaSyAAAAAAAAA1B2C3D4E5F6G7H8I9J0K1L2M",
		"AKIAIOSFODNN7EXAMPLE",
		"AKIA0000000000000000",
		"pk_test_11111111111111111111",
		"sk_live_xxxxxxxxxxxxxxxxxxxx",
		"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"https://00000000000000000000000000000000@o1.ingest.sentry.io/1",
	}
	for _, p := range placeholders {
		if got := FindAll(p); len(got) != 0 {
			t.Errorf("placeholder %q was NOT rejected by FindAll: %+v", p, got)
		}
		masked := ReplaceAllFunc(`key="`+p+`"`, func( string) string { return "REDACTED" })
		if strings.Contains(masked, p) || masked != `key="REDACTED"` {
			t.Errorf("ReplaceAllFunc failed to mask placeholder %q: got %q", p, masked)
		}
	}
}
