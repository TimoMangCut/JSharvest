package flow

import (
	"net/url"
	"slices"
	"testing"
)

func TestNextActionOperationWithHeaders(t *testing.T) {
	u, _ := url.Parse("https://app.test/dashboard/settings")

	// Standard Next.js 14/15/16 App Router header (case-insensitive header key & hex normalized).
	hex40 := "40A1B2C3D4E5F60718293A4B5C6D7E8F90123456"
	want := "next-action=40a1b2c3d4e5f60718293a4b5c6d7e8f90123456"
	got := OperationWithHeaders(u, map[string]string{"Next-Action": hex40}, "text/plain;charset=UTF-8", `["inv_1"]`)
	if got != want {
		t.Fatalf("OperationWithHeaders(Next-Action) = %q, want %q", got, want)
	}
	if ops := OperationsWithHeaders(u, map[string]string{"next-action": hex40}, "text/plain;charset=UTF-8", `["inv_1"]`); !slices.Equal(ops, []string{want}) {
		t.Fatalf("OperationsWithHeaders = %v, want [%q]", ops, want)
	}

	// Progressive-enhancement form body ($ACTION_ID_<hex>, raw and URL-encoded) and multipart field name.
	hex42 := "7f0123456789abcdef0123456789abcdef01234567"
	want42 := "next-action=" + hex42
	for _, body := range []string{
		"$ACTION_ID_" + hex42 + "=&name=alice",
		"%24ACTION_ID_" + hex42 + "=&name=alice",
		"------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"$ACTION_ID_" + hex42 + "\"\r\n\r\n\r\n------WebKitFormBoundary--",
	} {
		if got := Operation(u, "application/x-www-form-urlencoded", body); got != want42 {
			t.Fatalf("Operation(form %q) = %q, want %q", body, got, want42)
		}
	}

	// Reject malformed or non-hex Next-Action headers.
	for _, bad := range []string{"", "short1234", "not-a-hex-string-at-all-0000000000000000", "40a1b2c3d4e5f60718293a4b5c6d7e8f9012345z"} {
		if got := OperationWithHeaders(u, map[string]string{"Next-Action": bad}, "text/plain", `[]`); got != "" {
			t.Fatalf("OperationWithHeaders(bad=%q) = %q, want empty", bad, got)
		}
	}

	// Next.js protocol routing headers are plain (never credentials or kept_headers).
	for _, h := range []string{"Next-Action", "next-action", "Next-Router-State-Tree", "Next-Router-Prefetch", "Next-Url", "RSC"} {
		if !PlainHeader(h) {
			t.Fatalf("PlainHeader(%q) = false, want true", h)
		}
	}
}
