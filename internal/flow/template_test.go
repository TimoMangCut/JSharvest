package flow

import "testing"

func TestSegment(t *testing.T) {
	for s, want := range map[string]string{
		"42": "{id}", "1730000000": "{id}",
		"3f2b6c1e-9a4d-4c1e-8b7a-2d9f0e1c4a5b": "{uuid}", "01HF7YAT00T6YRW5GJ5KJXW3QZ": "{uuid}",
		"5f3e9c2a7b1d4e6f": "{hash}", "507f1f77bcf86cd799439011": "{hash}",
		"aGVsbG8gV29ybGQxMjM0NTY":                  "{hash}",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig": "{token}",
		"bob@example.com":                          "{email}", "2026-11-03": "{date}",
		// Names stay.
		"api": "", "users": "", "my-first-project": "", "settings": "", "v2": "", "deadbeef": "",
		"reviews": "", "abcdefabcdefabcdef": "", "export.csv": "", "ThisIsALongCamelCaseName": "",
	} {
		if got := Segment(s); got != want {
			t.Errorf("Segment(%q) = %q, want %q", s, got, want)
		}
	}
}

func TestTemplates(t *testing.T) {
	calls := []Call{
		{"GET", "http://a/api/items/42", "app.js#open:20"},
		{"GET", "http://a/api/items/108/reviews", "app.js#open:20"},
		{"GET", "http://a/api/projects/my-first/settings", "app.js#project:7"},
		{"GET", "http://a/api/projects/demo/settings", "app.js#project:7"},
		{"GET", "http://a/api/projects/third/settings", "app.js#project:7"},
		// Two values from one frame: could be two endpoints; left alone.
		{"GET", "http://a/export/csv", "app.js#export:9"},
		{"GET", "http://a/export/pdf", "app.js#export:9"},
		// Same frame, but two segments differ: left alone.
		{"GET", "http://a/api/users/list", "app.js#nav:3"},
		{"GET", "http://a/api/orders/all", "app.js#nav:3"},
		// No frame: shape rules only.
		{"GET", "http://a/api/teams/blue", ""},
		{"GET", "http://a/api/teams/red", ""},
	}
	want := []string{
		"/api/items/{id}", "/api/items/{id}/reviews",
		"/api/projects/{param}/settings", "/api/projects/{param}/settings", "/api/projects/{param}/settings",
		"/export/csv", "/export/pdf",
		"/api/users/list", "/api/orders/all",
		"/api/teams/blue", "/api/teams/red",
	}
	got := Templates(calls)
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s: %q, want %q", calls[i].URL, got[i], want[i])
		}
	}
}
