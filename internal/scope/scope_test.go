package scope

import (
	"net/url"
	"testing"
)

func TestScope(t *testing.T) {
	cases := []struct {
		target, mode, host string
		in                 bool
	}{
		{"www.example.com", "rdn", "example.com", true},
		{"www.example.com", "rdn", "api.example.com", true},
		{"www.example.com", "rdn", "cdn.other.com", false},
		{"www.example.com", "rdn", "badexample.com", false},
		{"app.example.co.uk", "rdn", "api.example.co.uk", true},
		{"app.example.co.uk", "rdn", "other.co.uk", false},
		{"www.example.com", "fqdn", "example.com", false},
		{"www.example.com", "fqdn", "a.www.example.com", true},
		{"127.0.0.1", "rdn", "127.0.0.1", true},
		{"127.0.0.1", "rdn", "localhost", false},
		{"localhost", "rdn", "LOCALHOST", true},
		{"www.jsh.test", "rdn", "jsh.test", true},
	}
	for _, c := range cases {
		in, err := New(c.target, c.mode)
		if err != nil {
			t.Fatal(err)
		}
		if got := in(c.host); got != c.in {
			t.Errorf("New(%s, %s)(%s) = %v, want %v", c.target, c.mode, c.host, got, c.in)
		}
	}
	if _, err := New("example.com", "nope"); err == nil {
		t.Error("unknown mode accepted")
	}
}

func TestTargetDir(t *testing.T) {
	for raw, want := range map[string]string{
		"https://site.example.com:3016":   "site.example.com_3016",
		"https://site.example.com":        "site.example.com",
		"https://site.example.com:443":    "site.example.com",
		"http://site.example.com:80":      "site.example.com",
		"http://site.example.com:443":     "site.example.com_443",
		"http://127.0.0.1:45123":          "127.0.0.1",
		"http://localhost:8770":           "localhost",
		"http://[::1]:8770":               "::1",
		"http://a.jsh.test:8770/x":        "a.jsh.test_8770",
		"https://Portal.Example.com:8443": "portal.example.com_8443",
	} {
		u, _ := url.Parse(raw)
		if got := TargetDir(u); got != want {
			t.Errorf("TargetDir(%s) = %q, want %q", raw, got, want)
		}
	}
	for raw, want := range map[string][2]string{
		"site.example.com_3016":         {"site.example.com_3016", "site.example.com"},
		"site.example.com:3016":         {"site.example.com_3016", "site.example.com"},
		"https://site.example.com:3016": {"site.example.com_3016", "site.example.com"},
		"site.example.com":              {"site.example.com", "site.example.com"},
		"site.example.com:443":          {"site.example.com", "site.example.com"},
		"example.com:80":                {"example.com", "example.com"},
		"site.example.com_443":          {"site.example.com_443", "site.example.com"},
		"127.0.0.1":                     {"127.0.0.1", "127.0.0.1"},
		"127.0.0.1:8770":                {"127.0.0.1", "127.0.0.1"},
		"my_host":                       {"my_host", "my_host"},
	} {
		if got := NormalizeTargetArg(raw); got != want[0] {
			t.Errorf("NormalizeTargetArg(%s) = %q, want %q", raw, got, want[0])
		}
		if got := TargetHost(raw); got != want[1] {
			t.Errorf("TargetHost(%s) = %q, want %q", raw, got, want[1])
		}
	}
}

// ENH-04a: -page-scope auto narrows subdomain targets to fqdn for pages while
// keeping apex and www.<rdn> at rdn.
func TestPageScope(t *testing.T) {
	cases := []struct {
		target, scopeMode, pageMode, host string
		want                              bool
	}{
		{"sub.example.com", "rdn", "auto", "sub.example.com", true},
		{"sub.example.com", "rdn", "auto", "cdn.sub.example.com", true},
		{"sub.example.com", "rdn", "auto", "example.com", false},
		{"sub.example.com", "rdn", "auto", "shop.example.com", false},
		{"sub.example.com", "rdn", "rdn", "example.com", true},
		{"example.com", "rdn", "auto", "sub.example.com", true},
		{"www.example.com", "rdn", "auto", "example.com", true},
		{"www.example.com", "rdn", "fqdn", "example.com", false},
		{"www.jsh.test", "rdn", "auto", "jsh.test", true},
		{"app.jsh.test", "rdn", "auto", "jsh.test", false},
	}
	for _, c := range cases {
		ps, err := PageScope(c.target, c.scopeMode, c.pageMode)
		if err != nil {
			t.Fatalf("PageScope(%s, %s, %s): %v", c.target, c.scopeMode, c.pageMode, err)
		}
		if got := ps(c.host); got != c.want {
			t.Errorf("PageScope(%s, %s, %s)(%s) = %v, want %v", c.target, c.scopeMode, c.pageMode, c.host, got, c.want)
		}
	}
	if _, err := PageScope("example.com", "rdn", "bad"); err == nil {
		t.Error("expected error for invalid page-scope mode")
	}
}
