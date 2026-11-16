package netsafe

import (
	"net/http"
	"strings"
	"testing"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestProxyFromOrder(t *testing.T) {
	all := map[string]string{"JSHARVEST_PROXY": "http://j:1", "HTTPS_PROXY": "http://hs:2", "https_proxy": "http://hl:3", "HTTP_PROXY": "http://p:4", "http_proxy": "http://pl:5"}
	for _, tc := range []struct {
		flag string
		env  map[string]string
		want string
		src  string
	}{
		{"http://f:9", all, "http://f:9", "-proxy"},
		{"", all, "http://j:1", "JSHARVEST_PROXY"},
		{"", map[string]string{"HTTPS_PROXY": "http://hs:2", "http_proxy": "http://pl:5"}, "http://hs:2", "HTTPS_PROXY"},
		{"", map[string]string{"https_proxy": "http://hl:3", "HTTP_PROXY": "http://p:4"}, "http://hl:3", "https_proxy"},
		{"", map[string]string{"HTTP_PROXY": "http://p:4", "http_proxy": "http://pl:5"}, "http://p:4", "HTTP_PROXY"},
		{"", map[string]string{"http_proxy": "127.0.0.1:8080"}, "http://127.0.0.1:8080", "http_proxy"},
		{"none", all, "", "-proxy"},
		{"", map[string]string{"JSHARVEST_PROXY": "none", "HTTPS_PROXY": "http://hs:2"}, "", "JSHARVEST_PROXY"},
		{"", nil, "", ""},
	} {
		u, src, err := ProxyFrom(tc.flag, envOf(tc.env))
		got := ""
		if u != nil {
			got = u.String()
		}
		if err != nil || got != tc.want || src != tc.src {
			t.Errorf("%+v: %q %q %v", tc, got, src, err)
		}
	}
	if _, _, err := ProxyFrom("ftp://x:1", nil); err == nil {
		t.Error("ftp accepted")
	}
	_, _, err := ProxyFrom("http://", nil)
	if err == nil {
		t.Error("no host accepted")
	}
	if _, _, err := ProxyFrom("http://u:secret@", nil); err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("error leaks the credential: %v", err)
	}
}

func TestProxyLineNoCredential(t *testing.T) {
	u, _, _ := ProxyFrom("http://user:s3cret@127.0.0.1:8080", nil)
	line := ProxyLine(u)
	if line != "proxy: http://127.0.0.1:8080" || strings.Contains(line, "s3cret") || strings.Contains(line, "user") {
		t.Fatalf("%q", line)
	}
	if u.User == nil {
		t.Fatal("the URL's own credential was dropped: the proxy needs it")
	}
	if Redact("http://a:b@h:1") != "http://h:1" {
		t.Fatal(Redact("http://a:b@h:1"))
	}
}

func TestProxyFuncHostRules(t *testing.T) {
	u, _, _ := ProxyFrom("http://127.0.0.1:8899", nil)
	rules, _ := ParseHostRules("MAP app.jsh.test 127.0.0.1")
	f := ProxyFunc(u, rules)
	get := func(raw string) *http.Request { r, _ := http.NewRequest("GET", raw, nil); return r }
	if p, _ := f(get("http://app.jsh.test:8770/")); p != nil {
		t.Error("a host in the rules went through the proxy")
	}
	if p, _ := f(get("https://app.jsh.test/")); p != nil {
		t.Error("a host in the rules (no port) went through the proxy")
	}
	if p, _ := f(get("http://x.jsh.test:8770/")); p == nil || p.Host != "127.0.0.1:8899" {
		t.Error("a host not in the rules did not go through the proxy")
	}
	if ProxyFunc(nil, rules) != nil {
		t.Error("no proxy, a func")
	}
}

func TestProxyFuncLoopbackDirect(t *testing.T) {
	u, _, _ := ProxyFrom("http://127.0.0.1:8899", nil)
	f := ProxyFunc(u, nil)
	for _, h := range []string{"localhost", "LOCALHOST.", "a.localhost", "127.0.0.1", "127.1", "2130706433", "[::1]", "[::ffff:127.0.0.1]"} {
		r, _ := http.NewRequest("GET", "http://"+h+":8770/", nil)
		if p, _ := f(r); p != nil {
			t.Errorf("%s went through the proxy", h)
		}
	}
	for _, h := range []string{"example.com", "10.0.0.5", "localhostx.com", "x.jsh.test"} {
		r, _ := http.NewRequest("GET", "http://"+h+"/", nil)
		if p, _ := f(r); p == nil {
			t.Errorf("%s did not go through the proxy", h)
		}
	}
}
