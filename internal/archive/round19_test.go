package archive

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
)

// A path after a computed base is no other path whose end is placeholders.
func TestSamePathTail(t *testing.T) {
	cases := []struct {
		a, b string
		same bool
	}{
		{"{}/customer-profiles/webpush-reset", "/portal/console/v1/apps/{}/permission-scopes/{}/{}", false},
		{"{}/customer-profiles/{}", "/growth/api/v1.0/customer-profiles/{}", true},
		{"{}/customer-profiles/{}", "/growth/api/v1.0/customer-profiles/42", true},
		{"/api/v1/{}", "/api/v1/users", true},
		{"/{}/{}", "/a/b", false},
		{"/v1/{}", "/v1/{}", false},
	}
	for _, c := range cases {
		if got := samePath(c.a, c.b); got != c.same {
			t.Errorf("samePath(%q, %q) = %v", c.a, c.b, got)
		}
		if got := samePath(c.b, c.a); got != c.same {
			t.Errorf("samePath(%q, %q) = %v", c.b, c.a, got)
		}
	}
}

// Body kept zstd-coded, header or not.
func TestDecodeZstd(t *testing.T) {
	src := []byte("fetch('/api/v1/x');")
	enc, _ := zstd.NewWriter(nil)
	z := enc.EncodeAll(src, nil)
	for _, coding := range []string{"zstd", ""} {
		out, err := decode(coding, z, 1<<20)
		if err != nil || !bytes.Equal(out, src) {
			t.Errorf("%q: %q %v", coding, out, err)
		}
	}
}

// A host today's code names as its API's base is one the live check may
// ask, though the crawl sent it nothing.
func TestCrawlHostsBases(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "example.com", "anon")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "intel.json"), []byte(`{"bases":["https://api.example.com/v1","https://api.dev.other.net","/rel"]}`), 0o600)
	hosts, _ := CrawlHosts(root, func(h string) bool { return h == "example.com" || strings.HasSuffix(h, ".example.com") })
	if !hosts["api.example.com"] || hosts["api.dev.other.net"] || len(hosts) != 1 {
		t.Fatalf("%v", hosts)
	}
}

// FIN-06: a call with a method to a path of its own name (GET
// /conversations) is no weak template; /api/{} of a wrapper, a string or
// a path without a method is.
func TestWeak(t *testing.T) {
	for _, c := range []struct {
		e    endpoints.Endpoint
		weak bool
	}{
		{endpoints.Endpoint{Method: "GET", Path: "/conversations", Kind: "wrapper"}, false},
		{endpoints.Endpoint{Method: "DELETE", Path: "/conversations/{}", Kind: "wrapper"}, false},
		{endpoints.Endpoint{Method: "POST", Path: "/api/{}", Kind: "wrapper"}, true},
		{endpoints.Endpoint{Path: "/conversations", Kind: "wrapper"}, true},
		{endpoints.Endpoint{Method: "GET", Path: "/a/b", Kind: "string"}, true},
		{endpoints.Endpoint{Method: "GET", Path: "/users/list", Kind: "fetch"}, false},
	} {
		if got := weak(c.e); got != c.weak {
			t.Errorf("%+v: weak %v", c.e, got)
		}
	}
}
