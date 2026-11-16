package endpoints

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

// Passive telemetry: what the servers run and the CORS / TLS configuration
// worth a look, read from the answers alone; third parties' are not the target's.
func TestInfra(t *testing.T) {
	dir := t.TempDir()
	lines := `{"url":"https://site.example.com:3016/","response":{"status":200,"headers":{"x-powered-by":"Express","content-type":"text/html"}}}
{"url":"https://site.example.com:3016/favicon.ico","response":{"status":404,"headers":{"access-control-allow-origin":"*","access-control-allow-credentials":"true"},"body":"{\"statusCode\":404,\"message\":\"Cannot GET /favicon.ico\",\"error\":\"Not Found\"}"}}
{"url":"https://api.site.example.com/x","headers":{"origin":"https://app.site.example.com"},"response":{"status":200,"headers":{"access-control-allow-origin":"https://app.site.example.com","access-control-allow-credentials":"true","server":"nginx/1.18.0 (Ubuntu)"},"tls_incomplete_chain":true}}
{"url":"https://api.site.example.com/y","headers":{"origin":"https://api.site.example.com"},"response":{"status":200,"headers":{"access-control-allow-origin":"https://api.site.example.com","access-control-allow-credentials":"true"}}}
{"url":"https://cdn.other.com/z","response":{"status":404,"headers":{"server":"AmazonS3","access-control-allow-origin":"*","access-control-allow-credentials":"true"}}}
{"url":"https://site.example.com:3016/nothing","response":{"status":404,"headers":{"content-type":"text/html"},"body":"<pre>Cannot GET /nothing</pre>"}}
{"url":"https://site.example.com:3016/failed"}
`
	if err := os.WriteFile(filepath.Join(dir, "requests.jsonl"), []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	in := func(h string) bool {
		return h == "site.example.com" || strings.HasSuffix(h, ".site.example.com")
	}
	hints, notes := Infra(dir, in)
	var names []string
	for _, h := range hints {
		names = append(names, h.Name)
	}
	if !slices.Equal(names, []string{"Express", "NestJS", "nginx/1.18.0 (Ubuntu)"}) {
		t.Errorf("hints %v", names)
	}
	kinds := map[string][]string{}
	for _, n := range notes {
		kinds[n.Kind] = n.Origins
	}
	want := map[string][]string{
		"cors_wildcard_with_credentials": {"https://site.example.com:3016"},
		"cors_credentials_for_origin":    {"https://api.site.example.com"},
		"tls_incomplete_chain":           {"https://api.site.example.com"},
	}
	if len(kinds) != len(want) {
		t.Errorf("notes %v", kinds)
	}
	for k, o := range want {
		if !slices.Equal(kinds[k], o) {
			t.Errorf("%s: %v, want %v", k, kinds[k], o)
		}
	}
}

// PIP-01: today's line, a document's, filled from the archive's code of
// the same path; not when the methods differ, nor two methods for one with
// none; bases untouched.
func TestEnrichFromArchive(t *testing.T) {
	eps := []Endpoint{
		{Method: "POST", Path: "/api/v1/conversations/{}/messages/send", Kind: "doc", Confidence: "doc", Bases: []string{"https://hub.x"}},
		{Method: "POST", Path: "/api/v1/conversations/{}/messages/{}/rating", Kind: "doc", Confidence: "doc"},
		{Path: "/api/v1/items", Kind: "string", Confidence: "string"},
		{Path: "/api/v1/two", Kind: "string", Confidence: "string"},
		{Method: "GET", Host: "other.x", Path: "/api/v1/conversations/{}/messages/send", Confidence: "code"},
	}
	archived := []Endpoint{
		{Method: "POST", Path: "{}/api/v1/conversations/{}/messages/send", Body: []string{"prompt", "clientMsgId"}, Confidence: "code",
			Params: []jsapi.ParamSpec{{Name: "prompt", In: "body", Type: "string"}}},
		{Method: "PUT", Path: "{}/api/v1/conversations/{}/messages/{}/rating", Body: []string{"rating"}, Confidence: "code"},
		{Method: "GET", Path: "/api/v1/items", Query: []string{"page"}, Confidence: "code"},
		{Method: "GET", Path: "/api/v1/two", Confidence: "code"},
		{Method: "DELETE", Path: "/api/v1/two", Confidence: "code"},
	}
	got := EnrichFromArchive(eps, archived)
	if e := got[0]; !slices.Equal(e.Body, []string{"clientMsgId", "prompt"}) || e.Confidence != "code" || !slices.Equal(e.Enriched, []string{"archive"}) ||
		len(e.Params) != 1 || !slices.Equal(e.Bases, []string{"https://hub.x"}) {
		t.Errorf("send: %+v", e)
	}
	if e := got[1]; e.Body != nil || e.Enriched != nil {
		t.Errorf("rating (POST vs PUT) filled: %+v", e)
	}
	if e := got[2]; e.Method != "GET" || !slices.Equal(e.Query, []string{"page"}) || e.Confidence != "code" {
		t.Errorf("items: %+v", e)
	}
	if e := got[3]; e.Method != "" || e.Enriched != nil {
		t.Errorf("two methods for one line: %+v", e)
	}
	if e := got[4]; e.Body != nil {
		t.Errorf("another method: %+v", e)
	}
}

// PIP-03: a description with no servers is its origin's; the code's call of
// the same URL on a port of its own is the same line (canonHost).
func TestOpenAPIWithoutServers(t *testing.T) {
	spec := Script{SHA256: "s", URLs: []string{"http://api.jsh.test:8770/api-json"}, Result: jsapi.Result{Endpoints: []jsapi.Endpoint{
		{Method: "GET", URL: "/v1/items", Kind: "openapi", Client: true},
	}}}
	code := Script{SHA256: "c", URLs: []string{"http://app.jsh.test:8770/app.js"}, Result: jsapi.Result{Endpoints: []jsapi.Endpoint{
		{Method: "GET", URL: "http://api.jsh.test:8770/v1/items", Kind: "fetch"},
	}}}
	oidc := Script{SHA256: "o", URLs: []string{"http://app.jsh.test:8770/.well-known/openid-configuration"},
		Result: jsapi.ExtractOIDC([]byte(`{"issuer":"http://app.jsh.test:8770","token_endpoint":"http://app.jsh.test:8770/oauth/token","jwks_uri":"http://app.jsh.test:8770/jwks"}`))}
	got := Build([]Script{spec, code, oidc}, nil, func(string) bool { return true })
	var items []Endpoint
	for _, e := range got {
		if e.Path == "/v1/items" {
			items = append(items, e)
		}
	}
	if len(items) != 1 || !slices.Equal(items[0].Bases, []string{"http://api.jsh.test:8770"}) || items[0].Confidence != "spec" || len(items[0].Static) != 2 {
		t.Errorf("items: %+v", items)
	}
	found := false
	for _, e := range got {
		if e.Method == "POST" && e.Host == "app.jsh.test:8770" && e.Path == "/oauth/token" && slices.Contains(e.Body, "grant_type") {
			found = true
		}
	}
	if !found {
		t.Errorf("oidc token endpoint: %+v", got)
	}
	if canonHost("API.x:443") != "api.x" || canonHost("api.x:8443") != "api.x:8443" {
		t.Error("canonHost")
	}
}
