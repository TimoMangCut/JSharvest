package endpoints

import (
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

func inExample(h string) bool { return h == "example.com" || strings.HasSuffix(h, ".example.com") }

// TRU-02: a base the path starts with, or shares a gateway's first
// segment with, is the one; a spec's paths go under its own base.
func TestBaseForExclusive(t *testing.T) {
	bases := []string{"https://api.example.com/hub/openapi", "https://api.example.com", "https://api.example.com/hub/auth",
		"https://api.example.com/hub/console/v1", "/hub/auth", "/console-api"}
	for _, c := range []struct {
		path, kind string
		want       []string
	}{
		{"/account/v1/tenants", "openapi", []string{"https://api.example.com/hub/openapi"}},
		{"/hub/console/v1/apps", "wrapper", []string{"https://api.example.com"}},
		{"/hub/api/account/v1/me", "wrapper", []string{"https://api.example.com"}},
		{"/v1/things", "client", []string{"https://api.example.com", "https://api.example.com/hub/auth", "https://api.example.com/hub/openapi", "https://api.example.com/hub/console/v1", "/hub/auth", "/console-api"}},
	} {
		if got := baseFor(bases, c.path, c.kind, inExample); !slices.Equal(got, c.want) {
			t.Errorf("%s (%s): %v", c.path, c.kind, got)
		}
	}
	// /api is every API's first segment: it names no gateway.
	if got := baseFor([]string{"https://a.example.com/api/v2", "https://b.example.com/x"}, "/api/v1/me", "client", inExample); len(got) != 2 {
		t.Errorf("a generic first segment: %v", got)
	}
}

// TRU-02: the setting a factory is given, through any export of its or a
// call in its script, is the base of all its methods'.
func TestFactorySettings(t *testing.T) {
	ep := func(m, u string) jsapi.Endpoint {
		return jsapi.Endpoint{Method: m, URL: u, Kind: "client", Client: true}
	}
	scripts := []Script{
		{SHA256: "cfg", URLs: []string{"https://accounts.example.com/"}, Result: jsapi.Result{
			Bases:    []string{"https://api.example.com", "https://api.example.com/hub/auth", "https://api.example.com/hub/api/account"},
			Settings: []jsapi.Header{{Name: "AUTH_API_URL", Value: "https://api.example.com/hub/auth"}, {Name: "CLIENT_API_URL", Value: "https://api.example.com/hub/api/account"}}}},
		{SHA256: "mod", URLs: []string{"https://accounts.example.com/c1.js"}, Result: jsapi.Result{
			Endpoints: []jsapi.Endpoint{ep("POST", "/v1/auth/mfa/verify"), ep("POST", "/v1/auth/mfa/totp/enroll"), ep("POST", "/v1/oauth/consent/accept")},
			Exports:   []jsapi.Export{{Module: "21666", Name: "u", Method: "POST", URL: "/v1/auth/mfa/verify", QueryArg: -1, BodyArg: 1, BaseArg: 0, Factory: "f1"}},
			Factories: []jsapi.Factory{{ID: "f1", Endpoints: []string{"POST /v1/auth/mfa/verify", "POST /v1/auth/mfa/totp/enroll", "POST /v1/oauth/consent/accept"}}}}},
		{SHA256: "use", URLs: []string{"https://accounts.example.com/c2.js"}, Result: jsapi.Result{
			Endpoints: []jsapi.Endpoint{ep("POST", "/v1/invite-links/preview")},
			Imports:   []jsapi.Import{{Module: "21666", Name: "u", Args: []jsapi.ImportArg{{Setting: "AUTH_API_URL"}, {Keys: []string{"code"}}}}},
			Factories: []jsapi.Factory{{ID: "f1", Endpoints: []string{"POST /v1/invite-links/preview"}, Settings: []string{"CLIENT_API_URL"}}}}},
	}
	got := map[string]Endpoint{}
	for _, e := range Build(scripts, nil, inExample) {
		got[e.Method+" "+e.Path] = e
	}
	for k, want := range map[string]string{"POST /v1/auth/mfa/verify": "https://api.example.com/hub/auth", "POST /v1/auth/mfa/totp/enroll": "https://api.example.com/hub/auth",
		"POST /v1/oauth/consent/accept": "https://api.example.com/hub/auth", "POST /v1/invite-links/preview": "https://api.example.com/hub/api/account"} {
		if b := got[k].Bases; !slices.Equal(b, []string{want}) {
			t.Errorf("%s: bases %v", k, b)
		}
	}
	if b := got["POST /v1/auth/mfa/verify"].Body; !slices.Equal(b, []string{"code"}) {
		t.Errorf("the caller's body: %v", b)
	}
}

// TRU-03/04/05: what a document names folds into the code's endpoint and
// into the whole path it gives elsewhere; a method-less join of a path
// into the call to it; a page the code goes to is no endpoint; an unknown
// host is an unknown base.
func TestCatalogMerges(t *testing.T) {
	doc := func(m, u string) jsapi.Endpoint {
		return jsapi.Endpoint{Method: m, URL: u, Kind: "doc", Client: !strings.Contains(u, "://")}
	}
	scripts := []Script{
		{SHA256: "docs", URLs: []string{"https://dev.example.com/a.js"}, Result: jsapi.Result{Endpoints: []jsapi.Endpoint{
			doc("POST", "/v1/public/feed/items/batch"), doc("POST", "https://api.partner.net/open/catalog/v1/public/feed/items/batch"),
			doc("GET", "/v1/apps"), doc("POST", "/{}/shortlinks"),
		}}},
		{SHA256: "code", URLs: []string{"https://dev.example.com/b.js"}, Result: jsapi.Result{Endpoints: []jsapi.Endpoint{
			{Method: "GET", URL: "{}/v1/apps", Kind: "wrapper", Client: true},
			{URL: "/auth/exchange", Kind: "wrapper"}, {Method: "POST", URL: "{}/auth/exchange", Kind: "wrapper", Client: true},
			{Method: "GET", URL: "https://chatgpt.com/", Kind: "navigation"}, {Method: "GET", URL: "/home", Kind: "navigation"},
			{Method: "GET", URL: "/api/export/pdf", Kind: "navigation"}, {Method: "GET", URL: "https://{}/settings/x", Kind: "navigation"},
			{Method: "GET", URL: "https://{}/api/v1/x", Kind: "fetch"},
		}}},
	}
	var keys []string
	byKey := map[string]Endpoint{}
	for _, e := range Build(scripts, nil, inExample) {
		k := e.Method + " " + e.Host + e.Path
		keys = append(keys, k)
		byKey[k] = e
	}
	want := []string{"GET /api/export/pdf", "POST /{}/shortlinks", "POST api.partner.net/open/catalog/v1/public/feed/items/batch",
		"GET {}/api/v1/x", "POST {}/auth/exchange", "GET {}/v1/apps"}
	slices.Sort(keys)
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Errorf("catalog %v, want %v", keys, want)
	}
	if e := byKey["GET {}/v1/apps"]; len(e.Static) != 2 || e.Kind != "wrapper" {
		t.Errorf("the document's source folded into the call: %+v", e)
	}
	if e := byKey["POST api.partner.net/open/catalog/v1/public/feed/items/batch"]; len(e.Static) != 2 || !e.ThirdParty {
		t.Errorf("the abbreviated path folded into the whole one: %+v", e)
	}
}

// FIN-01/06: an example's call folds into the template a document names,
// with its query; the base a document exports is the endpoint's; a
// relative base the path starts with is the page's own origin.
func TestDocTemplatesAndBases(t *testing.T) {
	doc := func(m, u, base string, q []string) jsapi.Endpoint {
		return jsapi.Endpoint{Method: m, URL: u, Kind: "doc", Client: true, Base: base, Query: q}
	}
	scripts := []Script{
		{SHA256: "a", URLs: []string{"https://dev.example.com/a.js"}, Result: jsapi.Result{Endpoints: []jsapi.Endpoint{
			doc("GET", "/cms/v1/content_types/{}/entries/{}", "", nil), doc("GET", "/cms/v1/content_types/page/entries/{}", "", []string{"include"}),
			doc("GET", "/{}/shortlinks/deep-link", "", nil),
		}}},
		{SHA256: "b", URLs: []string{"https://dev.example.com/b.js"}, Result: jsapi.Result{Endpoints: []jsapi.Endpoint{
			doc("GET", "/{}/shortlinks/deep-link", "https://api.example.com/slink/api/v1", []string{"short_url"}),
		}}},
		{SHA256: "c", URLs: []string{"https://www.example.com/c.js"}, Result: jsapi.Result{Bases: []string{"/console-api", "https://api.example.com/hub"},
			Endpoints: []jsapi.Endpoint{{Method: "GET", URL: "/console-api/v1/apps", Kind: "client", Client: true}}}},
	}
	got := map[string]Endpoint{}
	for _, e := range Build(scripts, nil, inExample) {
		got[e.Method+" "+e.Path] = e
	}
	if _, ok := got["GET /cms/v1/content_types/page/entries/{}"]; ok {
		t.Error("the example's call beside its template")
	}
	if e := got["GET /cms/v1/content_types/{}/entries/{}"]; !slices.Equal(e.Query, []string{"include"}) {
		t.Errorf("the template: %+v", e)
	}
	if e := got["GET /{}/shortlinks/deep-link"]; !slices.Equal(e.Bases, []string{"https://api.example.com/slink/api/v1"}) || !slices.Equal(e.Query, []string{"short_url"}) {
		t.Errorf("the exported base: %+v", e)
	}
	if e := got["GET /console-api/v1/apps"]; len(e.Bases) != 0 {
		t.Errorf("a proxy of the page's origin: bases %v", e.Bases)
	}
}

// FIN-21C (2): a document's $SLINK_HOST takes the value another script of
// the same origin exports, and none when the origin's scripts disagree.
func TestDocVarsAcrossScripts(t *testing.T) {
	dev := "https://developer.example.org/assets/"
	use := Script{SHA256: "a", URLs: []string{dev + "delete.js"}, Result: jsapi.Result{Endpoints: []jsapi.Endpoint{
		{Method: "DELETE", URL: "/{}/shortlinks/{}", Kind: "doc", Client: true, Base: "$SLINK_HOST"}}}}
	set := Script{SHA256: "b", URLs: []string{dev + "auth.js"}, Result: jsapi.Result{DocVars: []jsapi.Header{
		{Name: "SLINK_HOST", Value: "https://api.example.org/slink/api/v1"}}}}
	other := Script{SHA256: "c", URLs: []string{"https://else.example.org/x.js"}, Result: jsapi.Result{DocVars: []jsapi.Header{
		{Name: "SLINK_HOST", Value: "https://wrong.example.org"}}}}
	got := Build([]Script{use, set, other}, nil, nil)
	if len(got) != 1 || !slices.Equal(got[0].Bases, []string{"https://api.example.org/slink/api/v1"}) {
		t.Errorf("got %+v", got)
	}
	clash := Script{SHA256: "d", URLs: []string{dev + "other.js"}, Result: jsapi.Result{DocVars: []jsapi.Header{
		{Name: "SLINK_HOST", Value: "https://api2.example.org"}}}}
	if got := Build([]Script{use, set, clash}, nil, nil); len(got) != 1 || len(got[0].Bases) != 0 {
		t.Errorf("two values: %+v", got)
	}
}
