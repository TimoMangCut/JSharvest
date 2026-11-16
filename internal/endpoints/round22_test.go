package endpoints

import (
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

// QAL-05: lines that go to one URL once their bases are known are one, the
// one under the most specific base kept, with what each knows; a relative
// call with no base has its pages' origin, its bases none.
func TestCanonicalMergeAndOrigin(t *testing.T) {
	inScope := func(h string) bool { return h == "example.biz" || strings.HasSuffix(h, ".example.biz") }
	app := Script{SHA256: "a", URLs: []string{"https://example.biz/_vite/index.js"}, Result: jsapi.Result{
		Bases: []string{"https://api.example.biz/hub"},
		Endpoints: []jsapi.Endpoint{
			{Method: "GET", URL: "/api/account/v1/me/tenants", Kind: "client", Client: true},
			{Method: "GET", URL: "/console-api/v1/apps/by-slug/{}", Kind: "client"},
		}}}
	acc := Script{SHA256: "b", URLs: []string{"https://accounts.example.biz/_next/a.js"}, Result: jsapi.Result{
		Bases: []string{"https://api.example.biz/hub/api/account"},
		Endpoints: []jsapi.Endpoint{
			{Method: "GET", URL: "/v1/me/tenants", Kind: "client", Client: true, Query: []string{"page_size", "status"},
				Params: []jsapi.ParamSpec{{Name: "page_size", In: "query", Type: "number"}}},
			{Method: "GET", URL: "/hub/auth", Kind: "fetch"},
		}}}
	cdn := Script{SHA256: "c", URLs: []string{"https://cdn.example.biz/sdk.js"}, Result: jsapi.Result{
		Endpoints: []jsapi.Endpoint{{Method: "POST", URL: "/collect", Kind: "fetch"}}}}
	got := Build([]Script{app, acc, cdn}, nil, inScope)
	var tenants []Endpoint
	byPath := map[string]Endpoint{}
	for _, e := range got {
		byPath[e.Path] = e
		if e.Method == "GET" && (e.Path == "/v1/me/tenants" || e.Path == "/api/account/v1/me/tenants") {
			tenants = append(tenants, e)
		}
	}
	if len(tenants) != 1 || tenants[0].Path != "/v1/me/tenants" || !slices.Equal(tenants[0].Query, []string{"page_size", "status"}) ||
		len(tenants[0].Static) != 2 || len(tenants[0].Params) != 1 {
		t.Errorf("tenants: %+v", tenants)
	}
	if e := byPath["/hub/auth"]; e.Origin != "https://accounts.example.biz" || e.Bases != nil {
		t.Errorf("origin: %+v", e)
	}
	if e := byPath["/console-api/v1/apps/by-slug/{}"]; e.Origin != "https://example.biz" {
		t.Errorf("origin: %+v", e)
	}
	if e := byPath["/collect"]; e.Origin != "" {
		t.Errorf("a CDN's script gives no origin: %+v", e)
	}
	for _, e := range got {
		if e.Confidence != "code" {
			t.Errorf("%s: confidence %q", e.Path, e.Confidence)
		}
	}
}

// QAL-02: a collector's URL takes no base and is a third party's; a
// configuration file under a URL the caller gives is dropped.
func TestCollectorsAndConfigFiles(t *testing.T) {
	sdk := Script{SHA256: "a", URLs: []string{"https://cdn.example.biz/sdk.js"}, Result: jsapi.Result{
		Bases: []string{"https://api.example.biz/growth/api/v1.0"},
		Endpoints: []jsapi.Endpoint{
			{Method: "POST", URL: "{}/customer-profiles", Kind: "wrapper"},
			{Method: "POST", URL: "{}/com.snowplowanalytics.snowplow/tp2", Kind: "wrapper", NoInheritBase: true, Collector: true},
			{Method: "GET", URL: "{}/app-config.json", Kind: "fetch", NoInheritBase: true},
		}}}
	got := map[string]Endpoint{}
	for _, e := range Build([]Script{sdk}, nil, nil) {
		got[e.Path] = e
	}
	if e := got["{}/customer-profiles"]; !slices.Equal(e.Bases, []string{"https://api.example.biz/growth/api/v1.0"}) {
		t.Errorf("client: %+v", e)
	}
	if e := got["{}/com.snowplowanalytics.snowplow/tp2"]; e.Bases != nil || !e.ThirdParty {
		t.Errorf("collector: %+v", e)
	}
	if _, ok := got["{}/app-config.json"]; ok {
		t.Errorf("config file kept")
	}
}

// QAL-04: a document's placeholder host is the portal's setting of that
// name; its variable set to a development host, production's; a lone path
// of the document, the base its siblings share.
func TestDocHosts(t *testing.T) {
	dev := "https://developer.example.biz/assets/"
	env := Script{SHA256: "e", URLs: []string{dev + "env-config.js"}, Result: jsapi.Result{Settings: []jsapi.Header{
		{Name: "VITE_OAUTH_TOKEN_BASE_URL", Value: "https://api.example.biz/hub/auth"},
		{Name: "VITE_OAUTH_AUTH_BASE", Value: "https://api.example.biz/hub/auth"},
		{Name: "VITE_OPENAPI_BASE_URL", Value: "https://api.example.biz/hub/openapi"},
		{Name: "VITE_CONSOLE_API_BASE_URL", Value: "https://api.example.biz/hub/console/v1"},
	}}}
	docs := Script{SHA256: "d", URLs: []string{dev + "service-token.js"}, Result: jsapi.Result{
		DocDev: []jsapi.Header{{Name: "CMS_HOST", Value: "https://api.ecom-dev.example.services"}},
		Endpoints: []jsapi.Endpoint{
			{Method: "POST", URL: "/v1/oauth/token", Kind: "doc", Client: true, Base: "<auth-host>"},
			{Method: "GET", URL: "/developer/v1/apps", Kind: "doc", Client: true, Base: "<open-platform-host>"},
			{Method: "GET", URL: "/cms/delivery/v1/entries/{}", Kind: "doc", Client: true, Base: "$CMS_HOST"},
			{Method: "GET", URL: "/cms/delivery/health", Kind: "doc", Client: true, Base: "$CMS_HOST"},
			{Method: "GET", URL: "/cms/delivery/v1/categories", Kind: "doc", Client: true},
		}}}
	table := Script{SHA256: "t", URLs: []string{dev + "overview.js"}, Result: jsapi.Result{DocProd: []string{"https://api.ecom.example.services"}}}
	got := map[string]Endpoint{}
	for _, e := range Build([]Script{env, docs, table}, nil, nil) {
		got[e.Path] = e
	}
	for p, want := range map[string]string{
		"/v1/oauth/token":             "https://api.example.biz/hub/auth",
		"/developer/v1/apps":          "https://api.example.biz/hub/openapi",
		"/cms/delivery/v1/entries/{}": "https://api.ecom.example.services",
		"/cms/delivery/v1/categories": "https://api.ecom.example.services",
	} {
		if e := got[p]; !slices.Equal(e.Bases, []string{want}) || e.Confidence != "doc" {
			t.Errorf("%s: %+v, want %s", p, e, want)
		}
	}
	if settingFor("<host>", env.Settings) != "" || settingFor("<console-host>", env.Settings) != "https://api.example.biz/hub/console/v1" {
		t.Errorf("settingFor")
	}
}
