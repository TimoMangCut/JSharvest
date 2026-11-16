package endpoints

import (
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

// ENH-01: when a client endpoint on sub.example.com is observed calling
// api.example.com/fe/v1/itemType, Host records "api.example.com" while
// Base stays "/fe/v1"; same-origin observed endpoints keep Host == "".
func TestCrossOriginObservedHost(t *testing.T) {
	inScope := func(h string) bool { return h == "example.com" || strings.HasSuffix(h, ".example.com") }
	cfg := Script{
		SHA256: "cfg",
		URLs:   []string{"https://sub.example.com/assets/config.js"},
		Result: jsapi.Extract([]byte(`window.__ENV__ = { API_BASE_URL: "https://api.example.com/fe/v1" };`)),
	}
	app := Script{
		SHA256: "sub",
		URLs:   []string{"https://sub.example.com/assets/index.js"},
		Result: jsapi.Extract([]byte(`
			const env = window.__RUNTIME__;
			const sr = axios.create({ baseURL: env.api });
			sr.get("/itemType");
			sr.get("/manualAvailability");
		`)),
	}
	local := Script{
		SHA256: "local",
		URLs:   []string{"https://local.example.com/assets/app.js"},
		Result: jsapi.Extract([]byte(`
			const env = window.__RUNTIME__;
			const api = axios.create({ baseURL: env.api });
			api.get("/ping");
		`)),
	}
	reqs := []Request{
		req(1, "GET", "https://api.example.com/fe/v1/itemType?country=vn"),
		req(2, "GET", "https://local.example.com/local-api/ping"),
	}
	got := Build([]Script{cfg, app, local}, reqs, inScope)
	byKey := byPath(got)

	cross := byKey["GET api.example.com/itemType"]
	if cross.Status != Both || cross.Host != "api.example.com" || cross.Base != "/fe/v1" || cross.Bases != nil {
		t.Fatalf("cross-origin both endpoint lost host or broke Base invariant: %+v (all: %+v)", cross, byKey)
	}
	unobs := byKey["GET /manualAvailability"]
	if unobs.Status != Static || unobs.Host != "" || !slices.Equal(unobs.Bases, []string{"https://api.example.com/fe/v1"}) {
		t.Fatalf("unobserved cross-origin static endpoint: %+v", unobs)
	}
	same := byKey["GET /ping"]
	if same.Status != Both || same.Host != "" || same.Base != "/local-api" || same.Bases != nil {
		t.Fatalf("same-origin both endpoint must keep Host empty (Invariant #16): %+v", same)
	}
}

// ENH-10 (Vế B): when same-origin client endpoints ({}/active-workflows) have
// no static in-scope base (only an out-of-scope telemetry URL), a confirmed
// sibling request (/rest/settings) propagates https://<origin>/rest to them.
func TestObservedClientBasePropagation(t *testing.T) {
	inScope := func(h string) bool { return h == "site.test" }
	chunk := Script{
		SHA256: "n8n",
		URLs:   []string{"https://site.test/assets/users.store.js"},
		Result: jsapi.Result{
			Bases: []string{"https://api.n8n.io/api"},
			Endpoints: []jsapi.Endpoint{
				{Method: "GET", URL: "{}/settings", Kind: "wrapper", Client: true},
				{Method: "GET", URL: "{}/active-workflows", Kind: "wrapper", Client: true},
				{Method: "POST", URL: "{}/workflows", Kind: "wrapper", Client: true, Body: []string{"name"}},
			},
		},
	}
	reqs := []Request{
		req(1, "GET", "https://site.test/rest/settings"),
	}
	got := byPath(Build([]Script{chunk}, reqs, inScope))

	if s := got["GET {}/settings"]; s.Status != Both || s.Base != "/rest" || s.Host != "" {
		t.Fatalf("observed settings: %+v", s)
	}
	for _, k := range []string{"GET {}/active-workflows", "POST {}/workflows"} {
		e := got[k]
		if !slices.Equal(e.Bases, []string{"https://site.test/rest"}) {
			t.Errorf("%s: bases = %v, want [https://site.test/rest]", k, e.Bases)
		}
	}
}

// ENH-03 & ENH-05:
//   - Relative Vite ESM imports ("./index-qLgN_Why.js") link across chunks and
//     propagate QueryArg keys (itemType, version, lang, country) to the catalog;
//   - Observed traffic query & JSON body values populate ep.Params while
//     redacted or credential-named parameters are excluded.
func TestObservedParamValuesAndViteESMLinking(t *testing.T) {
	inScope := func(h string) bool { return strings.HasSuffix(h, "example.com") }
	idx := Script{
		SHA256: "idx",
		URLs:   []string{"https://sub.example.com/assets/index-qLgN_Why.js"},
		Result: jsapi.Extract([]byte(`
			const sr = axios.create({ baseURL: "https://api.example.com/fe/v1" });
			const ly = e => sr.get("/manualAvailability", { params: e });
			const my = e => sr.get("/menu", { params: { content: "chapter", ...e } });
			const sy = d => sr.post("/feedback", d);
			export { ly as e, my as d, sy as f };
		`)),
	}
	view := Script{
		SHA256: "view",
		URLs:   []string{"https://sub.example.com/assets/HomeView-123.js"},
		Result: jsapi.Extract([]byte(`
			import { e as Z, d as M, f as F } from "./index-qLgN_Why.js";
			Z({ itemType: "ModelA", version: "1.0", lang: "en", country: "vn" });
			M({ itemType: "ModelA", lang: "en" });
			F({ itemType: "ModelA", secretToken: "shh", code: "x" });
		`)),
	}
	r1 := req(1, "GET", "https://api.example.com/fe/v1/manualAvailability?country=vn&lang=en&secretToken=dontkeep")
	r2 := req(2, "POST", "https://api.example.com/fe/v1/feedback")
	r2.Body = `{"itemType":"ModelA","secretToken":"dontkeep","code":"<REDACTED>"}`

	got := byPath(Build([]Script{idx, view}, []Request{r1, r2}, inScope))

	ma := got["GET api.example.com/fe/v1/manualAvailability"]
	if !slices.Equal(ma.Query, []string{"country", "itemType", "lang", "secretToken", "version"}) {
		t.Fatalf("ESM linked query = %v, want [country itemType lang secretToken version]", ma.Query)
	}
	paramVals := map[string][]string{}
	for _, p := range ma.Params {
		paramVals[p.In+":"+p.Name] = p.Values
	}
	if !slices.Equal(paramVals["query:country"], []string{"vn"}) || !slices.Equal(paramVals["query:lang"], []string{"en"}) {
		t.Errorf("observed query values = %+v", paramVals)
	}
	if _, bad := paramVals["query:secretToken"]; bad {
		t.Errorf("sensitive query param should not retain sample values: %+v", paramVals)
	}

	menu := got["GET api.example.com/fe/v1/menu"]
	if !slices.Equal(menu.Query, []string{"content", "itemType", "lang"}) {
		t.Errorf("ESM spread query = %v, want [content itemType lang]", menu.Query)
	}

	fb := got["POST api.example.com/fe/v1/feedback"]
	fbVals := map[string][]string{}
	for _, p := range fb.Params {
		fbVals[p.In+":"+p.Name] = p.Values
	}
	if !slices.Equal(fbVals["body:itemType"], []string{"ModelA"}) {
		t.Errorf("observed JSON body value missing: %+v", fbVals)
	}
	if _, bad := fbVals["body:secretToken"]; bad {
		t.Errorf("sensitive body param retained: %+v", fbVals)
	}
	if _, bad := fbVals["body:code"]; bad {
		t.Errorf("redacted body param retained: %+v", fbVals)
	}
}
