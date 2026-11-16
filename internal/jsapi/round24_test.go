package jsapi

import (
	"slices"
	"testing"
)

// ENH-10 (Vế A): options objects using {method, baseURL, endpoint} (and
// helpers wrapping them), context-first wrapper calls Y(ctx, METHOD, PATH, body),
// and store configs combining baseUrl + restEndpoint ("rest" -> "/rest").
func TestOptionsEndpointAndContextWrapper(t *testing.T) {
	src := `
const si = k => window.__META__?.[k];
const state = ref({
	baseUrl: window.BASE_PATH,
	restEndpoint: si("rest-endpoint") ?? "rest",
	endpointForm: "form",
});
const restUrl = computed(() => ` + "`${state.value.baseUrl}${state.value.restEndpoint}`" + `);
function wz(opts) { return axios.request(opts); }
function Tz(e, t, n, r) { return wz({ method: t, baseURL: e.baseUrl, endpoint: n, data: r }); }
function run(ctx) {
	Da({ method: "POST", baseURL: ctx.baseUrl, endpoint: "/workflows/from-url", data: { url: "x" } });
	Tz(ctx, "PATCH", "/settings/smtp", { host: "h", port: 587 });
	Y(ctx, "GET", "/active-workflows");
	Y(ctx, "POST", "/workflows", { name: "wf", active: true });
	render({ type: "PUSH", pathname: "/home" });
}
`
	res := Extract([]byte(src))
	got := byURL(res)

	for _, want := range []struct {
		key  string
		body []string
	}{
		{"POST {}/workflows/from-url", []string{"url"}},
		{"PATCH {}/settings/smtp", []string{"host", "port"}},
		{"GET {}/active-workflows", nil},
		{"POST {}/workflows", []string{"active", "name"}},
	} {
		e, ok := got[want.key]
		if !ok || !e.Client {
			t.Errorf("%s: missing or Client=false: %+v in %v", want.key, e, eps(src))
			continue
		}
		if !slices.Equal(e.Body, want.body) {
			t.Errorf("%s: body %v, want %v", want.key, e.Body, want.body)
		}
	}
	if !slices.Contains(res.Bases, "/rest") {
		t.Errorf("expected /rest in Bases, got %v", res.Bases)
	}
	if slices.Contains(res.Bases, "/form") {
		t.Errorf("/form should not be treated as an API base: %v", res.Bases)
	}
	for k := range got {
		if k == "GET /home" || k == "PUSH /home" {
			t.Errorf("non-HTTP {type, pathname} misread as endpoint: %s", k)
		}
	}
}

// ENH-05: Vite multi-chunk ESM exports & imports (including aliased named
// exports/imports, QueryArg on { params: e }, and spread { params: { ..., ...e } }).
func TestViteESModuleImportsAndExports(t *testing.T) {
	if Version < 18 {
		t.Fatalf("jsapi Version = %d, want >= 18", Version)
	}
	indexChunk := `
const sr = axios.create({ baseURL: "https://api.example.com/fe/v1" });
const ly = e => sr.get("/manualAvailability", { params: e });
const my = e => sr.get("/menu", { params: { content: "chapter", ...e } });
const cy = (e, d) => sr.post("/search", d, { params: e });
export { cy as a6, ly as e, my as d };
`
	resIdx := Extract([]byte(indexChunk))
	if len(resIdx.Exports) != 3 {
		t.Fatalf("expected 3 ESM exports, got %+v", resIdx.Exports)
	}
	byExport := map[string]Export{}
	for _, ex := range resIdx.Exports {
		byExport[ex.Name] = ex
	}
	if ex := byExport["e"]; ex.URL != "https://api.example.com/fe/v1/manualAvailability" || ex.QueryArg != 0 {
		t.Errorf("export e = %+v", ex)
	}
	if ex := byExport["d"]; ex.QueryArg != 0 || !slices.Equal(byURL(resIdx)["GET https://api.example.com/fe/v1/menu"].Query, []string{"content"}) {
		t.Errorf("export d = %+v", ex)
	}
	if ex := byExport["a6"]; ex.QueryArg != 0 || ex.BodyArg != 1 {
		t.Errorf("export a6 = %+v", ex)
	}

	viewChunk := `
import { e as Z, a6 as Ca, d as M } from "./index-qLgN_Why.js";
export function load(o, l, t, n, q, f) {
	Z({ itemType: o, version: l, lang: t, country: n });
	M({ itemType: o, version: l });
	Ca({ keywords: q, page: 1 }, { filter: f });
}
`
	resView := Extract([]byte(viewChunk))
	if len(resView.Imports) != 3 {
		t.Fatalf("expected 3 ESM imports, got %+v", resView.Imports)
	}
	if im := resView.Imports[0]; im.Module != "./index-qLgN_Why.js" || im.Name != "e" || !slices.Equal(im.Args[0].Keys, []string{"country", "itemType", "lang", "version"}) {
		t.Errorf("import Z = %+v", im)
	}
}

// ENH-08: suppress generic Axios/cURL-parser Authorization: Basic {} headers
// reading username+password, while keeping literal Basic constants and API-key
// Basic auth.
func TestAxiosBasicAuthSuppression(t *testing.T) {
	axiosVariants := `
function xhrAdapter(e, i) {
	if (e.auth) {
		const c = e.auth.username || "", u = e.auth.password ? unescape(encodeURIComponent(e.auth.password)) : "";
		i.set("Authorization", "Basic " + btoa(c + ":" + u));
	}
	fetch("/v1/a", { headers: i });
}
function fetchAdapter(c, a) {
	if (c) {
		const f = w.getSafeProp(c, "username") || "", d = w.getSafeProp(c, "password") ? unescape(encodeURIComponent(w.getSafeProp(c, "password"))) : "";
		a.set("Authorization", "Basic " + btoa(f + ":" + d));
	}
	fetch("/v1/b", { headers: a });
}
function curlImporter(curlJson) {
	let { user, password: pass } = curlJson.auth;
	const headers = { authorization: ` + "`Basic ${encodeBasicAuthentication(user, pass)}`" + ` };
	fetch("/v1/c", { headers });
}
`
	res := Extract([]byte(axiosVariants))
	for _, h := range res.ClientHeaders {
		if h.Name == "Authorization" || h.Name == "authorization" {
			t.Errorf("generic Basic auth leaked into Result.ClientHeaders: %+v", h)
		}
	}

	realBasic := `
const c1 = axios.create({ headers: { Authorization: "Basic dXNlcjpwYXNz" } });
function setStripe(h) {
	h.set("Authorization", "Basic " + btoa(process.env.STRIPE_KEY + ":"));
}
`
	res2 := Extract([]byte(realBasic))
	var vals []string
	for _, h := range res2.ClientHeaders {
		if h.Name == "Authorization" {
			vals = append(vals, h.Value)
		}
	}
	if !slices.Contains(vals, "Basic dXNlcjpwYXNz") || !slices.Contains(vals, "Basic {}") {
		t.Errorf("expected literal and API-key Basic headers to stay, got %+v", res2.ClientHeaders)
	}
}

// ENH-09: OpenAPI 3 & Swagger 2 security contracts (global security, operation
// security: [] public override, bearerAuth, and apiKey in header/query).
func TestOpenAPISecurityExtraction(t *testing.T) {
	spec := `{
		"openapi": "3.0.3",
		"security": [{"bearerAuth": []}],
		"components": {
			"securitySchemes": {
				"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
				"tenantKey": {"type": "apiKey", "in": "header", "name": "X-Tenant-Key"},
				"queryKey": {"type": "apiKey", "in": "query", "name": "api_key"}
			}
		},
		"paths": {
			"/v1/room/create": {
				"post": {"operationId": "createRoom", "responses": {"200": {"description": "ok"}}}
			},
			"/v1/test": {
				"get": {"security": [], "responses": {"200": {"description": "public"}}}
			},
			"/v1/partner/sync": {
				"post": {
					"security": [{"tenantKey": [], "queryKey": []}],
					"responses": {"200": {"description": "partner"}}
				}
			}
		}
	}`
	res := ExtractOpenAPI([]byte(spec))
	if len(res.Endpoints) == 0 {
		t.Fatal("ExtractOpenAPI returned no endpoints")
	}
	got := byURL(res)

	room := got["POST /v1/room/create"]
	if !slices.Equal(room.Auth, []string{"bearer"}) || !slices.Contains(room.Headers, "Authorization") {
		t.Errorf("POST /v1/room/create = %+v, want Auth=[bearer] and Authorization header", room)
	}
	pub := got["GET /v1/test"]
	if len(pub.Auth) != 0 || slices.Contains(pub.Headers, "Authorization") {
		t.Errorf("GET /v1/test with security:[] = %+v, want empty Auth and no Authorization", pub)
	}
	partner := got["POST /v1/partner/sync"]
	if !slices.Equal(partner.Auth, []string{"apiKey:X-Tenant-Key", "apiKey:api_key"}) {
		t.Errorf("POST /v1/partner/sync Auth = %v", partner.Auth)
	}
	if !slices.Contains(partner.Headers, "X-Tenant-Key") || !slices.Contains(partner.Query, "api_key") {
		t.Errorf("POST /v1/partner/sync Headers=%v Query=%v", partner.Headers, partner.Query)
	}
}

// P0-1: context-wrapper calls must not turn endpoint paths (/api-keys) into
// Result.Bases, and non-API calls (sendEvent, bus.emit, router.register) must
// not be treated as {}/... client endpoints.
func TestContextWrapperNoGhostBases(t *testing.T) {
	n8nChunk := `
import { g as R } from "./rest-client.js";
export async function listApiKeys(e) {
	return await R(e, "GET", "/api-keys");
}
export function createApiKey(e, body) {
	return R(e, "POST", "/api-keys", body);
}
`
	res := Extract([]byte(n8nChunk))
	got := byURL(res)
	if e, ok := got["GET {}/api-keys"]; !ok || !e.Client {
		t.Errorf("missing GET {}/api-keys client endpoint: %+v in %v", e, eps(n8nChunk))
	}
	if e, ok := got["POST {}/api-keys"]; !ok || !e.Client {
		t.Errorf("missing POST {}/api-keys client endpoint: %+v in %v", e, eps(n8nChunk))
	}
	if len(res.Bases) != 0 {
		t.Errorf("endpoint path leaked into Result.Bases: %v", res.Bases)
	}

	negSrc := `
function ui(ctx, app, bar) {
	sendEvent("click", "POST", "/api/track");
	bus.emit(ctx, "POST", "/api/events");
	router.register(app, "GET", "/api-docs");
	unknownHelper(bar, "GET", "/api-tokens");
}
`
	neg := Extract([]byte(negSrc))
	for _, ep := range neg.Endpoints {
		if ep.Client || slices.Contains([]string{"{}/api/track", "{}/api/events", "{}/api-docs", "{}/api-tokens"}, ep.URL) {
			t.Errorf("non-context-wrapper call misclassified as client {}/...: %+v", ep)
		}
	}
	if len(neg.Bases) != 0 {
		t.Errorf("unexpected Bases from negative wrapper calls: %v", neg.Bases)
	}
}

// P1-2 & P1-4: hardcoded Basic credentials ({username:"svc", password:"hunter2"})
// evaluate via btoa to Basic c3ZjOmh1bnRlcjI= and partial hardcoded credentials
// ({username:"svc", password:dyn}) stay as Basic {} instead of being dropped;
// OpenAPI type:"http" without scheme yields "bearer" (never "<nil>").
func TestHardcodedBasicAuthAndOpenAPIMissingScheme(t *testing.T) {
	src := `
const cfg = { username: "svc", password: "hunter2" };
const partial = { username: "svc", password: window.__SECRET__ };
function callFull() {
	fetch("/v1/full", { headers: { Authorization: "Basic " + btoa(cfg.username + ":" + cfg.password) } });
}
function callPartial() {
	fetch("/v1/partial", { headers: { "X-Dummy": "1", Authorization: "Basic " + customEncode(partial.username + ":" + partial.password) } });
}
`
	res := Extract([]byte(src))
	var authVals []string
	for _, h := range res.ClientHeaders {
		if h.Name == "Authorization" {
			authVals = append(authVals, h.Value)
		}
	}
	if !slices.Contains(authVals, "Basic c3ZjOmh1bnRlcjI=") {
		t.Errorf("expected hardcoded btoa Basic c3ZjOmh1bnRlcjI=, got %+v", res.ClientHeaders)
	}
	if !slices.Contains(authVals, "Basic {}") {
		t.Errorf("expected partial hardcoded Basic {} to be preserved, got %+v", res.ClientHeaders)
	}

	spec := `{
		"openapi": "3.0.3",
		"security": [{"httpNoScheme": []}],
		"components": {
			"securitySchemes": {
				"httpNoScheme": {"type": "http"}
			}
		},
		"paths": {
			"/v1/items": {
				"get": {"responses": {"200": {"description": "ok"}}}
			}
		}
	}`
	oa := ExtractOpenAPI([]byte(spec))
	got := byURL(oa)["GET /v1/items"]
	if !slices.Equal(got.Auth, []string{"bearer"}) {
		t.Errorf("OpenAPI http without scheme Auth = %v, want [bearer] (no <nil>)", got.Auth)
	}
}
