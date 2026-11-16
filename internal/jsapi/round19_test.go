package jsapi

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

// Regression round 19 API extraction patterns.

// Helpers through three levels, two URLs in one, and a helper
// that builds the RequestInit.
const consoleSrc = `function eT(e,t){let r=t?.headers;return fetch(e,{...t,headers:r,credentials:"include"})}
function mT(e){return lT()+"/"+e}
function yT(e,t){return eT(mT(e),t)}
function bT(e,t,n){return t===void 0?{method:e,...n}:t instanceof FormData?{method:e,body:t,...n}:{method:e,headers:{"Content-Type":"application/json"},body:JSON.stringify(t),...n}}
async function ST(e,t,n,r){if(n==="third_party")return yT(t,r);let i=await yT(e,r);return i}
async function a(e,t){return yT(` + "`hub/console/v1/apps/${encodeURIComponent(e)}/members?${t}`" + `,{signal:t})}
async function b(e,t){return yT(` + "`hub/console/v1/apps/${encodeURIComponent(e)}/members`" + `,bT("POST",{user_id:t.userId,role:t.role}))}
async function c(e,t){return yT(` + "`hub/console/v1/apps/${encodeURIComponent(e)}/members/${encodeURIComponent(t)}`" + `,{method:"DELETE"})}
async function d(e){return yT(` + "`hub/console/v1/tenant/apps/${encodeURIComponent(e)}/keys`" + `)}
async function f(e,t){return ST(` + "`hub/console/v1/apps/${e}`,`hub/console/v1/marketplace/apps/${e}`" + `,t,{signal:t})}
async function g(e,t,n){return yT(` + "`hub/console/v1/apps/${e}/versions/${t}/builds/${n}/cancel-submit`" + `,{method:"POST"})}
async function h(e,t){return yT(` + "`hub/console/v1/apps/${e}/trusted-domains/challenge/dns`" + `,bT("POST",{domain:t}))}`

func TestHelpersThroughLevels(t *testing.T) {
	r := Extract([]byte(consoleSrc))
	if r.Error != "" {
		t.Fatal(r.Error)
	}
	want := map[string][]string{
		"GET hub/console/v1/apps/{}/members":                              nil,
		"POST hub/console/v1/apps/{}/members":                             {"role", "user_id"},
		"DELETE hub/console/v1/apps/{}/members/{}":                        nil,
		"GET hub/console/v1/tenant/apps/{}/keys":                          nil,
		"GET hub/console/v1/apps/{}":                                      nil,
		"GET hub/console/v1/marketplace/apps/{}":                          nil,
		"POST hub/console/v1/apps/{}/versions/{}/builds/{}/cancel-submit": nil,
		"POST hub/console/v1/apps/{}/trusted-domains/challenge/dns":       {"domain"},
	}
	got := map[string]Endpoint{}
	for _, e := range r.Endpoints {
		got[e.Method+" "+e.URL] = e
	}
	for k, body := range want {
		e, ok := got[k]
		if !ok {
			t.Errorf("missing %s in %v", k, eps(consoleSrc))
			continue
		}
		if !slices.Equal(e.Body, body) {
			t.Errorf("%s: body %v, want %v (never the options' keys)", k, e.Body, body)
		}
		if !e.Client || e.Kind != "wrapper" {
			t.Errorf("%s: client %v kind %s", k, e.Client, e.Kind)
		}
		// Each snippet matches where its own call is, not another template prefix.
		segs := strings.Split(strings.TrimSuffix(e.URL, "/{}"), "/")
		if last := segs[len(segs)-1]; !strings.Contains(e.Snippet, last) {
			t.Errorf("%s: snippet %q", k, e.Snippet)
		}
	}
	if len(r.Endpoints) != len(want) {
		t.Errorf("%d endpoints, want %d: %v", len(r.Endpoints), len(want), eps(consoleSrc))
	}
}

// Store puts, router pages, and request option keys are ignored as bodies.
func TestNoStoreRouteOrOptionKeys(t *testing.T) {
	src := `const K=` + "`${location.origin}/__app_shell__`" + `;caches.open("x").then(cache=>cache.put(K,response.clone()));
var Xj=R("/auth/fail")({component:Zj});
helper("/api/v1/items/"+id,{method:"DELETE"});
up("/api/v1/upload",{method:"POST",body:form,signal:s})`
	got := eps(src)
	for _, e := range got {
		if strings.Contains(e, "__app_shell__") || strings.Contains(e, "/auth/fail") {
			t.Errorf("not an API call: %s", e)
		}
	}
	for _, url := range []string{"/api/v1/items/{}", "/api/v1/upload"} {
		var e Endpoint
		for _, x := range Extract([]byte(src)).Endpoints {
			if x.URL == url {
				e = x
			}
		}
		if len(e.Body) > 0 {
			t.Errorf("%s: body %v: the options' keys", url, e.Body)
		}
	}
	if r := Extract([]byte(src)); !slices.Contains(r.Routes, "/auth/fail") {
		t.Errorf("routes %v: /auth/fail is a page", r.Routes)
	}
}

// Settings in base64 (reversed), in an RSC payload's JSON, an
// env lookup's default, a function returning a constant.
func TestConfigSettings(t *testing.T) {
	cfg := `{"apiBaseUrl":"https://api.example.com/hub","firebase":{"apiKey":"AIzaSyTESTKEY123456"}}`
	b64 := b64std(cfg)
	rev := []byte(b64)
	slices.Reverse(rev)
	src := `globalThis._$c="` + string(rev) + `";
self.__next_f.push([1,"28:[\"$\",\"$L29\",null,{\"config\":{\"AUTH_API_URL\":\"https://api.example.com/hub/auth\"}}]"]);
var b=dT("VITE_AUTH_API_BASE_URL","/hub/auth");
function fe(){return"/openapi.yaml"}fetch(fe());
window.__ENV__={VITE_CONSOLE_API_BASE_URL:"https://api.example.com/hub/console/v1",VITE_LOGIN_URL:"https://accounts.example.com/login"}`
	r := Extract([]byte(src))
	for _, b := range []string{"https://api.example.com/hub", "https://api.example.com/hub/auth", "/hub/auth", "https://api.example.com/hub/console/v1"} {
		if !slices.Contains(r.Bases, b) {
			t.Errorf("bases %v: no %s", r.Bases, b)
		}
	}
	if slices.Contains(r.Bases, "https://accounts.example.com/login") {
		t.Errorf("a login page is no base: %v", r.Bases)
	}
	found := false
	for _, k := range r.Keys {
		found = found || k.Name == "apiKey" && k.Value == "AIzaSyTESTKEY123456"
	}
	if !found {
		t.Errorf("keys %v: no apiKey", r.Keys)
	}
	got := eps(src)
	if !slices.Contains(got, "GET /openapi.yaml fetch") {
		t.Errorf("fetch(fe()): %v", got)
	}
	for _, e := range got {
		if strings.Contains(e, "/hub/auth") {
			t.Errorf("a setting's default is no call: %s", e)
		}
	}
}

// Each client object's prefix.
func TestClientPrefixes(t *testing.T) {
	src := `var Sy=class{constructor(e){this.baseUrl=e}get(e){return this.request("GET",e)}post(e,t){return this.request("POST",e,t)}};
var Cy=e=>new Sy(` + "`${W.apiBaseUrl}${e}`" + `),wy=e=>W.sameOriginApi?new Sy(e):Cy(e),Z=wy("/api"),Ey=wy("/api/public"),Dy=Cy("/auth");
Z.get("/account/v1/me");Dy.post("/v1/oauth/token",{grant_type:g});Ey.get(` + "`/v1/workspaces/${s}/config`" + `)`
	got := eps(src)
	for _, w := range []string{"GET /api/account/v1/me client", "POST /auth/v1/oauth/token client", "GET /api/public/v1/workspaces/{}/config client"} {
		if !slices.Contains(got, w) {
			t.Errorf("no %s in %v", w, got)
		}
	}
	for _, e := range got {
		if e == "/api/public wrapper" || e == "/auth wrapper" || strings.HasSuffix(e, " /account/v1/me client") {
			t.Errorf("%s: a factory's call, or a path without its client's prefix", e)
		}
	}
}

// OpenAPI document's operations.
func TestOpenAPI(t *testing.T) {
	doc := `openapi: 3.0.1
servers:
  - url: https://api.example.com/hub/openapi
paths:
  /v1/orders/{orderId}:
    parameters:
      - {name: orderId, in: path}
    get:
      operationId: getOrder
      parameters:
        - {name: expand, in: query}
        - $ref: '#/components/parameters/Tenant'
    patch:
      requestBody:
        content:
          application/json:
            schema: {$ref: '#/components/schemas/Order'}
components:
  parameters:
    Tenant: {name: X-Tenant-Id, in: header}
  schemas:
    Order:
      properties:
        status: {type: string}
        shipping: {properties: {city: {type: string}}}
`
	if !IsOpenAPI([]byte(doc)) {
		t.Fatal("not read as OpenAPI")
	}
	r := ExtractOpenAPI([]byte(doc))
	if r.Error != "" || len(r.Endpoints) != 2 || !slices.Equal(r.Bases, []string{"https://api.example.com/hub/openapi"}) {
		t.Fatalf("%+v", r)
	}
	g, p := r.Endpoints[0], r.Endpoints[1]
	if g.Method != "GET" || g.URL != "/v1/orders/{}" || !slices.Equal(g.Query, []string{"expand"}) || !slices.Equal(g.Headers, []string{"X-Tenant-Id"}) {
		t.Errorf("get: %+v", g)
	}
	if p.Method != "PATCH" || !slices.Equal(p.Body, []string{"shipping.city", "status"}) {
		t.Errorf("patch: %+v", p)
	}
	if IsOpenAPI([]byte(`{"name":"x","paths":[]}`)) {
		t.Error("any JSON with paths is no OpenAPI")
	}
	if IsOpenAPI([]byte("var spec = {\n  openapi: \"3.0.0\",\n  paths: {}\n}")) {
		t.Error("a script that names the key is no OpenAPI document")
	}
	if !IsOpenAPI([]byte("# API\n---\nopenapi: '3.1.0'\npaths: {}\n")) || !IsOpenAPI([]byte(`{"info":{"title":"x"},"openapi":"3.0.1","paths":{}}`)) {
		t.Error("a document after a comment, or with info first, is one")
	}
}

func b64std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
