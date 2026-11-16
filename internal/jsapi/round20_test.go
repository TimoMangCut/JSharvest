package jsapi

import (
	"slices"
	"strings"
	"testing"
)

// Regression round 20 (COV-01 → COV-06) API extraction patterns.

func byURL(r Result) map[string]Endpoint {
	out := map[string]Endpoint{}
	for _, e := range r.Endpoints {
		// As the catalog does: one endpoint whatever kind of call names it.
		k := e.Method + " " + e.URL
		if o, ok := out[k]; ok {
			e.Query, e.Body = uniq(append(o.Query, e.Query...)), uniq(append(o.Body, e.Body...))
			if o.Kind == "doc" {
				e.Kind = o.Kind
			}
		}
		out[k] = e
	}
	return out
}

// COV-01: a helper given fetch (n = e.fetch), its query an argument; a
// template of the helper's parameters; a URL in an options object; a
// helper making a URL of a base.
func TestChatCoreShapes(t *testing.T) {
	src := "function wr(e){let t=Object.entries(e);let n=new URLSearchParams;for(let[e,r]of t)n.set(e,String(r));return`?${n.toString()}`}" +
		"function Cr(e){let t=e.apiBase,n=e.fetch,r=e=>`${t}${e}`,i=e=>encodeURIComponent(e);async function a(e,t,i,a){let o=a?wr(a):``,s={method:e,body:i===void 0?void 0:JSON.stringify(i)},c=await n(r(t)+o,s);return c}" +
		"return{list(e){return a(`GET`,`/conversations`,void 0,{cursor:e?.cursor,limit:e?.limit})},erase(){return a(`POST`,`/conversations/erase`,{})},rate(e,t,n){return a(`PUT`,`/conversations/${i(e)}/messages/${i(t)}/rating`,{rating:n})},sendUrl(e){return r(`/conversations/${i(e)}/messages/send`)}}}" +
		"function H(e,t){switch(t){case`a`:return 1;case`b`:return 2;case`c`:return 3;case`d`:return 4;case`e`:return 5;case`f`:return 6;case`g`:return 7;case`h`:return 8;case`i`:return 9}}" +
		"function Rr(e){let{apiBase:t,getConvId:n,fetchFn:i=globalThis.fetch}=e,o=t,s=encodeURIComponent(e.id);async function c(e,t,r){let c=n();let l=H({convId:c,...t},`json.object`);return await i(`${o}/mcps/${s}/${e}`,{method:`POST`,body:JSON.stringify(l)})}" +
		"return{callTool(e,t){return c(`tools/call`,{toolName:e,input:t})},listPrompts(){return c(`prompts/list`,{})}}}" +
		"async function Jr(e){let t=await e.fetchImpl(e.url,{method:`GET`});return t}Jr({url:`${cfg.hub}/agent/config`,fetchImpl:f})"
	r := Extract([]byte(src))
	if r.Error != "" {
		t.Fatal(r.Error)
	}
	got := byURL(r)
	want := map[string][2][]string{ // query, body
		"GET /conversations":                       {{"cursor", "limit"}, nil},
		"POST /conversations/erase":                {nil, nil},
		"PUT /conversations/{}/messages/{}/rating": {nil, {"rating"}},
		"POST {}/mcps/{}/tools/call":               {nil, {"convId", "input", "toolName"}},
		"POST {}/mcps/{}/prompts/list":             {nil, {"convId"}},
		"GET {}/agent/config":                      {nil, nil},
		" /conversations/{}/messages/send":         {nil, nil},
	}
	for k, qb := range want {
		e, ok := got[k]
		if !ok {
			t.Errorf("no %s in %v", k, eps(src))
			continue
		}
		if !slices.Equal(e.Query, qb[0]) || !slices.Equal(e.Body, qb[1]) {
			t.Errorf("%s: query %v body %v, want %v %v", k, e.Query, e.Body, qb[0], qb[1])
		}
	}
	if !slices.ContainsFunc(r.ClientHeaders, func(h Header) bool { return h.Name == "Authorization" }) {
		// not in this source; checked below
	}
}

// COV-03: spreads, a function returning a filled object, URLSearchParams
// with set, a query helper, the queries option, a helper of a constant
// URL given the body, a wrapper filling a template's last segment.
func TestFieldsThroughCode(t *testing.T) {
	src := "var Sy=class{get(e,t){}post(e,t){}};var Z=new Sy(`/api`);" +
		"function dx(e,t,n=50){let r={page_size:n};return e.view&&(r.view=e.view),t&&(r.page_token=t),r}" +
		"function fx(e={},t){let{page_token:n,page_size:r,...i}=e;return Z.get(`/me/notifications`,{...t,queries:dx(i,n,r)})}" +
		"async function Ax(e,t){return(await Z.post(`/me/push-devices`,e,t)).data}Ax({platform:`web`,device_name:d});" +
		"function FE(e){if(!e)return``;let t=new URLSearchParams;e.a&&t.set(`is_active`,e.a);let n=t.toString();return n?`?${n}`:``}" +
		"function yT(e,t){return fetch(e,{...t,credentials:`include`})}function bT(e,t,n){return t===void 0?{method:e,...n}:{method:e,body:JSON.stringify(t),...n}}" +
		"async function IE(e,t,n){return yT(`/v1/apps/${e}/permission-scopes${FE(n)}`,{signal:t})}" +
		"function RE(e,t,n,r){return yT(`/v1/apps/${e}/scopes/${t}/${n}`,{method:`POST`,signal:r})}function zE(e,t,n){return RE(e,t,`remove`,n)}zE(a,b,c);" +
		"function _D(e){return{display_name:e.n,locales:e.l.map(e=>({locale:e.x,tagline:e.y}))}}" +
		"async function PUT(e,r){return yT(`/v1/apps/${e}/metadata`,bT(`PUT`,_D(r)))}" +
		"async function RT(e){let t={app_type:e.t};return yT(`/v1/apps`,bT(`POST`,{...t,...e.h?{homepage_url:e.h}:{}}))}"
	r := Extract([]byte(src))
	got := byURL(r)
	check := func(k string, q, b []string) {
		t.Helper()
		e, ok := got[k]
		if !ok {
			t.Errorf("no %s in %v", k, eps(src))
			return
		}
		if q != nil && !slices.Equal(e.Query, q) || b != nil && !slices.Equal(e.Body, b) {
			t.Errorf("%s: query %v body %v", k, e.Query, e.Body)
		}
	}
	check("GET /api/me/notifications", []string{"page_size", "page_token", "view"}, nil)
	check("POST /api/me/push-devices", nil, []string{"device_name", "platform"})
	check("GET /v1/apps/{}/permission-scopes", []string{"is_active"}, nil)
	check("POST /v1/apps/{}/scopes/{}/remove", nil, nil)
	check("PUT /v1/apps/{}/metadata", nil, []string{"display_name", "locales.locale", "locales.tagline"})
	check("POST /v1/apps", nil, []string{"app_type", "homepage_url"})
}

// COV-04: a module's exported request helper, and another's call to it.
func TestModuleExportsAndImports(t *testing.T) {
	def := `e.s(["$",0,(e,t)=>l(e).verifyMfa(t),"k",0,(e,t)=>s(e).updateProfile(t)],21666);` +
		`function l(e){let t=o(e);return{verifyMfa:async function(e){return(await t.post("/v1/auth/mfa/verify",e)).data}}}` +
		`function s(e){let t=o(e);return{updateProfile:async function(e){return(await t.patch("/v1/me",e)).data}}}`
	r := Extract([]byte(def))
	if len(r.Exports) != 2 || r.Exports[0] != (Export{Module: "21666", Name: "$", Method: "POST", URL: "/v1/auth/mfa/verify", QueryArg: -1, BodyArg: 1, BaseArg: 0, Factory: "f1"}) {
		t.Fatalf("exports %+v", r.Exports)
	}
	use := `var H=e.i(21666);(0,H.$)(cfg.AUTH_API_URL,{mfa_token:m,code:c});H.k(cfg.CLIENT_API_URL,{display_name:n})`
	r = Extract([]byte(use))
	if len(r.Imports) != 2 || r.Imports[0].Args[0].Setting != "AUTH_API_URL" || !slices.Equal(r.Imports[0].Args[1].Keys, []string{"code", "mfa_token"}) {
		t.Fatalf("imports %+v", r.Imports)
	}
}

// COV-05: a client chosen by a condition; COV-06: the headers a client
// sets.
func TestConditionalClientAndHeaders(t *testing.T) {
	src := "var Sy=class{post(e,t){}};var Z=new Sy(`/api`),Dy=new Sy(`/auth`);" +
		"function Mt(e,t){return(W.same?Z:Dy).post(`/v1/auth/token/exchange`,{app_id:e},t)}" +
		"function eT(e,t){let r=new Headers(t?.headers);r.set(`X-CSRF-Token`,tok());return fetch(e,{...t,headers:r})}" +
		"function Cr(e){return fetch(`/x/y`,{headers:{Authorization:`Bearer ${e}`,\"Content-Type\":`application/json`}})}"
	r := Extract([]byte(src))
	got := byURL(r)
	for _, k := range []string{"POST /api/v1/auth/token/exchange", "POST /auth/v1/auth/token/exchange"} {
		if _, ok := got[k]; !ok {
			t.Errorf("no %s in %v", k, eps(src))
		}
	}
	var names []string
	for _, h := range r.ClientHeaders {
		names = append(names, h.Name+"="+h.Value)
	}
	if !slices.Contains(names, "X-CSRF-Token={}") || !slices.Contains(names, "Authorization=Bearer {}") || slices.ContainsFunc(names, func(s string) bool { return strings.HasPrefix(s, "Content-Type") }) {
		t.Errorf("headers %v", names)
	}
}

// COV-02: what a developer portal's pages name, and no error message.
// TRU-04: a base the reader fills in ({base}) or a host made up
// (example.com) is no part of the path; nor is an example's code.
func TestDocEndpoints(t *testing.T) {
	src := "var a=`| Method | Path |\\n|---|---|\\n| \\`GET\\` | \\`/admin/v1/marketplace/apps/{app_id}\\` | x |\\n`;" +
		"var b=`POST /v1/public/feed/items/batch\\n`;" +
		"var c=`curl -X PATCH \\\\\\n  'https://<host>/open/v1/feed/items/SKU-001?x=1' \\\\\\n`;" +
		"var d=`POST {base}/{workspace_code}/shortlinks\\n`;" +
		"var e=\"Cannot GET /some/where/else\";var f=`GET /`;"
	got := byURL(Extract([]byte(src)))
	for _, k := range []string{"GET /admin/v1/marketplace/apps/{}", "POST /v1/public/feed/items/batch", "PATCH /open/v1/feed/items/{}",
		"POST /{}/shortlinks"} {
		e, ok := got[k]
		if !ok || e.Kind != "doc" {
			t.Errorf("no doc %s in %v", k, eps(src))
		}
	}
	if _, ok := got["GET /some/where/else"]; ok {
		t.Error("an error message is no document")
	}
}
