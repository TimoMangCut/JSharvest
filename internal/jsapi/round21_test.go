package jsapi

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// TRU-01: a field whose value is a variable holding an object (or a
// condition between one and nothing) nests its fields; a query string a
// helper makes of an object's entries, added to a URL, is its query.
func TestNestsThroughVariables(t *testing.T) {
	src := "function bT(e,t){return{method:e,body:JSON.stringify(t)}}async function yT(e,t){return fetch(`/${e}`,t)}" +
		"async function PS(e,t){let n=t.map(e=>({scope_string:e.scopeString,token_modes:e.tokenModes})),r=await yT(`hub/console/v1/apps/${e}/permission-scopes`,bT(`POST`,{entries:n}));return r}" +
		"function _D(e){return{category_id:e.c,locales:e.l?.map(e=>({locale:e.locale}))}}" +
		"async function SB(e,r){let a=r?_D(r):void 0;return yT(`hub/console/v1/apps/${e}/submit`,bT(`POST`,a?{metadata:a}:void 0))}" +
		"function wr(e){let t=Object.entries(e).filter(([,e])=>e!==void 0);if(t.length===0)return``;let n=new URLSearchParams;for(let[e,r]of t)n.set(e,String(r));return`?${n.toString()}`}" +
		"function Cr(e){let t=e.apiBase,n=e.fetch,r=e=>`${t}${e}`;async function a(e,t){return n(r(t),{method:e})}" +
		"return{list(){return a(`GET`,`/conversations`)},eventsUrl(e,t){return r(`/conversations/${e}/events`)+wr({lastEventId:t})}}}"
	got := byURL(Extract([]byte(src)))
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
	check("POST /hub/console/v1/apps/{}/permission-scopes", nil, []string{"entries.scope_string", "entries.token_modes"})
	check("POST /hub/console/v1/apps/{}/submit", nil, []string{"metadata.category_id", "metadata.locales.locale"})
	check(" /conversations/{}/events", []string{"lastEventId"}, nil)
}

// TRU-02: a client factory's methods, exported or not, with a template
// URL; a factory this script gives a setting's base.
func TestFactories(t *testing.T) {
	src := `e.s(["j",0,(e,t)=>l(e).refreshSession(t),"g",0,(e,t)=>l(e).verifyMfa(t)],21666);` +
		"function l(e){let t=o(e);return{refreshSession:async function(e){let r=e?`?tenant_id=${e}`:``;return(await t.post(`/v1/auth/sessions/refresh${r}`)).data}," +
		`verifyMfa:async function(e){return(await t.post("/v1/auth/mfa/verify",e)).data},enrollTotp:async function(){return(await t.post("/v1/auth/mfa/totp/enroll")).data}}}` +
		`function a(e){let t=o(e);return{previewInviteLink:async function(e){return(await t.post("/v1/invite-links/preview",{invite_token:e})).data}}}let d=a(cfg.CLIENT_API_URL);`
	r := Extract([]byte(src))
	if len(r.Exports) != 2 || r.Exports[0].URL != "/v1/auth/sessions/refresh" || r.Exports[0].Factory == "" || r.Exports[0].Factory != r.Exports[1].Factory {
		t.Fatalf("exports %+v", r.Exports)
	}
	var mfa, invite *Factory
	for i, f := range r.Factories {
		if f.ID == r.Exports[0].Factory {
			mfa = &r.Factories[i]
		} else {
			invite = &r.Factories[i]
		}
	}
	if mfa == nil || !slices.Contains(mfa.Endpoints, "POST /v1/auth/mfa/totp/enroll") || len(mfa.Settings) != 0 {
		t.Errorf("the exported factory: %+v", mfa)
	}
	if invite == nil || !slices.Equal(invite.Endpoints, []string{"POST /v1/invite-links/preview"}) || !slices.Equal(invite.Settings, []string{"CLIENT_API_URL"}) {
		t.Errorf("the factory given a setting: %+v", invite)
	}
}

// TRU-03: a helper's frame (…/{}/{}) is no endpoint when every call to
// it makes the URL whole; it is when a call leaves it unknown; a function
// making a client (Rr(cfg)) says nothing either way.
func TestHelperFrames(t *testing.T) {
	src := "async function yT(e,t){return fetch(`/${e}`,t)}" +
		"function RE(e,t,n){return yT(`hub/apps/${e}/scopes/${t}/${n}`,{method:`POST`})}" +
		"let zE=(e,t)=>RE(e,t,`remove`),BE=(e,t)=>RE(e,t,`withdraw`);" +
		"function Rr(e){let{apiBase:t,fetchFn:i=globalThis.fetch}=e,o=t;async function c(e,t){return i(`${o}/mcps/x/${e}`,{method:`POST`,body:JSON.stringify(t)})}" +
		"return{callTool(e){return c(`tools/call`,{toolName:e})},listPrompts(){return c(`prompts/list`,{})}}}Rr({apiBase:q});" +
		"function GE(e,t){return yT(`hub/apps/${e}/keys/${t}`,{method:`POST`})}GE(a,`rotate`);GE(a,b);"
	got := byURL(Extract([]byte(src)))
	for _, k := range []string{"POST /hub/apps/{}/scopes/{}/remove", "POST /hub/apps/{}/scopes/{}/withdraw", "POST {}/mcps/x/tools/call",
		"POST /hub/apps/{}/keys/rotate", "POST /hub/apps/{}/keys/{}"} {
		if _, ok := got[k]; !ok {
			t.Errorf("no %s in %v", k, eps(src))
		}
	}
	for _, k := range []string{"POST /hub/apps/{}/scopes/{}/{}", "POST {}/mcps/x/{}"} {
		if _, ok := got[k]; ok {
			t.Errorf("a helper's frame %s in %v", k, eps(src))
		}
	}
}

// TRU-05: a function joining a router's basepath makes pages; one a
// request's URL calls makes endpoints. A chart's {"X-AXIS": 48} is no
// header.
func TestBuildersAndHeaders(t *testing.T) {
	src := "function Ct(){return xt().basepath}function wt(e){return`${Ct()??``}${e}`}" +
		"go(wt(`/apps/${e}`));location.assign(wt(`/home`));" +
		"function Cr(e){let t=e.apiBase,n=e.fetch,r=e=>`${t}${e}`;return{a(e){return n(r(`/x/${e}`),{})},sendUrl(e){return r(`/conversations/${e}/messages/send`)}}}" +
		`var Q={"X-AXIS":48,"Y-AXIS":49};var H={"X-Api-Key":k};`
	r := Extract([]byte(src))
	got := byURL(r)
	if _, ok := got[" /apps/{}"]; ok {
		t.Errorf("a route as an endpoint: %v", eps(src))
	}
	if _, ok := got[" /conversations/{}/messages/send"]; !ok {
		t.Errorf("no URL of the API's builder in %v", eps(src))
	}
	var names []string
	for _, h := range r.ClientHeaders {
		names = append(names, h.Name)
	}
	if slices.Contains(names, "X-AXIS") || !slices.Contains(names, "X-Api-Key") {
		t.Errorf("headers %v", names)
	}
}

// FIN-01: a document's curl commands (with or without -X), their query
// and body, the base it exports; the code it shows; a made-up host.
func TestDocCurl(t *testing.T) {
	doc := "export SLINK_HOST=\"https://api.example.biz/slink-integration/api/v1\"\nexport BAL=\"https://balance.dev.x.services\"\n\n" +
		"curl -sS -o /dev/null -w '%{http_code}' \\\n  -G \"$SLINK_HOST/$WORKSPACE/shortlinks/deep-link\" \\\n  --data-urlencode \"short_url=https://go/x\" \\\n  -H \"X-Api-Key: $K\"\n\n" +
		"curl -sS -X POST \"$SLINK_HOST/$WORKSPACE/shortlinks\" \\\n  -H 'Content-Type: application/json' \\\n  -d '{\n \"name\": \"a\",\n \"params\": {\"web_url\": \"u\"},\n \"tags\": [\"x\"]\n }'\n\n" +
		"curl -sS \"$BAL/internal/v1/accounts/balance\" | jq\n" +
		"curl -sS -X POST \"$BAL/internal/v1/disbursements/batch/upload\" -F \"statement_code=S\" -F \"file=@a.csv\"\n" +
		"curl -X POST \\\n  '{hook-base}/api/v1/promo-codes/redeem' \\\n  -d '{\"promo_code\": \"G\", \"order_code\": <code>}'\n" +
		"curl 'https://api.partner.vn/open/feed/tasks/3fa85f64-5717-4562-b3fc-2c963f66afa6?x=1' -H 'X: y'\n" +
		"curl -sS -X POST \"https://my-space.example.com/api/revalidate?path=/vi\"\n" +
		"GET /cms/delivery/v1/entries/$ID?include=2\n"
	code := "```ts\nconst r = await fetch('/admin/v1/marketplace/apps/installations', {\n  method: 'POST',\n  body: JSON.stringify({ app_id: a, expected_build_id: b }),\n})\n```\n"
	src := "var a=" + strconvQuote(doc) + ";var b=" + strconvQuote(code) + ";"
	got := map[string]Endpoint{}
	for _, e := range Extract([]byte(src)).Endpoints {
		got[e.Method+" "+e.URL] = e
	}
	check := func(k, base string, q, b []string) {
		t.Helper()
		e, ok := got[k]
		if !ok {
			t.Errorf("no %s in %v", k, got)
			return
		}
		if e.Kind != "doc" || e.Base != base || q != nil && !slices.Equal(e.Query, q) || b != nil && !slices.Equal(e.Body, b) {
			t.Errorf("%s: %+v", k, e)
		}
	}
	check("GET /{}/shortlinks/deep-link", "https://api.example.biz/slink-integration/api/v1", []string{"short_url"}, nil)
	check("POST /{}/shortlinks", "https://api.example.biz/slink-integration/api/v1", nil, []string{"name", "params.web_url", "tags"})
	check("GET /internal/v1/accounts/balance", "$BAL", nil, nil)
	check("POST /internal/v1/disbursements/batch/upload", "$BAL", nil, []string{"file", "statement_code"})
	check("POST /api/v1/promo-codes/redeem", "<hook-base>", nil, []string{"order_code", "promo_code"})
	check("GET https://api.partner.vn/open/feed/tasks/{}", "", []string{"x"}, nil)
	check("GET /cms/delivery/v1/entries/{}", "", []string{"include"}, nil)
	check("POST /admin/v1/marketplace/apps/installations", "", nil, []string{"app_id", "expected_build_id"})
	for k := range got {
		if strings.Contains(k, "revalidate") {
			t.Errorf("a made-up host's path: %s", k)
		}
	}
}

func strconvQuote(s string) string { b, _ := json.Marshal(s); return string(b) }

// FIN-03/04/05: FormData's fields; an array of objects' fields; a
// method called on an object, its body given at the call.
func TestFormArraysMethods(t *testing.T) {
	src := "async function yT(e,t){return fetch(`/${e}`,t)}function bT(e,t){return{method:e,body:JSON.stringify(t)}}" +
		"async function JT(e,t){let r=new FormData;r.append(`file`,t);return yT(`v1/apps/${e}/icon`,{method:`POST`,body:r})}" +
		"async function YT(e,t){return yT(`v1/apps/${e}/shots`,{method:`POST`,body:JSON.stringify({files:[{content_type:t.type,file_size:t.size}]})})}" +
		"async function sE(e,t,n){return yT(`v1/apps/${e}/members/${t}`,bT(`PUT`,n))}var QT=g({changeRole:()=>sE}),DD={auth:lE,members:QT};" +
		"async function go(e,t,s){await DD.members.changeRole(e,t.userId,{role:s})}" +
		"function Cr(e){let n=e.fetch;async function a(e,t,i){return n(`/c${t}`,{method:e,body:JSON.stringify(i)})}return{async sendNote(e,t){await a(`POST`,`/conversations/${e}/notes`,t)}}}" +
		"function P(){let c=(0,R.useMemo)(()=>Cr({fetch:f}),[f]);return{conversations:c}}" +
		"async function U(n,i,e,r){await n.conversations.sendNote(i,{message:e,data:r});JSON.stringify({x:1});Object.assign({},{a:1})}"
	got := byURL(Extract([]byte(src)))
	for k, want := range map[string][]string{
		"POST /v1/apps/{}/icon":          {"file"},
		"POST /v1/apps/{}/shots":         {"files.content_type", "files.file_size"},
		"PUT /v1/apps/{}/members/{}":     {"role"},
		"POST /c/conversations/{}/notes": {"data", "message"},
	} {
		if e, ok := got[k]; !ok || !slices.Equal(e.Body, want) {
			t.Errorf("%s: %+v in %v", k, e, eps(src))
		}
	}
}

// FIN-06: a client given a path of the page's origin (new Sy("/console-api"))
// makes whole URLs; one given it after a computed base (`${base}/console`)
// does not; a prefix both make stays relative to a base.
func TestOwnOriginClients(t *testing.T) {
	src := "var Sy=class{constructor(e){this.baseUrl=e}get(e){return fetch(`${this.baseUrl}${e}`)}};" +
		"var Cy=e=>new Sy(`${W.apiBaseUrl}${e}`),wy=e=>W.same?new Sy(e):Cy(e),Z=wy(`/api`),Ty=W.same?new Sy(`/console-api`):Cy(`/console`);" +
		"function a(e){return Ty.get(`/v1/apps/${e}`)}function b(){return Z.get(`/v1/me`)}"
	client := map[string]bool{}
	for _, e := range Extract([]byte(src)).Endpoints {
		if e.Kind == "client" {
			client[e.URL] = e.Client
		}
	}
	for u, want := range map[string]bool{"/console-api/v1/apps/{}": false, "/console/v1/apps/{}": true, "/api/v1/me": true} {
		if got, ok := client[u]; !ok || got != want {
			t.Errorf("%s: client %v (found %v) in %v", u, got, ok, client)
		}
	}
}

// FIN-21C (1): a method call is joined to a function of that name only
// through what the script holds: the receiver's chain of constants, or a
// receiver named as what holds the method, taking as many arguments.
func TestMethodsJoinedByName(t *testing.T) {
	lib := "function Cr(e){let n=e.fetch;return{async sendNote(e,t){await n(`/c/conversations/${e}/notes`,{method:`POST`,body:JSON.stringify(t)})}}}" +
		"function P(){let c=(0,R.useMemo)(()=>Cr({fetch:f}),[f]);return{conversations:c}}"
	for name, c := range map[string]struct {
		call string
		body bool
	}{
		"held":            {"async function U(n,i){await n.conversations.sendNote(i,{message:1,data:2})}", true},
		"unminified":      {"async function U(conversations,i){await conversations.sendNote(i,{message:1,data:2})}", true},
		"other receiver":  {"async function U(n,i){await n.tickets.sendNote(i,{message:1,data:2})}", false},
		"no parent":       {"async function U(n,i){await n.sendNote(i,{message:1,data:2})}", false},
		"more arguments":  {"async function U(n,i){await n.conversations.sendNote(i,{message:1,data:2},3)}", false},
		"fewer arguments": {"async function U(n,i){await n.conversations.sendNote({message:1,data:2})}", false},
	} {
		got := byURL(Extract([]byte(lib + c.call)))
		e := got["POST /c/conversations/{}/notes"]
		if has := slices.Equal(e.Body, []string{"data", "message"}); has != c.body {
			t.Errorf("%s: body %v, want joined %v", name, e.Body, c.body)
		}
	}
	// Two objects whose names hold a method of that name: neither.
	two := lib + "function Tr(){return{async sendNote(e,t){await fetch(`/t/${e}`,{method:`POST`,body:JSON.stringify(t)})}}}" +
		"var Q={conversations:Tr()};async function U(n,i){await n.conversations.sendNote(i,{message:1,data:2})}"
	if e := byURL(Extract([]byte(two)))["POST /c/conversations/{}/notes"]; len(e.Body) != 0 {
		t.Errorf("two holders: body %v", e.Body)
	}
	// A class's instance: this.api = new Api().
	cls := "class Api{async fetchUsers(e){return fetch(`/api/users`,{method:`POST`,body:JSON.stringify(e)})}}" +
		"class S{constructor(){this.api=new Api}async load(){await this.api.fetchUsers({page:1})}}"
	if e := byURL(Extract([]byte(cls)))["POST /api/users"]; !slices.Equal(e.Body, []string{"page"}) {
		t.Errorf("class: body %v", e.Body)
	}
}

// FIN-21C (4): a helper's parameters destructured ({baseUrl: e, body: n})
// are the properties of the object the call gives.
func TestDestructuredParams(t *testing.T) {
	src := "async function Gr({baseUrl:e,apiKey:t,body:n}){return fetch(`${e}/customer-profiles/webpush-subscription`,{method:`POST`,headers:{\"x-api-key\":t},body:JSON.stringify(n)})}" +
		"async function S(){let w={anonymous_id:a,device_id:b};await Gr({baseUrl:this.baseUrl,apiKey:k,body:w})}"
	e := byURL(Extract([]byte(src)))["POST {}/customer-profiles/webpush-subscription"]
	if !slices.Equal(e.Body, []string{"anonymous_id", "device_id"}) {
		t.Errorf("body %v in %v", e.Body, eps(src))
	}
}

// FIN-21C (3): a curl a comment says goes to a route that does not exist
// is no endpoint; one to a missing resource on a real route is.
func TestDocNoRoute(t *testing.T) {
	doc := "x=" + strconvQuote("## Lỗi\n```bash\n# 404 của gateway — route tồn tại, tài nguyên không\ncurl -sS \"$CMS_HOST/cms/delivery/v1/spaces/x/datasets/main/entries/x\"\n\n"+
		"# 404 của router — route KHÔNG tồn tại → text thuần\ncurl -sS \"$CMS_HOST/cms/delivery/v1/spaces/$SPACE/datasets/$DATASET/entries\"\n"+
		"# The endpoint does not exist\ncurl https://<host>/v1/nope/things\n```\n")
	got := byURL(Extract([]byte(doc)))
	if _, ok := got["GET /cms/delivery/v1/spaces/x/datasets/main/entries/x"]; !ok {
		t.Errorf("the real route is gone: %v", eps(doc))
	}
	for _, k := range []string{"GET /cms/delivery/v1/spaces/{}/datasets/{}/entries", "GET /v1/nope/things"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s kept: %v", k, eps(doc))
		}
	}
}

// FIN-21C (2): $SLINK_HOST a page uses without exporting it stays a name,
// for the page of the portal that exports it.
func TestDocVarsElsewhere(t *testing.T) {
	use := "x=" + strconvQuote("Delete it:\ncurl -X DELETE \"$SLINK_HOST/shortlinks/1042\"\n")
	r := Extract([]byte(use))
	e := byURL(r)["DELETE /shortlinks/{}"]
	if e.Base != "$SLINK_HOST" {
		t.Errorf("base %q in %v", e.Base, eps(use))
	}
	set := "a=" + strconvQuote("Set it:\nexport SLINK_HOST=\"https://api.example.biz/slink-integration/api/v1\"\ncurl -X POST \"$SLINK_HOST/shortlinks\"\n") + ";" + use
	r = Extract([]byte(set))
	if e := byURL(r)["DELETE /shortlinks/{}"]; e.Base != "https://api.example.biz/slink-integration/api/v1" {
		t.Errorf("same script: base %q", e.Base)
	}
	if len(r.DocVars) != 1 || r.DocVars[0].Name != "SLINK_HOST" {
		t.Errorf("doc vars %v", r.DocVars)
	}
}
