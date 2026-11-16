package jsapi

import (
	"slices"
	"testing"
)

// QAL-01b: this.x(…) is the method of the object the calling method is on;
// a Vue component's, its methods: {…} and a mixin's one of that name; a
// parameter left out is optional. this.fetchComponent of a class of the
// app's is read as what it does, not as fetch.
func TestThisMethods(t *testing.T) {
	src := "var ln={methods:{genBySection:function(e,n,t,o){var a=this,r=o||Object.assign({},this.form);r.start_index=e,r.end_index=n;this.$gateway.post(t,JSON.stringify(r)).then(function(){a.genBySection(r.end_index+1,n,t,o)})},getPrefixFromModel:function(e){this.$gateway.get(e)}}};" +
		"var C={mixins:[ln],data:function(){return{form:{model:1}}},created:function(){this.getPrefixFromModel(\"manufacturing-tool/v1.0/component/model?type=ecu\")},methods:{go:function(){this.genBySection(1,9,\"manufacturing-tool/v1.0/ecus/generation\")}}};" +
		"var D={methods:{getStats:function(e){this.getChartData(\"report/v1.0/dashboard/daily?tag=\"+e,e)},getChartData:function(e,n){this.$gateway.get(e)}}};" +
		"var E={methods:{getStats:function(e){this.getChartData(\"report/v1.0/dashboard/monthly\",e)},getChartData:function(e,n){this.$gateway.post(e,{n:n})}}};" +
		"class R{fetchComponent(e){return this.pageLoader.loadPage(e)}async onError(){await this.fetchComponent(\"/_error\")}}"
	got := byURL(Extract([]byte(src)))
	for k, body := range map[string][]string{
		"GET manufacturing-tool/v1.0/component/model":  nil,
		"POST manufacturing-tool/v1.0/ecus/generation": {"end_index", "model", "start_index"},
		"GET report/v1.0/dashboard/daily":              nil,
		"POST report/v1.0/dashboard/monthly":           {"n"},
	} {
		e, ok := got[k]
		if !ok || body != nil && !slices.Equal(e.Body, body) {
			t.Errorf("%s: %+v in %v", k, e, eps(src))
		}
	}
	for k := range got {
		if k == "GET /_error" {
			t.Errorf("this.fetchComponent read as fetch: %v", eps(src))
		}
	}
	// Two mixins defining it, the call in neither: no guess.
	two := "var a={methods:{genBySection:function(e,t){this.$gateway.post(t,{e:e})}}},b={methods:{genBySection:function(e,t){this.$gateway.put(t,{e:e})}}};" +
		"var C={methods:{go:function(){this.genBySection(1,\"x/v1.0/items/generation\")}}};"
	for k, e := range byURL(Extract([]byte(two))) {
		if e.URL == "x/v1.0/items/generation" && e.Method != "" {
			t.Errorf("%s: two definitions, one chosen", k)
		}
	}
}

// QAL-01a: fetch(e.url, {headers: e.headers}) has the headers its caller
// gives.
func TestHeadersFromCall(t *testing.T) {
	src := "async function Xe(e){return fetch(e.url,{method:e.method,headers:e.headers,body:JSON.stringify(e.body)})}" +
		"async function Ea({baseUrl:e,apiKey:t}){return Xe({url:`${e}/customer-profiles/webpush-public-key`,method:\"GET\",headers:{\"x-api-key\":t}})}"
	e := byURL(Extract([]byte(src)))["GET {}/customer-profiles/webpush-public-key"]
	if !slices.Equal(e.Headers, []string{"x-api-key"}) {
		t.Errorf("headers %v in %v", e.Headers, eps(src))
	}
}

// QAL-01c: a factory's base read off its options keeps its callers' path
// (Cr({apiBase: `${hub}/api/v1`})); a stream's reader is GET; an AI SDK
// transport's prepareSendMessagesRequest is a POST with its body.
func TestBaseFromCallersSSETransport(t *testing.T) {
	src := "function Cr(e){let t=e.apiBase.replace(/\\/$/,``),n=e.fetch,r=e=>`${t}${e}`;async function a(e,t,i){return n(r(t),{method:e,body:JSON.stringify(i)})}" +
		"return{list(){return a(`GET`,`/conversations`)},sendNote(e,t){return a(`POST`,`/conversations/${e}/notes`,t)},sendUrl(e){return r(`/conversations/${e}/messages/send`)},eventsUrl(e){return r(`/conversations/${e}/events`)}}}" +
		"function Rr(e){let{apiBase:t,fetchFn:i=globalThis.fetch}=e,o=t.replace(/\\/+$/,``);return{call(e){return i(`${o}/mcps/${e}/tools/call`,{method:`POST`,body:JSON.stringify({toolName:e})})}}}" +
		"var Fa=`text/event-stream`;function Ra(e,t){var{fetch:l}=t,u=Pa(t,[`fetch`]);let f={};f.accept||=Fa;let v=l??window.fetch;return v(e,Object.assign({},u,{headers:f}))}" +
		"function Co(e,t){return{prompt:e,clientMsgId:t.id,...t.x?{thinkingEnabled:t.x}:{}}}" +
		"function So(e){return new P({api:e.placeholderUrl,prepareSendMessagesRequest:async({messages:t})=>{let n=await e.ensure(),r=Co(t,{});return{api:e.buildSendUrl(n),body:r}}})}" +
		"function V(){let n=W(),i=`${n.endpoints.agentHub.replace(/\\/+$/,``)}/api/v1`,c=(0,R.useMemo)(()=>Cr({apiBase:i,fetch:f}),[i]),o=Rr({apiBase:i});" +
		"let ctx={conversations:c};So({placeholderUrl:ctx.conversations.sendUrl(`p`),buildSendUrl:e=>ctx.conversations.sendUrl(e)});Ra(ctx.conversations.eventsUrl(z),{fetch:f})}"
	got := byURL(Extract([]byte(src)))
	for k, kind := range map[string]string{
		"GET {}/api/v1/conversations":                   "wrapper",
		"POST {}/api/v1/conversations/{}/notes":         "wrapper",
		"POST {}/api/v1/mcps/{}/tools/call":             "wrapper",
		"GET {}/api/v1/conversations/{}/events":         "sse",
		"POST {}/api/v1/conversations/{}/messages/send": "transport",
	} {
		if e, ok := got[k]; !ok || e.Kind != kind {
			t.Errorf("%s: %+v in %v", k, e, eps(src))
		}
	}
	if e := got["POST {}/api/v1/conversations/{}/messages/send"]; !slices.Equal(e.Body, []string{"clientMsgId", "prompt", "thinkingEnabled"}) {
		t.Errorf("transport body %v", e.Body)
	}
}

// QAL-02: an analytics collector's URLs (one expression) take no base; a
// configuration file under a URL the caller gives is no API's.
func TestCollectorAndStaticJSON(t *testing.T) {
	src := "function jo(e){var t=e.endpoint,g=e.postPath===void 0?\"/com.snowplowanalytics.snowplow/tp2\":e.postPath,L=e.post;function B(){var N=L?g:\"/i\";return t+N}return fetch(B(),{method:\"POST\",body:JSON.stringify({schema:1,data:2})})}" +
		"async function Ay(e){let t=`${e.endsWith(\"/\")?e:`${e}/`}app-config.json`;return fetch(t)}"
	got := byURL(Extract([]byte(src)))
	for _, k := range []string{"POST {}/com.snowplowanalytics.snowplow/tp2", "POST {}/i"} {
		if e := got[k]; !e.Collector || !e.NoInheritBase {
			t.Errorf("%s: %+v in %v", k, e, eps(src))
		}
	}
	if e := got["GET {}/app-config.json"]; !e.NoInheritBase {
		t.Errorf("app-config: %+v in %v", e, eps(src))
	}
}

// QAL-03: a path's names, a field's type and values, a lookup's values;
// an OpenAPI document's parameters.
func TestParamSpecs(t *testing.T) {
	src := "function f(tenantId,e){return fetch(`/api/tenants/${tenantId}/apps/${encodeURIComponent(e.appSlug)}`,{method:\"POST\",body:JSON.stringify({name:\"x\",count:2,on:!0,tags:e.t.map(x=>x),period:{day:\"daily\",month:\"monthly\"}[e.p]})})}"
	e := byURL(Extract([]byte(src)))["POST /api/tenants/{}/apps/{}"]
	want := map[string]ParamSpec{
		"path/tenantId": {Name: "tenantId", In: "path", Position: 0, Type: "string", Required: true},
		"path/appSlug":  {Name: "appSlug", In: "path", Position: 1, Type: "string", Required: true},
		"body/name":     {Name: "name", In: "body", Type: "string", Values: []string{"x"}, Required: true},
		"body/count":    {Name: "count", In: "body", Type: "number", Values: []string{"2"}, Required: true},
		"body/on":       {Name: "on", In: "body", Type: "boolean", Values: []string{"true"}, Required: true},
		"body/tags":     {Name: "tags", In: "body", Type: "array"},
		"body/period":   {Name: "period", In: "body", Type: "string", Values: []string{"daily", "monthly"}},
	}
	for _, p := range e.Params {
		w, ok := want[p.In+"/"+p.Name]
		if !ok {
			continue
		}
		delete(want, p.In+"/"+p.Name)
		if p.Position != w.Position || p.Type != w.Type || !slices.Equal(p.Values, w.Values) || p.Required != w.Required {
			t.Errorf("%s: %+v, want %+v", p.Name, p, w)
		}
	}
	if len(want) > 0 {
		t.Errorf("missing %v in %+v", want, e.Params)
	}
	spec := "openapi: 3.0.0\npaths:\n  /v1/apps/{app_id}/members:\n    post:\n      parameters:\n        - {name: app_id, in: path, required: true, schema: {type: string}}\n        - {name: page_size, in: query, schema: {type: integer, default: 20}}\n" +
		"      requestBody:\n        content:\n          application/json:\n            schema:\n              type: object\n              required: [role]\n              properties:\n                role: {type: string, enum: [admin, member]}\n"
	r := ExtractOpenAPI([]byte(spec))
	if len(r.Endpoints) != 1 {
		t.Fatalf("openapi: %+v", r)
	}
	got := map[string]ParamSpec{}
	for _, p := range r.Endpoints[0].Params {
		got[p.In+"/"+p.Name] = p
	}
	if p := got["path/app_id"]; !p.Required || p.Type != "string" {
		t.Errorf("app_id %+v", p)
	}
	if p := got["query/page_size"]; p.Type != "number" || !slices.Equal(p.Values, []string{"20"}) {
		t.Errorf("page_size %+v", p)
	}
	if p := got["body/role"]; !p.Required || !slices.Equal(p.Values, []string{"admin", "member"}) {
		t.Errorf("role %+v", p)
	}
}

// QAL-04: what documents say beyond a method and a path.
func TestDocsContext(t *testing.T) {
	doc := "## Preview\n```bash\ncurl -sS \"$CMS_HOST/cms/preview/v1/entries/$ENTRY_ID?include=2\" \\\n  -H \"X-API-Key: $KEY\" \\\n  -H \"X-PREVIEW-TOKEN: $TOKEN\" \\\n  -H \"Accept: application/json\"\n```\n" +
		"export CMS_HOST=\"https://api.ecom-dev.example.services\"\n\n| Env | Host |\n| --- | --- |\n| dev | `https://api.ecom-dev.example.services` |\n| prd | `https://api.ecom.example.services` |\n\n" +
		"## Scan\n```http\nPOST /developer/v1/apps/update-build-status\nX-CI-TOKEN: <job-token>\nContent-Type: application/json\n```\n\nBody:\n\n```json\n{\"build_id\": \"370d\", \"scan_status\": \"success\"}\n```\n\n" +
		"## List\n```http\nGET /developer/v1/apps\n```\n\nResponse:\n\n```json\n{\"items\": [{\"app_id\": \"a\"}]}\n```\n\n" +
		"Các lời gọi còn lại nằm dưới `{agentHub}/api/v1`:\n\n| Mục đích | Phương thức & đường dẫn |\n|---|---|\n| Danh sách / tạo | `GET` / `POST /conversations` |\n\n" +
		"Client delivery mặc định `next: { revalidate: 60 }`. Chờ hết cửa sổ ISR, hoặc gọi `POST /api/revalidate?path=…`.\n"
	r := Extract([]byte("var d=" + strconvQuote(doc) + ";"))
	got := byURL(r)
	if e := got["GET /cms/preview/v1/entries/{}"]; !slices.Equal(e.Headers, []string{"X-API-Key", "X-PREVIEW-TOKEN"}) || e.Base != "https://api.ecom.example.services" {
		t.Errorf("curl -H / prd: %+v", e)
	}
	if e := got["POST /developer/v1/apps/update-build-status"]; !slices.Equal(e.Headers, []string{"X-CI-TOKEN"}) || !slices.Equal(e.Body, []string{"build_id", "scan_status"}) {
		t.Errorf("http block: %+v", e)
	}
	if e := got["GET /developer/v1/apps"]; len(e.Query) != 0 {
		t.Errorf("a response read as the request: %+v", e)
	}
	for _, k := range []string{"GET /api/v1/conversations", "POST /api/v1/conversations"} {
		if e, ok := got[k]; !ok || e.Base != "<agentHub>" {
			t.Errorf("%s: %+v in %v", k, e, got)
		}
	}
	if _, ok := got["POST /api/revalidate"]; ok {
		t.Errorf("the integrator's ISR route kept")
	}
	// A page compiled to strings: the request alone, its data in the next.
	mdx := "a=[" + strconvQuote("POST https://<auth-host>/v1/oauth/token\nContent-Type: application/x-www-form-urlencoded\n") + "," + strconvQuote("\n") + "," +
		strconvQuote("grant_type=client_credentials\nclient_id=<client_id>\nclient_secret=<client_secret>\n") + "]"
	e := byURL(Extract([]byte(mdx)))["POST /v1/oauth/token"]
	if e.Base != "<auth-host>" || !slices.Equal(e.Body, []string{"client_id", "client_secret", "grant_type"}) {
		t.Errorf("mdx http: %+v", e)
	}
	if ProdOf("https://api.ecom-dev.example.services", []string{"https://api.ecom.example.services"}) != "https://api.ecom.example.services" ||
		ProdOf("https://api.ecom-dev.example.services", nil) != "" {
		t.Errorf("ProdOf")
	}
}

// A path that names its parameter (by-slug/{}) has it when the code's name
// is a minifier's.
func TestSlotNames(t *testing.T) {
	src := "async function Qg(e,t){return Ty.get(`/v1/apps/by-slug/${encodeURIComponent(e)}/x/${t}`)}"
	for _, e := range Extract([]byte(src)).Endpoints {
		if e.URL != "/v1/apps/by-slug/{}/x/{}" {
			continue
		}
		if len(e.Params) != 1 || e.Params[0].Name != "slug" || e.Params[0].Position != 0 {
			t.Errorf("%+v", e.Params)
		}
		return
	}
	t.Errorf("no endpoint in %v", eps(src))
}
