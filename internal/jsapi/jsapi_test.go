package jsapi

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// one returns the endpoints of src as "METHOD URL kind", sorted.
func eps(src string) []string {
	r := Extract([]byte(src))
	var out []string
	for _, e := range r.Endpoints {
		out = append(out, strings.TrimSpace(fmt.Sprintf("%s %s %s", e.Method, e.URL, e.Kind)))
	}
	slices.Sort(out)
	return out
}

func find(t *testing.T, src, method, url string) Endpoint {
	t.Helper()
	r := Extract([]byte(src))
	if r.Error != "" {
		t.Fatalf("parse: %s", r.Error)
	}
	for _, e := range r.Endpoints {
		if e.Method == method && e.URL == url {
			return e
		}
	}
	t.Fatalf("no %s %s in %v", method, url, eps(src))
	return Endpoint{}
}

func TestIdioms(t *testing.T) {
	cases := []struct {
		name, src, method, url, kind string
		query, body, headers         []string
	}{
		{"fetch with a template and URLSearchParams", "const a='/api';function f(t,p){return fetch(`${a}/articles?`+new URLSearchParams({tag:t,offset:p}))}",
			"GET", "/api/articles", "fetch", []string{"offset", "tag"}, nil, nil},
		{"fetch POST with a JSON body", `fetch("/api/articles",{method:"post",headers:{"Content-Type":"application/json"},body:JSON.stringify({article:{title:t,body:b},draft:!0})})`,
			"POST", "/api/articles", "fetch", nil, []string{"article.body", "article.title", "draft"}, []string{"Content-Type"}},
		{"fetch with a computed method", `fetch("/api/x",{method:m})`, "", "/api/x", "fetch", nil, nil, nil},
		{"client method with a base elsewhere", "r.LV.post(`/profiles/${e}/follow`,{note:n},{params:{v:1},headers:{'X-A':1}})",
			"POST", "/profiles/{}/follow", "client", []string{"v"}, []string{"note"}, []string{"X-A"}},
		{"wrapper taking the method", `(0,r.Em)("DELETE","/api/articles/"+e)`, "DELETE", "/api/articles/{}", "wrapper", nil, nil, nil},
		{"options object, jQuery style", `i({url:"/api/tags",type:"POST",data:{a:1}})`, "POST", "/api/tags", "options", nil, []string{"a"}, nil},
		{"XHR with send and a header", `const x=new XMLHttpRequest;x.open("PUT","/api/c/"+id);x.setRequestHeader("X-T","1");x.send(JSON.stringify({c:{body:b}}))`,
			"PUT", "/api/c/{}", "xhr", nil, []string{"c.body"}, []string{"X-T"}},
		{"a helper that fetches its argument", `const s=(e,t)=>fetch(e,{method:"POST",body:new URLSearchParams(t)});s("/api/users/login",{email:a,password:b})`,
			"POST", "/api/users/login", "wrapper", nil, []string{"email", "password"}, nil},
		{"a helper declared as a function", `function r(e,t,n){return fetch(t,{method:e,body:n&&JSON.stringify(n)})}r("PUT","/api/s",{on:1})`,
			"PUT", "/api/s", "wrapper", nil, []string{"on"}, nil},
		{"WebSocket on the page's host", `new WebSocket(("https:"===location.protocol?"wss://":"ws://")+location.host+"/ws/notes")`,
			"", "/ws/notes", "websocket", nil, nil, nil},
		{"EventSource", `new EventSource("/api/events?channel="+encodeURIComponent(c))`, "GET", "/api/events", "sse", []string{"channel"}, nil, nil},
		{"sendBeacon", `navigator.sendBeacon("/api/t",JSON.stringify({event:e}))`, "POST", "/api/t", "beacon", nil, []string{"event"}, nil},
		{"window.open", `window.open("/api/export/pdf?id="+i)`, "GET", "/api/export/pdf", "navigation", []string{"id"}, nil, nil},
		{"location.href", `location.href="/logout?next="+n`, "GET", "/logout", "navigation", []string{"next"}, nil, nil},
		{"a table of endpoints", `const E={up:"/api/uploads"};fetch(E.up,{method:"POST",body:f})`, "POST", "/api/uploads", "fetch", nil, nil, nil},
		{"concat", `fetch("/api/".concat(v,"/items"))`, "GET", "/api/{}/items", "fetch", nil, nil, nil},
		{"new URL on the origin", `fetch(new URL("/api/u",location.origin))`, "GET", "/api/u", "fetch", nil, nil, nil},
		{"absolute URL", `fetch("https://api.example.com/v2/status")`, "GET", "https://api.example.com/v2/status", "fetch", nil, nil, nil},
		{"Angular-style service", "this.http.get(`${this.config.apiUrl}/profiles/${u}`)", "GET", "{}/profiles/{}", "client", nil, nil, nil},
		{"relative path in fetch", `fetch("data/items.json")`, "GET", "data/items.json", "fetch", nil, nil, nil},
		{"string with an API path", `const u="/api/v1/admin/users";`, "", "/api/v1/admin/users", "string", nil, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := find(t, c.src, c.method, c.url)
			if e.Kind != c.kind || !slices.Equal(e.Query, c.query) || !slices.Equal(e.Body, c.body) || !slices.Equal(e.Headers, c.headers) {
				t.Fatalf("got %+v", e)
			}
		})
	}
}

func TestGraphQL(t *testing.T) {
	src := `fetch("/graphql",{method:"POST",body:JSON.stringify({query:"mutation Fav($s: String!) { favorite(slug: $s) { slug } }",variables:{s}})});
const Q=gql` + "`query FeedQuery { feed { id } }`"
	r := Extract([]byte(src))
	e := find(t, src, "POST", "/graphql")
	if !slices.Equal(e.Operations, []string{"mutation Fav"}) || !slices.Contains(e.Body, "variables.s") {
		t.Fatalf("graphql call: %+v", e)
	}
	if !slices.Equal(r.Operations, []string{"query FeedQuery"}) {
		t.Fatalf("operations on their own: %v", r.Operations)
	}
}

// Strings that look like paths and are not endpoints.
func TestNoise(t *testing.T) {
	src := `const n={icon:"M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z",t:["application/json","text/plain","image/svg+xml"],d:"yyyy/mm/dd",r:"2026/11/03",
svg:"http://www.w3.org/2000/svg",m:"./utils/format.js",ratio:"16/9",copy:"Read and/or write",u:"https://react.dev/errors/",x:"http://n",a:"https://a@b"};
p.startsWith("/api/");m.get("@babel/plugin-x/version");require("json/parse");console.error("see https://react.dev/link/hydration-mismatch");
fetch("/static/js/main.js");join(d,"package.json");r.u=e=>"static/js/"+e+".chunk.js";`
	if got := eps(src); len(got) != 0 {
		t.Fatalf("noise reported: %v", got)
	}
}

func TestRoutes(t *testing.T) {
	src := `const R=[{path:"/settings"},{path:"/editor/:slug"}];history.pushState(null,"","/profile/"+u);navigate("/account/billing")`
	r := Extract([]byte(src))
	if len(r.Endpoints) != 0 || !slices.Equal(r.Routes, []string{"/account/billing", "/editor/:slug", "/profile/{}", "/settings"}) {
		t.Fatalf("endpoints %v, routes %v", eps(src), r.Routes)
	}
}

// Constants are read in their own scope: a name used again in another
// function is another variable.
func TestScope(t *testing.T) {
	src := `const a="/api";function f(){const a=g();return fetch(a+"/x")}function h(){return fetch(a+"/y")}let b="/v1";b="/v2";fetch(b+"/z");` +
		`for(let i=0;i<4;i++)fetch("/api/upload/"+i,{method:"PUT"});let k=1;k*=2;fetch("/api/k/"+k)`
	got := eps(src)
	// b is set twice: both of its values are URLs it may hold.
	want := []string{"GET /api/k/{} fetch", "GET /api/y fetch", "GET /v1/z fetch", "GET /v2/z fetch", "GET {}/x fetch", "PUT /api/upload/{} fetch"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestBasesAndPlaces(t *testing.T) {
	src := "const c=mk({baseURL:\"/api/\"});\nc.get(\"/a/one\");\nc.get(\"/a/one\",x)"
	r := Extract([]byte(src))
	if !slices.Equal(r.Bases, []string{"/api"}) {
		t.Fatalf("bases %v", r.Bases)
	}
	e := find(t, src, "GET", "/a/one")
	if !e.Client || e.Line != 2 || e.Col != 7 || !strings.Contains(e.Snippet, `c.get("/a/one")`) {
		t.Fatalf("%+v", e)
	}
}

func TestParseError(t *testing.T) {
	r := Extract([]byte(`fetch("/api/x" {`))
	if r.Error == "" || len(r.Endpoints) != 0 {
		t.Fatalf("%+v", r)
	}
	// A huge script made of one long string is not a problem.
	big := `fetch("/api/` + strings.Repeat("a", 1<<20) + `")`
	if r := Extract([]byte(big)); r.Error != "" || len(r.Endpoints) != 0 {
		t.Fatalf("big: %s %d", r.Error, len(r.Endpoints))
	}
}

// Paths are the strings a frontier visits: a.href = "/x", links written
// as HTML, absolute URLs; never the noise, the routes or the endpoints.
func TestPaths(t *testing.T) {
	src := `var domain="http://app.test/";var path="test/concat.found";var full=domain+path;a.href="/score/links/02";el.innerHTML='<a href="/score/js/01">x</a><img src=\'/img/a.png\'>';` +
		`const u="https://app.test/docs/intro";const R=[{path:"/settings"}];fetch("/api/x");` +
		"const t=`/page/${n}`;const s=`/fixed/page`;" +
		// HTML written in a template, its attribute unquoted around a
		// substitution: no "/items/${" (Reviewer NEW-4.6-01: the joined parts
		// read "/items/${}", which holds the unknown "{}" and is dropped).
		"el.innerHTML=`<a href=/items/${id}>x</a><a href=\"/about\">a</a>`;" +
		`const n={icon:"M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z",t:"application/json",d:"2026/11/03",m:"./utils/format.js",r:"16/9",` +
		`w:"http://www.w3.org/2000/svg",j:"/static/js/main.js",c:"Read and/or write",h:"http://n"}`
	r := Extract([]byte(src))
	want := []string{"/about", "/fixed/page", "/score/js/01", "/score/links/02", "http://app.test/", "http://app.test/test/concat.found", "https://app.test/docs/intro"}
	if !slices.Equal(r.Paths, want) {
		t.Fatalf("paths %v, want %v", r.Paths, want)
	}
}

// Round 15 (OPT-01..07): the idioms of a Vue 2 admin bundle (Babel, an
// axios client whose base is computed), as minified admin apps often do.
func TestVueAdminIdioms(t *testing.T) {
	cases := []struct {
		name, src, method, url string
		query, body            []string
	}{
		{"replace fills a template", `this.$gateway.delete("system-user/v1.0/admin/roles/{id}".replace("{id}",this.r.id))`,
			"DELETE", "system-user/v1.0/admin/roles/{}", nil, nil},
		{"replace through a variable", `var n="system-user/v1.0/admin/system-users/{system_user_id}/status".replace("{system_user_id}",u.id);this.$gateway.put(n,t)`,
			"PUT", "system-user/v1.0/admin/system-users/{}/status", nil, nil},
		{"replace with a plain regexp", `var t="report/v1.0/report-vehicle";this.$gateway.get(t.replace(/report-vehicle/g,"export-vehicle"))`,
			"GET", "report/v1.0/export-vehicle", nil, nil},
		{"a leading slash keeps its method", `this.$gateway.put("/customer/v1.0/admin/no-scu/{vin}/visible".replace("{vin}",v),b)`,
			"PUT", "/customer/v1.0/admin/no-scu/{}/visible", nil, nil},
		{"+= and a query builder", `function f(e){var t="charge-point/v1.0/admin/firmwares/search?query=";this.q&&(t+="".concat(this.q));` +
			`t=new be.a(t).ctx(e).sortBy("x").toRequest(),t="".concat(t,"&size=").concat(e.perPage,"&page=").concat(e.p);return this.$gateway.get(t)}`,
			"GET", "charge-point/v1.0/admin/firmwares/search", []string{"page", "query", "size"}, nil},
		{"a lookup on a computed key", `var t={original:"v1.0/system-user/oauth/token",ldap:"v1.0/ldap/oauth/token"};this.$gateway.post(t[this.loginType],to.stringify(this.loginForm))`,
			"POST", "v1.0/ldap/oauth/token", nil, nil},
		{"this.<prop> set elsewhere", `a={methods:{open:function(e){this.detailUrl="manufacturing-tool/v1.0/charging-station/".concat(e.id)}}};` +
			`b={methods:{get:function(){this.$gateway.get(this.detailUrl)}}}`,
			"GET", "manufacturing-tool/v1.0/charging-station/{}", nil, nil},
		{"qs.stringify of data()'s form", `c={data:function(){return{loginForm:{grant_type:"password",username:"",password:""}}},` +
			`methods:{login:function(){this.$gateway.post("v1.0/system-user/oauth/token",to.stringify(this.loginForm))}}}`,
			"POST", "v1.0/system-user/oauth/token", nil, []string{"grant_type", "password", "username"}},
		{"a relative versioned path in an app's helper", `this.getChartData("report/v1.0/dashboard/counter-reporting/daily-reporting",x)`,
			"", "report/v1.0/dashboard/counter-reporting/daily-reporting", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := find(t, c.src, c.method, c.url)
			for _, q := range c.query {
				if !slices.Contains(e.Query, q) {
					t.Errorf("query %v, want %s", e.Query, q)
				}
			}
			for _, b := range c.body {
				if !slices.Contains(e.Body, b) {
					t.Errorf("body %v, want %s", e.Body, b)
				}
			}
		})
	}
	// Both values of a lookup, both sides of a ?:, both branches of an if.
	both := `var t={original:"v1.0/system-user/oauth/token",ldap:"v1.0/ldap/oauth/token"};this.$gateway.post(t[k],b);` +
		`this.$gateway.get(m?"scooter/v1.0/scooters-max/{id}/iot-device/report".replace("{id}",i):la.replace("{thing_name}",i));var la="scooter/v1.0/scooters/{thing_name}/iot-device/report";` +
		`var t2="charge-point/v1.0/charge-points/admin/search?query=a;";this.isEbus&&(t2="charging-station-ebus/v1.0/charging-stations/admin/search?query=b");this.$gateway.get(t2)`
	got := eps(both)
	for _, w := range []string{"POST v1.0/system-user/oauth/token client", "POST v1.0/ldap/oauth/token client",
		"GET scooter/v1.0/scooters-max/{}/iot-device/report client", "GET scooter/v1.0/scooters/{}/iot-device/report client",
		"GET charge-point/v1.0/charge-points/admin/search client", "GET charging-station-ebus/v1.0/charging-stations/admin/search client"} {
		if !slices.Contains(got, w) {
			t.Errorf("no %q in %v", w, got)
		}
	}
	// if/else branches that both append: the value is one or the other,
	// never the value before them ("…/detailsize={}").
	src := `var o="cp/v1.0/req/{id}/detail".replace("{id}",t);""!==q?o+="?query=".concat(q,"&"):o+="?",o="".concat(o,"size=").concat(n);this.$gateway.get(o)`
	for _, e := range eps(src) {
		if strings.Contains(e, "size") || !strings.HasSuffix(e, "client") {
			t.Errorf("branches read in a row: %v", eps(src))
		}
	}
	if e := find(t, src, "GET", "cp/v1.0/req/{}/detail"); !slices.Equal(e.Query, []string{"query", "size"}) {
		t.Errorf("query %v", e.Query)
	}
}

// A counter or a store's action name is no URL.
func TestVueNoise(t *testing.T) {
	src := `c="".concat("app","/setDeviceState"),s="".concat("app","/setLoginData");for(var i=0;i<3;i++)g.get("/api/x/"+i);require("json/parse")`
	r := Extract([]byte(src))
	if len(r.Routes) != 0 || len(r.Paths) != 0 {
		t.Fatalf("routes %v paths %v", r.Routes, r.Paths)
	}
	if got := eps(src); !slices.Equal(got, []string{"GET /api/x/{} client"}) {
		t.Fatalf("got %v", got)
	}
}

// A client whose baseURL the code computes: the API's root among its
// strings is the candidate, not a page's route.
func TestDynamicBase(t *testing.T) {
	src := `var cfg={urls:te()({},qn.c.API,"".concat("/","api-gateway/"))};var R=[{path:"/api-error-log"}];` +
		`var n=To.a.create({baseURL:e.getURL(qn.c.API),headers:{Accept:"application/json"}});n.get("customer/v1.0/x")`
	r := Extract([]byte(src))
	if !slices.Equal(r.Bases, []string{"/api-gateway"}) {
		t.Fatalf("bases %v", r.Bases)
	}
	if slices.Contains(r.Routes, "/api-gateway/") {
		t.Fatalf("a base read as a route: %v", r.Routes)
	}
	// A literal base wins: no guessing then.
	if r := Extract([]byte(`var n=mk({baseURL:"/api/"});var u="/gateway/";m({baseURL:g()})`)); !slices.Equal(r.Bases, []string{"/api"}) {
		t.Fatalf("bases %v", r.Bases)
	}
}

// Headers a client adds to every request, and cloud storage.
func TestClientHeadersAndCloud(t *testing.T) {
	src := "n.interceptors.request.use(function(e){var n=Ko();return n&&(e.headers.Authorization=\"Bearer \".concat(n)),\n" +
		`e.headers.client_id="WEBADMIN1",e.headers.client_secret="S3CR3T",e.headers["accept-language"]=L.code,e.headers.app_version=1.14,e});` +
		`ax.defaults.headers.common["X-Api-Key"]="k1";var tpl="https://assets-bucket.s3.ap-southeast-1.amazonaws.com/web-template/sample.XLSX";` +
		"var g=`https://storage.googleapis.com/b/${f}`;var a='https://acct.blob.core.windows.net/c/x.png';var not='https://example.com/s3.amazonaws.com.html'"
	r := Extract([]byte(src))
	want := map[string]string{"Authorization": "Bearer {}", "client_id": "WEBADMIN1", "client_secret": "S3CR3T", "accept-language": "{}", "app_version": "1.14", "X-Api-Key": "k1"}
	if len(r.ClientHeaders) != len(want) {
		t.Fatalf("headers %+v", r.ClientHeaders)
	}
	for _, h := range r.ClientHeaders {
		if want[h.Name] != h.Value {
			t.Errorf("%s = %q, want %q", h.Name, h.Value, want[h.Name])
		}
		if h.Name == "client_secret" && h.Line != 2 {
			t.Errorf("line %d", h.Line)
		}
	}
	wantCloud := []string{"https://acct.blob.core.windows.net/c/x.png", "https://assets-bucket.s3.ap-southeast-1.amazonaws.com/web-template/sample.XLSX", "https://storage.googleapis.com/b/"}
	if !slices.Equal(r.Cloud, wantCloud) {
		t.Fatalf("cloud %v", r.Cloud)
	}
}

// Ajv's standalone validator, verbatim from a real bundle (a HAR schema):
// its error objects hold JSON pointers, never URLs.
func TestJSONPointersAreNoPaths(t *testing.T) {
	src := "function v(e,{instancePath:t=``}={}){if(e.wait!==void 0){if(typeof e.wait!=`number`)return j.errors=[{instancePath:t+`/timings/wait`,schemaPath:`timings.json#/properties/wait/type`,keyword:`type`}],!1}" +
		"if(typeof e.cookies!=`object`)return O.errors=[{instancePath:t+`/postData/params/comment`,schemaPath:`#/properties/cookies/type`}],!1;" +
		"return fetch(`/real/page`),!0}"
	r := Extract([]byte(src))
	for _, p := range r.Paths {
		if strings.Contains(p, "timings") || strings.Contains(p, "postData") || strings.Contains(p, "properties") {
			t.Fatalf("a JSON pointer taken as a path: %v", r.Paths)
		}
	}
	if len(r.Endpoints) != 1 || r.Endpoints[0].URL != "/real/page" {
		t.Fatalf("endpoints %+v", r.Endpoints)
	}
}
