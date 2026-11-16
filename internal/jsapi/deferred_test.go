package jsapi

import (
	"slices"
	"strings"
	"testing"
)

// Round 27B: what a module's URL builder makes of arguments, read once
// (PrepareModule) and evaluated many times: the tests it makes of them
// decided on the values (key in table, a function's test, ?:, literals,
// list.includes over a list the code writes), and undecided tests with
// known arguments giving nothing.
func TestModuleEvalBuilder(t *testing.T) {
	src := "var tbl={app_tokens:`/auth/tokens`};" +
		"var meta={data:[{name:`app_users`},{name:`app_roles`}]};var SYS=meta.data.map(e=>e.name);var LIT=[`app_files`];" +
		"function isSys(e){return e.startsWith(`app_`)?SYS.includes(e)||LIT.includes(e):!1}" +
		"function endpointFor(e){return e in tbl?tbl[e]:isSys(e)?`/${e.substring(4)}`:`/records/${e}`}" +
		"function pick(e){return window.flags.v2?`/v2/x/${e}`:`/v1/x/${e}`}" +
		"function always(e){return !0?`/on/${e}`:`/off/${e}`}" +
		"export{endpointFor as eF,pick as pk,always as al};"
	m := PrepareModule([]byte(src))
	if m == nil {
		t.Fatal("not prepared")
	}
	for _, c := range []struct {
		name string
		args [][]string
		want []string
	}{
		{"eF", [][]string{{"app_roles"}}, []string{"/roles"}},        // a system name: SYS from a map
		{"eF", [][]string{{"app_files"}}, []string{"/files"}},        // || and an array literal
		{"eF", [][]string{{"app_tokens"}}, []string{"/auth/tokens"}}, // key in table
		{"eF", [][]string{{"app_other"}}, []string{"/records/app_other"}},
		{"eF", [][]string{{"posts"}}, []string{"/records/posts"}},
		{"eF", [][]string{{"posts"}, {"extra"}}, []string{"/records/posts"}},
		{"pk", [][]string{{"gadget"}}, nil},                                        // undecided with a known argument: nothing
		{"al", [][]string{{"x"}}, []string{"/on/x"}},                               // !0
		{"eF", [][]string{{"{}"}}, []string{"/auth/tokens", "/{}", "/records/{}"}}, // unknown: every way
		{"nope", [][]string{{"x"}}, nil},
	} {
		got := m.EvalBuilder(c.name, c.args)
		slices.Sort(got)
		want := slices.Clone(c.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s(%v) = %v, want %v", c.name, c.args, got, want)
		}
	}
}

// The caller's side: a request whose URL calls an imported function is
// deferred with its arguments, and its client's prefix (Deferred.Pre)
// when the call leads the URL; calls in a navigation, or inside another
// function the URL calls, are not.
func TestDeferredRecorded(t *testing.T) {
	src := "import{eF as ep,other}from\"./shared.js\";var api=axios.create({baseURL:`/api`});" +
		"function local(c){return `/x/${other(c)}`}" +
		"export const a=id=>api.get(`${ep(`app_roles`)}/${id}`);" +
		"export const b=id=>fetch(`/v2${ep(id)}`,{method:`DELETE`});" +
		"export const c=k=>api.get(local(k));" +
		"export const d=(r,c)=>r.push(`${ep(c)}/new`);"
	r := Extract([]byte(src))
	if len(r.Builders) != 0 {
		t.Errorf("builders %v", r.Builders)
	}
	byURL := map[string]Deferred{}
	for _, d := range r.Deferred {
		byURL[d.Method+" "+d.URL] = d
	}
	if d, ok := byURL["GET "+DeferredSlot+"/{}"]; !ok || !slices.EqualFunc(d.Args, [][]string{{"app_roles"}}, slices.Equal[[]string]) || !slices.Equal(d.Pre, []string{"/api"}) || d.Module != "./shared.js" || d.Name != "eF" {
		t.Errorf("a: %+v (all %v)", d, r.Deferred)
	}
	if d, ok := byURL["DELETE /v2"+DeferredSlot]; !ok || len(d.Pre) != 0 {
		t.Errorf("b: %+v (all %v)", d, r.Deferred)
	}
	if len(r.Deferred) != 2 {
		t.Errorf("deferred %v: want a and b only (not the navigation, not inside local())", r.Deferred)
	}
}

// The exporting side: a function that writes a path of its own is a
// builder; one that only joins a base it holds is not.
func TestBuildersRecorded(t *testing.T) {
	src := "var B=`https://api.example.test`;function withBase(e){return B+e}" +
		"function forName(e){return `/records/${e}`}export{withBase as wb,forName as fn};export function two(a,b){return `/alpha/${a}/beta/${b}`}"
	var names []string
	for _, b := range Extract([]byte(src)).Builders {
		names = append(names, b.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"fn", "two"}) {
		t.Errorf("builders %v, want [fn two]", names)
	}
}

// Round 27D: a function returning a URL built on the base the script's
// requests are built on (an SDK's getFilePreview, for an <img src>) is a
// GET of kind "url"; a router's link or a static asset's path, on no
// request's base, is not; a request's own method is listed once.
func TestURLReturningMethods(t *testing.T) {
	src := `
class Client { constructor(c){ this.config = c; } call(m, u, h, p){ return fetch(u, {method: m}); } }
class Storage {
  constructor(client){ this.client = client; }
  listFiles(b){ const apiPath = "/storage/buckets/{b}/files".replace("{b}", b); const uri = new URL(this.client.config.endpoint + apiPath); return this.client.call("get", uri, {}, {}); }
  getFilePreview(b, f){ const apiPath = "/storage/buckets/{b}/files/{f}/preview".replace("{b}", b).replace("{f}", f); const uri = new URL(this.client.config.endpoint + apiPath); uri.searchParams.append("project", this.client.config.project); return uri.toString(); }
  getFileView(b, f){ const uri = new URL(this.client.config.endpoint + "/storage/buckets/" + b + "/files/" + f + "/view"); return uri.href; }
  getFileDownload(b, f){ return ` + "`${this.client.config.endpoint}/storage/buckets/${b}/files/${f}/download`" + `; }
  link(id){ return ` + "`/settings/files/${id}`" + `; }
  thumb(name){ return this.client.config.cdn + "/img/" + name + ".png"; }
  short(id){ return this.base + "/x/" + id; }
}
export const storage = new Storage(new Client({ endpoint: window.API }));
`
	got := map[string]string{}
	for _, e := range Extract([]byte(src)).Endpoints {
		got[e.Method+" "+e.URL] = e.Kind
	}
	for _, want := range []string{"GET {}/storage/buckets/{}/files/{}/preview", "GET {}/storage/buckets/{}/files/{}/view", "GET {}/storage/buckets/{}/files/{}/download"} {
		if got[want] != "url" {
			t.Errorf("%s: kind %q (all %v)", want, got[want], got)
		}
	}
	for k, kind := range got {
		if kind == "url" && (strings.Contains(k, "settings") || strings.Contains(k, "/img/") || strings.Contains(k, "/x/") || strings.HasSuffix(k, "/files")) {
			t.Errorf("%s taken for a URL a function returns", k)
		}
	}
}

// Review of 27D: the forms of a URL's base the first version missed (.href
// on new URL(…) itself, new URL(path, base)), a minified bundle's
// parameters of one name in unrelated functions (not the same base), and
// the URL's place found from the start of the script, not from where the
// calls pass ended.
func TestURLReturningForms(t *testing.T) {
	pad := "/*" + strings.Repeat(" ", 300) + "*/\n" // pieces of one URL are not looked for across methods
	src := "class S{constructor(c){this.client=c}\n" +
		"list(b){return this.client.call(`get`,new URL(`/storage/buckets/`+b+`/files`,this.client.config.endpoint))}" + pad +
		"view(b,f){return new URL(this.client.config.endpoint+`/storage/buckets/`+b+`/files/`+f+`/view`).href}" + pad +
		"pre(b,f){return new URL(`/storage/buckets/`+b+`/files/`+f+`/preview`,this.client.config.endpoint).toString()}" + pad +
		"get(b){return this.client.call(`get`,new URL(this.client.config.endpoint+`/storage/buckets/`+b))}}\n" +
		"function q(e){return fetch(e.config.url+`/api/items`)}\n" +
		"function r(e){return e.config.url+`/settings/profile`}\n"
	got := map[string]Endpoint{}
	for _, e := range Extract([]byte(src)).Endpoints {
		got[e.Method+" "+e.URL] = e
	}
	for want, line := range map[string]int{"GET {}/storage/buckets/{}/files/{}/view": 3, "GET /storage/buckets/{}/files/{}/preview": 4} {
		e, ok := got[want]
		if !ok || e.Kind != "url" {
			t.Errorf("%s: %+v (all %v)", want, e, got)
		} else if e.Line != line {
			t.Errorf("%s: line %d, want %d", want, e.Line, line)
		}
	}
	for k := range got {
		if strings.Contains(k, "settings") {
			t.Errorf("%s: another function's parameter e taken for the request's", k)
		}
	}
	// The same pieces again after the last request (a link the page
	// builds): the returned URL's place is its own, before them.
	src = "class T{constructor(c){this.client=c}\n" +
		"thumb(b){return this.client.config.endpoint+`/avatars/initials/`+b+`/image`}" + pad +
		"get(b){return this.client.call(`get`,this.client.config.endpoint+`/avatars/`+b)}}" + pad +
		"function link(b){return location.origin+`/avatars/initials/`+b+`/image`}\n"
	for _, e := range Extract([]byte(src)).Endpoints {
		if e.Kind == "url" && e.Line != 2 {
			t.Errorf("%s %s: line %d, want 2", e.Method, e.URL, e.Line)
		}
	}
}
