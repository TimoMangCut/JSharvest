package endpoints

import (
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

// Round 27A: a request whose URL calls a URL builder another chunk exports
// is joined with that builder, evaluated with the call's arguments.
func TestDeferredURLsAcrossChunks(t *testing.T) {
	shared := "var tbl={app_tokens:`/auth/tokens`};var SYS=[{name:`app_users`},{name:`app_roles`}].map(e=>e.name);" +
		"function isSys(e){return e.startsWith(`app_`)?SYS.includes(e):!1}" +
		"function endpointFor(e){return e in tbl?tbl[e]:isSys(e)?`/${e.substring(4)}`:`/records/${e}`}" +
		"function pick(e){return window.flags.v2?`/v2/things/${e}`:`/v1/things/${e}`}" +
		"function envelope(e){let t=e.protocol?`${e.protocol}:`:``;return`${t}//${e.host}/api/${e.projectId}/envelope/`}" +
		"export{endpointFor as eF,pick as pk,envelope as env};"
	page := "import{eF as ep,pk,env}from\"./shared-1a2b.js\";import{other}from\"./missing.js\";var api=axios.create({baseURL:`/`});" +
		"export const loadRole=id=>api.get(`${ep(`app_roles`)}/${id}`);" +
		"export const dropToken=id=>api.delete(`${ep(`app_tokens`)}/${id}`);" +
		"export const saveAny=(c,k,d)=>api.patch(`${ep(c)}/${k}`,d);" +
		"export const listThings=()=>api.get(pk(`gadget`));" +
		"export const lost=()=>api.get(`${other(`x`)}/list`);" +
		"export const go=(r,c)=>r.push(`${ep(c)}/new`);" +
		"export const send=(dsn,b)=>fetch(env(dsn),{method:`POST`,body:b});"
	ra, rp := jsapi.Extract([]byte(shared)), jsapi.Extract([]byte(page))
	if len(ra.Builders) != 3 || len(rp.Deferred) < 5 {
		t.Fatalf("builders %+v deferred %+v", ra.Builders, rp.Deferred)
	}
	scripts := []Script{
		{Result: ra, SHA256: "a", URLs: []string{"http://app.test/assets/shared-1a2b.js"}, Load: func() []byte { return []byte(shared) }},
		{Result: rp, SHA256: "b", URLs: []string{"http://app.test/assets/page-9z.js"}, Load: func() []byte { return []byte(page) }},
	}
	got := map[string]bool{}
	for _, e := range Build(scripts, nil, func(h string) bool { return strings.HasSuffix(h, "app.test") }) {
		got[e.Method+" "+e.Path] = true
	}
	for _, want := range []string{"GET /roles/{}", "DELETE /auth/tokens/{}", "PATCH /records/{}/{}"} {
		if !got[want] {
			t.Errorf("no %s in %v", want, keysOf(got))
		}
	}
	for k := range got {
		// A literal argument whose test is undecided names nothing
		// (/v1/things/gadget, /v2/things/gadget); a navigation is no
		// request; a module not crawled joins nothing.
		// A builder's value led by what it does not know (a host)
		// joins a value to the unknown.
		if strings.Contains(k, "gadget") || strings.Contains(k, "/records/app_") || strings.Contains(k, "/new") || strings.Contains(k, "envelope") {
			t.Errorf("guessed %s in %v", k, keysOf(got))
		}
	}
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func TestUnknownOrigin(t *testing.T) {
	for v, want := range map[string]bool{"{}/x": true, "//{}/api/": true, "https://{}.example.test/a": true, "https:///a": true,
		"/items/{}": false, "https://api.example.test/{}/x": false, "//cdn.example.test/a": false} {
		if unknownOrigin(v) != want {
			t.Errorf("unknownOrigin(%q) != %v", v, want)
		}
	}
}

// Round 27B review: a client's prefix goes first when the builder's value
// is a path (axios.create({baseURL: "/api"})), and the endpoint is then
// a path of the page's origin, waiting for no client base.
func TestDeferredClientPrefix(t *testing.T) {
	shared := "function forName(e){return `/records/${e}`}export{forName as fn};"
	page := "import{fn}from\"./shared-1a2b.js\";var api=axios.create({baseURL:`/api`});" +
		"var ext=axios.create({baseURL:`https://api.app.test/v1`});export const health=()=>ext.get(`/health`);" +
		"export const load=id=>api.get(`${fn(`posts`)}/${id}`);"
	scripts := []Script{
		{Result: jsapi.Extract([]byte(shared)), SHA256: "a", URLs: []string{"http://app.test/assets/shared-1a2b.js"}, Load: func() []byte { return []byte(shared) }},
		{Result: jsapi.Extract([]byte(page)), SHA256: "b", URLs: []string{"http://app.test/assets/page-9z.js"}, Load: func() []byte { return []byte(page) }},
	}
	var got []string
	for _, e := range Build(scripts, nil, func(h string) bool { return strings.HasSuffix(h, "app.test") }) {
		if strings.Contains(e.Path, "posts") {
			got = append(got, e.Method+" "+e.Path)
			if len(e.Bases) > 0 || e.Origin != "http://app.test" {
				t.Errorf("%s %s waits for a client base (bases %v, origin %q): a path of the page's origin", e.Method, e.Path, e.Bases, e.Origin)
			}
		}
	}
	if !slices.Equal(got, []string{"GET /api/records/posts/{}"}) {
		t.Errorf("got %v, want [GET /api/records/posts/{}]", got)
	}
}

// The flag itself: a deferred URL its client's prefix made whole is no
// client's path; one with no prefix is.
func TestLinkDeferredClientFlag(t *testing.T) {
	shared := "function forName(e){return `/records/${e}`}export{forName as fn};"
	page := "import{fn}from\"./shared.js\";var api=axios.create({baseURL:`/api`});var raw=axios.create({});" +
		"export const a=id=>api.get(`${fn(`posts`)}/${id}`);export const b=id=>raw.get(`${fn(`tags`)}/${id}`);"
	scripts := []Script{
		{Result: jsapi.Extract([]byte(shared)), SHA256: "a", URLs: []string{"http://app.test/shared.js"}, Load: func() []byte { return []byte(shared) }},
		{Result: jsapi.Extract([]byte(page)), SHA256: "b", URLs: []string{"http://app.test/page.js"}},
	}
	byKey := map[string]*Endpoint{}
	var order []string
	linkDeferred(scripts, byKey, &order, map[*Endpoint]map[string]bool{}, func(int, string) ([]int, bool) { return []int{0}, false })
	for key, want := range map[string]bool{"GET  /api/records/posts/{}": false, "GET  /records/tags/{}": true} {
		ep := byKey[key]
		if ep == nil {
			t.Errorf("no %q in %v", key, order)
			continue
		}
		if ep.client != want {
			t.Errorf("%q client %v, want %v", key, ep.client, want)
		}
	}
}
