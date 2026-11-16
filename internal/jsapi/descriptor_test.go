package jsapi

import (
	"strings"
	"testing"
)

// Round 27F: an OpenAPI generator's typescript-axios ParamCreator, as
// TypeScript compiles it and as Babel's regenerator writes it minified
// (Jellyfin Web 12.4's SDK, shortened): the request an object {url,
// options} describes, its method from options built through Babel's
// object-spread helper, its path from the URL object, the placeholder base
// (DUMMY_BASE_URL) left out.
func TestRequestDescriptors(t *testing.T) {
	regen := `var f="https://example.com",g=function(e){return e.pathname+e.search+e.hash};
function h(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};Object.keys(n).forEach(function(k){e[k]=n[k]})}return e}
var P=function(e){return{refreshItem:(n=b(d().m((function t(n,r,o){var s,l,f2,p,v,m,y;return d().w((function(t){for(;;)switch(t.n){case 0:return s=arguments.length>3&&void 0!==arguments[3]?arguments[3]:{},l="/Items/{itemId}/Refresh".replace("{".concat("itemId","}"),encodeURIComponent(String(n))),f2=new URL(l,f),e&&(p=e.baseOptions),v=h(h({method:"POST"},p),s),m={},y={},t.n=1;case 1:return void 0!==r&&(y.metadataRefreshMode=r),t.a(2,{url:g(f2),options:v})}}),t)}))),function(e,t,r){return n.apply(this,arguments)}),
getCss:(c=b(d().m((function t(){var n,r,a;return d().w((function(t){for(;;)switch(t.n){case 0:return n={},r=new URL("/Branding/Configuration",f),a=h(h({method:"GET"},e&&e.baseOptions),n),t.a(2,{url:g(r),options:a})}}),t)}))))}};`
	plain := "export const P = function (configuration) { return {\n" +
		"  deleteItem: async (itemId, options = {}) => { const localVarPath = `/Items/{itemId}`.replace(`{${\"itemId\"}}`, encodeURIComponent(String(itemId))); const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL); let baseOptions; if (configuration) { baseOptions = configuration.baseOptions; } const localVarRequestOptions = { method: 'DELETE', ...baseOptions, ...options }; return { url: toPathString(localVarUrlObj), options: localVarRequestOptions }; },\n" +
		"}; };"
	for name, c := range map[string]struct {
		src  string
		want []string
	}{
		"regenerator": {regen, []string{"POST /Items/{}/Refresh", "GET /Branding/Configuration"}},
		"typescript":  {plain, []string{"DELETE /Items/{}"}},
	} {
		got := map[string]string{}
		for _, e := range Extract([]byte(c.src)).Endpoints {
			got[e.Method+" "+e.URL] = e.Kind
			if strings.Contains(e.URL, "example.com") {
				t.Errorf("%s: %s %s: the placeholder base kept", name, e.Method, e.URL)
			}
		}
		for _, w := range c.want {
			if got[w] != "descriptor" {
				t.Errorf("%s: %s: kind %q (all %v)", name, w, got[w], got)
			}
		}
	}
	// Not a request's: a router's navigation options, options with no
	// method, a method the code does not say.
	for _, src := range []string{
		`export const go = id => ({url: "/settings/" + id, options: {replace: true}});`,
		`export const a = id => ({url: "/api/items/" + id, options: {headers: {}}});`,
		`export const b = (id, m) => ({url: "/api/items/" + id, options: {method: m}});`,
	} {
		for _, e := range Extract([]byte(src)).Endpoints {
			if e.Kind == "descriptor" {
				t.Errorf("%s: %s %s taken for a request's description", src, e.Method, e.URL)
			}
		}
	}
}
