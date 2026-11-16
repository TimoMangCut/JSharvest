package resolve

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func urls(cs []Candidate, method string) []string {
	var out []string
	for _, c := range cs {
		if method == "" || c.Method == method {
			out = append(out, c.URL)
		}
	}
	slices.Sort(out)
	return out
}

func eq(t *testing.T, name string, got, want []string) {
	t.Helper()
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("%s:\n got  %v\n want %v", name, got, want)
	}
}

// Excerpts below are verbatim from the testbed builds.
func TestStaticVite(t *testing.T) {
	src := `const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/about-BTpJ0lc3.js","assets/format-DMgHOdkz.js","assets/hidden-RTNpOOzd.js"])))=>i.map(i=>d[i]);` +
		`const r={"/":()=>d(()=>import("./home-Bo3-JF6r.js"),[]),"/hidden":()=>d(()=>import("./hidden-RTNpOOzd.js"),__vite__mapDeps([2,1]))};` +
		`const w=new Worker(new URL("/assets/calc.worker-wfrOGA0t.js",import.meta.url),{type:"module"});`
	got := Static([]byte(src), "http://h/assets/index-tkF5t2Ua.js", "http://h/some/route")
	eq(t, "mapdeps", urls(got, "vite-mapdeps"), []string{"http://h/assets/about-BTpJ0lc3.js", "http://h/assets/format-DMgHOdkz.js", "http://h/assets/hidden-RTNpOOzd.js"})
	eq(t, "import", urls(got, "import"), []string{"http://h/assets/home-Bo3-JF6r.js", "http://h/assets/hidden-RTNpOOzd.js"})
	eq(t, "new-url", urls(got, "new-url"), []string{"http://h/assets/calc.worker-wfrOGA0t.js"})
}

func TestStaticAngular(t *testing.T) {
	src := `loadComponent:()=>import("./chunk-LADWWXNY.js").then(e=>e.About)},{path:"vault",loadChildren:()=>import("./chunk-MPYIDHFO.js")`
	eq(t, "angular", urls(Static([]byte(src), "http://h/main-PMUWVAJ4.js", "http://h/"), ""),
		[]string{"http://h/chunk-LADWWXNY.js", "http://h/chunk-MPYIDHFO.js"})
}

func TestStaticNextBuildManifest(t *testing.T) {
	src := `self.__BUILD_MANIFEST=function(e,s,t,a){return{"/":[a,"static/chunks/pages/index-4f351d505ee1cb62.js"],` +
		`"/items/[id]":["static/chunks/pages/items/[id]-148c5e1c4d48bae8.js"],"/unlisted":["static/chunks/pages/unlisted-43ca79481c3ad841.js"],` +
		`sortedPages:["/","/_app"]}}(1,0,0,"static/chunks/106-978a919f3c5bd7ad.js"),self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB();`
	got := Static([]byte(src), "http://h/_next/static/DcWEr2SWWp4WwZN19z4lC/_buildManifest.js", "http://h/")
	eq(t, "next", urls(got, "build-manifest"), []string{
		"http://h/_next/static/chunks/pages/index-4f351d505ee1cb62.js",
		"http://h/_next/static/chunks/pages/items/[id]-148c5e1c4d48bae8.js",
		"http://h/_next/static/chunks/pages/unlisted-43ca79481c3ad841.js",
		"http://h/_next/static/chunks/106-978a919f3c5bd7ad.js",
	})
	// The same strings in any other script are not a manifest.
	if got := Static([]byte(src), "http://h/_next/static/chunks/main.js", "http://h/"); len(urls(got, "build-manifest")) != 0 {
		t.Errorf("non-manifest script parsed as manifest: %v", got)
	}
}

// A runtime without a chunk map: one lazy chunk, or chunkFilename "[id].js".
func TestStaticWebpackPlain(t *testing.T) {
	one := `n.u=e=>"static/js/"+e+".3fd8376a.chunk.js",n.o=(e,t)=>1;n.p="/";e&&"admin"===e.role&&n.e(447).then(n.bind(n,447))`
	eq(t, "one chunk", urls(Static([]byte(one), "http://h/static/js/main.js", "http://h/"), "webpack-runtime"), []string{
		"http://h/static/js/447.3fd8376a.chunk.js",
	})
	ids := `r.u=function(e){return e+".js"};r.p="/js/";r.e(12).then(a);r.e("about").then(b);r.e(12)`
	eq(t, "[id].js", urls(Static([]byte(ids), "http://h/js/main.js", "http://h/"), "webpack-runtime"), []string{
		"http://h/js/12.js", "http://h/js/about.js",
	})
}

func TestStaticWebpackRuntime(t *testing.T) {
	cra := `__webpack_require__.u=e=>"static/js/"+e+"."+{1:"bd8bf3d5",42:"fd0bc6d7",220:"4c3ac0f2"}[e]+".chunk.js",__webpack_require__.o=(e,_)=>1;` +
		`__webpack_require__.p="/";`
	eq(t, "cra", urls(Static([]byte(cra), "http://h/static/js/main.c0f31fe0.js", "http://h/"), "webpack-runtime"), []string{
		"http://h/static/js/1.bd8bf3d5.chunk.js", "http://h/static/js/42.fd0bc6d7.chunk.js", "http://h/static/js/220.4c3ac0f2.chunk.js",
	})
	next := `r.u=e=>"static/chunks/"+e+"."+({472:"fc7b8c7ef44800b8",681:"868462f1d403bef2"})[e]+".js",r.miniCssF=e=>{};r.p="/_next/"`
	eq(t, "next", urls(Static([]byte(next), "http://h/_next/static/chunks/webpack-22167be87b431096.js", "http://h/"), "webpack-runtime"), []string{
		"http://h/_next/static/chunks/472.fc7b8c7ef44800b8.js", "http://h/_next/static/chunks/681.868462f1d403bef2.js",
	})
	named := `n.u=function(e){return"static/js/"+({42:"about","x-y":"admin"}[e]||e)+"."+{42:"aa11",7:"bb22","x-y":"cc33"}[e]+".chunk.js"};n.p="https://cdn.h/app/"`
	eq(t, "named", urls(Static([]byte(named), "http://h/main.js", "http://h/"), "webpack-runtime"), []string{
		"https://cdn.h/app/static/js/about.aa11.chunk.js", "https://cdn.h/app/static/js/7.bb22.chunk.js", "https://cdn.h/app/static/js/admin.cc33.chunk.js",
	})
	// Split vendor bundles named one by one before the map, no prefix
	// (Jellyfin Web 12.4's runtime, shortened).
	split := `s.u=function(e){return 45642===e?"node_modules.@jellyfin.sdk.bundle.js":23247===e?"node_modules.@mui.material.bundle.js":({2:"syncPlay-core",1500:"cs-json"}[e]||e)+"."+{2:"aa11",1500:"bb22",10092:"cc33"}[e]+".chunk.js"},s.miniCssF=function(e){};s.p=""`
	eq(t, "split", urls(Static([]byte(split), "http://h/web/runtime.bundle.js", "http://h/"), "webpack-runtime"), []string{
		"http://h/web/node_modules.@jellyfin.sdk.bundle.js", "http://h/web/node_modules.@mui.material.bundle.js",
		"http://h/web/syncPlay-core.aa11.chunk.js", "http://h/web/cs-json.bb22.chunk.js", "http://h/web/10092.cc33.chunk.js",
	})
	// A runtime whose public path is computed ("auto") is left to the probe.
	auto := `r.u=e=>"js/"+e+"."+{5:"aa"}[e]+".js";r.p=t+"../"`
	if got := urls(Static([]byte(auto), "http://h/js/main.js", "http://h/"), "webpack-runtime"); len(got) != 0 {
		t.Errorf("auto public path guessed: %v", got)
	}
}

func TestStaticWorkbox(t *testing.T) {
	src := `e.precacheAndRoute([{url:"registerSW.js",revision:"1872c500"},{url:"index.html",revision:"e3b8f0c2"},{url:"assets/telemetry-D0VeaxRd.js",revision:null}],{})`
	eq(t, "workbox", urls(Static([]byte(src), "http://h/sw.js", "http://h/"), "workbox"),
		[]string{"http://h/registerSW.js", "http://h/assets/telemetry-D0VeaxRd.js"})
}

func TestStaticImports(t *testing.T) {
	// A fetched chunk never runs, so its static dependencies are only found
	// by reading it.
	src := `import{f as o}from"./format-DMgHOdkz.js";import"./side-effect-Ab12Cd34.js";export*from"../lib/util-x9.mjs";const s="not an import"`
	eq(t, "static", urls(Static([]byte(src), "http://h/assets/about-BTpJ0lc3.js", "http://h/"), "import"), []string{
		"http://h/assets/format-DMgHOdkz.js", "http://h/assets/side-effect-Ab12Cd34.js", "http://h/lib/util-x9.mjs",
	})
}

func TestStaticWorkboxInjectManifest(t *testing.T) {
	src := `workbox.precacheAndRoute([{"revision":"3ca0b8","url":"js/app.4f2a.js"},{"url":"index.html","revision":"1"}])`
	eq(t, "inject", urls(Static([]byte(src), "http://h/service-worker.js", "http://h/"), "workbox"), []string{"http://h/js/app.4f2a.js"})
}

func TestStaticIgnores(t *testing.T) {
	for _, src := range []string{
		"import(`./x-${name}.js`)",            // computed: not a URL
		`import(e)`,                           // dynamic
		`const s="import(\"./data.json\")"`,   // not JS
		`{url:"assets/a.js",revision:"1"}`,    // Workbox shape outside a service worker
		`import("data:text/javascript,1.js")`, // not http(s)
		// A webpack lazy context's keys: module ids and chunks, not files.
		`var r={"./te/_lib/match/index.js":[59222,7,[59222]],"./te/index.js":[55355,7,[55355]]};`,
	} {
		if got := Static([]byte(src), "http://h/a.js", "http://h/"); len(got) != 0 {
			t.Errorf("%s -> %v, want nothing", src, got)
		}
	}
}

func TestStaticAbsoluteKept(t *testing.T) {
	// Absolute references are returned so that the scope policy can judge
	// them; the resolver never decides scope itself.
	got := Static([]byte(`import("http://elsewhere.example/x.js")`), "http://h/a.js", "http://h/")
	eq(t, "absolute", urls(got, ""), []string{"http://elsewhere.example/x.js"})
}

func TestNgsw(t *testing.T) {
	manifest := `{"assetGroups":[{"name":"app","urls":["/chunk-64GWSIQM.js","/index.html","/main-PMUWVAJ4.js","/styles.css"]}],"hashTable":{}}`
	eq(t, "ngsw", urls(NgswURLs([]byte(manifest), "http://h/ngsw.json"), ""),
		[]string{"http://h/chunk-64GWSIQM.js", "http://h/main-PMUWVAJ4.js"})
}

func TestWorkers(t *testing.T) {
	src := `navigator.serviceWorker?.register("/extra/sw.js");new SharedWorker('shared.js');new Worker(` + "`/w/${x}.js`" + `);navigator.serviceWorker.register(n,{scope:t})`
	got := map[string]string{}
	for _, c := range Static([]byte(src), "https://h.test/static/js/main.js", "https://h.test/app/page") {
		got[c.URL] = c.Method
	}
	if got["https://h.test/extra/sw.js"] != "worker" || got["https://h.test/app/shared.js"] != "worker" {
		t.Errorf("workers: %v", got)
	}
	if len(got) != 2 {
		t.Errorf("a computed worker URL was taken: %v", got)
	}
}

// Excerpts verbatim from a real Vite 7 / rolldown build with Module
// Federation: a shared worker by new URL(“+import.meta.url), chunks a
// wrapper imports, a service worker's URL in a variable, a runtime's
// fallback URL. Module ids from the bundle's comments are no files.
func TestStaticRolldown(t *testing.T) {
	src := "let{port:e}=new SharedWorker(new URL(`/_vite/notification-shared-worker-p2vDeuwL.js`,``+import.meta.url),{type:`module`});" +
		`const __mfImport = (src) => import(src);const h = await __mfImport("./hostInit-DmR_J6KV.js");` +
		`const p = await __mfImport("./pendingShares-Bvo3aJY2.js").catch(() => undefined);` +
		"var ps=`/firebase-messaging-sw.js`,ms=`/firebase-cloud-messaging-push-scope`;" +
		"if(!e)return{url:`/_vite/app-runtime.js`};" +
		`n=new Worker(new URL("w/calc.js",self.location));` +
		`"../../node_modules/.pnpm/vscode-jsonrpc@8.2.0/node_modules/vscode-jsonrpc/lib/common/ral.js";` +
		"x=`./a-${n}.js`;y=\"//cdn.example/x.js\""
	got := Static([]byte(src), "https://h.test/_vite/mf-entry-bootstrap-0-bae0e06e.js", "https://h.test/apps/x")
	eq(t, "new-url", urls(got, "new-url"), []string{"https://h.test/_vite/notification-shared-worker-p2vDeuwL.js", "https://h.test/apps/w/calc.js"})
	eq(t, "js-string", urls(got, "js-string"), []string{
		"https://h.test/_vite/hostInit-DmR_J6KV.js", "https://h.test/_vite/pendingShares-Bvo3aJY2.js",
		"https://h.test/firebase-messaging-sw.js", "https://h.test/_vite/app-runtime.js",
	})
}

// base + '/x.js', base a relative directory of the script's.
func TestStaticConcatBase(t *testing.T) {
	src := `(function(){var base = "./static";
if (base.charAt(0) === '.') { base = new URL(base, document.currentScript.src).href; }
var s = document.createElement('script'); s.src = base + '/app-chat-core-1793115836.js';
var o = cfg.cdn + "/other.js";})()`
	got := Static([]byte(src), "https://api.example.com/gw/chat/entry.js", "https://www.example.com/")
	var urls []string
	for _, c := range got {
		urls = append(urls, c.URL)
	}
	want := "https://api.example.com/gw/chat/static/app-chat-core-1793115836.js"
	if len(urls) != 1 || urls[0] != want {
		t.Fatalf("got %v, want [%s] (and not /other.js on the root)", urls, want)
	}
}

// FIN-02: a script's absolute URL written in a page's text (an SDK's
// documentation); the caller's policy keeps the target's hosts only.
func TestStaticAbsoluteURL(t *testing.T) {
	src := "var d=`IIFE:\\n\\n\\x60\\x60\\x60\\nhttps://cdn.example.biz/media/martech/sdk-0.0.15.js\\n\\x60\\x60\\x60`;var j=\"https://x.com/a.json\";"
	var urls []string
	for _, c := range Static([]byte(src), "https://developer.example.biz/assets/a.js", "https://developer.example.biz/") {
		urls = append(urls, c.URL+" "+c.Method)
	}
	if !slices.Contains(urls, "https://cdn.example.biz/media/martech/sdk-0.0.15.js js-url") || len(urls) != 1 {
		t.Errorf("candidates %v", urls)
	}
}

func TestStaticWebpackMultiGen(t *testing.T) {
	// Webpack 4 inline .src IIFE + webpackAsyncContext ([1476, 0], [1477, 1]).
	w4Inline := `(function(e){var r={};r.p="/js/";r.e=function(e){var c=document.createElement("script");` +
		`c.src=function(e){return r.p + "" + ({}[e]||e) + ".js"}(e);document.head.appendChild(c)};` +
		`var map={"./en-US.json":[1476,0],"./vi-VN.json":[1477,1]};` +
		`function webpackAsyncContext(req){if(!r.o(map,req))return Promise.reject();var ids=map[req],id=ids[0];` +
		`return Promise.all(ids.slice(1).map(r.e)).then(function(){return r(id)})}})({})`
	eq(t, "w4-inline-async-ctx", urls(Static([]byte(w4Inline), "http://admin.example.com/js/app.js", "http://admin.example.com/"), "webpack-runtime"), []string{
		"http://admin.example.com/js/0.js",
		"http://admin.example.com/js/1.js",
	})

	// Webpack 3/4 standalone jsonpScriptSrc with partial nameMap and hashMap.
	w4Hashed := `(function(modules){var a={};a.p="/";` +
		`function jsonpScriptSrc(e){return a.p + "static/js/" + ({0:"admin"}[e]||e) + "." + {0:"ab12cd",1:"ef34ab"}[e] + ".chunk.js"}` +
		`a.e=function(e){var s=document.createElement("script");s.src=jsonpScriptSrc(e)};})([])`
	eq(t, "w34-jsonpScriptSrc-hashed", urls(Static([]byte(w4Hashed), "http://admin.example.com/static/js/runtime.js", "http://admin.example.com/"), "webpack-runtime"), []string{
		"http://admin.example.com/static/js/1.ef34ab.chunk.js",
		"http://admin.example.com/static/js/admin.ab12cd.chunk.js",
	})

	// Webpack 3/4 standalone jsonpScriptSrc unhashed with partial nameMap.
	w4PartialPlain := `(function(){var a={};a.p="/assets/";` +
		`function jsonpScriptSrc(e){return a.p + "chunks/" + ({0:"chunkA"}[e]||e) + ".js"}` +
		`a.e(1).then(function(){});})()`
	eq(t, "w34-jsonpScriptSrc-plain-named", urls(Static([]byte(w4PartialPlain), "http://admin.example.com/assets/main.js", "http://admin.example.com/"), "webpack-runtime"), []string{
		"http://admin.example.com/assets/chunks/1.js",
		"http://admin.example.com/assets/chunks/chunkA.js",
	})

	// Webpack 3 direct script.src assignment without helper function.
	w3Direct := `(function(){var n={};n.p="/dist/";n.e=function(e){var c=document.createElement("script");` +
		`c.src=n.p+""+({0:"vendors"}[e]||e)+".bundle.js";document.head.appendChild(c)};n.e(3);})()`
	eq(t, "w3-direct-src", urls(Static([]byte(w3Direct), "http://admin.example.com/dist/entry.js", "http://admin.example.com/"), "webpack-runtime"), []string{
		"http://admin.example.com/dist/3.bundle.js",
		"http://admin.example.com/dist/vendors.bundle.js",
	})
}

func TestStaticWebpackAsyncContextVariants(t *testing.T) {
	// Multi-chunk [1502, 2, 5] + eager length-1 [1499] -> chunks 2 and 5 ONLY (never 1502 or 1499).
	multi := `r.u=function(e){return e+".js"};r.p="/chunks/";` +
		`var map={"./BaseView.vue":[1499],"./OrderView.vue":[1502,2,5]};` +
		`function webpackAsyncContext(req){var ids=map[req],id=ids[0];` +
		`return Promise.all(ids.slice(1).map(function(e){return r.e(e)})).then(function(){return r(id)})}`
	eq(t, "multi-chunk-ctx", urls(Static([]byte(multi), "http://admin.example.com/chunks/app.js", "http://admin.example.com/"), "webpack-runtime"), []string{
		"http://admin.example.com/chunks/2.js",
		"http://admin.example.com/chunks/5.js",
	})

	// Terser single-chunk indexing variant: t.e(n[1]).
	terserIdx := `t.u=e=>"c/"+e+".js";t.p="/";` +
		`var m={"./a.json":[801,4],"./b.json":[802,"locale-vi"]};` +
		`function ctx(e){var n=m[e];return n?t.e(n[1]).then(function(){return t(n[0])}):Promise.reject()}`
	eq(t, "terser-index-ctx", urls(Static([]byte(terserIdx), "http://admin.example.com/app.js", "http://admin.example.com/"), "webpack-runtime"), []string{
		"http://admin.example.com/c/4.js",
		"http://admin.example.com/c/locale-vi.js",
	})
}

func TestStaticWebpackNoiseTraps(t *testing.T) {
	plainRT := `r.u=function(e){return e+".js"};r.p="/js/";`

	// Synchronous require.context: scalar moduleId and length-1 [522] without .e anchor -> 0 chunks.
	syncScalar := plainRT + `var map={"./a.js":522,"./b.js":523};function webpackContext(req){return r(map[req])}`
	eq(t, "sync-context-scalar", urls(Static([]byte(syncScalar), "http://admin.example.com/js/app.js", "http://admin.example.com/"), "webpack-runtime"), nil)

	syncLen1 := plainRT + `var map={"./a.js":[522],"./b.js":[523]};function webpackContext(req){return r(map[req][0])}`
	eq(t, "sync-context-len1", urls(Static([]byte(syncLen1), "http://admin.example.com/js/app.js", "http://admin.example.com/"), "webpack-runtime"), nil)

	// Browserify prelude + module map -> 0 chunks.
	browserify := plainRT + `(function e(t,n,r){function s(o,u){if(!n[o]){var a=n[o]={exports:{}};t[o][0].call(a.exports,function(e){return s(t[o][1][e]||e)},a,a.exports)}}return s(1)})({1:[function(require,module,exports){require("./dep")},{"./dep":2}],2:[function(require,module,exports){},{}]},{},[1]);`
	eq(t, "browserify", urls(Static([]byte(browserify), "http://admin.example.com/js/bundle.js", "http://admin.example.com/"), "webpack-runtime"), nil)

	// Invalid / newline / path-traversal chunk IDs rejected; valid one kept.
	dirty := plainRT + "r.e(\"bad\\nid\");r.e(\"bad\nid\");r.e(\"has space\");r.e(\"../escape\");r.e(\"..\");r.e(\"ok_chunk-1\");"
	eq(t, "dirty-chunk-ids", urls(Static([]byte(dirty), "http://admin.example.com/js/app.js", "http://admin.example.com/"), "webpack-runtime"), []string{
		"http://admin.example.com/js/ok_chunk-1.js",
	})

	// Cross-module boundary: an object in module 1 must not pair with r.e(n[1]) in module 2.
	crossMod := plainRT + `({10:function(e,t,r){var cfg={"./a":[500,600]};e.exports=cfg},11:function(e,t,r){function f(n){return r.e(n[1])}}});`
	eq(t, "cross-module-boundary", urls(Static([]byte(crossMod), "http://admin.example.com/js/app.js", "http://admin.example.com/"), "webpack-runtime"), nil)

	// Anchor beyond the 1000-byte window is ignored.
	farAnchor := plainRT + `var map={"./a.json":[1476,77]};` + strings.Repeat("/*pad*/", 200) + `function f(req){var ids=map[req];return Promise.all(ids.slice(1).map(r.e))}`
	eq(t, "beyond-1000b-window", urls(Static([]byte(farAnchor), "http://admin.example.com/js/app.js", "http://admin.example.com/"), "webpack-runtime"), nil)

	// Unhashed plain runtime caps candidates at maxPlainChunks (128).
	var many strings.Builder
	many.WriteString(plainRT)
	for i := range 200 {
		fmt.Fprintf(&many, "r.e(%d);", i)
	}
	if got := urls(Static([]byte(many.String()), "http://admin.example.com/js/app.js", "http://admin.example.com/"), "webpack-runtime"); len(got) != maxPlainChunks {
		t.Errorf("plain chunk cap: got %d candidates, want %d", len(got), maxPlainChunks)
	}
}

func TestExtractWebpackRuntimeAndChunkIDsAPI(t *testing.T) {
	// mini-css-extract-plugin CSS builder right before jsonpScriptSrc JS builder.
	src := `var a={};a.p="/app/";` +
		`function cssHref(e){return a.p+"static/css/"+({0:"admin"}[e]||e)+"."+{0:"112233"}[e]+".chunk.css"}` +
		`function jsonpScriptSrc(e){return a.p + "static/js/" + ({0:"admin"}[e]||e) + "." + {0:"ab12cd",1:"ef34ab"}[e] + ".chunk.js"}`
	rt := ExtractWebpackRuntime([]byte(src), "https://admin.example.com/app/static/js/runtime.js", "https://admin.example.com/app/")
	if rt == nil {
		t.Fatal("ExtractWebpackRuntime returned nil")
	}
	if rt.PublicBase.String() != "https://admin.example.com/app/" || rt.Prefix != "static/js/" || rt.Suffix != ".chunk.js" {
		t.Errorf("unexpected runtime fields: %+v", rt)
	}
	if rt.NameMap["0"] != "admin" || rt.HashMap["0"] != "ab12cd" || rt.HashMap["1"] != "ef34ab" {
		t.Errorf("unexpected maps: NameMap=%v HashMap=%v", rt.NameMap, rt.HashMap)
	}

	// Webpack 5 slice(2) heterogeneous namespace bitmask: index 1 is bitmask 7, index 2 is chunk 42.
	w5Mode := `var r={"./en.json":[1476,7,42]};function o(e){var n=r[e];return Promise.all(n.slice(2).map(t.e)).then(()=>t.t(n[0],n[1]))}`
	eq(t, "w5-slice2-ids", ExtractWebpackChunkIDs([]byte(w5Mode)), []string{"42"})
}

func TestWebpackLinkerCrossScriptAndIsolation(t *testing.T) {
	rtSrc := []byte(`!function(){var r={};r.p="/js/";r.e=function(e){var c=document.createElement("script");c.src=function(e){return r.p+""+({}[e]||e)+".js"}(e)}}();`)
	appSrc := []byte(`var map={"./en.json":[1476,0],"./Order.vue":[1502,2,5]};function ctx(q){var ids=map[q];return Promise.all(ids.slice(1).map(r.e))}`)
	trackerSrc := []byte(`t.e(88);`)
	otherSubSrc := []byte(`t.e(77);`)

	// Order 1: app.js arrives before runtime.js (worker race).
	var l1 WebpackLinker
	if got := l1.Add(appSrc, "https://admin.example.com/js/app.js", "https://admin.example.com/", false, false); len(got) != 0 {
		t.Fatalf("expected 0 candidates before runtime arrives, got %v", got)
	}
	// Tracker & other subdomain scripts must never pair with admin.example.com's runtime.
	l1.Add(trackerSrc, "https://www.googletagmanager.com/gtm.js", "https://admin.example.com/", false, true)
	l1.Add(otherSubSrc, "https://docs.example.com/js/docs.js", "https://docs.example.com/", false, false)

	got1 := l1.Add(rtSrc, "https://admin.example.com/js/runtime.js", "https://admin.example.com/", false, false)
	eq(t, "app-before-runtime", urls(got1, "webpack-runtime"), []string{
		"https://admin.example.com/js/0.js",
		"https://admin.example.com/js/2.js",
		"https://admin.example.com/js/5.js",
	})

	// Order 2: inline runtime arrives first, then external app.js, then sub-chunk 0.js.
	var l2 WebpackLinker
	if got := l2.Add(rtSrc, "https://admin.example.com/", "https://admin.example.com/", true, false); len(got) != 0 {
		t.Fatalf("expected 0 candidates on bare runtime, got %v", got)
	}
	if got := l2.Add(trackerSrc, "https://analytics.vendor.example/sdk.js", "https://admin.example.com/", false, true); len(got) != 0 {
		t.Fatalf("third-party script paired with inline runtime: %v", got)
	}
	got2 := l2.Add(appSrc, "https://admin.example.com/js/app.js", "https://admin.example.com/", false, false)
	eq(t, "inline-runtime-then-app", urls(got2, "webpack-runtime"), []string{
		"https://admin.example.com/js/0.js",
		"https://admin.example.com/js/2.js",
		"https://admin.example.com/js/5.js",
	})
	gotSub := l2.Add([]byte(`r.e(9)`), "https://admin.example.com/js/0.js", "https://admin.example.com/", false, false)
	eq(t, "subchunk-chain", urls(gotSub, "webpack-runtime"), []string{
		"https://admin.example.com/js/9.js",
	})
}
