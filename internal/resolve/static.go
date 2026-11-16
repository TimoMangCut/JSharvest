// Package resolve finds the JavaScript an app can load but has not loaded
// yet: lazy chunks named in bundler runtimes, manifests and import() calls.
// It only reads; fetching is the engine's job, under the scope policy.
package resolve

import (
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// Candidate is a script URL a resolver found, and how.
type Candidate struct {
	URL    string // absolute
	Method string // import, new-url, vite-mapdeps, build-manifest, workbox, ngsw, webpack-runtime, worker, js-string, js-url
	From   string // the script or manifest it was found in
}

var (
	// import("./chunk.js"), also with single quotes or backticks without
	// substitutions; absolute URLs too, so that the scope policy sees them.
	importRe = regexp.MustCompile("import\\(\\s*([\"'`])((?:\\.{1,2}/|/|https?://)[^\"'`$\\s]+?\\.m?js)([?#][^\"'`$\\s]*)?[\"'`]\\s*\\)")
	// Static imports and re-exports: import"./x.js", import{a}from"./x.js",
	// export*from"./x.js". A fetched chunk never runs, so its static
	// dependencies are only found here.
	staticImportRe = regexp.MustCompile(`(?:\bfrom|\bimport)\s*["']((?:\.{1,2}/|/|https?://)[^"'\s]+?\.m?js)["']`)
	// new URL("./worker.js", import.meta.url), as Vite emits for workers;
	// rolldown writes new URL(`/_vite/w.js`, ``+import.meta.url).
	newURLRe = regexp.MustCompile("new URL\\(\\s*([\"'`])((?:\\.{1,2}/|/|https?://)[^\"'`$\\s]+?\\.m?js)[\"'`]\\s*,\\s*(?:([\"'`])[\"'`]\\s*\\+\\s*)?import\\.meta\\.url\\s*\\)")
	// new URL("w.js", location.href), self.location, document.baseURI: the
	// document's base.
	newURLDocRe = regexp.MustCompile("new URL\\(\\s*[\"'`]((?:\\.{1,2}/|/)?[\\w@~.+%-][^\"'`$\\s]*?\\.m?js)[\"'`]\\s*,\\s*(?:(?:self|window|globalThis)\\.)?(?:location(?:\\.href)?|document\\.baseURI)\\s*\\)")
	// jsStringPathRe is any string that reads as a script's path, relative
	// to the script (./x.js, ../x.js) or to the origin (/x.js): what a
	// wrapper loads (__mfImport("./x.js")), a service worker's URL in a
	// variable, a fallback ({url:"/runtime.js"}). No bare name (a.js), no
	// scheme, no substitution.
	jsStringPathRe = regexp.MustCompile("[\"'`]((?:\\.{1,2}/|/)[\\w@~.+%-]+(?:/[\\w@~.+%-]+)*\\.m?js)[\"'`]")
	// jsURLRe is a script's absolute URL anywhere in the text: a page
	// documenting an SDK (<script src="https://cdn…/sdk-0.0.15.js">). The
	// caller's policy keeps the target's hosts only.
	jsURLRe = regexp.MustCompile(`(https?://[A-Za-z0-9.-]+(?::\d+)?/[\w@~.+%/-]*?[\w-]\.m?js)(?:[^\w./-]|$)`)
	// Vite's preload list: m.f=["assets/a.js","assets/b.js"].
	viteDepsRe = regexp.MustCompile(`__vite__mapDeps\s*=.*?m\.f\s*=\s*\[([^\]]*)\]`)
	jsStringRe = regexp.MustCompile(`"([^"\s]+?\.m?js)"`)
	// Next.js Pages Router: chunk paths in _buildManifest.js, relative to
	// /_next/, in the route table and in the arguments of its wrapper.
	nextChunkRe = regexp.MustCompile(`"(static/[^"\s]+?\.js)"`)
	// Workers the code starts by a constant URL: navigator.serviceWorker
	// (?.)register("/sw.js"), new Worker("w.js"), new SharedWorker("/s.js").
	// Their URL is relative to the document, not to the script.
	workerRe = regexp.MustCompile("(?:serviceWorker\\??\\.register|new\\s+(?:Shared)?Worker)\\(\\s*[\"'`]((?:\\.{1,2}/|/|https?://|[\\w-]+/)?[^\"'`\\s$]+?\\.m?js)(?:[?#][^\"'`\\s$]*)?[\"'`]")
	// Workbox precache manifest entries in a service worker.
	// generateSW writes {url:"…",revision:…}; injectManifest writes quoted
	// keys in either order, so match the url key alone inside a service
	// worker that precaches.
	workboxRe = regexp.MustCompile(`"?url"?\s*:\s*"([^"\s]+?\.m?js)"`)
)

// Static finds the candidates a script body names. scriptURL is where the
// script came from (relative paths resolve against it); pageURL is the page
// it ran in (root-relative bundler paths resolve against its origin).
func Static(body []byte, scriptURL, pageURL string) []Candidate {
	base, err := url.Parse(scriptURL)
	if err != nil || base.Host == "" {
		return nil
	}
	src := string(body)
	var out []Candidate
	add := func(ref, method string, against *url.URL) {
		if against == nil {
			return
		}
		u, err := against.Parse(ref)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		u.Fragment = ""
		out = append(out, Candidate{URL: u.String(), Method: method, From: scriptURL})
	}

	for _, m := range importRe.FindAllStringSubmatch(src, -1) {
		add(m[2]+m[3], "import", base)
	}
	for _, m := range staticImportRe.FindAllStringSubmatch(src, -1) {
		add(m[1], "import", base)
	}
	for _, m := range newURLRe.FindAllStringSubmatch(src, -1) {
		add(m[2], "new-url", base)
	}
	if strings.Contains(src, "new URL") {
		doc := documentURL(pageURL, base)
		for _, m := range newURLDocRe.FindAllStringSubmatch(src, -1) {
			add(m[1], "new-url", doc)
		}
	}

	// Vite writes preload paths relative to its base, "/" unless configured.
	if m := viteDepsRe.FindStringSubmatch(src); m != nil {
		root := originRoot(pageURL, base)
		for _, s := range jsStringRe.FindAllStringSubmatch(m[1], -1) {
			add(s[1], "vite-mapdeps", root)
		}
	}

	if strings.HasSuffix(base.Path, "/_buildManifest.js") {
		if i := strings.Index(base.Path, "/_next/"); i >= 0 {
			next := *base
			next.Path, next.RawQuery = base.Path[:i+len("/_next/")], ""
			for _, s := range nextChunkRe.FindAllStringSubmatch(src, -1) {
				add(s[1], "build-manifest", &next)
			}
		}
	}

	if strings.Contains(src, "Worker") || strings.Contains(src, "serviceWorker") {
		doc := base
		if p, err := url.Parse(pageURL); err == nil && p.Host != "" {
			doc = p
		}
		for _, m := range workerRe.FindAllStringSubmatch(src, -1) {
			add(m[1], "worker", doc)
		}
	}

	out = append(out, webpackChunks(body, scriptURL, pageURL)...)

	if strings.Contains(src, "precacheAndRoute") || strings.Contains(src, "__WB_MANIFEST") {
		for _, s := range workboxRe.FindAllStringSubmatch(src, -1) {
			add(s[1], "workbox", base)
		}
	}

	// The weakest: a path no loader above was seen to take. A relative one
	// is the script's (an ES module's import is); a root one is the page's
	// origin's (a worker's, a fallback's). One that is not there costs a
	// 404, or the SPA's shell, which the fetch drops as no script.
	found := map[string]bool{}
	for _, c := range out {
		found[c.URL] = true
	}
	root := originRoot(pageURL, base)
	for _, m := range jsStringPathRe.FindAllStringSubmatchIndex(src, -1) {
		ref := src[m[2]:m[3]]
		if strings.Contains(ref, "/node_modules/") || strings.HasPrefix(ref, "//") {
			continue // a module id in a bundle's comments or names, never served
		}
		if moduleID(src, m[0], m[1]) {
			continue // a bundled module's id: in the bundle, not on the server
		}
		against := base
		if strings.HasPrefix(ref, "/") {
			against = root
		}
		// base + '/x.js': the path goes after what base holds. A relative
		// value the script gives it (var base = "./static") is its
		// directory's; any other is unknown, and the origin's root a guess
		// that is wrong.
		if v := concatVar.FindStringSubmatch(src[max(0, m[0]-64):m[0]]); v != nil {
			dir, ok := relativeValue(src, v[1])
			if !ok {
				continue
			}
			ref = strings.TrimRight(dir, "/") + ref
			against = base
		}
		u, err := against.Parse(ref)
		if err != nil || found[u.String()] {
			continue
		}
		found[u.String()] = true
		add(ref, "js-string", against)
	}
	for _, m := range jsURLRe.FindAllStringSubmatchIndex(src, 200) {
		ref := src[m[2]:m[3]]
		if strings.Contains(ref, "/node_modules/") || found[ref] {
			continue
		}
		found[ref] = true
		add(ref, "js-url", base)
	}
	return dedupe(out)
}

// requireCallRe ends the text before a module id a bundle's require is
// given: __webpack_require__(/*! ./x.js */ "./x.js"), require("./lib/x").
// A dynamic import() or a loader's own call (__mfImport) is not one.
var requireCallRe = regexp.MustCompile(`(?:(?:__webpack_require__|\brequire)\s*\(|__webpack_require__\.bind\(\s*__webpack_require__\s*,)\s*(?:/\*[\s\S]*?\*/\s*)?$`)

// moduleKeyRe starts the text after a module map's key, its comments
// skipped: "./x.js": function(…), "./x.js": (…) =>, "./x.js": 12 (a
// Browserify map), "./x.js": [12, 7, [12]] (a webpack lazy context's
// module id and chunks), or webpack 5's method shorthand "./x.js"(…) {.
var moduleKeyRe = regexp.MustCompile(`^(?::\s*(?:\(?\s*function\b|\(?[\w$,\s]*\)?\s*=>|\d+\b|\[\s*(?:\d+|"[^"\r\n]+"|'[^'\r\n]+')\s*[,\]])|\([\w$,\s]*\)\s*\{)`)

// moduleID reports a string at src[i:j] that is a bundled module's id: what
// a bundle's require is given, or a key of its module map.
func moduleID(src string, i, j int) bool {
	if requireCallRe.MatchString(src[max(0, i-160):i]) {
		return true
	}
	post := src[j:min(len(src), j+600)]
	for {
		post = strings.TrimLeft(post, " \t\r\n")
		switch {
		case strings.HasPrefix(post, "/*"):
			k := strings.Index(post, "*/")
			if k < 0 {
				return false
			}
			post = post[k+2:]
			continue
		case strings.HasPrefix(post, "//"):
			k := strings.IndexByte(post, '\n')
			if k < 0 {
				return false
			}
			post = post[k:]
			continue
		}
		return moduleKeyRe.MatchString(post)
	}
}

// concatVar is a variable a string is appended to: base + "/x.js".
var concatVar = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*\+\s*$`)

// relativeValue is the relative path a script gives a variable (var base =
// "./static", base = '../lib'), when that is the one value it gives it as
// a string.
func relativeValue(src, name string) (string, bool) {
	re, err := regexp.Compile(`(?:^|[^\w$.])` + regexp.QuoteMeta(name) + `\s*=\s*["'\x60]([^"'\x60\s]*)["'\x60]`)
	if err != nil {
		return "", false
	}
	var val string
	for _, m := range re.FindAllStringSubmatch(src, 8) {
		if val != "" && m[1] != val {
			return "", false
		}
		val = m[1]
	}
	if !strings.HasPrefix(val, "./") && !strings.HasPrefix(val, "../") && val != "." && val != ".." {
		return "", false
	}
	return val, true
}

// documentURL is the page a script ran in, or the script's own URL when
// that is not known.
func documentURL(pageURL string, fallback *url.URL) *url.URL {
	if p, err := url.Parse(pageURL); err == nil && p.Host != "" {
		return p
	}
	return fallback
}

// NgswURLs lists the script URLs in an Angular ngsw.json, relative to the
// manifest's own URL.
func NgswURLs(manifest []byte, manifestURL string) []Candidate {
	base, err := url.Parse(manifestURL)
	if err != nil {
		return nil
	}
	var m struct {
		AssetGroups []struct {
			URLs []string `json:"urls"`
		} `json:"assetGroups"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil
	}
	var out []Candidate
	for _, g := range m.AssetGroups {
		for _, ref := range g.URLs {
			if p := strings.ToLower(path.Ext(strings.SplitN(ref, "?", 2)[0])); p != ".js" && p != ".mjs" && p != ".cjs" {
				continue
			}
			if u, err := base.Parse(ref); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
				out = append(out, Candidate{URL: u.String(), Method: "ngsw", From: manifestURL})
			}
		}
	}
	return dedupe(out)
}

func originRoot(pageURL string, fallback *url.URL) *url.URL {
	if p, err := url.Parse(pageURL); err == nil && p.Host != "" {
		return &url.URL{Scheme: p.Scheme, Host: p.Host, Path: "/"}
	}
	return &url.URL{Scheme: fallback.Scheme, Host: fallback.Host, Path: "/"}
}

// dedupe drops repeats of a URL found the same way; one URL found by two
// methods stays twice, so that both are on record. Fetching dedupes by URL.
func dedupe(in []Candidate) []Candidate {
	seen := map[string]bool{}
	out := in[:0]
	for _, c := range in {
		k := c.Method + " " + c.URL
		if !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	return out
}
