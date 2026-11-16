package jsapi

// This file: endpoints added, and the strings a script holds: URLs, paths, operations.

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/tdewolff/parse/v2/js"

	"github.com/TimoMangCut/JSharvest/internal/secretsig"
)

// add records an endpoint for the URL expression u, as part of call (for
// the GraphQL operations in its arguments). It returns the endpoint's key,
// or "" when u was no URL.
func (x *extractor) add(u js.IExpr, ep Endpoint, at js.INode, lv level) string {
	var q []string
	x.lits = x.lits[:0]
	first := ""
	// A request's URL may call a function another module exports
	// (`${Qi(c)}/${k}`): that call is marked, the catalog joins it.
	if ep.Kind != "navigation" && ep.Kind != "route" && ep.Kind != "url" && ep.Method != "" {
		x.noteRequestBase(u)
	}
	saved0 := x.deferring
	x.deferring = ep.Kind != "navigation" && ep.Kind != "route"
	vals := x.eval(u, &q, 0)
	x.deferring = saved0
	all := slices.Clone(x.lits)
	saved := x.curNames
	x.curNames = x.pathNames(u)
	defer func() { x.curNames = saved }()
	// An analytics collector's URL ("/com.snowplowanalytics.snowplow/tp2"
	// or "/i", one expression): none of the app's bases is its own.
	for _, t := range vals {
		if collectorRe.MatchString(t) {
			ep.NoInheritBase, ep.Collector = true, true
		}
	}
	for _, t := range vals {
		// Each value is found by its own literals: r = "/a"; c && (r =
		// "/b") gives two, each at its place.
		x.lits = litsOf(all, t, len(vals) > 1)
		if strings.HasPrefix(t, deferOpen) {
			// `${ep(c)}/${k}`: whether the client's prefix goes first
			// depends on the builder's value (a path, or a whole URL); the
			// prefixes go with the deferred request (Deferred.Pre).
			e := ep
			e.Query, e.Operations = slices.Clone(ep.Query), slices.Clone(ep.Operations)
			if key := x.addDeferred(t, e, q, at, lv); key != "" && first == "" {
				first = key
			}
			continue
		}
		for _, t := range x.prefixed(t) {
			e := ep
			e.Query, e.Operations = slices.Clone(ep.Query), slices.Clone(ep.Operations)
			if strings.Contains(t, deferOpen) {
				if key := x.addDeferred(t, e, q, at, lv); key != "" && first == "" {
					first = key
				}
				continue
			}
			if key := x.addOne(cleanURL(t), e, q, at, lv); key != "" && first == "" {
				first = key
			}
		}
	}
	x.lits = all
	return first
}

func (x *extractor) addOne(t string, ep Endpoint, q []string, at js.INode, lv level) string {
	if !looksLikePath(t, lv) || devToolPath(t) {
		return ""
	}
	path, query, _ := strings.Cut(t, "?")
	ep.URL = path
	ep.Query = append(ep.Query, q...)
	if staticJSONRe.MatchString(path) && !specNameRe.MatchString(path) {
		// `${e}/app-config.json`: a file under a URL the caller gives,
		// not under the app's API base.
		ep.NoInheritBase = true
	}
	if c, ok := at.(*js.CallExpr); ok {
		ep.Query = append(ep.Query, x.tailQuery[c]...)
	}
	for _, kv := range strings.Split(query, "&") {
		if k, _, _ := strings.Cut(kv, "="); isQueryKey(k) {
			ep.Query = append(ep.Query, k)
		}
	}
	if ep.Kind == "client" && !strings.Contains(path, "://") && !strings.HasPrefix(path, "//") && !x.ownPrefix(x.pre, path) {
		ep.Client = true
		if c, ok := at.(*js.CallExpr); ok {
			if d, ok := unwrapEnumGroup(c.X).(*js.DotExpr); ok {
				for _, k := range x.baseKeysOf(d.X, false, 0) {
					if strings.HasPrefix(k, "client:") {
						ep.BaseKeys = append(ep.BaseKeys, k)
					} else if _, rest, ok := strings.Cut(k, ":"); ok && rest != "" {
						ep.BaseKeys = append(ep.BaseKeys, "client:"+rest)
					} else if k != "" {
						ep.BaseKeys = append(ep.BaseKeys, "client:"+k)
					}
				}
				ep.BaseKeys = uniq(ep.BaseKeys)
			}
		}
	}
	// An app's helper given "report/v1.0/…" hands it to its client: a
	// path with no slash before it is relative to that client's base.
	// So does a helper's that reads it as relative to its base (a path
	// with no slash before it, which the summary saw it hand to a fetch
	// through a function that builds the full URL).
	if (ep.Kind == "wrapper" || ep.Kind == "options") && (relAPIRe.MatchString(path) || relative(path) && apiLike("/"+path)) {
		ep.Client = true
	}
	if at != nil {
		js.Walk(opsVisitor{x: x, ep: &ep}, at)
	}
	x.locate(&ep, x.lits)
	if ep.Line == 0 {
		if c, ok := at.(*js.CallExpr); ok {
			x.locateCall(&ep, c)
		}
		if ep.Line == 0 && len(x.src) > 0 {
			pos := min(x.cursor, len(x.src)-1)
			x.place(&ep, pos, min(pos+1, len(x.src)))
		}
	}
	key := ep.Method + " " + ep.URL + " " + ep.Kind
	x.producers[key] = append(x.producers[key], at)
	if x.made != nil {
		*x.made = append(*x.made, key)
	}
	names := x.curNames
	if len(names) != pathSlots(path) {
		names = nil
	}
	names = slotNames(path, names)
	if specs := x.specsOf(&ep, names); len(specs) > 0 {
		ep.Params = mergeSpecs(ep.Params, specs)
	}
	if old, ok := x.eps[key]; ok {
		old.Params = mergeSpecs(old.Params, ep.Params)
		old.BaseKeys = uniq(append(old.BaseKeys, ep.BaseKeys...))
		old.Query = append(old.Query, ep.Query...)
		old.Body = append(old.Body, ep.Body...)
		old.Headers = append(old.Headers, ep.Headers...)
		old.Operations = append(old.Operations, ep.Operations...)
		old.NoInheritBase = old.NoInheritBase || ep.NoInheritBase
		old.Collector = old.Collector || ep.Collector
		if old.Line == 0 && ep.Line > 0 {
			old.Line, old.Col, old.Snippet = ep.Line, ep.Col, ep.Snippet
		}
		return key
	}
	x.eps[key] = &ep
	x.order = append(x.order, key)
	return key
}

// litsOf are the literals a value is made of: those whose text is in it.
func litsOf(all [][]byte, val string, several bool) [][]byte {
	if !several {
		return all
	}
	var out [][]byte
	for _, l := range all {
		t := string(l)
		t = strings.TrimPrefix(strings.TrimPrefix(t, "`"), "}")
		t = strings.TrimSuffix(strings.TrimSuffix(t, "`"), "${")
		t = strings.Trim(t, `"'`)
		if t == "" || strings.Contains(val, unescape(t)) {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return all
	}
	return out
}

// --- GraphQL ---

var operationRe = regexp.MustCompile(`\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[({@]`)

func operations(s string) []string {
	var out []string
	for _, m := range operationRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1]+" "+m[2])
	}
	return out
}

type opsVisitor struct {
	x  *extractor
	ep *Endpoint
}

func (v opsVisitor) Enter(n js.INode) js.IVisitor {
	if l, ok := n.(*js.LiteralExpr); ok && l.TokenType == js.StringToken {
		for _, op := range operations(unquote(l.Data)) {
			v.ep.Operations = append(v.ep.Operations, op)
			v.x.opsUsed[op] = true
		}
	}
	if t, ok := n.(*js.TemplateExpr); ok {
		var b strings.Builder
		for _, p := range t.List {
			b.Write(p.Value)
		}
		b.Write(t.Tail)
		for _, op := range operations(b.String()) {
			v.ep.Operations = append(v.ep.Operations, op)
			v.x.opsUsed[op] = true
		}
	}
	return v
}

func (opsVisitor) Exit(js.INode) {}

// --- pass 3: strings on their own ---

type stringVisitor struct {
	x    *extractor
	prop string
}

// jsonPointerProps name the values that are JSON pointers or schema paths.
var jsonPointerProps = map[string]bool{"instancePath": true, "dataPath": true, "schemaPath": true, "errorPath": true,
	"keywordLocation": true, "instanceLocation": true, "absoluteKeywordLocation": true}

func (v stringVisitor) Enter(n js.INode) js.IVisitor {
	switch n := n.(type) {
	case *js.Property:
		// {instancePath: t + "/timings/wait", schemaPath: "#/properties/x"}:
		// a JSON pointer into data, as a JSON schema validator (Ajv's
		// standalone code) writes its errors, never a URL.
		if n.Name != nil && jsonPointerProps[propName(n.Name)] {
			return nil
		}
		if n.Name != nil && !n.Spread {
			if n.Name.Computed != nil {
				js.Walk(stringVisitor{x: v.x}, n.Name.Computed)
				if n.Value != nil {
					js.Walk(stringVisitor{x: v.x, prop: propName(n.Name)}, n.Value)
				}
				return nil
			}
			return stringVisitor{x: v.x, prop: propName(n.Name)}
		}
		v.prop = ""
	case *js.ObjectExpr, *js.ArrayExpr, *js.FuncDecl, *js.MethodDecl, *js.ArrowFunc, *js.ClassDecl, *js.NewExpr:
		v.prop = ""
	case *js.LiteralExpr:
		if n.TokenType != js.StringToken {
			return v
		}
		s := unquote(n.Data)
		for _, op := range operations(s) {
			v.x.ops[op] = true
		}
		v.x.htmlURLs(s)
		v.x.cloudURLs(s)
		v.x.baseCand(s)
		v.x.encoded(s, n.Data)
		if len(s) > 24 && strings.Contains(s, `":"`) {
			v.x.configPairs(s, n.Data)
		}
		if secretsig.HasHint(s) {
			v.x.secretKeys(v.prop, s, v.x.litLine(n.Data))
		}
		v.x.docEndpoints(s)
		if v.x.used[n] {
			return v
		}
		if !v.x.bare(s, [][]byte{n.Data}) {
			v.x.path(s)
		}
	case *js.BinaryExpr:
		// var full = domain + path: a URL put together outside any call.
		if n.Op == js.AddToken {
			v.x.joined(n)
		}
	case *js.CallExpr:
		v.prop = ""
		// "".concat("/api/", "users"), Babel's template literal.
		if v.x.concatChain(n) && !v.x.concats[n] {
			v.x.joined(n)
		}
	case *js.TemplateExpr:
		var b strings.Builder
		for _, p := range n.List {
			b.Write(p.Value)
		}
		b.Write(n.Tail)
		for _, op := range operations(b.String()) {
			v.x.ops[op] = true
		}
		v.x.htmlURLs(b.String())
		v.x.cloudURLs(b.String())
		if len(n.List) == 0 {
			st := templateText(n.Tail, true, true)
			v.x.docEndpoints(st)
			if n.Tag == nil && secretsig.HasHint(st) {
				v.x.secretKeys(v.prop, st, v.x.litLine(n.Tail))
			}
		}
		if n.Tag == nil {
			var q []string
			for _, t := range v.x.eval(n, &q, 0) {
				if !strings.Contains(t, unknown) {
					v.x.path(t)
				}
			}
		}
		v.prop = ""
	}
	return v
}

// joined reads a string put together outside any call: a + b, or
// "".concat(a, b). Its pieces are used up, not paths of their own
// ("".concat("app", "/setUser") is a store's action, not "/setUser").
func (x *extractor) joined(e js.IExpr) {
	// One a call took (fetch(base + "/x")) is that call's endpoint already.
	inCall := false
	js.Walk(litFinder(func(l *js.LiteralExpr) { inCall = inCall || x.used[l] }), e)
	var q []string
	x.lits = x.lits[:0]
	for _, t := range x.eval(e, &q, 0) {
		if strings.Contains(t, unknown) {
			continue
		}
		x.baseCand(t)
		if inCall || !x.bare(t, x.lits) {
			x.path(t)
		}
	}
}

type litFinder func(*js.LiteralExpr)

func (f litFinder) Enter(n js.INode) js.IVisitor {
	if l, ok := n.(*js.LiteralExpr); ok && l.TokenType == js.StringToken {
		f(l)
	}
	return f
}

func (litFinder) Exit(js.INode) {}

// concatChain reports whether a call is "<string>".concat(…), or a
// concat on one, and marks the calls inside it as read.
func (x *extractor) concatChain(c *js.CallExpr) bool {
	d, ok := c.X.(*js.DotExpr)
	if !ok || propName(d.Y) != "concat" {
		return false
	}
	switch in := d.X.(type) {
	case *js.LiteralExpr:
		return in.TokenType == js.StringToken
	case *js.TemplateExpr:
		return in.Tag == nil
	case *js.CallExpr:
		if x.concatChain(in) {
			x.concats[in] = true
			return true
		}
	}
	return false
}

// cloudRe is a URL of cloud storage: S3 (both styles), Google Cloud
// Storage, Azure blobs, DigitalOcean Spaces, Cloudflare R2, Firebase,
// Alibaba OSS, Backblaze, Wasabi.
var cloudRe = regexp.MustCompile(`(?i)(?:https?:)?//[a-z0-9.-]*(?:\bs3[a-z0-9.-]*\.amazonaws\.com|storage\.googleapis\.com|storage\.cloud\.google\.com|firebasestorage\.googleapis\.com|\.blob\.core\.windows\.net|\.digitaloceanspaces\.com|\.r2\.cloudflarestorage\.com|\.r2\.dev|\.aliyuncs\.com|\.backblazeb2\.com|\.wasabisys\.com)(?:[/?][^\s"'<>\\$` + "`" + `]*)?`)

func (x *extractor) cloudURLs(s string) {
	if !strings.Contains(s, "//") {
		return
	}
	for _, m := range cloudRe.FindAllString(s, 20) {
		x.cloud[strings.TrimRight(m, ".,;)")] = true
	}
}

// baseCandRe is a string that reads as an API's root ("/api-gateway/",
// "/api/v1"): a client's base when its baseURL is computed.
var baseCandRe = regexp.MustCompile(`(?i)^(?:https?://[a-z0-9.:-]+)?/(?:[a-z0-9_]+[-_.])*(?:api|apis|gateway|backend|graphql)(?:[-_.](?:gateway|backend|proxy|server|service|root|v\d+(?:\.\d+)*))?(?:/v\d+(?:\.\d+)*)?/?$`)

func (x *extractor) baseCand(s string) {
	if len(s) < 64 && baseCandRe.MatchString(s) {
		x.baseCands[s] = true
	}
}

func (stringVisitor) Exit(js.INode) {}

var htmlAttrRe = regexp.MustCompile(`(?i)\b(?:href|src|action|formaction|data-href|data-url)\s*=\s*\\?["']?([^"'\s<>\\]+)`)

// htmlURLs takes the URLs out of HTML written as a string:
// '<a href="/x">', which innerHTML makes a link of.
func (x *extractor) htmlURLs(s string) {
	if !strings.Contains(s, "=") {
		return
	}
	for _, m := range htmlAttrRe.FindAllStringSubmatch(s, -1) {
		x.path(m[1])
	}
}

// path keeps a string that reads as a page's or a resource's URL.
func (x *extractor) path(s string) {
	t := cleanURL(s)
	if strings.Contains(t, unknown) || x.routes[t] || !looksLikePath(t, weak) {
		return
	}
	x.paths[t] = true
}

// bare records a string no call used, when it reads as an API's URL: a
// path with an API segment, or an absolute URL with a path.
func (x *extractor) bare(s string, lits [][]byte) bool {
	t := cleanURL(s)
	if !(looksLikePath(t, weak) || relAPIRe.MatchString(t) && looksLikePath(t, call)) || !apiLike(t) {
		return false
	}
	path, query, _ := strings.Cut(t, "?")
	ep := Endpoint{URL: path, Kind: "string"}
	for _, kv := range strings.Split(query, "&") {
		if k, _, _ := strings.Cut(kv, "="); k != "" {
			ep.Query = append(ep.Query, k)
		}
	}
	key := " " + path + " string"
	if _, ok := x.eps[key]; ok {
		return true
	}
	x.locate(&ep, lits)
	x.eps[key] = &ep
	x.order = append(x.order, key)
	return true
}

// --- what a URL looks like ---

var (
	mimeRe    = regexp.MustCompile(`^(application|text|image|audio|video|font|multipart|model|message)/[A-Za-z0-9.+*-]+$`)
	svgPathRe = regexp.MustCompile(`^[MmZzLlHhVvCcSsQqTtAa0-9.,\s-]+$`)
	numericRe = regexp.MustCompile(`^[\d\s/:.,-]+$`)
	dateFmtRe = regexp.MustCompile(`^(?i)[ymdhs]{1,4}([/.:-][ymdhs]{1,4})+$`)
	assetRe   = regexp.MustCompile(`(?i)\.(m?js|cjs|ts|tsx|jsx|css|scss|less|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|otf|eot|map|mp4|webm|mp3|ogg|wav|wasm|vue|md|dtd|xsd|xslt?)$`)
	apiRe     = regexp.MustCompile(`(?i)(^|/)(api|apis|v\d+(\.\d+)?|graphql|gql|rest|rpc|json|ajax|ws|wss|socket\.io|oauth2?|auth|services?|backend|_api|odata|soap|webhooks?)(/|$|\?)|\.(json|php|aspx?|ashx|asmx|jsp|do|action|cgi|pl)($|\?)`)
	schemeRe  = regexp.MustCompile(`^(https?|wss?):`)
	// toolFileRe is the files build tools look for, which their code names
	// with a slash ("/package.json"); an app does not request them.
	toolFileRe = regexp.MustCompile(`(^|/)(package|tsconfig|jsconfig|composer|bower|lerna|nx|angular|project)\.json$`)
	placeRunRe = regexp.MustCompile(`(\{\})+`)
	// namedRe is a placeholder a template names: {id}, {scooter_id}.
	namedRe = regexp.MustCompile(`\{[A-Za-z_][A-Za-z0-9_.-]*\}`)
	// relAPIRe is a path relative to a client's base with a version
	// segment after one to three others ("orders/v1.0/items/{}",
	// "hub/console/v1/apps"), which is an API's even on its own.
	relAPIRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+){0,2}/v\d+(\.\d+)*/[A-Za-z0-9_{}]`)
	originRe = regexp.MustCompile(`^(?:\{\}|(?:https?|wss?):)?(?://)?\{origin\}`)
)

// cleanURL tidies an evaluated template: one {} for each run of computed
// parts, and nothing for the page's own origin.
func cleanURL(t string) string {
	t = strings.TrimSpace(t)
	for strings.Contains(t, "{origin}//") {
		t = strings.ReplaceAll(t, "{origin}//", "{origin}/")
	}
	t = originRe.ReplaceAllString(t, "")
	t = strings.ReplaceAll(t, "{origin}", unknown)
	t = namedRe.ReplaceAllString(t, unknown)
	t = placeRunRe.ReplaceAllString(t, unknown)
	return t
}

func isQueryKey(k string) bool {
	return k != "" && len(k) <= 128 && k != unknown && !strings.ContainsAny(k, " \t\r\n<>\"'`\\{};:")
}

// level is how sure the context is that a value is a URL.
type level int

const (
	weak level = iota // a string on its own, or a route
	call              // an argument of a client method or of the app's own function
	sure              // what fetch, XHR, WebSocket, EventSource, sendBeacon or open are given
)

// looksLikePath tells URLs from other strings. A relative path ("api/x",
// "{}/x") counts only where a request is made with it, and, unless the
// call surely makes one, only when it reads as an API's: Map.get("a/b"),
// require("json/parse") and path.join(dir, "package.json") do not.
func looksLikePath(t string, lv level) bool {
	path, query, hasQuery := strings.Cut(t, "?")
	if path == "" || path == "/" || len(t) > 2048 || strings.ContainsAny(path, " \t\r\n<>\"'`\\") {
		return false
	}
	if hasQuery {
		if lv == weak && strings.ContainsAny(query, " \t\r\n<>\"'`\\") {
			return false
		}
		if strings.ContainsAny(query, "\r\n\t<>\\") {
			return false
		}
	}
	letters := strings.ReplaceAll(path, unknown, "")
	if !strings.ContainsFunc(letters, func(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }) {
		return false
	}
	switch {
	case mimeRe.MatchString(path), svgPathRe.MatchString(path), numericRe.MatchString(path), dateFmtRe.MatchString(path):
		return false
	case strings.Contains(t, "www.w3.org/"), strings.HasPrefix(t, "data:"), strings.HasPrefix(t, "blob:"):
		return false
	case strings.HasPrefix(path, "./"), strings.HasPrefix(path, "../"):
		return !assetRe.MatchString(path) && (lv == sure || lv == call && apiLike(t))
	case assetRe.MatchString(path), toolFileRe.MatchString(path):
		return false
	case schemeRe.MatchString(path):
		rest := schemeRe.ReplaceAllString(path, "")
		// https://{} alone: a host the code computes and nothing else.
		if h := strings.TrimSuffix(strings.TrimPrefix(rest, "//"), "/"); h == unknown {
			return false
		}
		return strings.HasPrefix(rest, "//") && realHost(rest[2:])
	case strings.HasPrefix(path, "//"):
		return realHost(path[2:])
	case strings.HasPrefix(path, "/"):
		return path[1] != '/' && path[1] != ' '
	case strings.HasPrefix(path, unknown+"/"):
		return lv == sure || lv == call && !strings.HasSuffix(path, ".json")
	}
	if strings.HasPrefix(path, unknown) || strings.ContainsAny(path, ":@") || !strings.Contains(path, "/") && lv != sure {
		return false
	}
	return lv == sure || lv == call && apiLike(t)
}

// relative reports whether a path has no slash, scheme or {} before it
// ("hub/auth/v1/sessions").
func relative(p string) bool {
	return p != "" && p[0] != '/' && p[0] != '.' && !strings.HasPrefix(p, unknown) && !schemeRe.MatchString(p)
}

// realHost reports whether the start of an authority is a host a request
// can go to: a name with a dot, an address, localhost, or computed ({}),
// not "a", "x" or "a@b" as URL parsers' tests have them.
func realHost(rest string) bool {
	host, _, _ := strings.Cut(rest, "/")
	host, _, _ = strings.Cut(host, "?")
	// a@b as parsers' tests have it; *.example.com,https://… a CSP's list.
	if host == "" || strings.ContainsAny(host, "@,*") {
		return false
	}
	if host == unknown || strings.HasPrefix(host, "localhost") {
		return true
	}
	name, _, _ := strings.Cut(host, ":")
	return strings.Contains(name, ".") && !strings.HasPrefix(name, ".") && !strings.HasSuffix(name, ".")
}

// apiRootRe is a path that is only an API's root: code that checks
// whether a path is under it (startsWith("/api/")), not a call.
var apiRootRe = regexp.MustCompile(`(?i)^/?(api|apis|rest|rpc|v\d+|_api|services?)/?$`)

// apiLike reports whether a URL reads as an API's rather than a page's or
// a link to documentation: its path has an API segment.
// APILike reports whether a URL's path reads as an API's (/api/, /v1/,
// .json…) rather than a page's.
func APILike(t string) bool { return apiLike(t) }

func apiLike(t string) bool {
	p := t
	if schemeRe.MatchString(p) || strings.HasPrefix(p, "//") {
		rest := strings.TrimPrefix(schemeRe.ReplaceAllString(p, ""), "//")
		_, p, _ = strings.Cut(rest, "/")
		p = "/" + p
	}
	return apiRe.MatchString(p) && !apiRootRe.MatchString(strings.SplitN(p, "?", 2)[0])
}

// --- strings ---

func unquote(b []byte) string {
	if len(b) >= 2 && (b[0] == '"' || b[0] == '\'') {
		b = b[1 : len(b)-1]
	}
	return unescape(string(b))
}

// unescape reads JavaScript string escapes.
func unescape(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 == len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					b.WriteRune(rune(v))
					i += 2
					continue
				}
			}
			b.WriteByte('x')
		case 'u':
			if i+1 < len(s) && s[i+1] == '{' {
				if end := strings.IndexByte(s[i:], '}'); end > 0 {
					if v, err := strconv.ParseUint(s[i+2:i+end], 16, 32); err == nil {
						b.WriteRune(rune(v))
						i += end
						continue
					}
				}
			}
			if i+4 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+5], 16, 16); err == nil {
					b.WriteRune(rune(v))
					i += 4
					continue
				}
			}
			b.WriteByte('u')
		case '\n':
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// --- where ---

// devToolPaths are the first segments of a development server's own
// endpoints, which a bundle can carry (a framework's devtools: Vue's
// fetch(`${host}__open-in-editor?file=…`)) and no deployed app serves.
var devToolPaths = map[string]bool{"__open-in-editor": true, "__vite_ping": true, "__webpack_hmr": true,
	"__webpack_dev_server__": true, "__nextjs_original-stack-frame": true, "__nextjs_launch-editor": true,
	"__nuxt_vite_node__": true, "__inspect": true}

// devToolPath reports whether a URL is a development server's endpoint.
func devToolPath(u string) bool {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
		if j := strings.IndexByte(u, '/'); j >= 0 {
			u = u[j:]
		} else {
			return false
		}
	}
	u = strings.TrimPrefix(u, unknown)
	u = strings.TrimPrefix(u, "/")
	first, _, _ := strings.Cut(u, "/")
	first, _, _ = strings.Cut(first, "?")
	return devToolPaths[first]
}
