package jsapi

// This file: calls: the HTTP calls, wrappers, parameters and higher-order helpers.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

// branches are the values an expression may be: each side of a ?:.
func branches(e js.IExpr) []js.IExpr {
	switch n := e.(type) {
	case *js.GroupExpr:
		return branches(n.X)
	case *js.CondExpr:
		return append(branches(n.X), branches(n.Y)...)
	}
	return []js.IExpr{e}
}

// --- pass 2: calls ---

type callVisitor struct{ x *extractor }

func (v callVisitor) Enter(n js.INode) js.IVisitor {
	switch n.(type) {
	case *js.ClassDecl, *js.FuncDecl, *js.MethodDecl:
		v.x.thisStack = append(v.x.thisStack, n)
	}
	switch n := n.(type) {
	case *js.FuncDecl, *js.MethodDecl, *js.ArrowFunc:
		v.x.fnStack = append(v.x.fnStack, n)
	case *js.CallExpr:
		v.x.keyInfo = map[string]keyInfo{}
		v.x.entryClass, v.x.fnBase = v.x.thisClass(), len(v.x.fnStack)
		v.x.callInInstances(n)
		v.x.entryClass, v.x.fnBase = nil, 0
		v.x.keyInfo = nil
	case *js.NewExpr:
		v.x.construct(n)
	case *js.ObjectExpr:
		v.x.descriptor(n)
		v.x.routerObject(n)
	case *js.BinaryExpr:
		if n.Op == js.EqToken && isLocation(n.X) {
			v.x.add(n.Y, Endpoint{Method: "GET", Kind: "navigation"}, nil, sure)
		}
		if n.Op == js.AddToken {
			v.x.queryTail(n)
		}
	case *js.Property:
		if n.Name != nil && propName(n.Name) == "prepareSendMessagesRequest" {
			v.x.transport(n)
		}
	}
	return v
}

func (v callVisitor) Exit(n js.INode) {
	switch n.(type) {
	case *js.FuncDecl, *js.MethodDecl, *js.ArrowFunc:
		v.x.fnStack = v.x.fnStack[:len(v.x.fnStack)-1]
	}
	switch n.(type) {
	case *js.ClassDecl, *js.FuncDecl, *js.MethodDecl:
		v.x.thisStack = v.x.thisStack[:len(v.x.thisStack)-1]
	}
}

// thisClass is the class whose instance this is where the call pass is:
// a class's field initialiser, or a method of a class (arrow functions
// share the this around them; a plain function has its own).
func (x *extractor) thisClass() *js.ClassDecl {
	if len(x.thisStack) == 0 {
		return nil
	}
	switch n := x.thisStack[len(x.thisStack)-1].(type) {
	case *js.ClassDecl:
		return n
	case *js.MethodDecl, *js.FuncDecl:
		// A method; a function a class field is set to (the arrow
		// lowering's function too, whose this is _this).
		c, _ := x.ownerOf[n].(*js.ClassDecl)
		return c
	}
	return nil
}

// queryTail reads url(path) + query(params): the query string added to
// what a call makes (r(`/conversations/${e}/events`) + wr({lastEventId:
// t})) is the endpoint's query.
func (x *extractor) queryTail(n *js.BinaryExpr) {
	l := n.X
	for {
		g, ok := l.(*js.GroupExpr)
		if !ok {
			break
		}
		l = g.X
	}
	c, ok := l.(*js.CallExpr)
	if !ok {
		return
	}
	switch n.Y.(type) {
	case *js.CallExpr, *js.Var, *js.TemplateExpr:
	default:
		return
	}
	var q []string
	vals := x.eval(n.Y, &q, 0)
	if len(q) == 0 {
		return
	}
	for _, v := range vals {
		if v != "" && !strings.HasPrefix(v, "?") && v != unknown {
			return
		}
	}
	x.tailQuery[c] = append(x.tailQuery[c], q...)
}

// isLocation reports whether an assignment target navigates the page:
// location, location.href, window.location(.href).
func isLocation(e js.IExpr) bool {
	if isGlobal(e, "location") {
		return true
	}
	d, ok := e.(*js.DotExpr)
	if !ok {
		return false
	}
	switch {
	case propName(d.Y) == "location":
		return isGlobal(d.X, "window", "self", "document")
	case propName(d.Y) == "href":
		return isLocation(d.X)
	}
	return false
}

func args(a *js.Args) []js.IExpr {
	if a == nil {
		return nil
	}
	out := make([]js.IExpr, 0, len(a.List))
	for _, x := range a.List {
		out = append(out, x.Value)
	}
	return out
}

func (x *extractor) call(c *js.CallExpr) {
	if x.routeCalls[c] || x.factoryCalls[c] {
		return
	}
	if x.routerCall(c) {
		return
	}
	as := args(&c.Args)
	// createRoute("/auth/fail")({component}): a router's page, the call
	// that names it no API's.
	if in, ok := c.X.(*js.CallExpr); ok && len(as) > 0 && routeObject(as[0]) {
		if ias := args(&in.Args); len(ias) > 0 {
			x.route(ias[0])
			x.routeCalls[in] = true
			return
		}
	}
	if len(as) == 0 {
		return
	}
	name := globalName(c.X)
	switch name {
	case "fetch":
		ep := Endpoint{Kind: "fetch", Method: "GET"}
		if len(as) > 1 {
			if o, ok := x.options(as[1]); ok {
				ep.Method, ep.Body, ep.Headers, ep.Query = o.method, o.body, o.headers, o.query
				if !o.known {
					ep.Method = ""
				} else if ep.Method == "" {
					ep.Method = "GET"
				}
			} else {
				ep.Method = ""
			}
		}
		x.add(as[0], ep, c, sure)
		return
	case "open":
		x.add(as[0], Endpoint{Method: "GET", Kind: "navigation"}, c, sure)
		return
	}
	d, member := c.X.(*js.DotExpr)
	if member {
		prop := propName(d.Y)
		if prop == "create" {
			// axios.create({baseURL, headers: {…}}): the client's own headers.
			if obj, ok := x.object(as[0]); ok {
				if h, ok := x.object(objectValue(obj, "headers")); ok {
					for _, p := range h.List {
						if p.Name != nil && !p.Spread {
							x.headers = append(x.headers, propDef{name: propName(p.Name), value: p.Value})
						}
					}
				}
			}
		}
		switch {
		case prop == "sendBeacon" && isGlobal(d.X, "navigator"):
			ep := Endpoint{Method: "POST", Kind: "beacon"}
			if len(as) > 1 {
				ep.Body = x.keys(as[1], "", 0)
			}
			x.add(as[0], ep, c, sure)
			return
		case prop == "open" && isGlobal(d.X, "window", "self"):
			x.add(as[0], Endpoint{Method: "GET", Kind: "navigation"}, c, sure)
			return
		case (prop == "assign" || prop == "replace") && isLocation(d.X):
			x.add(as[0], Endpoint{Method: "GET", Kind: "navigation"}, c, sure)
			return
		case (prop == "pushState" || prop == "replaceState") && len(as) > 2:
			x.route(as[2])
			return
		case prop == "open" && len(as) > 1:
			// XMLHttpRequest: open(method, url), then setRequestHeader and
			// send(body) on the same object.
			if m, ok := literalString(as[0]); ok && httpMethods[strings.ToUpper(m)] {
				if key := x.add(as[1], Endpoint{Method: strings.ToUpper(m), Kind: "xhr"}, c, sure); key != "" {
					if v, ok := d.X.(*js.Var); ok {
						x.xhrs[root(v)] = key
					}
				}
				return
			}
		case prop == "send" || prop == "setRequestHeader":
			if v, ok := d.X.(*js.Var); ok {
				if ep := x.eps[x.xhrs[root(v)]]; ep != nil {
					if prop == "send" {
						ep.Body = append(ep.Body, x.keys(as[0], "", 0)...)
					} else if h, ok := literalString(as[0]); ok {
						ep.Headers = append(ep.Headers, h)
					}
					return
				}
			}
		}
		// this.post(path, body) a class of the app's defines (or
		// inherits), and that makes a request, is read as that helper;
		// a client class whose methods the script does not show (a stub,
		// a library's) stays a client.
		if m, ok := clientMethods[prop]; ok && !storeLike(d.X, as) && !x.requestMethod(d, len(as)) {
			ep := Endpoint{Method: m, Kind: "client"}
			cfg := 1
			if m == "POST" || m == "PUT" || m == "PATCH" {
				if len(as) > 1 {
					ep.Body = x.keys(as[1], "", 0)
				}
				cfg = 2
			}
			if len(as) > cfg {
				if o, ok := x.options(as[cfg]); ok {
					ep.Query, ep.Headers = o.query, o.headers
				}
			}
			x.pre = x.prefixesOf(d.X)
			key := x.add(as[0], ep, c, call)
			x.pre = nil
			if key != "" {
				return
			}
		}
	}
	if member {
		switch propName(d.Y) {
		case "map", "forEach", "flatMap":
			if len(as) >= 1 && len(as) <= 2 && !c.Args.List[0].Rest && x.arrayIterCall(d.X, as[0]) {
				return
			}
		}
	}
	if member && stringMethods[propName(d.Y)] {
		return // path.startsWith("/api/") and the like
	}
	x.generic(c, as)
}

// storeNames are the objects whose get, put and delete are a store's, not
// an HTTP client's: the Cache API, Map, IndexedDB, Headers.
var storeNames = map[string]bool{"cache": true, "caches": true, "store": true, "storage": true, "db": true, "idb": true,
	"map": true, "set": true, "headers": true, "cookies": true, "searchParams": true, "formData": true, "localStorage": true,
	"sessionStorage": true, "params": true, "objectStore": true, "tx": true, "transaction": true}

// storeLike reports whether a method call is a store's: on an object
// named as one, or put(key, response.clone()) / put(key, new Response()).
func storeLike(obj js.IExpr, as []js.IExpr) bool {
	name := ""
	switch o := obj.(type) {
	case *js.Var:
		name = string(o.Data)
	case *js.DotExpr:
		name = propName(o.Y)
	}
	if storeNames[name] {
		return true
	}
	if len(as) > 1 {
		switch v := as[1].(type) {
		case *js.CallExpr:
			if d, ok := v.X.(*js.DotExpr); ok && propName(d.Y) == "clone" {
				return true
			}
		case *js.NewExpr:
			return globalName(v.X) == "Response"
		}
	}
	return false
}

// routeKeys are the keys of a client router's route options.
var routeKeys = map[string]bool{"component": true, "beforeLoad": true, "loader": true, "errorComponent": true,
	"pendingComponent": true, "notFoundComponent": true, "validateSearch": true, "loaderDeps": true, "head": true}

func routeObject(e js.IExpr) bool {
	o, ok := e.(*js.ObjectExpr)
	if !ok {
		return false
	}
	for _, p := range o.List {
		if p.Name != nil && !p.Spread && routeKeys[propName(p.Name)] {
			return true
		}
	}
	return false
}

// stringMethods are methods of strings, arrays and regexps, which code
// calls with paths to test or cut them, never to request them.
var stringMethods = map[string]bool{"concat": true, "startsWith": true, "endsWith": true, "includes": true, "indexOf": true, "lastIndexOf": true,
	"replace": true, "replaceAll": true, "split": true, "match": true, "matchAll": true, "test": true, "exec": true, "search": true,
	"slice": true, "substring": true, "substr": true, "localeCompare": true, "padStart": true, "padEnd": true, "push": true,
	"unshift": true, "join": true, "set": true, "has": true, "add": true, "warn": true, "error": true, "log": true, "info": true,
	"debug": true, "trace": true, "assert": true}

// generic reads a call to some function of the app's own: a wrapper that
// takes the method and the URL, or an options object with a url.
func (x *extractor) generic(c *js.CallExpr, as []js.IExpr) {
	// env("VITE_AUTH_API_BASE_URL", "/hub/auth"): a setting and its
	// default, a base when the setting names one, never a call.
	for _, a := range as {
		if k, ok := literalString(a); ok && envKeyRe.MatchString(k) {
			if isBaseName(k) {
				for _, b := range as {
					if b != a {
						if s, ok := literalString(b); ok && (strings.HasPrefix(s, "/") || schemeRe.MatchString(s)) {
							x.addBase(s)
						}
					}
				}
			}
			for _, b := range as {
				if l, ok := b.(*js.LiteralExpr); ok {
					x.used[l] = true
				}
			}
			return
		}
	}
	if i := x.sseParam(c.X); i >= 0 && i < len(as) {
		// An event stream's reader: GET, its URL.
		if x.add(as[i], Endpoint{Kind: "sse", Method: "GET"}, c, call) != "" {
			return
		}
	}
	if x.helper(c, as) {
		return
	}
	if x.instantiateHOF(c, as) {
		return
	}
	method := ""
	mIdx := -1
	var objs []js.IExpr
	for idx, a := range as {
		if s, ok := x.argString(a); ok && httpMethods[strings.ToUpper(s)] {
			method = strings.ToUpper(s)
			if mIdx < 0 {
				mIdx = idx
			}
		}
		if _, ok := x.object(a); ok {
			objs = append(objs, a)
		}
	}
	// An options object: $.ajax({url, type, data}), Da({method, baseURL, endpoint}).
	for _, a := range objs {
		o, _ := x.options(a)
		if o.url == nil {
			continue
		}
		ep := Endpoint{Kind: "options", Method: o.method, Body: o.body, Headers: o.headers, Query: o.query}
		if ep.Method == "" {
			ep.Method = method
		}
		if ep.Method == "" && o.known && o.methodExpr == nil && x.isClientRequestCallee(c.X) {
			ep.Method = "GET"
		}
		pre, isClient := x.optBasePre(o.base)
		if isClient {
			ep.Client = true
			ep.BaseKeys = x.baseKeysOf(o.base, false, 0)
		}
		saved := x.pre
		if len(pre) > 0 {
			x.pre = pre
		}
		key := x.add(o.url, ep, c, call)
		x.pre = saved
		if key != "" {
			return
		}
	}
	for i, a := range as {
		var q []string
		cu := ""
		for _, u := range x.eval(a, &q, 0) {
			if c := cleanURL(u); looksLikePath(c, call) {
				cu = c
				break
			}
		}
		if cu == "" {
			continue
		}
		ep := Endpoint{Kind: "wrapper", Method: method}
		methodUnknown := false
		isFetch := x.fetchLike(c.X)
		for j, o := range as {
			if j == i || (mIdx >= 1 && i > mIdx && j <= mIdx) {
				continue
			}
			opt, ok := x.options(o)
			if !ok && isFetch && j == i+1 {
				// X.fetch(path, opts), opts what the code does not show:
				// it is the request's init, and may say any method.
				methodUnknown = true
			}
			if ok {
				if opt.method != "" && ep.Method == "" {
					ep.Method = opt.method
				}
				if opt.method == "" && (opt.methodExpr != nil || !opt.known) {
					methodUnknown = true
				}
				if len(opt.body) > 0 || len(opt.headers) > 0 || len(opt.query) > 0 || opt.isOpt {
					// {method: "DELETE"}, {body: formData, signal}: a
					// request's options, whose keys are no fields.
					ep.Body, ep.Headers, ep.Query = append(ep.Body, opt.body...), append(ep.Headers, opt.headers...), append(ep.Query, opt.query...)
				} else {
					ep.Body = append(ep.Body, x.keys(o, "", 0)...)
				}
			} else if k := x.keys(o, "", 0); len(k) > 0 {
				ep.Body = append(ep.Body, k...)
			}
		}
		// X.fetch(path, {headers, query}): a fetch, whatever object it is
		// on, its options showing no method: fetch's default, GET.
		if ep.Method == "" && !methodUnknown && isFetch {
			ep.Method = "GET"
		}
		if ep.Method != "" {
			x.noteRequestBase(a) // the base a request's URL is built on (urlreturn.go)
		}
		// Without a method, a call that takes a path is as often a router's
		// navigate("/settings") as an API call: only paths that read as an
		// API's count, the others are routes.
		// A relative path counts when it has a version segment
		// (this.getChartData("report/v1.0/dashboard/…")), not require("json/x").
		if ep.Method == "" && !strings.HasPrefix(cu, "/") && !schemeRe.MatchString(cu) && !relAPIRe.MatchString(cu) {
			continue
		}
		if ep.Method == "" && !apiLike(cu) && !x.urlBuilder(c.X) {
			x.route(a)
			return
		}
		if pre := x.builderPath(c, &q, 0); pre != nil {
			// r(`/conversations/${e}/events`), r = e => `${t}${e}`, t
			// `${hub}/api/v1`: the base's own path first.
			for _, u := range cat(pre, x.eval(a, &q, 0)) {
				e := ep
				e.Query = slices.Clone(ep.Query)
				x.addOne(cleanURL(u), e, q, c, call)
			}
			return
		}
		if mIdx >= 1 && i > mIdx {
			// Y(ctx, "GET", "/active-workflows"): as[0] is the client or
			// context whose baseURL precedes a root-relative path.
			var ctxPre []string
			if obj, ok := x.object(as[0]); ok {
				bProp := "baseURL"
				b := objectValue(obj, "baseURL")
				if b == nil {
					bProp = "baseUrl"
					b = objectValue(obj, "baseUrl")
				}
				var isClient bool
				ctxPre, isClient = x.optBasePre(b)
				if isClient {
					ep.Client = true
					ep.BaseKeys = x.baseKeysOf(b, false, 0)
					if len(ep.BaseKeys) == 0 && b != nil {
						ep.BaseKeys = []string{"prop:" + bProp}
					}
				}
			} else if cp := x.prefixesOf(as[0]); len(cp) > 0 {
				ctxPre = cp
				ep.Client = true
				ep.BaseKeys = x.baseKeysOf(as[0], false, 0)
			} else if mIdx == 1 && i == 2 && strings.HasPrefix(cu, "/") && !strings.HasPrefix(cu, "//") && x.isContextWrapper(c, as[0]) {
				ctxPre = []string{unknown}
				ep.Client = true
				if mod, name, ok := x.imported(c.X); ok {
					ep.BaseKeys = append(ep.BaseKeys, "imp:"+mod+"\x00"+name)
				}
				ep.BaseKeys = uniq(append(ep.BaseKeys, x.baseKeysOf(as[0], false, 0)...))
			}
			if len(ctxPre) > 0 {
				saved := x.pre
				x.pre = ctxPre
				x.add(a, ep, c, call)
				x.pre = saved
				return
			}
		}
		x.add(a, ep, c, call)
		return
	}
}

var (
	nonWrapperWords = map[string]bool{
		"event": true, "events": true, "track": true, "tracker": true, "tracking": true,
		"analytic": true, "analytics": true, "metric": true, "metrics": true, "telemetry": true,
		"log": true, "logs": true, "logger": true, "logging": true, "warn": true, "error": true,
		"debug": true, "trace": true, "emit": true, "emitter": true, "bus": true, "dispatch": true,
		"publish": true, "notify": true, "trigger": true, "on": true, "off": true, "once": true,
		"listen": true, "listener": true, "subscribe": true, "route": true, "routes": true,
		"router": true, "register": true, "mock": true, "stub": true, "spy": true, "expect": true, "assert": true,
	}
	apiWrapperWords = map[string]bool{
		"request": true, "req": true, "api": true, "rest": true, "http": true,
		"client": true, "fetch": true, "ajax": true, "invoke": true, "rpc": true,
	}
	ctxIdentWords = map[string]bool{
		"ctx": true, "context": true, "rootstore": true, "store": true,
		"client": true, "api": true, "http": true, "instance": true, "app": true,
	}
)

func identWords(s string) []string {
	var out []string
	var cur []byte
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isUpper := c >= 'A' && c <= 'Z'
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		if !isUpper && !isLower && !isDigit {
			flush()
			continue
		}
		if isUpper && len(cur) > 0 {
			prevLower := s[i-1] >= 'a' && s[i-1] <= 'z'
			nextLower := i+1 < len(s) && s[i+1] >= 'a' && s[i+1] <= 'z'
			if prevLower || nextLower {
				flush()
			}
		}
		cur = append(cur, c)
	}
	flush()
	return out
}

// isContextWrapper reports whether f(arg0, "METHOD", "/path") is a request
// wrapper whose first argument supplies a runtime client/context (e.g. n8n's
// makeRestApiRequest(ctx, "GET", "/active-workflows")), rather than an event,
// analytics, router or mock call like sendEvent("click", "POST", "/api/track").
func (x *extractor) isContextWrapper(c *js.CallExpr, arg0 js.IExpr) bool {
	for {
		if g, ok := arg0.(*js.GroupExpr); ok {
			arg0 = g.X
			continue
		}
		break
	}
	switch a := arg0.(type) {
	case nil, *js.TemplateExpr, *js.ArrayExpr, *js.ObjectExpr,
		*js.ArrowFunc, *js.FuncDecl, *js.BinaryExpr, *js.UnaryExpr:
		return false
	case *js.LiteralExpr:
		if a.TokenType != js.ThisToken {
			return false
		}
	case *js.Var:
		if string(a.Data) == "undefined" {
			return false
		}
	}
	callee := c.X
	for {
		switch ce := callee.(type) {
		case *js.GroupExpr:
			callee = ce.X
			continue
		case *js.CommaExpr:
			if len(ce.List) > 0 {
				callee = ce.List[len(ce.List)-1]
				continue
			}
		}
		break
	}
	var names []string
	switch ce := callee.(type) {
	case *js.Var:
		names = append(names, string(ce.Data))
	case *js.DotExpr:
		names = append(names, propName(ce.Y))
		if rv, ok := ce.X.(*js.Var); ok {
			names = append(names, string(rv.Data))
		}
	}
	hasAPIName := false
	for _, nm := range names {
		for _, w := range identWords(nm) {
			if nonWrapperWords[w] {
				return false
			}
			if apiWrapperWords[w] {
				hasAPIName = true
			}
		}
	}
	if hasAPIName || x.awaited[c] {
		return true
	}
	if _, _, ok := x.imported(c.X); ok {
		return true
	}
	if x.isThis(arg0) {
		return true
	}
	switch a := arg0.(type) {
	case *js.Var:
		if ctxIdentWords[strings.ToLower(string(a.Data))] {
			return true
		}
	case *js.DotExpr:
		if ctxIdentWords[strings.ToLower(propName(a.Y))] || x.isThis(a.X) {
			return true
		}
	}
	return false
}

// fnOf is the parameters and body of the function a callee is, when it is
// one of the app's own, set once.
func (x *extractor) fnOf(callee js.IExpr) (*js.Var, js.Params, *js.BlockStmt, bool) {
	for {
		g, ok := callee.(*js.GroupExpr)
		if !ok {
			break
		}
		callee = g.X
	}
	v, ok := callee.(*js.Var)
	if !ok {
		return nil, js.Params{}, nil, false
	}
	v = root(v)
	switch f := x.constant(v).(type) {
	case *js.ArrowFunc:
		return v, f.Params, &f.Body, true
	case *js.FuncDecl:
		return v, f.Params, &f.Body, true
	}
	return nil, js.Params{}, nil, false
}

// paramIndex is a function's parameters, by their variable (including
// object and array destructuring bindings).
func paramIndex(params js.Params) func(js.IExpr) int {
	index := map[*js.Var]int{}
	for i, b := range params.List {
		switch t := b.Binding.(type) {
		case *js.Var:
			index[root(t)] = i
		case *js.BindingObject:
			for _, it := range t.List {
				if v, ok := it.Value.Binding.(*js.Var); ok {
					index[root(v)] = i
				}
			}
		case *js.BindingArray:
			for _, it := range t.List {
				if v, ok := it.Binding.(*js.Var); ok {
					index[root(v)] = i
				}
			}
		}
	}
	return func(e js.IExpr) int {
		if p, ok := e.(*js.Var); ok {
			if i, ok := index[root(p)]; ok {
				return i
			}
		}
		return -1
	}
}

// paramOrigin traces an expression back to an outer parameter index and
// optional object property name (e.g. (0, "endpoint") for `const {endpoint} = cfg`
// or `cfg.endpoint`, or (2, "") for a direct parameter `path`), bounded to depth <= 8.
func (x *extractor) paramOrigin(params js.Params, e js.IExpr, depth int) (int, string) {
	if depth > 8 || e == nil {
		return -1, ""
	}
	for {
		if g, ok := e.(*js.GroupExpr); ok {
			e = g.X
			continue
		}
		break
	}
	type origin struct {
		idx  int
		prop string
	}
	pmap := map[*js.Var]origin{}
	for i, b := range params.List {
		switch t := b.Binding.(type) {
		case *js.Var:
			pmap[root(t)] = origin{i, ""}
		case *js.BindingObject:
			for _, it := range t.List {
				v, ok := it.Value.Binding.(*js.Var)
				if !ok {
					continue
				}
				key := string(v.Data)
				if it.Key != nil {
					key = propName(it.Key)
				}
				pmap[root(v)] = origin{i, key}
			}
		}
	}
	var trace func(cur js.IExpr, d int) (int, string)
	trace = func(cur js.IExpr, d int) (int, string) {
		if d > 8 || cur == nil {
			return -1, ""
		}
		for {
			if g, ok := cur.(*js.GroupExpr); ok {
				cur = g.X
				continue
			}
			break
		}
		switch n := cur.(type) {
		case *js.Var:
			r := root(n)
			if o, ok := pmap[r]; ok {
				return o.idx, o.prop
			}
			if a, ok := x.args[r]; ok && a != nil && a != js.IExpr(n) {
				return trace(a, d+1)
			}
			if src := x.destructFrom[r]; src != nil && x.propOf[r] != "" {
				if obj, ok := x.object(src); ok {
					if val := objectValue(obj, x.propOf[r]); val != nil {
						return trace(val, d+1)
					}
				}
				idx, outerProp := trace(src, d+1)
				if idx >= 0 {
					if outerProp == "" {
						return idx, x.propOf[r]
					}
					return idx, outerProp + "." + x.propOf[r]
				}
			}
			if c := x.constant(n); c != nil && c != js.IExpr(n) {
				return trace(c, d+1)
			}
		case *js.DotExpr:
			idx, outerProp := trace(n.X, d+1)
			if idx >= 0 {
				k := propName(n.Y)
				if outerProp == "" {
					return idx, k
				}
				return idx, outerProp + "." + k
			}
		case *js.CallExpr:
			if len(n.Args.List) == 1 && !n.Args.List[0].Rest {
				if idx, prop := trace(n.Args.List[0].Value, d+1); idx >= 0 {
					return idx, prop
				}
			}
		case *js.ObjectExpr:
			for _, p := range n.List {
				if p.Spread && p.Value != nil {
					if idx, prop := trace(p.Value, d+1); idx >= 0 {
						return idx, prop
					}
				}
			}
		case *js.BinaryExpr:
			if n.Op == js.NullishToken || n.Op == js.OrToken {
				if idx, prop := trace(n.X, d+1); idx >= 0 {
					return idx, prop
				}
			}
		}
		return -1, ""
	}
	return trace(e, depth)
}

// omittedCondBranch picks the deterministic branch of `p ? a : b` or `!p ? a : b`
// when `p` is an optional parameter omitted by the caller (`x.omitted[root(p)]`),
// or when `p` was explicitly supplied (`x.supplied[root(p)]`) to an optional
// path-segment ternary (`p ? "/" + p : ""`).
func (x *extractor) omittedCondBranch(n *js.CondExpr) js.IExpr {
	cond := unwrapEnumGroup(n.Cond)
	var v *js.Var
	var omittedBranch, suppliedBranch js.IExpr
	switch c := cond.(type) {
	case *js.Var:
		v, omittedBranch, suppliedBranch = root(c), n.Y, n.X
	case *js.UnaryExpr:
		if c.Op == js.NotToken {
			if uv, ok := unwrapEnumGroup(c.X).(*js.Var); ok {
				v, omittedBranch, suppliedBranch = root(uv), n.X, n.Y
			} else if u2, ok := unwrapEnumGroup(c.X).(*js.UnaryExpr); ok && u2.Op == js.NotToken {
				if uv2, ok := unwrapEnumGroup(u2.X).(*js.Var); ok {
					v, omittedBranch, suppliedBranch = root(uv2), n.Y, n.X
				}
			}
		}
	case *js.BinaryExpr:
		isNilOrEmptyLit := func(e js.IExpr, allowEmpty bool) bool {
			switch u := unwrapEnumGroup(e).(type) {
			case *js.LiteralExpr:
				if u.TokenType == js.NullToken {
					return true
				}
				if allowEmpty && u.TokenType == js.StringToken && unquote(u.Data) == "" {
					return true
				}
			case *js.Var:
				return string(u.Data) == "undefined"
			case *js.UnaryExpr:
				return u.Op == js.VoidToken
			}
			return false
		}
		var cand *js.Var
		allowEmpty := c.Op == js.NotEqToken || c.Op == js.NotEqEqToken || c.Op == js.EqEqToken || c.Op == js.EqEqEqToken
		if lv, ok := unwrapEnumGroup(c.X).(*js.Var); ok && isNilOrEmptyLit(c.Y, allowEmpty) {
			cand = root(lv)
		} else if rv, ok := unwrapEnumGroup(c.Y).(*js.Var); ok && isNilOrEmptyLit(c.X, allowEmpty) {
			cand = root(rv)
		}
		if cand != nil {
			switch c.Op {
			case js.EqEqToken, js.EqEqEqToken:
				if !emptyTextExpr(c.X) && !emptyTextExpr(c.Y) || x.supplied[cand] {
					v, omittedBranch, suppliedBranch = cand, n.X, n.Y
				}
			case js.NotEqToken, js.NotEqEqToken:
				if !emptyTextExpr(c.X) && !emptyTextExpr(c.Y) || x.supplied[cand] {
					v, omittedBranch, suppliedBranch = cand, n.Y, n.X
				}
			}
		}
	}
	if v == nil {
		return nil
	}
	if x.omitted[v] {
		return omittedBranch
	}
	if x.supplied[v] && emptyTextExpr(omittedBranch) && slashSegmentWithVar(suppliedBranch, v) {
		return suppliedBranch
	}
	return nil
}

func emptyTextExpr(e js.IExpr) bool {
	switch u := unwrapEnumGroup(e).(type) {
	case *js.LiteralExpr:
		return u.TokenType == js.StringToken && unquote(u.Data) == ""
	case *js.TemplateExpr:
		return u.Tag == nil && len(u.List) == 0 && templateText(u.Tail, true, true) == ""
	}
	return false
}

func slashSegmentWithVar(e js.IExpr, target *js.Var) bool {
	e = unwrapEnumGroup(e)
	startsSlash := false
	switch u := e.(type) {
	case *js.TemplateExpr:
		if u.Tag == nil && len(u.List) > 0 && strings.HasPrefix(templateText(u.List[0].Value, true, false), "/") {
			startsSlash = true
		}
	case *js.BinaryExpr:
		if u.Op == js.AddToken {
			if s, ok := literalString(u.X); ok && strings.HasPrefix(s, "/") {
				startsSlash = true
			}
		}
	}
	if !startsSlash {
		return false
	}
	used := false
	js.Walk(varFinderAll(func(v *js.Var) {
		if root(v) == target {
			used = true
		}
	}), e)
	return used
}

func (x *extractor) isNullishOrEmptyArg(e js.IExpr) bool {
	return x.isNullishOrEmptyArgAt(e, 0)
}

func (x *extractor) isNullishOrEmptyArgAt(e js.IExpr, depth int) bool {
	if e == nil {
		return true
	}
	if depth > 6 {
		return false
	}
	switch u := unwrapEnumGroup(e).(type) {
	case *js.LiteralExpr:
		return u.TokenType == js.NullToken || u.TokenType == js.FalseToken || (u.TokenType == js.StringToken && unquote(u.Data) == "")
	case *js.TemplateExpr:
		return emptyTextExpr(u)
	case *js.Var:
		if string(u.Data) == "undefined" {
			return true
		}
		rv := root(u)
		if x.omitted[rv] {
			return true
		}
		if rv.Decl != js.ArgumentDecl {
			if c := x.constant(rv); c != nil && c != u && c != rv {
				return x.isNullishOrEmptyArgAt(c, depth+1)
			}
		}
	case *js.UnaryExpr:
		return u.Op == js.VoidToken
	case *js.CondExpr:
		return x.isNullishOrEmptyArgAt(u.X, depth+1) || x.isNullishOrEmptyArgAt(u.Y, depth+1)
	}
	return false
}

// baseKeysOf extracts normalized provenance keys for a dynamic base expression
// (e.g. `prop:baseUrl`, `prop:templatesHost`, `setting:API_URL`, `client:api`,
// or `param:fn:0` when includeParam is true).
func (x *extractor) baseKeysOf(e js.IExpr, includeParam bool, depth int) []string {
	if e == nil || depth > 8 {
		return nil
	}
	e = unwrapEnumGroup(e)
	switch n := e.(type) {
	case *js.BinaryExpr:
		if n.Op == js.OrToken || n.Op == js.NullishToken {
			if ks := x.baseKeysOf(n.X, includeParam, depth+1); len(ks) > 0 {
				return ks
			}
			return x.baseKeysOf(n.Y, includeParam, depth+1)
		}
	case *js.CondExpr:
		return uniq(append(x.baseKeysOf(n.X, includeParam, depth+1), x.baseKeysOf(n.Y, includeParam, depth+1)...))
	case *js.DotExpr:
		p := propName(n.Y)
		if p == "" {
			return nil
		}
		if p == "value" {
			if sub := x.baseKeysOf(n.X, includeParam, depth+1); len(sub) > 0 {
				return sub
			}
			if v, ok := unwrapEnumGroup(n.X).(*js.Var); ok && len(v.Data) > 0 {
				return []string{"var:" + string(v.Data)}
			}
			return nil
		}
		// If n.X is a bound parameter mapped to an object literal `{ baseUrl: ctx.baseUrl }`,
		// follow the property value first; if none, `"prop:" + p` is the property name itself.
		if v, ok := unwrapEnumGroup(n.X).(*js.Var); ok {
			if arg, bound := x.args[root(v)]; bound && arg != nil && arg != e {
				if obj, isObj := x.object(arg); isObj {
					if pv := objectValue(obj, p); pv != nil {
						if sub := x.baseKeysOf(pv, includeParam, depth+1); len(sub) > 0 {
							return sub
						}
					}
				}
			}
		}
		return []string{"prop:" + p}
	case *js.Var:
		rv := root(n)
		if arg, bound := x.args[rv]; bound && arg != nil && arg != n {
			if sub := x.baseKeysOf(arg, includeParam, depth+1); len(sub) > 0 {
				return sub
			}
		}
		if prop := x.propOf[rv]; prop != "" {
			if src, ok := x.destructFrom[rv].(*js.Var); ok {
				if arg, bound := x.args[root(src)]; bound && arg != nil {
					if obj, isObj := x.object(arg); isObj {
						if pv := objectValue(obj, prop); pv != nil {
							if sub := x.baseKeysOf(pv, includeParam, depth+1); len(sub) > 0 {
								return sub
							}
						}
					}
				}
			}
			return []string{"prop:" + prop}
		}
		if c := x.constant(n); c != nil && c != n {
			if sub := x.baseKeysOf(c, includeParam, depth+1); len(sub) > 0 {
				return sub
			}
		}
		if x.clients[rv] {
			return []string{"client:" + string(rv.Data)}
		}
		if pp, isParam := x.paramOf[rv]; isParam && pp.fn != nil {
			var callerKeys []string
			for _, call := range x.callsTo[pp.fn] {
				as := args(&call.Args)
				if pp.i < len(as) && as[pp.i] != n {
					callerKeys = append(callerKeys, x.baseKeysOf(as[pp.i], false, depth+1)...)
				}
			}
			if len(callerKeys) > 0 {
				return uniq(callerKeys)
			}
			if includeParam {
				return []string{fmt.Sprintf("param:%s:%d", string(pp.fn.Data), pp.i)}
			}
		} else if includeParam && rv.Decl == js.ArgumentDecl {
			return []string{"param:" + string(rv.Data)}
		}
	}
	return nil
}

// namedAfterSlot reports whether every evaluated path has a named resource
// segment (at least 3 letters) after its first `{}` placeholder, distinguishing
// resource URL builders (`/workflows/{}/test-runs`) from base prefixers (`/api/{}`).
func namedAfterSlot(out []string) bool {
	if len(out) == 0 {
		return false
	}
	for _, u := range out {
		i := strings.Index(u, unknown)
		if i < 0 || !ownPath([]string{u[i+len(unknown):]}) {
			return false
		}
	}
	return true
}

// instantiateHOF instantiates an API factory or curried endpoint helper
// (e.g. `createTagApi("/tags")` returning `{getTags, createTag, ...}` or
// `makePrefsEndpoint("POST")` returning `(ctx, data) => req(ctx, method, ...)`),
// when given an HTTP method, "/path", or URL argument.
func (x *extractor) instantiateHOF(c *js.CallExpr, as []js.IExpr) bool {
	if len(as) == 0 || x.calls > 0 {
		return false
	}
	v, params, body, ok := x.fnOf(c.X)
	if !ok || len(params.List) == 0 || x.busy[v] {
		return false
	}
	hasAPIArg := false
	for _, a := range as {
		if s, ok := x.argString(a); ok {
			if httpMethods[strings.ToUpper(s)] || (strings.HasPrefix(s, "/") && len(s) > 1 && !strings.HasPrefix(s, "//")) || schemeRe.MatchString(s) {
				hasAPIArg = true
				break
			}
			continue
		}
		switch a.(type) {
		case *js.TemplateExpr, *js.BinaryExpr:
			var q []string
			for _, s := range x.eval(a, &q, 0) {
				if (strings.HasPrefix(s, "/") && len(s) > 1 && !strings.HasPrefix(s, "//")) || schemeRe.MatchString(s) {
					hasAPIArg = true
					break
				}
			}
		}
		if hasAPIArg {
			break
		}
	}
	if !hasAPIArg {
		return false
	}
	rets := returnsOf(body)
	if len(rets) == 0 || len(rets) > 4 {
		return false
	}
	var innerBodies []*js.BlockStmt
	for _, r := range rets {
		r = unwrapEnumGroup(r)
		if _, ib, isFn := fnParts(r); isFn {
			innerBodies = append(innerBodies, ib)
			continue
		}
		obj, isObj := r.(*js.ObjectExpr)
		if !isObj {
			return false
		}
		gotMethod := false
		for _, p := range obj.List {
			if _, mb, isFn := fnParts(p.Value); isFn {
				innerBodies = append(innerBodies, mb)
				gotMethod = true
			}
		}
		if !gotMethod {
			return false
		}
	}
	if len(innerBodies) == 0 {
		return false
	}
	x.busy[v] = true
	defer delete(x.busy, v)
	var q []string
	undo := x.bindParams(params, as, &q, 0)
	defer undo()
	x.maker[c] = true
	for _, ib := range innerBodies {
		js.Walk(fetchFinder(func(ic *js.CallExpr) {
			var made []string
			saved := x.made
			x.made = &made
			x.call(ic)
			x.made = saved
			if len(made) > 0 {
				x.inst[ic] = append(x.inst[ic], made...)
			}
		}), ib)
		mv := &moduleVisitor{x: x}
		if cur := x.selfClass(); cur != nil {
			mv.clsStack = []*js.ClassDecl{cur}
		}
		js.Walk(mv, ib)
	}
	return true
}

// paramIn finds the parameter a body expression is made from:
// JSON.stringify(data), new URLSearchParams(data), data && ….
func paramIn(e js.IExpr, param func(js.IExpr) int) int {
	switch n := e.(type) {
	case *js.CallExpr:
		for _, a := range n.Args.List {
			if i := paramIn(a.Value, param); i >= 0 {
				return i
			}
		}
	case *js.NewExpr:
		if n.Args != nil {
			for _, a := range n.Args.List {
				if i := paramIn(a.Value, param); i >= 0 {
					return i
				}
			}
		}
	case *js.BinaryExpr:
		if i := paramIn(n.X, param); i >= 0 {
			return i
		}
		return paramIn(n.Y, param)
	case *js.GroupExpr:
		return paramIn(n.X, param)
	}
	return param(e)
}

type fetchFinder func(*js.CallExpr)

func (f fetchFinder) Enter(n js.INode) js.IVisitor {
	if c, ok := n.(*js.CallExpr); ok {
		f(c)
	}
	return f
}

func (fetchFinder) Exit(js.INode) {}

// walker visits every node.
type walker func(js.INode)

func (w walker) Enter(n js.INode) js.IVisitor {
	w(n)
	return w
}

func (walker) Exit(js.INode) {}

func (x *extractor) construct(n *js.NewExpr) {
	x.routerNew(n)
	as := args(n.Args)
	if len(as) == 0 {
		return
	}
	switch globalName(n.X) {
	case "WebSocket":
		x.add(as[0], Endpoint{Kind: "websocket"}, n, sure)
	case "EventSource":
		x.add(as[0], Endpoint{Method: "GET", Kind: "sse"}, n, sure)
	case "Request":
		ep := Endpoint{Kind: "fetch", Method: "GET"}
		if len(as) > 1 {
			if o, ok := x.options(as[1]); ok {
				ep.Method, ep.Body, ep.Headers = o.method, o.body, o.headers
				if ep.Method == "" && o.known {
					ep.Method = "GET"
				}
			}
		}
		x.add(as[0], ep, n, sure)
	}
}

func (x *extractor) route(e js.IExpr) {
	var q []string
	for _, u := range x.eval(e, &q, 0) {
		if p, _, _ := strings.Cut(cleanURL(u), "?"); strings.HasPrefix(p, "/") && looksLikePath(p, weak) {
			x.routes[p] = true
		}
	}
}
