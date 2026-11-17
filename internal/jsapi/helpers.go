package jsapi

import (
	"regexp"
	"slices"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

// --- the app's request helpers ---

// summary is what a function of the app does with its parameters when it
// makes a request: the call that makes it (a fetch, a client's method,
// or another helper's), read again at each call of the function with its
// parameters bound to what that call gives them. URL, method, body,
// options and query are then whatever the call site's arguments make of
// them: a template the helper builds (`${base}/mcps/${id}/${e}`), a body
// it adds fields to ({convId, ...t}), a query it appends (wr(params)).
type summary struct {
	params js.Params
	// urls are the parameters that are the URL as they are (or through a
	// function making it whole: withBase(e)): the call site's own
	// arguments, where its endpoints are found.
	urls []int
	// The call the helper makes: another helper's (via, sub), or a leaf.
	via *js.CallExpr
	sub *summary
	leaf
	// call is the call in the helper's body that makes the request: what
	// it makes there, its parameters unknown (POST /apps/{}/scopes/{}/{}),
	// is the helper's frame, not an endpoint, when every call to the
	// helper makes it whole (…/scopes/{}/remove).
	call *js.CallExpr
	// nested: that call is in a function the helper makes (a client's
	// methods it returns), not one it runs: calling the helper makes no
	// request of its own.
	nested bool
	// lazy: via is a call on a field of this whose class is known only at
	// the call, when the constructor's parameters are bound (sub is nil).
	lazy bool
}

// leaf is the request a helper makes itself.
type leaf struct {
	url    js.IExpr // the URL expression
	base   js.IExpr // the base expression when split from `${ctx.baseUrl}${path}` or options
	method string   // a literal method; "" with methodExpr or opts unknown
	// methodExpr is the expression the method is (a parameter); opts the
	// options object, read at the call (fetch(e, {...t}), fetch(e, t));
	// body the body's expression.
	methodExpr, opts, body js.IExpr
	extra                  *js.ObjectExpr // the fetch's own options object
	client                 []string       // a client's prefixes (Z.post(…))
	isClient               bool
}

// fetchLike reports whether a callee is fetch: the global, or a variable
// set to one (n = e.fetch, {fetchFn: i = globalThis.fetch} = e).
func (x *extractor) fetchLike(callee js.IExpr) bool {
	if globalName(callee) == "fetch" {
		return true
	}
	if d, ok := callee.(*js.DotExpr); ok {
		// e.fetchImpl(url, …), this.fetchFn(…); not a method of the app's
		// own (this.fetchComponent("/_error") of Next's router), read as
		// what it does.
		if x.isThis(d.X) && x.thisMethod(propName(d.Y), -1) != nil {
			return false
		}
		p := strings.ToLower(propName(d.Y))
		return strings.Contains(p, "fetch") && p != "prefetch" && !strings.HasPrefix(p, "on")
	}
	v, ok := callee.(*js.Var)
	if !ok {
		return false
	}
	v = root(v)
	if strings.Contains(strings.ToLower(x.propOf[v]), "fetch") {
		return true
	}
	if d, ok := x.constant(v).(*js.DotExpr); ok {
		return strings.Contains(strings.ToLower(propName(d.Y)), "fetch")
	}
	return false
}

// summaryOf reads a called function of the app's own, once: a helper such
// as post(url, data) => fetch(url, {method: "POST", body: …}), or one
// that hands its parameters on to such a helper, through as many levels
// as there are (get(p, init) => request(withBase(p), init)).
func (x *extractor) summaryOf(callee js.IExpr, nargs int) *summary {
	for {
		g, ok := callee.(*js.GroupExpr)
		if !ok {
			break
		}
		callee = g.X
	}
	if d, ok := callee.(*js.DotExpr); ok {
		// n.conversations.sendNote(i, {message, data}): the one method of
		// that name the script defines.
		fn := x.methodOf(d, nargs)
		if fn == nil {
			return nil
		}
		if v, ok := fn.(*js.Var); ok {
			return x.summaryOf(v, nargs)
		}
		if s, ok := x.msums[fn]; ok {
			return s
		}
		x.msums[fn] = nil
		params, body, _ := fnParts(fn)
		x.fnStack = append(x.fnStack, fn)
		s := x.summarize(params, body)
		x.fnStack = x.fnStack[:len(x.fnStack)-1]
		x.msums[fn] = s
		return s
	}
	v, params, body, ok := x.fnOf(callee)
	if !ok {
		return nil
	}
	if s, ok := x.sums[v]; ok {
		return s
	}
	x.sums[v] = nil // a recursive helper reads as none
	found := x.summarize(params, body)
	x.sums[v] = found
	return found
}

// summarize reads what a function's body does with its parameters when it
// makes a request.
func (x *extractor) summarize(params js.Params, body *js.BlockStmt) *summary {
	directURLParam := func(e js.IExpr) int {
		idx, prop := x.paramOrigin(params, e, 0)
		if idx >= 0 && prop == "" {
			return idx
		}
		return -1
	}
	var found, lazy *summary
	nf := &nestFinder{}
	nf.f = func(c *js.CallExpr) {
		as := args(&c.Args)
		if len(as) == 0 {
			return
		}
		s := &summary{params: params, call: c, nested: nf.depth > 0}
		switch {
		case x.fetchLike(c.X):
			s.leaf = x.fetchLeaf(params, as)
			if s.leaf.base == nil {
				if u := paramIn(s.leaf.url, directURLParam); u >= 0 && !hasLiteral(s.leaf.url) {
					s.urls = []int{u}
				}
			}
		case x.clientLeaf(c, as, &s.leaf):
			if u := directURLParam(as[0]); u >= 0 {
				s.urls = []int{u}
			}
		case x.optionsLeaf(c, params, as, &s.leaf):
			if s.leaf.base == nil && s.leaf.url != nil {
				if u := paramIn(s.leaf.url, directURLParam); u >= 0 && !hasLiteral(s.leaf.url) {
					s.urls = []int{u}
				}
			}
		default:
			sub := x.summaryOf(c.X, nargsOf(c))
			if sub == nil {
				// this.http.send(…), http what the constructor is given:
				// the method is known at the call, read then (lazy).
				if lazy == nil && x.thisFieldCall(c) {
					s.via, s.lazy = c, true
					lazy = s
				}
				return
			}
			s.via, s.sub = c, sub
			for _, i := range sub.urls {
				if i < len(as) && !hasLiteral(as[i]) {
					if u := paramIn(as[i], directURLParam); u >= 0 {
						s.urls = append(s.urls, u)
					}
				}
			}
		}
		// A helper that names no parameter of its own in the URL makes
		// one request whatever it is given: the URL is constant there, or
		// a template of its parameters; either is read at the call.
		if found == nil {
			found = s
			return
		}
		// Another call in the same helper: more URLs it may go to.
		for _, u := range s.urls {
			if !slices.Contains(found.urls, u) {
				found.urls = append(found.urls, u)
			}
		}
	}
	js.Walk(nf, body)
	if found == nil {
		return lazy
	}
	return found
}

// fetchLeaf reads fetch(url, options).
func (x *extractor) fetchLeaf(params js.Params, as []js.IExpr) leaf {
	l := leaf{url: as[0], method: "GET"}
	if baseExpr, pathExpr, ok := x.splitBaseAndPath(params, as[0]); ok {
		l.base, l.url, l.isClient = baseExpr, pathExpr, true
	}
	if len(as) < 2 {
		return l
	}
	obj, ok := x.object(as[1])
	if !ok {
		l.opts, l.method = as[1], ""
		return l
	}
	l.extra = obj
	for _, p := range obj.List {
		if p.Spread {
			l.opts = p.Value // fetch(e, {...t, headers}): t's method and body
			continue
		}
		if p.Name == nil {
			continue
		}
		switch propName(p.Name) {
		case "method":
			l.method = ""
			if m, ok := literalString(p.Value); ok {
				l.method = strings.ToUpper(m)
			} else {
				l.methodExpr = p.Value
			}
		case "body":
			l.body = p.Value
		}
	}
	return l
}

// clientLeaf reads client.post(url, body, config): a client's method,
// not a store's.
func (x *extractor) clientLeaf(c *js.CallExpr, as []js.IExpr, l *leaf) bool {
	d, ok := c.X.(*js.DotExpr)
	if !ok {
		return false
	}
	m, ok := clientMethods[propName(d.Y)]
	if !ok || storeLike(d.X, as) || !x.isClientObj(d.X) {
		return false
	}
	*l = leaf{url: as[0], method: m, isClient: true}
	cfg := 1
	if m == "POST" || m == "PUT" || m == "PATCH" {
		if len(as) > 1 {
			l.body = as[1]
		}
		cfg = 2
	}
	if len(as) > cfg {
		l.opts = as[cfg]
	}
	l.client = x.prefixesOf(d.X)
	return true
}

// optionsLeaf reads req({method, baseURL, url|endpoint, data}) or
// client.request(optionsVar) in a helper body.
func (x *extractor) optionsLeaf(c *js.CallExpr, params js.Params, as []js.IExpr, l *leaf) bool {
	if len(as) != 1 {
		return false
	}
	obj, ok := x.object(as[0])
	if !ok {
		if idx, prop := x.paramOrigin(params, as[0], 0); idx >= 0 && prop == "" && x.isClientRequestCallee(c.X) {
			*l = leaf{opts: as[0], isClient: true, client: x.calleePrefixes(c.X)}
			return true
		}
		return false
	}
	o, ok := x.options(as[0])
	if !ok || o.url == nil || !o.httpOpt {
		return false
	}
	*l = leaf{url: o.url, base: o.base, method: o.method, methodExpr: o.methodExpr, body: o.bodyExpr, opts: as[0], extra: obj}
	return true
}

func (x *extractor) calleePrefixes(callee js.IExpr) []string {
	callee = ungroup(callee)
	if d, ok := callee.(*js.DotExpr); ok {
		return x.prefixesOf(d.X)
	}
	return x.prefixesOf(callee)
}

func (x *extractor) isBaseExpr(e js.IExpr) bool {
	for {
		if g, ok := e.(*js.GroupExpr); ok {
			e = g.X
			continue
		}
		break
	}
	switch n := e.(type) {
	case *js.DotExpr:
		return isBaseName(propName(n.Y))
	case *js.Var:
		r := root(n)
		if isBaseName(string(r.Data)) || isBaseName(x.propOf[r]) {
			return true
		}
	}
	return false
}

func (x *extractor) splitPair(params js.Params, left, right js.IExpr) bool {
	if x.isBaseExpr(left) {
		return true
	}
	li, lp := x.paramOrigin(params, left, 0)
	ri, rp := x.paramOrigin(params, right, 0)
	// this.base + path in a class's method: a field the class sets, then
	// the path the method is given, whatever the field is named.
	if d, ok := left.(*js.DotExpr); ok && ri >= 0 && rp == "" && x.isThis(d.X) {
		if c := x.ownerClass(); c != nil && len(x.classField(c, propName(d.Y))) > 0 {
			return true
		}
	}
	return li >= 0 && ri >= 0 && (li != ri || (lp != "" && rp != "" && lp != rp))
}

// splitBaseAndPath decomposes `${ctx.baseUrl}${apiEndpoint}`, `${srv}${path}`,
// or `base + path` into (baseExpr, pathExpr) when the leading term names a base
// URL or both terms trace to distinct parameters/properties of the helper.
func (x *extractor) splitBaseAndPath(params js.Params, e js.IExpr) (js.IExpr, js.IExpr, bool) {
	for {
		if g, ok := e.(*js.GroupExpr); ok {
			e = g.X
			continue
		}
		break
	}
	switch n := e.(type) {
	case *js.TemplateExpr:
		if n.Tag == nil && len(n.List) == 2 && len(templateText(n.List[0].Value, true, false)) == 0 && len(templateText(n.Tail, false, true)) == 0 {
			sep := templateText(n.List[1].Value, false, false)
			if (sep == "" || sep == "/") && x.splitPair(params, n.List[0].Expr, n.List[1].Expr) {
				if sep == "/" {
					return n.List[0].Expr, &js.BinaryExpr{Op: js.AddToken, X: &js.LiteralExpr{TokenType: js.StringToken, Data: []byte(`"/"`)}, Y: n.List[1].Expr}, true
				}
				return n.List[0].Expr, n.List[1].Expr, true
			}
		}
	case *js.BinaryExpr:
		if n.Op == js.AddToken && x.splitPair(params, n.X, n.Y) {
			return n.X, n.Y, true
		}
	}
	return nil, nil, false
}

// hasLiteral reports whether an expression has text of its own: a
// template with fixed parts, a string; withBase(e) or base + e has none.
func hasLiteral(e js.IExpr) bool {
	found := false
	js.Walk(litFinder(func(l *js.LiteralExpr) { found = found || len(l.Data) > 2 }), e)
	if t, ok := e.(*js.TemplateExpr); ok {
		for _, p := range t.List {
			found = found || len(templateText(p.Value, false, false)) > 0
		}
		found = found || len(templateText(t.Tail, len(t.List) == 0, true)) > 0
	}
	return found
}

// call is what a helper's call makes: its URLs (evaluated, for those
// not read off the call site), method, and fields.
type helperCall struct {
	urls        []string
	method      string
	known       bool // the method is known (or the request has none: GET)
	body, query []string
	headers     []string
	isClient    bool
	baseKeys    []string
	// own are the client's prefixes that are paths of the page's origin
	// (new Client("/console-api")): a URL under one is whole.
	own []string
	// pre is the path a URL builder's base puts before what the helper is
	// given (`${hub}/api/v1` + path): "{}/api/v1".
	pre []string
}

// maxHelperDepth is how many helpers in each other a call is read through.
const maxHelperDepth = 8

// readCall reads a helper's request with its parameters bound to the
// call's arguments: x.args for what fields and options read, x.bind for
// what URLs evaluate to.
func (x *extractor) readCall(s *summary, as []js.IExpr, q *[]string, depth int) helperCall {
	if depth > maxHelperDepth {
		return helperCall{}
	}
	restore := x.bindParams(s.params, as, q, depth)
	defer restore()
	return x.readBound(s, q, depth)
}

// readBound is readCall with the helper's parameters bound already.
func (x *extractor) readBound(s *summary, q *[]string, depth int) helperCall {
	if s.call != nil && !slices.Contains(x.readChain, s.call) {
		x.readChain = append(x.readChain, s.call)
	}
	if s.sub != nil || s.lazy {
		return x.readVia(s, q, depth)
	}
	l := s.leaf
	r := helperCall{method: l.method, known: true, isClient: l.isClient}
	if l.methodExpr != nil {
		r.known = false
		if m, ok := x.argString(l.methodExpr); ok && httpMethods[strings.ToUpper(m)] {
			r.method, r.known = strings.ToUpper(m), true
		} else {
			// e.type || "GET", read with the call's options bound: one
			// method, whichever way.
			var one string
			for _, m := range x.eval(l.methodExpr, q, depth+1) {
				m = strings.ToUpper(m)
				if !httpMethods[m] || one != "" && one != m {
					one = ""
					break
				}
				one = m
			}
			if one != "" {
				r.method, r.known = one, true
			}
		}
	}
	var optBase js.IExpr = l.base
	var optURL js.IExpr
	if l.opts != nil {
		if o, ok := x.options(l.opts); ok {
			optURL = o.url
			switch {
			case o.method != "":
				r.method, r.known = o.method, true
			case !o.known && r.method == "":
				r.known = false
			case o.known && r.method == "" && o.methodExpr == nil:
				// Options the code wholly shows, with no method in them
				// (this.client.fetch(path, {headers, query})): fetch's and
				// a client's default, GET.
				r.method, r.known = "GET", true
			}
			if o.base != nil {
				optBase = o.base
			}
			r.body = append(r.body, o.body...)
			r.headers, r.query = append(r.headers, o.headers...), append(r.query, o.query...)
		} else if !l.isClient && l.methodExpr == nil && l.extra == nil {
			r.known = false // options the code computes: any method
		}
	}
	if l.body != nil {
		r.body = append(r.body, x.keys(l.body, "", 0)...)
	}
	if l.extra != nil {
		// fetch(e.url, {headers: e.headers}): the headers the call gives,
		// read with its arguments bound.
		if v := objectValue(l.extra, "headers"); v != nil {
			r.headers = append(r.headers, x.keys(v, "", 2)...)
		}
	}
	// The URL: a template of the helper's parameters is evaluated; one
	// that is a parameter through a function making it whole (withBase(e))
	// is that parameter's value, the path the app gave.
	u := l.url
	if u == nil {
		u = optURL
	}
	if u == nil {
		return helperCall{}
	}
	if !hasLiteral(u) {
		if v := boundVar(x, u); v != nil {
			r.urls = x.bind[v]
			if pre := x.builderPath(u, q, depth); pre != nil {
				r.urls, r.pre = cat(pre, r.urls), pre
			}
		}
	}
	if r.urls == nil {
		r.urls = x.eval(u, q, depth+1)
	}
	if len(r.urls) == 1 && r.urls[0] == unknown {
		// s = check(e.exchangeUrl, "url.api"): a check of many cases
		// hands back the URL it is given.
		if c := x.checked(u); c != nil {
			r.urls = x.eval(c, q, depth+1)
		}
	}
	r.urls = x.prefixedAll(l.client, r.urls)
	r.own = l.client
	if optBase != nil {
		pre, isClient := x.optBasePre(optBase)
		if isClient {
			r.isClient = true
			r.baseKeys = x.baseKeysOf(optBase, false, 0)
		}
		if len(pre) > 0 {
			r.pre = pre
			r.urls = x.prefixedAll(pre, r.urls)
		}
	}
	// The other parameters the URL is made of, given an object: its query
	// (path + wr({cursor, limit})).
	js.Walk(standaloneVars(func(v *js.Var) {
		if a, ok := x.args[root(v)]; ok && a != nil {
			if _, isObj := x.object(a); isObj {
				r.query = append(r.query, x.keys(a, "", 0)...)
			}
		}
	}), x.expandVars(u, 2))
	return r
}

// bindParams binds a function's parameters to a call's arguments, and
// returns what undoes it.
func (x *extractor) bindParams(params js.Params, as []js.IExpr, q *[]string, depth int) func() {
	type saved struct {
		v          *js.Var
		arg        js.IExpr
		val        []string
		hadA, hadV bool
	}
	type pair struct {
		p *js.Var
		a js.IExpr
	}
	var pairs []pair
	for i, b := range params.List {
		var a js.IExpr
		if i < len(as) {
			a = as[i]
		}
		if a == nil && b.Default != nil {
			a = b.Default // (e, t = {}): what is not given is the default
		}
		switch t := b.Binding.(type) {
		case *js.Var:
			pairs = append(pairs, pair{t, a})
		case *js.BindingObject:
			// ({baseUrl: e, body: n}): each name is the value of that
			// property of the object given, when it is a literal.
			var obj *js.ObjectExpr
			if a != nil {
				obj, _ = x.object(a)
			}
			for _, it := range t.List {
				v, ok := it.Value.Binding.(*js.Var)
				if !ok {
					continue
				}
				key := string(v.Data)
				if it.Key != nil {
					key = propName(it.Key)
				}
				var pa js.IExpr
				if obj != nil && key != "" {
					pa = x.objectValueSpread(obj, key, 0)
				}
				if pa == nil {
					pa = it.Value.Default // ({path = ""}): the default
				}
				pairs = append(pairs, pair{v, pa})
			}
		}
	}
	var undo []saved
	for _, pr := range pairs {
		p, a := root(pr.p), pr.a
		sv := saved{v: p}
		sv.arg, sv.hadA = x.args[p]
		sv.val, sv.hadV = x.bind[p]
		undo = append(undo, sv)
		val := unk
		if a != nil {
			if v := boundVar(x, a); v != nil && !hasLiteral(a) && !x.readsSelfField(a) {
				val = x.bind[v] // withBase(e): e's value
			} else {
				val = x.eval(a, q, depth+1)
			}
		}
		x.args[p], x.bind[p] = a, val
	}
	return func() {
		for i := len(undo) - 1; i >= 0; i-- {
			s := undo[i]
			if s.hadA {
				x.args[s.v] = s.arg
			} else {
				delete(x.args, s.v)
			}
			if s.hadV {
				x.bind[s.v] = s.val
			} else {
				delete(x.bind, s.v)
			}
		}
	}
}

// boundVar is the bound parameter an expression is made from, through
// calls (withBase(e), encodeURIComponent(e)): the first one found.
func boundVar(x *extractor, e js.IExpr) *js.Var {
	var out *js.Var
	js.Walk(standaloneVars(func(v *js.Var) {
		if out == nil {
			if _, ok := x.bind[root(v)]; ok {
				out = root(v)
			}
		}
	}), e)
	return out
}

// expandVars is an expression with its local constants' values beside it
// (o = a ? wr(a) : "" in r(t) + o), levels deep: what the parameters it
// is made of are.
func (x *extractor) expandVars(e js.IExpr, levels int) js.IExpr {
	list := []js.IExpr{e}
	seen := map[*js.Var]bool{}
	for l := 0; l < levels; l++ {
		var more []js.IExpr
		for _, ex := range list {
			js.Walk(varFinderAll(func(v *js.Var) {
				v = root(v)
				if seen[v] {
					return
				}
				seen[v] = true
				if _, bound := x.args[v]; bound {
					return
				}
				if c := x.constant(v); c != nil {
					switch c.(type) {
					case *js.FuncDecl, *js.ArrowFunc, *js.ClassDecl:
					default:
						more = append(more, c)
					}
				}
			}), ex)
		}
		list = append(list, more...)
	}
	items := make([]js.Element, 0, len(list))
	for _, ex := range list {
		items = append(items, js.Element{Value: ex})
	}
	return &js.ArrayExpr{List: items}
}

type varFinderAll func(*js.Var)

func (f varFinderAll) Enter(n js.INode) js.IVisitor {
	switch n := n.(type) {
	case *js.Var:
		f(n)
	case *js.FuncDecl, *js.ArrowFunc, *js.MethodDecl:
		return nil
	}
	return f
}

func (varFinderAll) Exit(js.INode) {}

func (x *extractor) prefixedAll(pre []string, urls []string) []string {
	if len(pre) == 0 {
		return urls
	}
	saved := x.pre
	x.pre = pre
	defer func() { x.pre = saved }()
	var out []string
	for _, u := range urls {
		for _, p := range x.prefixed(u) {
			out = addAlt(out, p)
		}
	}
	return out
}

// helper reads a call to one of the app's request helpers, and records
// what it makes. It reports whether it found one.
func (x *extractor) helper(c *js.CallExpr, as []js.IExpr) bool {
	if x.curriedHelper(c, as) {
		return true
	}
	sum := x.summaryOf(c.X, nargsOf(c))
	if sum == nil {
		// this.http.send(…) in an instance being read: the field's class
		// known now, its constructor's parameters bound.
		if d, ok := c.X.(*js.DotExpr); ok && len(x.self) > 0 {
			if fn, cls, cas := x.readCallee(d, nargsOf(c)); fn != nil {
				if sum = x.fnSummary(fn); sum != nil {
					var q []string
					restore := x.bindParams(sum.params, as, &q, 0)
					undo := x.bindInstance(cls, cas, &q, 0)
					defer func() {
						undo()
						restore()
					}()
					return x.applyBound(sum, c, as, 0)
				}
			}
		}
		return false
	}
	// A method called on an instance from outside its class
	// (sdk.raw.send(…)): read in that instance.
	if d, ok := c.X.(*js.DotExpr); ok && len(x.self) == 0 && !x.isThis(d.X) {
		if cls, cas := x.instanceOf(d.X, true, 0); cls != nil && x.classMember(cls, propName(d.Y)) != nil {
			var q []string
			undo := x.bindInstance(cls, cas, &q, 0)
			defer undo()
		}
	}
	return x.applyHelper(sum, c, as, 0)
}

func (x *extractor) applyHelper(sum *summary, c *js.CallExpr, as []js.IExpr, depth int) bool {
	return x.applyRead(sum, c, as, depth, false)
}

// applyBound is applyHelper for a summary whose parameters are bound
// already (and the instance it is read in pushed).
func (x *extractor) applyBound(sum *summary, c *js.CallExpr, as []js.IExpr, depth int) bool {
	return x.applyRead(sum, c, as, depth, true)
}

func (x *extractor) applyRead(sum *summary, c *js.CallExpr, as []js.IExpr, depth int, bound bool) bool {
	var made []string
	saved, savedChain := x.made, x.readChain
	x.made, x.readChain = &made, nil
	defer func() {
		chain := x.readChain
		x.made, x.readChain = saved, savedChain
		if sum.nested {
			x.maker[c] = true
			return
		}
		// What this call made, the calls in the helpers it went through
		// made at it (get(p) → this.http.send(…) → fetch(…)): each is a
		// frame where it is less whole (frame).
		for _, ic := range chain {
			if ic != c {
				x.inst[ic] = append(x.inst[ic], made...)
			}
		}
	}()
	var q []string
	x.lits = x.lits[:0]
	var r helperCall
	if bound {
		r = x.readBound(sum, &q, depth)
	} else {
		r = x.readCall(sum, as, &q, depth)
	}
	lits := slices.Clone(x.lits)
	ep := Endpoint{Kind: "wrapper", Method: r.method, Body: r.body, Headers: r.headers, Query: append(r.query, q...)}
	if !r.known {
		ep.Method = ""
	}
	if ep.Method == "GET" || ep.Method == "HEAD" {
		// A GET has no body: what it is given goes in its query.
		ep.Query, ep.Body = append(ep.Query, ep.Body...), nil
	}
	added := false
	if len(sum.urls) > 0 && r.pre == nil {
		// In the order of the source, each found after the one before.
		for _, u := range slices.Sorted(slices.Values(sum.urls)) {
			if u < len(as) && x.add(as[u], ep, c, call) != "" {
				added = true
			}
		}
		return added
	}
	for _, u := range r.urls {
		e := ep
		e.Query, e.Operations = slices.Clone(ep.Query), nil
		x.lits = lits
		if r.isClient && (strings.HasPrefix(u, "/") && !x.ownPrefix(r.own, u) || strings.HasPrefix(u, unknown+"/")) {
			e.Client = true
			e.BaseKeys = r.baseKeys
		}
		if x.addOne(cleanURL(u), e, nil, c, call) != "" {
			added = true
		}
	}
	return added
}

// curriedHelper resolves calls to curried functions (`const save = make("POST", "/prefs"); save(ctx, body)`)
// and factory-returned client objects (`const api = createApi("/tags"); api.create(ctx, body)`).
func (x *extractor) curriedHelper(c *js.CallExpr, as []js.IExpr) bool {
	callee := unwrapEnumGroup(c.X)
	var holderVar *js.Var
	prop := ""
	switch n := callee.(type) {
	case *js.Var:
		holderVar = n
	case *js.DotExpr:
		if v, ok := unwrapEnumGroup(n.X).(*js.Var); ok {
			holderVar = v
			prop = propName(n.Y)
		}
	}
	if holderVar == nil {
		return false
	}
	outerCall, ok := unwrapEnumGroup(x.constant(holderVar)).(*js.CallExpr)
	if !ok {
		return false
	}
	outerArgs := args(&outerCall.Args)
	if len(outerArgs) == 0 || len(outerArgs) > 4 || !x.hasHOFAPIArg(outerArgs) {
		return false
	}
	ov, outerParams, outerBody, ok := x.fnOf(outerCall.X)
	if !ok || x.busy[ov] {
		return false
	}
	rets := returnsOf(outerBody)
	if len(rets) != 1 {
		return false
	}
	ret := unwrapEnumGroup(rets[0])
	var innerFn js.IExpr
	var innerParams js.Params
	var innerBody *js.BlockStmt
	if prop == "" {
		var isFn bool
		innerParams, innerBody, isFn = fnParts(ret)
		if !isFn {
			return false
		}
		innerFn = ret
	} else {
		obj, isObj := ret.(*js.ObjectExpr)
		if !isObj {
			return false
		}
		pv := objectValue(obj, prop)
		if pv == nil {
			return false
		}
		innerFn = unwrapEnumGroup(pv)
		var isFn bool
		innerParams, innerBody, isFn = fnParts(innerFn)
		if !isFn {
			return false
		}
	}
	x.busy[ov] = true
	defer delete(x.busy, ov)
	var oq []string
	undo := x.bindParams(outerParams, outerArgs, &oq, 0)
	defer undo()
	sum, cached := x.msums[innerFn]
	if !cached {
		x.msums[innerFn] = nil
		sum = x.summarize(innerParams, innerBody)
		x.msums[innerFn] = sum
	}
	if sum == nil {
		return false
	}
	return x.applyHelper(sum, c, as, 1)
}

func (x *extractor) hasHOFAPIArg(as []js.IExpr) bool {
	for _, a := range as {
		if s, ok := x.argString(a); ok {
			if httpMethods[strings.ToUpper(s)] || (strings.HasPrefix(s, "/") && len(s) > 1 && !strings.HasPrefix(s, "//")) || schemeRe.MatchString(s) {
				return true
			}
			continue
		}
		switch a.(type) {
		case *js.TemplateExpr, *js.BinaryExpr:
			var q []string
			for _, s := range x.eval(a, &q, 0) {
				if (strings.HasPrefix(s, "/") && len(s) > 1 && !strings.HasPrefix(s, "//")) || schemeRe.MatchString(s) {
					return true
				}
			}
		}
	}
	return false
}

// clientNameRe names an HTTP client object: api, http, axios, client…
var clientNameRe = regexp.MustCompile(`(?i)(api|http|client|axios|request|service|fetcher|rest|gateway)`)

// isClientObj reports whether an object is an HTTP client: one made by
// new Client(base), a factory or axios.create, or one named as one
// (this.http, apiClient). A Map's or a Set's delete is not a request.
func (x *extractor) isClientObj(e js.IExpr) bool {
	switch o := e.(type) {
	case *js.GroupExpr:
		return x.isClientObj(o.X)
	case *js.CondExpr:
		return x.isClientObj(o.X) || x.isClientObj(o.Y)
	case *js.Var:
		r := root(o)
		if x.clients[r] {
			return true
		}
		if im, ok := x.esImports[r]; ok && (clientNameRe.MatchString(im[0]) || clientNameRe.MatchString(im[1])) {
			return true
		}
		return clientNameRe.MatchString(string(o.Data)) && len(o.Data) > 2
	case *js.DotExpr:
		return clientNameRe.MatchString(propName(o.Y))
	}
	return false
}

// builderParts reads a function making a URL of its one parameter and a
// base (r = e => `${base}${e}`): the function and the base.
func (x *extractor) builderParts(callee js.IExpr) (*js.Var, js.IExpr, bool) {
	fv, params, body, ok := x.fnOf(callee)
	if !ok || len(params.List) != 1 {
		return nil, nil, false
	}
	p, ok := params.List[0].Binding.(*js.Var)
	if !ok {
		return nil, nil, false
	}
	rets := returnsOf(body)
	if len(rets) != 1 {
		return nil, nil, false
	}
	var base, last js.IExpr
	switch r := rets[0].(type) {
	case *js.TemplateExpr:
		if r.Tag != nil || len(r.List) != 2 || len(templateText(r.Tail, false, true)) > 0 {
			return nil, nil, false
		}
		if len(templateText(r.List[0].Value, true, false)) > 0 || len(templateText(r.List[1].Value, false, false)) > 0 {
			return nil, nil, false
		}
		base, last = r.List[0].Expr, r.List[1].Expr
	case *js.BinaryExpr:
		if r.Op != js.AddToken {
			return nil, nil, false
		}
		base, last = r.X, r.Y
	default:
		return nil, nil, false
	}
	v, ok := last.(*js.Var)
	if !ok || root(v) != root(p) {
		return nil, nil, false
	}
	return fv, base, true
}

// builderPath is the path a URL builder's base puts first, when the base
// is a computed root and a path of its own (`${hub}/api/v1`): "{}/api/v1"
// for r(t) + o. Nothing for a base that is all computed, or all literal.
func (x *extractor) builderPath(u js.IExpr, q *[]string, depth int) []string {
	for {
		switch n := u.(type) {
		case *js.GroupExpr:
			u = n.X
			continue
		case *js.BinaryExpr:
			if n.Op == js.AddToken {
				u = n.X
				continue
			}
		}
		break
	}
	c, ok := u.(*js.CallExpr)
	if !ok || len(c.Args.List) != 1 {
		return nil
	}
	_, base, ok := x.builderParts(c.X)
	if !ok {
		return nil
	}
	vals := x.eval(base, q, depth+1)
	for _, b := range vals {
		rest, ok := strings.CutPrefix(b, unknown)
		if !ok || strings.Trim(rest, "/") == "" || strings.Contains(rest, unknown) {
			return nil
		}
	}
	return vals
}

// urlBuilder reports whether a function of the app's makes a URL of its
// one parameter and a base (r = e => `${base}${e}`): the paths it is
// given are endpoints', not routes.
//
// Such a function is the API's when a request's URL calls it (fetch(r(t) +
// o, s)), or its base reads as an API's: a router's basepath (wt(e) =>
// `${basepath}${e}`, for location.assign(wt("/home"))) makes pages.
func (x *extractor) urlBuilder(callee js.IExpr) bool {
	fv, base, ok := x.builderParts(callee)
	if !ok {
		return false
	}
	if x.apiBuilders[root(fv)] {
		return true
	}
	var q []string
	for _, b := range x.eval(base, &q, 0) {
		if b != unknown && apiLike(b) {
			return true
		}
	}
	return false
}

// builderVisitor finds the functions a request's URL is made with:
// fetch(r(t) + o, s), client.get(url(p)), u = r(p); fetch(u).
type builderVisitor struct{ x *extractor }

func (v builderVisitor) Enter(n js.INode) js.IVisitor {
	c, ok := n.(*js.CallExpr)
	if !ok || len(c.Args.List) == 0 {
		return v
	}
	x := v.x
	request := x.fetchLike(c.X)
	if d, ok := c.X.(*js.DotExpr); ok && !request {
		_, isMethod := clientMethods[propName(d.Y)]
		request = isMethod && x.isClientObj(d.X)
	}
	if !request {
		return v
	}
	var mark func(e js.IExpr, depth int)
	mark = func(e js.IExpr, depth int) {
		if depth > 2 {
			return
		}
		js.Walk(walker(func(n js.INode) {
			switch n := n.(type) {
			case *js.CallExpr:
				if fv, ok := n.X.(*js.Var); ok {
					x.apiBuilders[root(fv)] = true
				}
			case *js.Var:
				if c := x.constant(n); c != nil && c != js.IExpr(n) {
					if _, isCall := c.(*js.CallExpr); isCall {
						mark(c, depth+1)
					}
				}
			}
		}), e)
	}
	mark(c.Args.List[0].Value, 0)
	return v
}

func (builderVisitor) Exit(js.INode) {}

// checked is the first argument of the call a URL variable is set to,
// when that call is to a function of the app's that evalCall cannot read
// (a check of many cases): u = check(e.exchangeUrl, "url.api").
func (x *extractor) checked(u js.IExpr) js.IExpr {
	for i := 0; i < 3; i++ {
		v, ok := u.(*js.Var)
		if !ok {
			break
		}
		c := x.constant(v)
		if c == nil {
			return nil
		}
		u = c
	}
	c, ok := u.(*js.CallExpr)
	if !ok || len(c.Args.List) == 0 {
		return nil
	}
	if _, _, body, ok := x.fnOf(c.X); !ok || len(returnsOf(body)) <= maxReturns {
		return nil
	}
	return c.Args.List[0].Value
}

// standaloneVars finds the variables an expression uses as values, not
// those it reads a property of (e in e.exchangeUrl).
type standaloneVars func(*js.Var)

func (f standaloneVars) Enter(n js.INode) js.IVisitor {
	switch n := n.(type) {
	case *js.Var:
		f(n)
	case *js.DotExpr:
		if _, ok := n.X.(*js.Var); !ok {
			js.Walk(f, n.X)
		}
		return nil
	case *js.FuncDecl, *js.ArrowFunc, *js.MethodDecl:
		return nil
	}
	return f
}

func (standaloneVars) Exit(js.INode) {}

// nestFinder visits the calls of a function's body, knowing whether each
// is in a function the body makes.
type nestFinder struct {
	f     func(*js.CallExpr)
	depth int
}

func (v *nestFinder) Enter(n js.INode) js.IVisitor {
	switch n := n.(type) {
	case *js.CallExpr:
		v.f(n)
	case *js.FuncDecl, *js.ArrowFunc, *js.MethodDecl, *js.ClassDecl:
		v.depth++
	}
	return v
}

func (v *nestFinder) Exit(n js.INode) {
	switch n.(type) {
	case *js.FuncDecl, *js.ArrowFunc, *js.MethodDecl, *js.ClassDecl:
		v.depth--
	}
}

// fnParts is a function literal's parameters and body.
func fnParts(fn js.IExpr) (js.Params, *js.BlockStmt, bool) {
	switch f := fn.(type) {
	case *js.ArrowFunc:
		return f.Params, &f.Body, true
	case *js.FuncDecl:
		return f.Params, &f.Body, true
	case *js.MethodDecl:
		return f.Params, &f.Body, true
	}
	return js.Params{}, nil, false
}

// methodDef is a function the script gives a name as a method, and what
// holds it: an object literal, or a class.
type methodDef struct {
	fn    js.IExpr
	owner js.INode
}

// methodVisitor finds the functions the script gives a name as an
// object's or a class's method: {async sendNote(e, t){…}}, {changeRole:
// () => sE} (a module namespace's getter), class C {fetchUsers(){…}};
// and, for knowing which object a call's receiver is, the names objects
// are given ({appMembers: {…}}, conversations: c, this.api = new Api()),
// and the functions that return them (function Cr(){return {…}}).
type methodVisitor struct{ x *extractor }

func (v methodVisitor) Enter(n js.INode) js.IVisitor {
	x := v.x
	switch n := n.(type) {
	case *js.ObjectExpr:
		for i := range n.List {
			p := &n.List[i]
			name := propKey(p)
			if name == "" {
				continue
			}
			if fn := x.methodFn(p.Value); fn != nil {
				x.methodDefs[name] = append(x.methodDefs[name], methodDef{fn, n})
				x.ownerOf[p.Value] = n
				continue
			}
			if o, ok := p.Value.(*js.ObjectExpr); ok {
				x.objParent[o], x.objKey[o] = n, name
			}
			if holderValue(p.Value) {
				x.named[name] = append(x.named[name], p.Value)
			}
		}
	case *js.ClassDecl:
		for _, el := range n.List {
			if el.Method != nil {
				name := propName(&el.Method.Name.PropertyName)
				x.methodDefs[name] = append(x.methodDefs[name], methodDef{el.Method, n})
				x.ownerOf[el.Method] = n
			}
		}
		if _, named := x.classOf[n]; n.Name != nil && !named {
			// const X = class Y {…}: X, set as the declaration was
			// entered, is the name the script uses.
			x.classOf[n] = root(n.Name)
		}
	case *js.FuncDecl:
		if n.Name != nil {
			x.returned(root(n.Name), &n.Body)
			x.placeParams(root(n.Name), n.Params)
		}
	case *js.CallExpr:
		if v, ok := n.X.(*js.Var); ok {
			x.callsTo[root(v)] = append(x.callsTo[root(v)], n)
		}
	case *js.VarDecl:
		for _, b := range n.List {
			bv, ok := b.Binding.(*js.Var)
			if !ok || b.Default == nil {
				continue
			}
			switch f := ungroup(b.Default).(type) {
			case *js.ArrowFunc:
				x.returned(root(bv), &f.Body)
				x.placeParams(root(bv), f.Params)
			case *js.FuncDecl:
				x.returned(root(bv), &f.Body)
				x.placeParams(root(bv), f.Params)
			case *js.ClassDecl:
				x.classOf[f] = root(bv)
			default:
				if holderValue(b.Default) {
					x.named[string(bv.Data)] = append(x.named[string(bv.Data)], b.Default)
				}
			}
		}
	case *js.BinaryExpr:
		if d, ok := n.X.(*js.DotExpr); ok && n.Op == js.EqToken && holderValue(n.Y) {
			name := propName(d.Y)
			x.named[name] = append(x.named[name], n.Y)
		}
	}
	return v
}

func (methodVisitor) Exit(js.INode) {}

// holderValue reports whether a value can be an object holding methods:
// a variable, a call, an instance, an object, what is awaited.
func holderValue(e js.IExpr) bool {
	switch n := e.(type) {
	case *js.Var, *js.CallExpr, *js.NewExpr, *js.ObjectExpr, *js.GroupExpr:
		return true
	case *js.UnaryExpr:
		return n.Op == js.AwaitToken
	}
	return false
}

// returned records the object literals a function returns as made by it.
func (x *extractor) returned(f *js.Var, body *js.BlockStmt) {
	for _, r := range returnsOf(body) {
		if o, ok := unwrapEnumGroup(r).(*js.ObjectExpr); ok {
			x.madeBy[o] = f
		}
	}
}

// methodFn is the function a property's value is: a function, or a
// module namespace's getter of one (() => sE).
func (x *extractor) methodFn(e js.IExpr) js.IExpr {
	switch f := e.(type) {
	case *js.ArrowFunc:
		if len(f.Params.List) == 0 && f.Params.Rest == nil {
			if rets := returnsOf(&f.Body); len(rets) == 1 {
				if rv, ok := rets[0].(*js.Var); ok {
					if _, _, _, isFn := x.fnOf(rv); isFn {
						return root(rv)
					}
				}
			}
		}
		return f
	case *js.FuncDecl, *js.MethodDecl:
		return f
	}
	return nil
}

// methodNameRe is a method name of the app's: two words at least
// (sendNote, changeRole), not get or send, which every library has.
var methodNameRe = regexp.MustCompile(`^[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*$`)

// globalObjs are the platform's objects, whose methods are not the app's.
var globalObjs = map[string]bool{"Object": true, "JSON": true, "Math": true, "Reflect": true, "Promise": true, "Array": true,
	"document": true, "window": true, "self": true, "globalThis": true, "navigator": true, "console": true, "location": true,
	"history": true, "localStorage": true, "sessionStorage": true, "crypto": true, "Intl": true, "Date": true, "Number": true, "String": true}

// methodOf is the function a call of a method (X.name(…), n arguments, -1
// when spread) calls. The receiver read through the script's constants
// (DD.appMembers.changeRole, DD = {appMembers: QT}, QT = t({changeRole:
// () => sE})) is that function. A receiver the script does not hold
// (n.conversations.sendNote, n a component's props) is matched by name,
// only when one of the methods of that name takes that many arguments
// and is held by what the receiver's name is given (conversations: c, c =
// useMemo(() => Cr(…)), Cr returning the object that has sendNote).
func (x *extractor) methodOf(d *js.DotExpr, n int) js.IExpr {
	if fn := x.classCallee(d, n); fn != nil {
		return fn
	}
	// Every function a property or a class method holds is in methodDefs
	// (methodVisitor): a name none has is no method of the script's.
	if len(x.methodDefs[propName(d.Y)]) == 0 {
		return nil
	}
	// What it is does not change from call to call unless the receiver is
	// this or starts at a parameter a call binds.
	key := methodKey{d, n}
	if fixed := x.fixedReceiver(d.X); fixed {
		if fn, ok := x.methodMemo[key]; ok {
			return fn
		}
		fn := x.methodOfNow(d, n)
		x.methodMemo[key] = fn
		return fn
	}
	return x.methodOfNow(d, n)
}

// methodKey is a method call's receiver and its count of arguments.
type methodKey struct {
	d *js.DotExpr
	n int
}

// fixedReceiver reports whether a receiver reads the same wherever it is
// read: not this, not from a parameter bound now.
func (x *extractor) fixedReceiver(e js.IExpr) bool {
	for {
		switch n := e.(type) {
		case *js.DotExpr:
			e = n.X
			continue
		case *js.GroupExpr:
			e = n.X
			continue
		case *js.Var:
			if x.isThis(n) {
				return false
			}
			_, bound := x.args[root(n)]
			return !bound
		}
		return false
	}
}

func (x *extractor) methodOfNow(d *js.DotExpr, n int) js.IExpr {
	if v, ok := x.memberValue(d, 0); ok {
		return x.methodFn(v)
	}
	name := propName(d.Y)
	if x.isThis(d.X) {
		return x.thisMethod(name, n)
	}
	if !methodNameRe.MatchString(name) {
		return nil
	}
	parent := ""
	switch r := d.X.(type) {
	case *js.DotExpr:
		parent = propName(r.Y)
	case *js.Var:
		if len(r.Data) >= 3 && !globalObjs[string(r.Data)] {
			parent = string(r.Data) // conversations.sendNote, unminified
		}
	}
	if parent == "" {
		return nil
	}
	base := d.X
	for {
		if dd, ok := base.(*js.DotExpr); ok {
			base = dd.X
			continue
		}
		break
	}
	if v, ok := base.(*js.Var); ok && globalObjs[string(v.Data)] && x.constant(v) == nil {
		return nil
	}
	var found js.IExpr
	for _, def := range x.methodDefs[name] {
		params, _, _ := fnParts(def.fn)
		if v, ok := def.fn.(*js.Var); ok {
			_, params, _, _ = x.fnOf(v)
		}
		if !takes(params, n) || !x.holds(parent, def.owner) {
			continue
		}
		if found != nil {
			return nil // two of them: which one is not known
		}
		found = def.fn
	}
	return found
}

// genericMethods are names every client and library has: a this.x(…) of
// one is no method of the app's to look for elsewhere.
var genericMethods = map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "request": true,
	"fetch": true, "send": true, "call": true, "init": true, "load": true, "then": true}

// thisMethod is the function this.name(…) calls (n arguments): one of the
// object or class the method around the call is on; for a Vue component's
// method, one of the component's (its methods: {…}, the object a
// lifecycle hook is on). Failing those, the one function of that name the
// script's methods: {…} blocks define (a mixin's), taking n arguments.
func (x *extractor) thisMethod(name string, n int) js.IExpr {
	var owner js.INode
	for i := len(x.fnStack) - 1; i >= 0 && owner == nil; i-- {
		owner = x.ownerOf[x.fnStack[i]]
	}
	var local []js.IExpr
	switch o := owner.(type) {
	case *js.ClassDecl:
		for _, el := range o.List {
			if el.Method != nil && propName(&el.Method.Name.PropertyName) == name {
				local = append(local, el.Method)
			}
		}
	case *js.ObjectExpr:
		comp := o
		if k := x.objKey[o]; (k == "methods" || k == "computed" || k == "watch") && x.objParent[o] != nil {
			comp = x.objParent[o]
		}
		objs := []*js.ObjectExpr{comp}
		if m, ok := objectValue(comp, "methods").(*js.ObjectExpr); ok && m != comp {
			objs = append(objs, m)
		}
		if !slices.Contains(objs, o) {
			objs = append(objs, o)
		}
		for _, ob := range objs {
			for i := range ob.List {
				if propKey(&ob.List[i]) == name {
					if fn := x.methodFn(ob.List[i].Value); fn != nil {
						local = append(local, fn)
					}
				}
			}
		}
	}
	if len(local) > 0 {
		if len(local) == 1 && x.takesFn(local[0], n) {
			return local[0]
		}
		return nil
	}
	if !methodNameRe.MatchString(name) || genericMethods[strings.ToLower(name)] {
		return nil
	}
	var found js.IExpr
	for _, def := range x.methodDefs[name] {
		o, ok := def.owner.(*js.ObjectExpr)
		if !ok || x.objKey[o] != "methods" {
			continue
		}
		if found != nil {
			return nil
		}
		found = def.fn
	}
	if found == nil || !x.takesFn(found, n) {
		return nil
	}
	return found
}

// takesFn reports whether a method this.x(…) calls takes n arguments:
// no more than its parameters (or any with a rest one). Fewer is how
// JavaScript leaves one optional (o || Object.assign({}, this.form)).
func (x *extractor) takesFn(fn js.IExpr, n int) bool {
	params, _, _ := fnParts(fn)
	if v, ok := fn.(*js.Var); ok {
		_, params, _, _ = x.fnOf(v)
	}
	return n < 0 || params.Rest != nil || n <= len(params.List)
}

// takes reports whether a function takes n arguments: as many as its
// parameters, fewer when those left have defaults, any with a rest one.
func takes(params js.Params, n int) bool {
	if n < 0 || params.Rest != nil {
		return true
	}
	if n > len(params.List) {
		return false
	}
	for _, b := range params.List[n:] {
		if b.Default == nil {
			return false
		}
	}
	return true
}

// holds reports whether a name is given the object or class a method is
// on: as the property whose value it is, or a value made by the function
// returning it, or an instance of the class.
func (x *extractor) holds(name string, owner js.INode) bool {
	var maker *js.Var
	switch o := owner.(type) {
	case *js.ObjectExpr:
		maker = x.madeBy[o]
	case *js.ClassDecl:
		maker = x.classOf[o]
	}
	for _, val := range x.named[name] {
		if js.INode(val) == owner {
			return true
		}
		if maker != nil && x.producedBy(val, maker, 0) {
			return true
		}
	}
	return false
}

// producedBy reports whether a value is made by a function or class:
// f(…), new C(…), a constant set to one, a hook's (useMemo(() => f(…))).
func (x *extractor) producedBy(e js.IExpr, f *js.Var, depth int) bool {
	if depth > 4 {
		return false
	}
	switch n := e.(type) {
	case *js.GroupExpr:
		return x.producedBy(n.X, f, depth+1)
	case *js.UnaryExpr:
		if n.Op == js.AwaitToken {
			return x.producedBy(n.X, f, depth+1)
		}
	case *js.Var:
		if c := x.constant(n); c != nil {
			return x.producedBy(c, f, depth+1)
		}
	case *js.NewExpr:
		v, ok := n.X.(*js.Var)
		return ok && root(v) == f
	case *js.CallExpr:
		callee := n.X
		if g, ok := callee.(*js.GroupExpr); ok {
			callee = g.X
		}
		if c, ok := callee.(*js.CommaExpr); ok && len(c.List) > 0 {
			callee = c.List[len(c.List)-1] // (0, R.useMemo)
		}
		if v, ok := callee.(*js.Var); ok && root(v) == f {
			return true
		}
		if len(n.Args.List) > 0 {
			if af, ok := n.Args.List[0].Value.(*js.ArrowFunc); ok && len(af.Params.List) == 0 {
				for _, r := range returnsOf(&af.Body) {
					if x.producedBy(r, f, depth+1) {
						return true
					}
				}
			}
		}
	}
	return false
}

// memberValue is the value of a chain of properties the script holds
// (DD.appMembers.changeRole), through constant objects and module
// namespaces (t({changeRole: () => sE})).
func (x *extractor) memberValue(d *js.DotExpr, depth int) (js.IExpr, bool) {
	obj := x.objectOf(d.X, depth+1)
	if obj == nil {
		return nil, false
	}
	v := objectValue(obj, propName(d.Y))
	return v, v != nil
}

func (x *extractor) objectOf(e js.IExpr, depth int) *js.ObjectExpr {
	if depth > 6 {
		return nil
	}
	switch n := e.(type) {
	case *js.GroupExpr:
		return x.objectOf(n.X, depth+1)
	case *js.ObjectExpr:
		return n
	case *js.Var:
		if o, ok := x.object(n); ok {
			return o
		}
		if _, bound := x.args[root(n)]; bound {
			return nil
		}
		if c, ok := x.constant(n).(*js.CallExpr); ok {
			return x.objectOf(c, depth+1)
		}
	case *js.DotExpr:
		if v, ok := x.memberValue(n, depth+1); ok {
			return x.objectOf(v, depth+1)
		}
	case *js.CallExpr:
		// t({add: () => oE, changeRole: () => sE}): a module namespace,
		// every value a getter.
		if len(n.Args.List) != 1 {
			return nil
		}
		o, ok := n.Args.List[0].Value.(*js.ObjectExpr)
		if !ok || len(o.List) == 0 {
			return nil
		}
		for _, p := range o.List {
			af, ok := p.Value.(*js.ArrowFunc)
			if p.Spread || !ok || len(af.Params.List) != 0 {
				return nil
			}
		}
		return o
	}
	return nil
}

// nargsOf is how many arguments a call passes, -1 when it spreads some.
func nargsOf(c *js.CallExpr) int {
	for _, a := range c.Args.List {
		if a.Rest {
			return -1
		}
	}
	return len(c.Args.List)
}

// propKey is an object literal's property name, a method's written short
// ({async sendNote(e, t){…}}) included.
func propKey(p *js.Property) string {
	if p.Spread {
		return ""
	}
	if p.Name != nil {
		return propName(p.Name)
	}
	if m, ok := p.Value.(*js.MethodDecl); ok {
		return propName(&m.Name.PropertyName)
	}
	return ""
}

// ownPrefix reports whether a URL is under one of a client's prefixes
// that is a path of the page's origin (new Sy("/console-api"), no client
// putting it after a base): the whole URL, on the page's origin, no base
// to find.
func (x *extractor) ownPrefix(pre []string, u string) bool {
	for _, p := range pre {
		if x.ownPre[p] && !x.basedPre[p] && len(p) > 1 && strings.HasPrefix(u, strings.TrimRight(p, "/")+"/") {
			return true
		}
	}
	return false
}

// paramPlace is a parameter's function and place.
type paramPlace struct {
	fn *js.Var
	i  int
}

func (x *extractor) placeParams(fn *js.Var, params js.Params) {
	for i, b := range params.List {
		if v, ok := b.Binding.(*js.Var); ok {
			x.paramOf[root(v)] = paramPlace{fn, i}
		}
	}
}

// baseProps are the names of an options object's property that is a base
// URL (apiBase, baseUrl, apiUrl, endpoint, host); not a request's url,
// which every library's config has.
var baseProps = regexp.MustCompile(`(?i)(?:base|base_?ur[li]|api_?ur[li]|endpoint|host|prefix|root)$`)

// fromCallers is e.apiBase, e a function's parameter no call binds here,
// as its callers give it (Cr({apiBase: `${hub}/api/v1`, fetch})): the
// values of that property of the object each call passes, when there are
// four calls at most, each says, and they make a path of their own (a
// base the code computes says nothing).
func (x *extractor) fromCallers(d *js.DotExpr, q *[]string, depth int) []string {
	v, ok := d.X.(*js.Var)
	if !ok {
		return nil
	}
	return x.fromCallersOf(root(v), propName(d.Y), q, depth)
}

func (x *extractor) fromCallersOf(v *js.Var, name string, q *[]string, depth int) []string {
	if _, bound := x.args[v]; bound || !baseProps.MatchString(name) {
		return nil
	}
	pl, ok := x.paramOf[v]
	key := [2]any{v, name}
	if !ok || x.busy[key] {
		return nil
	}
	if out, ok := x.fromMemo[key]; ok {
		return out
	}
	var out []string
	defer func() { x.fromMemo[key] = out }()
	calls := x.callsTo[pl.fn]
	if len(calls) == 0 || len(calls) > 4 {
		return nil
	}
	x.busy[key] = true
	defer delete(x.busy, key)
	var all []string
	for _, c := range calls {
		if pl.i >= len(c.Args.List) || c.Args.List[pl.i].Rest {
			return nil
		}
		obj, ok := x.object(c.Args.List[pl.i].Value)
		if !ok {
			return nil
		}
		val := objectValue(obj, name)
		if val == nil {
			return nil
		}
		var cq []string
		vals := x.eval(val, &cq, depth+1)
		for _, s := range vals {
			if strings.Trim(strings.ReplaceAll(s, unknown, ""), "/") == "" {
				return nil
			}
		}
		all = union(all, vals)
	}
	out = all
	return out
}

// calleeFn is the function a call calls: one of the app's set once
// (fnOf), a method (methodOf), or one a caller gives for a parameter's
// property (So({buildSendUrl: e => …}), e.buildSendUrl(n) in So). The key
// marks it busy.
func (x *extractor) calleeFn(c *js.CallExpr) (key any, v *js.Var, params js.Params, body *js.BlockStmt, ok bool) {
	if v, params, body, ok = x.fnOf(c.X); ok {
		return v, v, params, body, true
	}
	callee := c.X
	for {
		switch g := callee.(type) {
		case *js.GroupExpr:
			callee = g.X
			continue
		case *js.CommaExpr:
			if len(g.List) > 0 {
				callee = g.List[len(g.List)-1]
				continue
			}
		}
		break
	}
	d, isDot := callee.(*js.DotExpr)
	if !isDot {
		return nil, nil, js.Params{}, nil, false
	}
	fn := x.methodOf(d, nargsOf(c))
	if fn == nil {
		fn = x.givenFn(d)
	}
	if fn == nil {
		fn, _ = x.wpMember(d, 0)
	}
	if fn == nil {
		return nil, nil, js.Params{}, nil, false
	}
	if fv, isVar := fn.(*js.Var); isVar {
		if v, params, body, ok = x.fnOf(fv); ok {
			return fn, nil, params, body, true
		}
		return nil, nil, js.Params{}, nil, false
	}
	params, body, ok = fnParts(fn)
	return fn, nil, params, body, ok
}

// givenFn is the function the one caller of a function gives as a
// property of its parameter (e.buildSendUrl, So({buildSendUrl: e => …})).
func (x *extractor) givenFn(d *js.DotExpr) js.IExpr {
	pv, ok := d.X.(*js.Var)
	if !ok {
		return nil
	}
	pv = root(pv)
	if _, bound := x.args[pv]; bound {
		if obj, ok := x.object(pv); ok {
			return x.methodFn(objectValue(obj, propName(d.Y)))
		}
		return nil
	}
	pl, ok := x.paramOf[pv]
	if !ok {
		return nil
	}
	if fn, ok := x.givenMemo[d]; ok {
		return fn
	}
	fn := x.givenFrom(pl, d)
	x.givenMemo[d] = fn
	return fn
}

func (x *extractor) givenFrom(pl paramPlace, d *js.DotExpr) js.IExpr {
	calls := x.callsTo[pl.fn]
	if len(calls) != 1 || pl.i >= len(calls[0].Args.List) {
		return nil
	}
	obj, ok := x.object(calls[0].Args.List[pl.i].Value)
	if !ok {
		return nil
	}
	if fn := x.methodFn(objectValue(obj, propName(d.Y))); fn != nil {
		return fn
	}
	if fv, ok := objectValue(obj, propName(d.Y)).(*js.Var); ok {
		if _, _, _, isFn := x.fnOf(fv); isFn {
			return root(fv)
		}
	}
	return nil
}

// ownPath reports whether the URLs a function makes have a path of their
// own: a segment of three letters outside what is unknown.
func ownPath(out []string) bool {
	if len(out) == 0 {
		return false
	}
	for _, u := range out {
		word := false
		for _, sg := range strings.Split(strings.ReplaceAll(u, unknown, "/"), "/") {
			letters := 0
			for _, r := range sg {
				if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
					letters++
				}
			}
			word = word || letters >= 3
		}
		if !word {
			return false
		}
	}
	return true
}

// sseParam is the parameter of an event stream's reader that is its URL
// (fetchEventSource(url, {headers, onmessage}), Ra(e, t) setting accept
// to text/event-stream and fetching e), or -1.
func (x *extractor) sseParam(callee js.IExpr) int {
	v, params, body, ok := x.fnOf(callee)
	if !ok {
		return -1
	}
	if i, ok := x.sse[v]; ok {
		return i
	}
	if !x.hasSSE {
		return -1
	}
	x.sse[v] = -1
	idx := paramIndex(params)
	stream, at := false, -1
	js.Walk(walker(func(n js.INode) {
		switch n := n.(type) {
		case *js.LiteralExpr:
			if n.TokenType == js.StringToken || n.TokenType == js.TemplateToken {
				stream = stream || strings.Contains(string(n.Data), "text/event-stream")
			}
		case *js.Var:
			switch c := x.constant(n).(type) {
			case *js.LiteralExpr:
				stream = stream || strings.Contains(string(c.Data), "text/event-stream")
			case *js.TemplateExpr:
				stream = stream || len(c.List) == 0 && strings.Contains(string(c.Tail), "text/event-stream")
			}
		case *js.TemplateExpr:
			for _, p := range n.List {
				stream = stream || strings.Contains(string(p.Value), "text/event-stream")
			}
			stream = stream || strings.Contains(string(n.Tail), "text/event-stream")
		case *js.CallExpr:
			// v(e, {...u, headers: f}): the parameter fetched; the first
			// one when it is (fetchEventSource(url, options)).
			if len(n.Args.List) > 1 {
				if i := idx(n.Args.List[0].Value); i >= 0 && (at < 0 || i < at) {
					at = i
				}
			}
		}
	}), body)
	if stream {
		x.sse[v] = at
	}
	return x.sse[v]
}

// transport reads an AI SDK transport's request ({api, prepareSendMessages
// Request: ({messages}) => ({api: e.buildSendUrl(n), body: Co(t, …)})}):
// the URL it sends to, POST with the body it returns.
func (x *extractor) transport(p *js.Property) {
	_, body, ok := fnParts(p.Value)
	if !ok {
		return
	}
	for _, r := range returnsOf(body) {
		obj, ok := x.object(r)
		if !ok {
			continue
		}
		u := objectValue(obj, "api")
		if u == nil {
			u = objectValue(obj, "url")
		}
		if u == nil {
			continue
		}
		ep := Endpoint{Kind: "transport", Method: "POST"}
		if b := objectValue(obj, "body"); b != nil {
			ep.Body = x.keys(b, "", 0)
		}
		if h := objectValue(obj, "headers"); h != nil {
			ep.Headers = x.keys(h, "", 2)
		}
		x.add(u, ep, nil, call)
	}
}
