package jsapi

// This file: keys: the fields of a request's body and options.

import (
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

const maxKeySteps = 2048

type keysBusyVar struct{ v *js.Var }

// keys lists the field names an expression sends: the leaves of an object
// literal (nested ones as a.b, three levels at most), through
// JSON.stringify, URLSearchParams and FormData, and constants.
func (x *extractor) keys(e js.IExpr, prefix string, depth int) []string {
	steps := 0
	return x.keysAt(e, prefix, depth, &steps)
}

func (x *extractor) keysAt(e js.IExpr, prefix string, depth int, steps *int) []string {
	if e == nil || steps == nil {
		return nil
	}
	*steps++
	// Three levels of nesting at most (a.b.c), and a bound on the
	// variables, calls, branches and spreads gone through to find them.
	if *steps > maxKeySteps || depth > 16 || strings.Count(prefix, ".") > 3 {
		return nil
	}
	switch n := e.(type) {
	case *js.ObjectExpr:
		var out []string
		for _, p := range n.List {
			if p.Spread {
				// {...base, ...cond ? {k: v} : {}}: the fields it spreads.
				out = append(out, x.keysAt(p.Value, prefix, depth+1, steps)...)
				continue
			}
			if p.Name == nil {
				continue
			}
			k := propName(p.Name)
			if k == "" {
				continue
			}
			x.noteKey(prefix+k, p.Value)
			if sub := x.keysAt(p.Value, prefix+k+".", depth+1, steps); len(sub) > 0 && x.nests(p.Value, 0) {
				out = append(out, sub...)
				continue
			}
			out = append(out, prefix+k)
		}
		return out
	case *js.CallExpr:
		d, ok := n.X.(*js.DotExpr)
		if !ok {
			// make(r): the object a function of the app's returns.
			return x.returnedKeys(n, prefix, depth, steps)
		}
		if len(n.Args.List) == 0 {
			break
		}
		switch propName(d.Y) {
		case "map", "flatMap":
			// list.map(e => ({k: e.v})): each element's fields.
			return x.fnKeys(n.Args.List[0].Value, prefix, depth, steps)
		case "stringify":
			// JSON.stringify, and qs.stringify for a form's body
			return x.keysAt(n.Args.List[0].Value, prefix, depth+1, steps)
		case "assign":
			if isGlobal(d.X, "Object") {
				var out []string
				for _, a := range n.Args.List {
					out = append(out, x.keysAt(a.Value, prefix, depth+1, steps)...)
				}
				return out
			}
		}
	case *js.DotExpr:
		if v, ok := x.member(n); ok {
			return x.keysAt(v, prefix, depth+1, steps)
		}
		// this.loginForm, when one object literal is all it is given:
		// several (this.form in many components) say nothing for sure.
		if x.isThis(n.X) {
			var obj *js.ObjectExpr
			for _, v := range x.thisProps[propName(n.Y)] {
				if o, ok := v.(*js.ObjectExpr); ok {
					if obj != nil && obj != o {
						return nil
					}
					obj = o
				}
			}
			if obj != nil {
				return x.keysAt(obj, prefix, depth+1, steps)
			}
		}
	case *js.NewExpr:
		switch globalName(n.X) {
		case "URLSearchParams", "FormData":
			if n.Args != nil && len(n.Args.List) > 0 {
				return x.keysAt(n.Args.List[0].Value, prefix, depth+1, steps)
			}
		}
	case *js.Var:
		rv := root(n)
		bk := keysBusyVar{rv}
		if x.busy[bk] {
			return nil
		}
		x.busy[bk] = true
		defer delete(x.busy, bk)
		if a, ok := x.args[rv]; ok {
			return x.keysAt(a, prefix, depth+1, steps)
		}
		if src := x.destructFrom[rv]; src != nil && x.propOf[rv] != "" {
			if obj, ok := x.object(src); ok {
				if val := objectValue(obj, x.propOf[rv]); val != nil {
					return x.keysAt(val, prefix, depth+1, steps)
				}
			}
		}
		if c := x.constant(n); c != nil {
			if ne, ok := c.(*js.NewExpr); ok {
				switch globalName(ne.X) {
				case "FormData", "URLSearchParams":
					// r = new FormData; r.append("file", t): what it is
					// given, and what is added to it.
					var out []string
					for _, k := range x.qset[rv] {
						out = append(out, prefix+k)
					}
					return append(out, x.keysAt(c, prefix, depth+1, steps)...)
				case "Map", "Set", "WeakMap", "WeakSet", "Headers":
				default:
					if len(x.qset[rv]) > 0 {
						var out []string
						for _, k := range x.qset[rv] {
							out = append(out, prefix+k)
						}
						return out
					}
				}
			}
			// r = o || Object.assign({}, this.form); r.start_index = e: what
			// it is set to, and the fields set on it after.
			out := x.keysAt(c, prefix, depth+1, steps)
			for _, k := range x.setOn(rv) {
				out = append(out, prefix+k)
			}
			return out
		}
		if len(x.qset[rv]) > 0 && len(x.chains[rv]) > 0 && len(x.chains[rv][0]) > 0 {
			if ne, ok := ungroup(x.chains[rv][0][0].expr).(*js.NewExpr); ok {
				switch globalName(ne.X) {
				case "Map", "Set", "WeakMap", "WeakSet", "Headers":
				default:
					// Immutable query builders reassigned across conditions
					// (let p = new HttpParams(); p = p.set("k", v)).
					var out []string
					for _, k := range x.qset[rv] {
						out = append(out, prefix+k)
					}
					return out
				}
			}
		}
	case *js.ArrayExpr:
		// {files: [{content_type, file_size}]}: its elements' fields.
		var out []string
		for _, el := range n.List {
			if !el.Spread {
				out = append(out, x.keysAt(el.Value, prefix, depth+1, steps)...)
			}
		}
		return out
	case *js.GroupExpr:
		return x.keysAt(n.X, prefix, depth+1, steps)
	case *js.CommaExpr:
		// return a && (r.x = a), r: the last is the value.
		if len(n.List) > 0 {
			return x.keysAt(n.List[len(n.List)-1], prefix, depth+1, steps)
		}
	case *js.CondExpr:
		// cond ? formData : {...fields}
		return append(x.keysAt(n.X, prefix, depth+1, steps), x.keysAt(n.Y, prefix, depth+1, steps)...)
	case *js.BinaryExpr:
		// body && JSON.stringify(body), headers ?? {}
		if n.Op == js.AndToken || n.Op == js.OrToken || n.Op == js.NullishToken {
			return append(x.keysAt(n.X, prefix, depth+1, steps), x.keysAt(n.Y, prefix, depth+1, steps)...)
		}
	}
	return nil
}

// setOn are the names of the fields set on a variable (r.start_index = e).
func (x *extractor) setOn(v *js.Var) []string {
	if x.propsOf == nil {
		x.propsOf = map[*js.Var][]string{}
		for _, p := range x.props {
			if o, ok := p.obj.(*js.Var); ok && p.name != "" {
				x.propsOf[root(o)] = append(x.propsOf[root(o)], p.name)
			}
		}
	}
	return x.propsOf[v]
}

func isObject(e js.IExpr) bool {
	_, ok := e.(*js.ObjectExpr)
	return ok
}

// nests reports whether a field's value is an object of fields whose
// names go under its own (a.b): an object literal, the list a .map makes
// of them, what a function of the app's returns; through the variables,
// groups and conditions that hold one ({entries: n}, n = t.map(…); {metadata:
// a}, a = r ? _D(r) : void 0).
func (x *extractor) nests(e js.IExpr, depth int) bool {
	if e == nil || depth > 6 {
		return false
	}
	switch n := e.(type) {
	case *js.ObjectExpr:
		return true
	case *js.CallExpr:
		if d, ok := n.X.(*js.DotExpr); ok {
			p := propName(d.Y)
			return p == "map" || p == "flatMap"
		}
		return true
	case *js.ArrayExpr:
		for _, el := range n.List {
			if x.nests(el.Value, depth+1) {
				return true
			}
		}
	case *js.GroupExpr:
		return x.nests(n.X, depth+1)
	case *js.CommaExpr:
		if len(n.List) > 0 {
			return x.nests(n.List[len(n.List)-1], depth+1)
		}
	case *js.CondExpr:
		return x.nests(n.X, depth+1) || x.nests(n.Y, depth+1)
	case *js.BinaryExpr:
		if n.Op == js.AndToken || n.Op == js.OrToken || n.Op == js.NullishToken {
			return x.nests(n.X, depth+1) || x.nests(n.Y, depth+1)
		}
	case *js.Var:
		if a, ok := x.args[root(n)]; ok && a != e {
			return x.nests(a, depth+1)
		}
		if c := x.constant(n); c != nil && c != e {
			return x.nests(c, depth+1)
		}
	}
	return false
}

// fnKeys are the fields of the object a function literal returns.
func (x *extractor) fnKeys(fn js.IExpr, prefix string, depth int, steps *int) []string {
	var body *js.BlockStmt
	switch f := fn.(type) {
	case *js.ArrowFunc:
		body = &f.Body
	case *js.FuncDecl:
		body = &f.Body
	default:
		return nil
	}
	var out []string
	for _, r := range returnsOf(body) {
		out = append(out, x.keysAt(r, prefix, depth+1, steps)...)
	}
	return out
}

// returnedKeys are the fields of what a function of the app's returns,
// its parameters bound to the call's arguments: an object literal, a
// parameter (a check that hands its argument back), or a local object it
// fills (const r = {page_size: t}; if (n) r.page_token = n; return r).
func (x *extractor) returnedKeys(c *js.CallExpr, prefix string, depth int, steps *int) []string {
	v, params, body, ok := x.fnOf(c.X)
	if !ok || x.busy[v] {
		return nil
	}
	rets := returnsOf(body)
	if len(rets) == 0 || len(rets) > maxReturns {
		// A check or a sanitizer of many cases (H(obj, "json.object")):
		// the object it is given is the one it hands back.
		if as := args(&c.Args); len(as) > 0 && isObject(as[0]) {
			return x.keysAt(as[0], prefix, depth+1, steps)
		}
		return nil
	}
	x.busy[v] = true
	defer delete(x.busy, v)
	var q []string
	restore := x.bindParams(params, args(&c.Args), &q, depth)
	defer restore()
	var out []string
	for _, r := range rets {
		out = append(out, x.keysAt(r, prefix, depth+1, steps)...)
		for {
			if c, ok := r.(*js.CommaExpr); ok && len(c.List) > 0 {
				r = c.List[len(c.List)-1]
				continue
			}
			if g, ok := r.(*js.GroupExpr); ok {
				r = g.X
				continue
			}
			break
		}
		if lv, ok := r.(*js.Var); ok {
			lv = root(lv)
			for _, p := range x.props {
				if o, ok := p.obj.(*js.Var); ok && root(o) == lv && p.name != "" {
					out = append(out, prefix+p.name)
				}
			}
		}
	}
	return out
}

// options reads a request options object: method (or jQuery's type),
// body (or data), headers, params, baseURL, and url (or endpoint).
type opts struct {
	url        js.IExpr
	base       js.IExpr
	method     string
	methodExpr js.IExpr
	bodyExpr   js.IExpr
	queryExpr  js.IExpr
	known      bool // the object says the method (or says nothing: fetch's GET)
	body       []string
	headers    []string
	query      []string
	// isOpt: the object has a key only a request's options have, so its
	// keys are no body's fields ({method: "DELETE"}, {signal}).
	isOpt   bool
	httpOpt bool // has a strict HTTP config key (method, baseURL, headers, params…)
}

// optKeys are the keys of a request's options (fetch's RequestInit,
// axios's config, jQuery's settings).
var optKeys = map[string]bool{"method": true, "type": true, "url": true, "body": true, "data": true, "json": true, "form": true,
	"headers": true, "params": true, "query": true, "queries": true, "searchParams": true, "signal": true, "credentials": true, "mode": true,
	"cache": true, "redirect": true, "referrer": true, "referrerPolicy": true, "keepalive": true, "integrity": true,
	"priority": true, "withCredentials": true, "timeout": true, "responseType": true, "baseURL": true, "baseUrl": true}

var httpOptKeys = map[string]bool{"method": true, "baseURL": true, "baseUrl": true, "headers": true, "params": true,
	"query": true, "queries": true, "searchParams": true, "withCredentials": true, "responseType": true, "credentials": true, "signal": true, "body": true}

func (x *extractor) options(e js.IExpr) (o opts, ok bool) {
	return x.optionsAt(e, 0)
}

func (x *extractor) optionsAt(e js.IExpr, depth int) (o opts, ok bool) {
	if depth > 4 {
		return o, false
	}
	switch n := e.(type) {
	case *js.GroupExpr:
		return x.optionsAt(n.X, depth+1)
	case *js.CallExpr:
		if d, ok := n.X.(*js.DotExpr); ok && propName(d.Y) == "assign" && isGlobal(d.X, "Object") || x.assignLike(n.X) {
			// Object.assign({}, init, {headers}): the objects in turn, as
			// {...init, headers} spreads them.
			// In the order written (overlay: a later method replaces
			// an earlier one; a part that cannot be read may hold one).
			o.known = true
			for _, a := range args(&n.Args) {
				in, ok := x.optionsAt(a, depth+1)
				o.overlay(in, ok)
			}
			return o, true
		}
		return x.initCall(n, depth)
	case *js.CondExpr:
		// ...(body ? {body} : {}): either side, its method known when
		// both sides agree on it.
		return x.eitherOptions(n.X, n.Y, depth)
	case *js.BinaryExpr:
		switch n.Op {
		case js.AndToken:
			// ...(token && {headers}): the object, or nothing.
			return x.eitherOptions(n.Y, &js.ObjectExpr{}, depth)
		case js.OrToken, js.NullishToken:
			return x.eitherOptions(n.X, n.Y, depth)
		}
	case *js.Var:
		if a, ok := x.args[root(n)]; ok {
			return x.optionsAt(a, depth+1)
		}
	}
	obj, ok := x.object(e)
	if !ok {
		return o, false
	}
	o.known = true
	var altURL js.IExpr
	for _, p := range obj.List {
		if p.Spread {
			// {...init, headers}: the options it builds on; one that
			// cannot be read may hold a method.
			in, ok := x.optionsAt(p.Value, depth+1)
			o.overlay(in, ok)
			continue
		}
		if p.Name == nil {
			continue
		}
		name := propName(p.Name)
		if optKeys[name] {
			o.isOpt = true
		}
		if httpOptKeys[name] {
			o.httpOpt = true
		}
		switch name {
		case "url":
			o.url = p.Value
		case "endpoint", "uri", "pathname":
			if altURL == nil {
				altURL = p.Value
			}
		case "baseURL", "baseUrl":
			o.base = p.Value
		case "method", "type":
			o.methodExpr = p.Value
			s, lit := x.argString(p.Value)
			if lit && httpMethods[strings.ToUpper(s)] {
				// Written after the parts before it: it is the method,
				// whatever they held ({...init, method: "POST"}).
				o.method, o.known = strings.ToUpper(s), true
			} else {
				o.method, o.known = "", false
			}
		case "body", "data", "json", "form":
			if o.bodyExpr == nil {
				o.bodyExpr = p.Value
			}
			o.body = append(o.body, x.keys(p.Value, "", 0)...)
		case "headers":
			o.headers = append(o.headers, x.keys(p.Value, "", 2)...)
		case "params", "query", "queries", "searchParams":
			if o.queryExpr == nil {
				o.queryExpr = p.Value
			}
			o.query = append(o.query, x.keys(p.Value, "", 2)...)
		}
	}
	if lv, isVar := e.(*js.Var); isVar {
		lv = root(lv)
		var propBody, propQuery js.IExpr
		for _, pd := range x.props {
			pv, ok := pd.obj.(*js.Var)
			if !ok || root(pv) != lv || pd.name == "" {
				continue
			}
			if optKeys[pd.name] {
				o.isOpt = true
			}
			if httpOptKeys[pd.name] {
				o.httpOpt = true
			}
			switch pd.name {
			case "url":
				if o.url == nil {
					o.url = pd.value
				}
			case "endpoint", "uri", "pathname":
				if altURL == nil {
					altURL = pd.value
				}
			case "baseURL", "baseUrl":
				if o.base == nil {
					o.base = pd.value
				}
			case "method", "type":
				if o.methodExpr == nil {
					o.methodExpr = pd.value
				}
				if o.method == "" {
					if s, lit := x.argString(pd.value); lit && httpMethods[strings.ToUpper(s)] {
						o.method, o.known = strings.ToUpper(s), true
					}
				}
			case "body", "data", "json", "form":
				if propBody == nil {
					propBody = pd.value
				}
				if o.bodyExpr == nil {
					o.bodyExpr = pd.value
				}
			case "params", "query", "queries", "searchParams":
				if propQuery == nil {
					propQuery = pd.value
				}
				if o.queryExpr == nil {
					o.queryExpr = pd.value
				}
			case "headers":
				o.headers = append(o.headers, x.keys(pd.value, "", 2)...)
			}
		}
		sameDataVar := false
		if bv, ok1 := propBody.(*js.Var); ok1 {
			if qv, ok2 := propQuery.(*js.Var); ok2 && root(bv) == root(qv) {
				sameDataVar = true
			}
		}
		if sameDataVar {
			switch o.method {
			case "GET", "HEAD", "DELETE":
				o.query = append(o.query, x.keys(propQuery, "", 2)...)
			case "POST", "PUT", "PATCH":
				o.body = append(o.body, x.keys(propBody, "", 0)...)
			default:
				o.body = append(o.body, x.keys(propBody, "", 0)...)
			}
		} else {
			if propBody != nil {
				o.body = append(o.body, x.keys(propBody, "", 0)...)
			}
			if propQuery != nil {
				o.query = append(o.query, x.keys(propQuery, "", 2)...)
			}
		}
	}
	if o.url == nil && altURL != nil && o.httpOpt {
		o.url = altURL
	}
	return o, true
}

// overlay lays a part of options over those before it, in the order they
// are written (Object.assign(a, b), {...a, ...b}): its fields join, and
// its method, when it says one, replaces the method so far. A part that
// cannot be read (a parameter left unbound, a call) may hold a method:
// with no method written before it, the method is unknown then, until a
// later part writes one ({...init, headers}). After a method written out
// ({method: "POST", body, ...extra}), the method stays: a request's extra
// options (a signal, headers) rarely restate it, and the method written is
// the code's own word.
func (o *opts) overlay(in opts, ok bool) {
	if !ok {
		if o.method == "" {
			o.known = false
		}
		return
	}
	method, methodExpr, known := o.method, o.methodExpr, o.known
	o.merge(in)
	switch {
	case in.method != "":
		o.method, o.methodExpr, o.known = in.method, in.methodExpr, true
	case !in.known:
		o.method, o.known = "", false
		if in.methodExpr != nil {
			o.methodExpr = in.methodExpr
		}
	default:
		o.method, o.methodExpr, o.known = method, methodExpr, known
	}
}

// eitherOptions is the options one of two expressions is (a ?: or ||):
// the fields of both; the method when both say the same, or neither says
// one; unknown otherwise, or when one side cannot be read.
func (x *extractor) eitherOptions(a, b js.IExpr, depth int) (o opts, ok bool) {
	oa, okA := x.optionsAt(a, depth+1)
	ob, okB := x.optionsAt(b, depth+1)
	if !okA || !okB {
		return o, false
	}
	o = oa
	o.merge(ob)
	o.known = oa.known && ob.known && oa.method == ob.method
	if !o.known {
		o.method = ""
	}
	return o, true
}

func (o *opts) merge(in opts) {
	if o.method == "" {
		o.method = in.method
	}
	if o.methodExpr == nil {
		o.methodExpr = in.methodExpr
	}
	if o.url == nil {
		o.url = in.url
	}
	if o.base == nil {
		o.base = in.base
	}
	if o.bodyExpr == nil {
		o.bodyExpr = in.bodyExpr
	}
	if o.queryExpr == nil {
		o.queryExpr = in.queryExpr
	}
	o.body, o.headers, o.query = append(o.body, in.body...), append(o.headers, in.headers...), append(o.query, in.query...)
	o.isOpt = o.isOpt || in.isOpt
	o.httpOpt = o.httpOpt || in.httpOpt
}

// optBasePre evaluates a request's baseURL expression to its prefixes, or
// to "{}" when it is computed at runtime.
func (x *extractor) optBasePre(base js.IExpr) (pre []string, isClient bool) {
	if base == nil {
		return nil, false
	}
	var bq []string
	sawRoot := false
	for _, v := range x.eval(base, &bq, 0) {
		c := strings.TrimRight(cleanURL(v), "/")
		switch {
		case c == "" || c == "/":
			sawRoot = true
		case c == unknown || strings.HasPrefix(c, unknown+"/"):
			pre = addAlt(pre, c)
			isClient = true
			x.dynBase = true
		case (strings.HasPrefix(c, "/") && !strings.HasPrefix(c, "//")) || schemeRe.MatchString(c):
			pre = addAlt(pre, c)
			isClient = true
		}
	}
	if len(pre) == 0 && !sawRoot {
		x.dynBase = true
		return []string{unknown}, true
	}
	return pre, isClient
}

// argString is a string literal, or a parameter/destructured property/constant
// bound to one at its call (bounded to depth <= 8).
func (x *extractor) argString(e js.IExpr) (string, bool) {
	return x.argStringAt(e, 0)
}

func (x *extractor) argStringAt(e js.IExpr, depth int) (string, bool) {
	for {
		if g, ok := e.(*js.GroupExpr); ok {
			e = g.X
			continue
		}
		break
	}
	if s, ok := literalString(e); ok {
		return s, true
	}
	if depth >= 8 || e == nil {
		return "", false
	}
	switch n := e.(type) {
	case *js.Var:
		r := root(n)
		if a, ok := x.args[r]; ok && a != nil && a != js.IExpr(n) {
			return x.argStringAt(a, depth+1)
		}
		if src := x.destructFrom[r]; src != nil && x.propOf[r] != "" {
			if obj, ok := x.object(src); ok {
				if val := objectValue(obj, x.propOf[r]); val != nil {
					return x.argStringAt(val, depth+1)
				}
			}
		}
		if b, ok := x.bind[r]; ok && len(b) == 1 && b[0] != unknown {
			return b[0], true
		}
		if c := x.constant(n); c != nil && c != js.IExpr(n) {
			return x.argStringAt(c, depth+1)
		}
	case *js.DotExpr:
		if m, ok := x.member(n); ok && m != nil {
			return x.argStringAt(m, depth+1)
		}
	}
	return "", false
}

// initCall reads a call to a helper of the app's that builds a request's
// options: init("POST", data, extra) returning {method: e, body:
// JSON.stringify(t), ...n} (on one or each branch of a ?:), its
// parameters bound to what the call gives them.
func (x *extractor) initCall(c *js.CallExpr, depth int) (o opts, ok bool) {
	v, params, body, isFn := x.fnOf(c.X)
	if !isFn || x.busy[v] {
		return o, false
	}
	var objs []js.IExpr
	for _, s := range body.List {
		if r, ok := s.(*js.ReturnStmt); ok && r.Value != nil {
			objs = append(objs, branches(r.Value)...)
		}
	}
	if len(objs) == 0 {
		return o, false
	}
	x.busy[v] = true
	defer delete(x.busy, v)
	as := args(&c.Args)
	saved := map[*js.Var]js.IExpr{}
	for i, b := range params.List {
		p, isVar := b.Binding.(*js.Var)
		if !isVar {
			continue
		}
		p = root(p)
		if old, had := x.args[p]; had {
			saved[p] = old
		}
		if i < len(as) {
			x.args[p] = as[i]
		} else {
			x.args[p] = nil
		}
	}
	defer func() {
		for _, b := range params.List {
			if p, isVar := b.Binding.(*js.Var); isVar {
				p = root(p)
				if old, had := saved[p]; had {
					x.args[p] = old
				} else {
					delete(x.args, p)
				}
			}
		}
	}()
	got := false
	for _, e := range objs {
		in, ok := x.optionsAt(e, depth+1)
		if !ok || !in.isOpt {
			continue
		}
		if !got {
			o, got = in, true
			continue
		}
		o.merge(in)
		o.known = o.known && in.known
	}
	if !got {
		return o, false
	}
	o.body, o.headers, o.query = uniq(o.body), uniq(o.headers), uniq(o.query)
	return o, true
}
