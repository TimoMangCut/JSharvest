package jsapi

// This file: request descriptors (round 27F): an object that describes a
// request another function makes, {url, options: {method, …}}. An OpenAPI
// generator's typescript-axios client writes one per operation (the
// ParamCreator: localVarPath = "/Items/{itemId}".replace(…), localVarUrlObj
// = new URL(localVarPath, DUMMY_BASE_URL), return {url:
// toPathString(localVarUrlObj), options: {method: "POST", ...baseOptions,
// ...options}}), and the request is made elsewhere, by one function for
// every operation (createRequestFunction: axios.request({...args.options,
// url: basePath + args.url})). Babel's regenerator writes the same object
// as the argument of its return op (t.a(2, {url, options})), so the object
// is what is read, wherever it is.

import (
	"github.com/tdewolff/parse/v2/js"
)

// descriptor adds the request an object describes: one with a url and
// options whose method is known.
func (x *extractor) descriptor(o *js.ObjectExpr) {
	var urlV, optV js.IExpr
	for _, p := range o.List {
		if p.Spread || p.Name == nil {
			continue
		}
		switch propName(p.Name) {
		case "url":
			urlV = p.Value
		case "options":
			optV = p.Value
		}
	}
	if urlV == nil || optV == nil {
		return
	}
	opt, ok := x.options(x.settled(optV))
	if !ok || !opt.known || opt.method == "" || !opt.isOpt {
		return
	}
	ep := Endpoint{Kind: "descriptor", Method: opt.method, Body: opt.body, Headers: opt.headers, Query: opt.query}
	x.add(x.urlObjectPath(urlV), ep, o, call)
}

// settled is an expression through the local constants it names, and the
// variables declared bare and assigned once (Babel's regenerator hoists
// every local: var s, l, f; … l = "/x".replace(…), f = new URL(l, base)).
func (x *extractor) settled(e js.IExpr) js.IExpr {
	for i := 0; i < 8; i++ {
		v, ok := ungroup(e).(*js.Var)
		if !ok {
			break
		}
		c := x.constant(v)
		if c == nil {
			c = x.assignedOnce(v)
		}
		if c == nil {
			break
		}
		e = c
	}
	return e
}

// assignedOnce is the value of a variable declared without one and assigned
// once after (defs: the bare declaration, the assignment and the mark it
// leaves); nil otherwise.
func (x *extractor) assignedOnce(v *js.Var) js.IExpr {
	d := x.defs[root(v)]
	if len(d) != 3 || d[0] != nil || d[1] == nil || d[2] != nil {
		return nil
	}
	return d[1]
}

// urlObjectPath is the path a descriptor's url is made of: of a URL object
// (new URL(path, base), alone or given to a function that writes it out,
// toPathString(u), u.toString()), its path, the base left out: the
// request's function puts its own base before the path, and the one the
// object was made with is a placeholder (DUMMY_BASE_URL). Anything else is
// the url as written.
func (x *extractor) urlObjectPath(e js.IExpr) js.IExpr {
	u := ungroup(e)
	if c, ok := u.(*js.CallExpr); ok {
		switch {
		case len(c.Args.List) == 1 && !c.Args.List[0].Rest:
			u = c.Args.List[0].Value // toPathString(u)
		case len(c.Args.List) == 0:
			if d, ok := c.X.(*js.DotExpr); ok && propName(d.Y) == "toString" {
				u = d.X
			}
		}
	}
	if n, ok := x.settled(u).(*js.NewExpr); ok && globalName(n.X) == "URL" && n.Args != nil && len(n.Args.List) >= 1 && !n.Args.List[0].Rest {
		return n.Args.List[0].Value
	}
	return e
}

// assignLike reports whether a function is an Object.assign of the app's
// (Babel's _objectSpread2 and _extends): it returns its first parameter,
// and only that.
func (x *extractor) assignLike(callee js.IExpr) bool {
	_, params, body, ok := x.fnOf(callee)
	if !ok || body == nil || len(params.List) == 0 {
		return false
	}
	p0, ok := params.List[0].Binding.(*js.Var)
	if !ok {
		return false
	}
	rets := returnsOf(body)
	if len(rets) == 0 {
		return false
	}
	for _, r := range rets {
		v, ok := ungroup(r).(*js.Var)
		if !ok || root(v) != root(p0) {
			return false
		}
	}
	return true
}
