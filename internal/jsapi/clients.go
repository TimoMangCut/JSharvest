package jsapi

import (
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

// --- clients and their prefixes ---

// clientVisitor finds the objects whose get, post… are called, and reads
// what their constructor gave them, before the calls are read:
//
//	var Cy = e => new Sy(`${W.apiBaseUrl}${e}`),
//	    wy = e => W.sameOriginApi ? new Sy(e) : Cy(e),
//	    Z = wy("/api"), Dy = Cy("/auth");
//	Z.get("/account/v1/me")  // /api/account/v1/me
type clientVisitor struct{ x *extractor }

func (v clientVisitor) Enter(n js.INode) js.IVisitor {
	c, ok := n.(*js.CallExpr)
	if !ok {
		return v
	}
	d, ok := c.X.(*js.DotExpr)
	if !ok {
		return v
	}
	if _, ok := clientMethods[propName(d.Y)]; !ok {
		return v
	}
	obj, ok := d.X.(*js.Var)
	if !ok {
		return v
	}
	x := v.x
	obj = root(obj)
	if _, done := x.clientPre[obj]; done {
		return v
	}
	x.clientPre[obj] = nil
	if def := x.constant(obj); def != nil {
		if vals, ok := x.clientOf(def, 0); ok {
			x.clientPre[obj] = x.prefixes(vals)
			x.clients[obj] = true
		}
	}
	return v
}

func (clientVisitor) Exit(js.INode) {}

// clientOf reads what makes a client object: new Client(base), a factory
// of the app's (withBase("/api") => new Client(`${cfg.api}${p}`)), a ?:
// of them, axios.create({baseURL}). It returns the bases it is given, and
// marks the factory calls, which are no endpoints.
func (x *extractor) clientOf(e js.IExpr, depth int) ([]string, bool) {
	if depth > 6 || e == nil {
		return nil, false
	}
	switch n := e.(type) {
	case *js.GroupExpr:
		return x.clientOf(n.X, depth+1)
	case *js.CondExpr:
		a, okA := x.clientOf(n.X, depth+1)
		b, okB := x.clientOf(n.Y, depth+1)
		return union(a, b), okA || okB
	case *js.Var:
		r := root(n)
		if def := x.constant(n); def != nil && !x.busy[r] {
			x.busy[r] = true
			defer delete(x.busy, r)
			return x.clientOf(def, depth+1)
		}
	case *js.NewExpr:
		// An app's own class given a base; a browser's (URL, Map) is none.
		if _, isVar := n.X.(*js.Var); isVar && globalName(n.X) == "" && n.Args != nil && len(n.Args.List) > 0 {
			var q []string
			return x.eval(n.Args.List[0].Value, &q, depth+1), true
		}
	case *js.CallExpr:
		return x.factory(n, depth)
	}
	return nil, false
}

// factory reads a call that makes a client: axios.create({baseURL}), or a
// function of the app's that returns one, its parameters bound to what
// the call gives them.
func (x *extractor) factory(n *js.CallExpr, depth int) ([]string, bool) {
	as := args(&n.Args)
	if d, ok := n.X.(*js.DotExpr); ok {
		if propName(d.Y) != "create" || len(as) == 0 {
			return nil, false
		}
		if obj, ok := x.object(as[0]); ok {
			if b := objectValue(obj, "baseURL"); b != nil {
				var q []string
				return x.eval(b, &q, depth+1), true
			}
		}
		return nil, false
	}
	v, params, body, ok := x.fnOf(n.X)
	if !ok || x.busy[v] {
		return nil, false
	}
	rets := returnsOf(body)
	if len(rets) == 0 || len(rets) > maxReturns {
		return nil, false
	}
	x.busy[v] = true
	defer delete(x.busy, v)
	var bound []*js.Var
	for i, b := range params.List {
		p, isVar := b.Binding.(*js.Var)
		if !isVar {
			continue
		}
		p = root(p)
		if _, had := x.bind[p]; had {
			continue
		}
		bound = append(bound, p)
		var q []string
		if i < len(as) {
			x.bind[p] = x.eval(as[i], &q, depth+1)
		} else {
			x.bind[p] = unk
		}
	}
	defer func() {
		for _, p := range bound {
			delete(x.bind, p)
		}
	}()
	var out []string
	made := false
	for _, r := range rets {
		if vals, ok := x.clientOf(r, depth+1); ok {
			out, made = union(out, vals), true
		}
	}
	if made {
		x.factoryCalls[n] = true
	}
	return out, made
}

// prefixes are the paths a client's bases put before its calls' paths:
// "{}/api" (a base set elsewhere, then /api) is /api, as "/api" is; an
// absolute base is kept whole.
//
// A path the client is given whole (new Sy("/console-api")) is on the
// page's origin: noted, so that the URLs under it are whole too, unless a
// client puts it after a base it computes (`${apiBaseUrl}/console`).
func (x *extractor) prefixes(vals []string) []string {
	var out []string
	for _, v := range vals {
		c := strings.TrimRight(cleanURL(v), "/")
		v = strings.TrimPrefix(c, unknown)
		switch {
		case v == "", strings.Contains(v, unknown):
		case strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//"), schemeRe.MatchString(v):
			out = addAlt(out, v)
			if strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") {
				if c == v {
					x.ownPre[v] = true
				} else {
					x.basedPre[v] = true
				}
			}
		}
	}
	return out
}

// prefixed is a path with each prefix of the client being read before it.
func (x *extractor) prefixed(t string) []string {
	if len(x.pre) == 0 || !strings.HasPrefix(t, "/") || strings.HasPrefix(t, "//") {
		return []string{t}
	}
	out := make([]string, 0, len(x.pre))
	for _, p := range x.pre {
		out = append(out, p+t)
	}
	return out
}

// prefixesOf are the prefixes of the client an expression is: a client
// object, or either of two ((cfg.sameOrigin ? Z : Dy).post(…): /api and
// /auth both).
func (x *extractor) prefixesOf(e js.IExpr) []string {
	switch n := e.(type) {
	case *js.GroupExpr:
		return x.prefixesOf(n.X)
	case *js.CondExpr:
		return union(x.prefixesOf(n.X), x.prefixesOf(n.Y))
	case *js.Var:
		v := root(n)
		if p, done := x.clientPre[v]; done {
			return p
		}
		x.clientPre[v] = nil
		if def := x.constant(v); def != nil {
			if vals, ok := x.clientOf(def, 0); ok {
				x.clientPre[v] = x.prefixes(vals)
				x.clients[v] = true
			}
		}
		return x.clientPre[v]
	}
	return nil
}
