package jsapi

// This file: functions that return a URL instead of requesting it (round
// 27D): an SDK's getFilePreview(…) builds new URL(this.client.config.
// endpoint + apiPath) as its request methods do, and returns
// uri.toString() for an <img src> or a download link: a GET the browser
// makes. Such a function is an endpoint's when the URL it returns is built
// on a base the script's own requests are built on (the same expression:
// this.client.config.endpoint); a router's link (`/settings/${id}`) or a
// static asset's path, on no request's base, is not.

import (
	"fmt"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

// baseKey is the expression a URL is built on, written as the code reads
// it (this.client.config.endpoint): the leading term of the URL, through
// local constants, new URL(…), a sum's or a template's first part,
// toString() and href. "" when the URL starts with no such expression (a
// literal, a call, a lone variable).
func (x *extractor) baseKey(e js.IExpr, depth int) string {
	if depth > 6 || e == nil {
		return ""
	}
	switch n := ungroup(e).(type) {
	case *js.Var:
		if c := x.constant(n); c != nil {
			return x.baseKey(c, depth+1)
		}
	case *js.NewExpr:
		if globalName(n.X) == "URL" && n.Args != nil {
			switch len(n.Args.List) {
			case 1:
				return x.baseKey(n.Args.List[0].Value, depth+1)
			case 2: // new URL(path, base): built on the base
				return x.baseKey(n.Args.List[1].Value, depth+1)
			}
		}
	case *js.BinaryExpr:
		// a + "/x/" + b + "/y": the leftmost term, however long the sum.
		var l js.IExpr = n
		for i := 0; i < 64; i++ {
			b, ok := ungroup(l).(*js.BinaryExpr)
			if !ok || b.Op != js.AddToken {
				break
			}
			l = b.X
		}
		if l != js.IExpr(n) {
			return x.baseKey(l, depth+1)
		}
	case *js.TemplateExpr:
		if n.Tag == nil && len(n.List) > 0 && templateText(n.List[0].Value, true, false) == "" { // `${base}…`: no text before it
			return x.baseKey(n.List[0].Expr, depth+1)
		}
	case *js.CallExpr:
		if d, ok := n.X.(*js.DotExpr); ok && propName(d.Y) == "toString" && len(n.Args.List) == 0 {
			return x.baseKey(d.X, depth+1)
		}
	case *js.DotExpr:
		if propName(n.Y) == "href" {
			switch ungroup(n.X).(type) {
			case *js.Var, *js.NewExpr: // uri.href, new URL(…).href
				return x.baseKey(n.X, depth+1)
			}
		}
		return memberChain(n)
	}
	return ""
}

// memberChain writes a member expression of three parts at least as the
// code reads it: this.client.config.endpoint; "" for anything else in it. A
// declared variable at its root is written with its declaration's identity:
// in a minified bundle, two functions' parameters both named e are not the
// same base.
func memberChain(d *js.DotExpr) string {
	var parts []string
	var e js.IExpr = d
	for i := 0; i < 8; i++ {
		switch n := e.(type) {
		case *js.DotExpr:
			name := propName(n.Y)
			if name == "" {
				return ""
			}
			parts = append(parts, name)
			e = n.X
			continue
		case *js.LiteralExpr:
			if n.TokenType != js.ThisToken {
				return ""
			}
			parts = append(parts, "this")
		case *js.Var:
			r := root(n)
			if r.Decl == js.NoDecl {
				parts = append(parts, string(r.Data))
			} else {
				parts = append(parts, fmt.Sprintf("%s#%p", r.Data, r))
			}
		default:
			return ""
		}
		break
	}
	if len(parts) < 3 { // this.base, cfg.url: too common a shape to tell a request's base by
		return ""
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

// noteRequestBase records the base a request's URL is built on.
func (x *extractor) noteRequestBase(u js.IExpr) {
	if k := x.baseKey(u, 0); k != "" {
		x.reqBases[k] = true
	}
}

// urlReturnVisitor finds the functions that return a URL built on a base
// the script's requests are built on.
type urlReturnVisitor struct{ x *extractor }

func (v urlReturnVisitor) Enter(n js.INode) js.IVisitor {
	var body *js.BlockStmt
	switch f := n.(type) {
	case *js.FuncDecl:
		body = &f.Body
	case *js.MethodDecl:
		body = &f.Body
	case *js.ArrowFunc:
		body = &f.Body
	}
	if body != nil {
		for _, r := range returnsOf(body) {
			v.x.urlReturn(r)
		}
	}
	return v
}

func (urlReturnVisitor) Exit(js.INode) {}

// urlReturn adds, as a GET of kind "url", the URL a function returns when
// it is built on a request's base.
func (x *extractor) urlReturn(r js.IExpr) {
	k := x.baseKey(r, 0)
	if k == "" || !x.reqBases[k] {
		return
	}
	u := r
	if c, ok := ungroup(r).(*js.CallExpr); ok {
		if d, ok := c.X.(*js.DotExpr); ok && propName(d.Y) == "toString" {
			u = d.X
		}
	}
	if d, ok := ungroup(u).(*js.DotExpr); ok && propName(d.Y) == "href" {
		u = d.X
	}
	x.add(u, Endpoint{Method: "GET", Kind: "url"}, r, call)
}
