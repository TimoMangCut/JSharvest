package jsapi

// This file: evaluation: what an expression may be as a string (variables, calls, builders, enums, members).

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// maxAlts is how many values an expression may stand for at once: both
// sides of a ?:, the URLs of a lookup table, a variable set on several
// paths. More is a table of data rather than a URL's variants.
const maxAlts = 16

var unk = []string{unknown}

func addAlt(out []string, s string) []string {
	if len(out) >= maxAlts || slices.Contains(out, s) {
		return out
	}
	return append(out, s)
}

func union(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		out = addAlt(out, s)
	}
	for _, s := range b {
		out = addAlt(out, s)
	}
	return out
}

// cat is every value of a followed by every value of b.
func cat(a, b []string) []string {
	out := make([]string, 0, len(a)*len(b))
	for _, s := range a {
		for _, t := range b {
			out = addAlt(out, s+t)
		}
	}
	return out
}

type inlineScopeKey struct{}

func (x *extractor) snapBind() func() {
	if len(x.bind) == 0 {
		return func() {
			if len(x.bind) > 0 {
				clear(x.bind)
			}
		}
	}
	saved := make(map[*js.Var][]string, len(x.bind))
	for k, v := range x.bind {
		saved[k] = v
	}
	return func() {
		clear(x.bind)
		for k, v := range saved {
			x.bind[k] = v
		}
	}
}

// eval turns an expression into templates: the strings it is made of,
// with {} for the parts the code computes; several when it stands for
// several (a ?: of two URLs, a variable set on two paths, a lookup table).
// Query parameter names that URLSearchParams objects add are collected in
// q.
func (x *extractor) eval(e js.IExpr, q *[]string, depth int) []string {
	if depth > 12 || e == nil {
		return unk
	}
	if !x.busy[inlineScopeKey{}] {
		x.busy[inlineScopeKey{}] = true
		if len(x.bind) == 0 {
			defer func() {
				delete(x.busy, inlineScopeKey{})
				if len(x.bind) > 0 {
					clear(x.bind)
				}
			}()
		} else {
			restore := x.snapBind()
			defer func() {
				delete(x.busy, inlineScopeKey{})
				restore()
			}()
		}
	}
	switch n := e.(type) {
	case *js.LiteralExpr:
		switch n.TokenType {
		case js.StringToken:
			if !x.noMarkUsed {
				if x.usedLog != nil && !x.used[n] {
					*x.usedLog = append(*x.usedLog, n)
				}
				x.used[n] = true
				x.lits = append(x.lits, n.Data)
			}
			return []string{unquote(n.Data)}
		case js.IntegerToken, js.DecimalToken:
			return []string{string(n.Data)}
		}
	case *js.TemplateExpr:
		if n.Tag != nil {
			return unk
		}
		out := []string{""}
		for i, p := range n.List {
			if !x.noMarkUsed {
				x.lits = append(x.lits, p.Value)
			}
			out = cat(out, []string{templateText(p.Value, i == 0, false)})
			out = cat(out, x.eval(p.Expr, q, depth+1))
		}
		if !x.noMarkUsed {
			x.lits = append(x.lits, n.Tail)
		}
		return cat(out, []string{templateText(n.Tail, len(n.List) == 0, true)})
	case *js.BinaryExpr:
		switch n.Op {
		case js.AddToken:
			return cat(x.eval(n.X, q, depth+1), x.eval(n.Y, q, depth+1))
		case js.OrToken, js.NullishToken:
			// url || "/api/default"
			return union(x.eval(n.X, q, depth+1), x.eval(n.Y, q, depth+1))
		case js.AndToken:
			return x.eval(n.Y, q, depth+1)
		case js.EqToken:
			cur := x.eval(n.Y, q, depth+1)
			if v, ok := ungroup(n.X).(*js.Var); ok {
				x.bind[root(v)] = cur
			}
			return cur
		case js.AddEqToken:
			if v, ok := ungroup(n.X).(*js.Var); ok {
				vr := root(v)
				if prev, bound := x.bind[vr]; bound {
					cur := cat(prev, x.eval(n.Y, q, depth+1))
					x.bind[vr] = cur
					return cur
				}
				cur := x.evalChainUntil(vr, n, q, depth)
				x.bind[vr] = cur
				return cur
			}
			return cat(x.eval(n.X, q, depth+1), x.eval(n.Y, q, depth+1))
		}
	case *js.GroupExpr:
		return x.eval(n.X, q, depth+1)
	case *js.CommaExpr:
		if len(n.List) > 0 {
			return x.eval(n.List[len(n.List)-1], q, depth+1)
		}
	case *js.Var:
		if ks := x.qset[root(n)]; len(ks) > 0 {
			if ne, ok := x.constant(n).(*js.NewExpr); ok && globalName(ne.X) == "URLSearchParams" {
				// new URLSearchParams; p.set("k", …): a query, its keys.
				*q = append(*q, ks...)
				if ne.Args != nil && len(ne.Args.List) > 0 {
					*q = append(*q, x.keys(ne.Args.List[0].Value, "", 0)...)
				}
				return []string{""}
			}
		}
		if out, ok := x.evalURLObject(root(n), q, depth); ok {
			return out
		}
		return x.evalVar(root(n), q, depth)
	case *js.DotExpr:
		if u, ok := n.X.(*js.Var); ok && propName(n.Y) == "pathname" {
			if p, ok := x.urlPath[root(u)]; ok {
				return p // the base's path, while its new one is read
			}
		}
		if origin(n) {
			return []string{"{origin}"}
		}
		if prop, ok := x.member(n); ok {
			return x.eval(prop, q, depth+1)
		}
		if x.isThis(n.X) {
			if out, ok := x.thisFieldValues(n.Y, q, depth); ok {
				return out
			}
			return x.evalThis(propName(n.Y), q, depth)
		}
		if out, ok := x.instanceField(n, q, depth); ok {
			return out
		}
		if out := x.fromCallers(n, q, depth); out != nil {
			return out
		}
		if baseSlashGlobal(n) {
			return []string{"{origin}/"}
		}
		if x.symConstMode {
			if cref, ok := x.extractConstRef(n); ok {
				if tok := EncodeSymConst(cref); tok != "" {
					return []string{tok}
				}
			}
		}
	case *js.IndexExpr:
		if ev := x.enumVar(n.X, 0); ev != nil {
			m := x.enumProps[ev]
			if key, ok := literalString(n.Y); ok {
				if v := m[key]; v != nil {
					return x.eval(v, q, depth+1)
				}
			} else if len(m) > 0 {
				ks := make([]string, 0, len(m))
				for k := range m {
					ks = append(ks, k)
				}
				sort.Strings(ks)
				var out []string
				for _, k := range ks {
					for _, s := range x.eval(m[k], q, depth+1) {
						out = addAlt(out, s)
					}
					if len(out) >= maxAlts {
						break
					}
				}
				if len(out) > 0 {
					return out
				}
			}
		}
		if obj, ok := x.object(n.X); ok {
			if key, ok := literalString(n.Y); ok {
				if v := objectValue(obj, key); v != nil {
					return x.eval(v, q, depth+1)
				}
			} else if out := x.lookup(obj, q, depth); len(out) > 0 {
				return out
			}
		}
	case *js.CondExpr:
		if br := x.omittedCondBranch(n); br != nil {
			return x.eval(br, q, depth+1)
		}
		if t, ok := x.condTruth(n.Cond, q, depth); ok {
			if t {
				return x.eval(n.X, q, depth+1)
			}
			return x.eval(n.Y, q, depth+1)
		}
		return union(x.eval(n.X, q, depth+1), x.eval(n.Y, q, depth+1))
	case *js.CallExpr:
		if x.deferring {
			if out, ok := x.deferImported(n, depth); ok {
				return out
			}
		}
		if d, ok := n.X.(*js.DotExpr); ok {
			switch propName(d.Y) {
			case "concat":
				s := x.eval(d.X, q, depth+1)
				for _, a := range n.Args.List {
					s = cat(s, x.eval(a.Value, q, depth+1))
				}
				return s
			case "toString", "trim", "valueOf":
				return x.eval(d.X, q, depth+1)
			case "replace", "replaceAll":
				return x.replace(n, d, q, depth)
			case "expand":
				// parseTemplate("/users/{id}").expand(params): an RFC 6570
				// template, its variables left as they are.
				if t := x.templateArg(d.X); t != nil {
					return x.eval(t, q, depth+1)
				}
			case "slice", "substring":
				if out, ok := x.sliceString(n, d, q, depth); ok {
					return out
				}
			case "join":
				if out, ok := x.arrayJoin(n, d, q, depth); ok {
					return out
				}
			}
		}
		if globalName(n.X) == "btoa" && len(n.Args.List) == 1 && !n.Args.List[0].Rest {
			var out []string
			for _, s := range x.eval(n.Args.List[0].Value, q, depth+1) {
				if s != "" && s != ":" && len(s) <= 256 && !strings.Contains(s, unknown) {
					out = addAlt(out, base64.StdEncoding.EncodeToString([]byte(s)))
				} else {
					out = addAlt(out, unknown)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
		if out, ok := x.joinCall(n, q, depth); ok {
			return out
		}
		if out := x.builder(n, q, depth); len(out) > 0 {
			return out
		}
		if out := x.evalCall(n, q, depth); len(out) > 0 {
			return out
		}
	case *js.NewExpr:
		switch globalName(n.X) {
		case "URLSearchParams":
			if n.Args != nil && len(n.Args.List) > 0 {
				*q = append(*q, x.keys(n.Args.List[0].Value, "", 0)...)
			}
		case "URL":
			if n.Args != nil && len(n.Args.List) > 0 {
				ss := x.eval(n.Args.List[0].Value, q, depth+1)
				var bs []string
				if len(n.Args.List) > 1 {
					bs = x.eval(n.Args.List[1].Value, q, depth+1)
				}
				var out []string
				for _, s := range ss {
					if strings.Contains(s, "://") || len(bs) == 0 {
						out = addAlt(out, s)
						continue
					}
					for _, b := range bs {
						if b == unknown || b == "{origin}" {
							out = addAlt(out, s)
						} else {
							out = addAlt(out, strings.TrimRight(b, "/")+"/"+strings.TrimLeft(s, "/"))
						}
					}
				}
				return out
			}
		}
	}
	return unk
}

// evalVar is what a variable may hold: the end of each of its chains.
// One set more ways than maxAlts is no URL's.
func (x *extractor) evalVar(v *js.Var, q *[]string, depth int) []string {
	if b, ok := x.bind[v]; ok {
		return b
	}
	cs := x.chains[v]
	if len(cs) == 0 {
		// let {apiBase: t} = e, e a parameter: e.apiBase as its callers
		// give it.
		if src, ok := x.destructFrom[v].(*js.Var); ok {
			if obj, ok := x.object(src); ok {
				// The call being read gave it: {apiBase: i, …}.
				if val := objectValue(obj, x.propOf[v]); val != nil && !x.busy[v] {
					x.busy[v] = true
					defer delete(x.busy, v)
					return x.eval(val, q, depth+1)
				}
			} else if out := x.fromCallersOf(root(src), x.propOf[v], q, depth); out != nil {
				return out
			}
		}
	}
	if len(cs) == 0 || len(cs) > maxAlts || x.busy[v] {
		return unk
	}
	for _, c := range cs {
		if c[0].expr == nil {
			return unk // a counter (i++, k *= 2): no URL's part
		}
	}
	x.busy[v] = true
	defer delete(x.busy, v)
	var out []string
	for _, c := range cs {
		out = union(out, x.evalChain(v, c, q, depth))
	}
	return out
}

func (x *extractor) evalChain(v *js.Var, c chain, q *[]string, depth int) []string {
	return x.evalChainSteps(v, c, false, q, depth)
}

func (x *extractor) evalChainSteps(v *js.Var, c chain, exactLast bool, q *[]string, depth int) []string {
	// before is the value the step before this one built on; branches,
	// what the branches of its fork made so far.
	var vals, before, branches []string
	for i, s := range c {
		sib := i > 1 && sibling(c[i-1], s)
		prev := vals
		switch {
		case i == 0:
			prev = unk
		case sib:
			prev = before
		default:
			before = vals
		}
		var cur []string
		restore := x.snapBind()
		switch s.op {
		case 's':
			cur = x.eval(s.expr, q, depth+1)
		case '+':
			x.bind[v] = prev
			cur = cat(prev, x.eval(s.expr, q, depth+1))
		case '=':
			x.bind[v] = prev
			cur = x.eval(s.expr, q, depth+1)
		}
		restore()
		if exactLast && i == len(c)-1 {
			return cur
		}
		if sib {
			// if (c) t += a; else t += b: t is one of the two, never t.
			branches = union(branches, cur)
			vals = branches
			continue
		}
		branches = cur
		if s.keep && i > 0 {
			cur = union(prev, cur)
		}
		vals = cur
	}
	return vals
}

func exprContains(rootExpr js.IExpr, target js.INode) bool {
	found := false
	js.Walk(nodeMatcher{target: target, found: &found}, rootExpr)
	return found
}

type nodeMatcher struct {
	target js.INode
	found  *bool
}

func (m nodeMatcher) Enter(n js.INode) js.IVisitor {
	if *m.found {
		return nil
	}
	if n == m.target {
		*m.found = true
		return nil
	}
	return m
}

func (nodeMatcher) Exit(js.INode) {}

// evalChainUntil evaluates a variable's assignment chain stopping right after
// the step produced by target (for standalone sub-expressions like
// fetch("".concat(t += "/archive", "?all=1")) followed later by t += "/purged").
func (x *extractor) evalChainUntil(v *js.Var, target *js.BinaryExpr, q *[]string, depth int) []string {
	if target == nil || x.busy[target] {
		return unk
	}
	cs := x.chains[v]
	if len(cs) == 0 || len(cs) > maxAlts || x.busy[v] {
		return unk
	}
	for _, c := range cs {
		if c[0].expr == nil {
			return unk
		}
	}
	x.busy[target] = true
	x.busy[v] = true
	defer func() {
		delete(x.busy, target)
		delete(x.busy, v)
	}()
	for _, c := range cs {
		for i, s := range c {
			if s.node == target {
				return x.evalChainSteps(v, c[:i+1], true, q, depth)
			}
			if s.expr != nil && exprContains(s.expr, target) {
				sub := append(slices.Clone(c[:i]), step{expr: target.Y, op: '+', forks: s.forks})
				return x.evalChainSteps(v, sub, true, q, depth)
			}
		}
	}
	return unk
}

func (x *extractor) constArrayElems(e js.IExpr, hopDepth int) ([]js.IExpr, bool) {
	if hopDepth > 6 || e == nil {
		return nil, false
	}
	e = ungroup(e)
	switch n := e.(type) {
	case *js.ArrayExpr:
		if len(n.List) == 0 || len(n.List) > maxAlts {
			return nil, false
		}
		out := make([]js.IExpr, 0, len(n.List))
		for _, el := range n.List {
			if el.Value == nil {
				continue
			}
			if el.Spread {
				sub, ok := x.constArrayElems(el.Value, hopDepth+1)
				if !ok || len(out)+len(sub) > maxAlts {
					return nil, false
				}
				out = append(out, sub...)
				continue
			}
			out = append(out, el.Value)
		}
		return out, len(out) > 0 && len(out) <= maxAlts
	case *js.Var:
		rv := root(n)
		if a, ok := x.args[rv]; ok && a != nil && a != e {
			return x.constArrayElems(a, hopDepth+1)
		}
		if c := x.constant(n); c != nil && c != e {
			return x.constArrayElems(c, hopDepth+1)
		}
	case *js.DotExpr:
		if m, ok := x.member(n); ok && m != nil {
			return x.constArrayElems(m, hopDepth+1)
		}
	}
	return nil, false
}

// forEachArrayItem yields elements of a bounded static array expression (<= maxAlts),
// including through at most one upstream .map(...) transformation stage so two-stage
// chains like arr.map(u => ({ url: u, params })).map(cfg => req(cfg)) preserve
// per-element parameter bindings cleanly.
func (x *extractor) forEachArrayItem(recv js.IExpr, mapDepth, hopDepth int, yield func(js.IExpr) bool) {
	if mapDepth > 1 || hopDepth > 6 || recv == nil {
		return
	}
	recv = ungroup(recv)
	switch n := recv.(type) {
	case *js.ArrayExpr:
		elems, ok := x.constArrayElems(n, hopDepth)
		if !ok {
			return
		}
		for _, el := range elems {
			if !yield(el) {
				return
			}
		}
	case *js.Var:
		rv := root(n)
		if x.busy[rv] {
			return
		}
		x.busy[rv] = true
		defer delete(x.busy, rv)
		if a, ok := x.args[rv]; ok && a != nil && a != recv {
			x.forEachArrayItem(a, mapDepth, hopDepth+1, yield)
			return
		}
		if c := x.constant(n); c != nil && c != recv {
			x.forEachArrayItem(c, mapDepth, hopDepth+1, yield)
		}
	case *js.DotExpr:
		if m, ok := x.member(n); ok && m != nil {
			x.forEachArrayItem(m, mapDepth, hopDepth+1, yield)
			return
		}
		if x.isThis(n.X) {
			if f := x.thisFieldExpr(n.Y); f != nil {
				x.forEachArrayItem(f, mapDepth, hopDepth+1, yield)
				return
			}
			if vs := x.thisProps[propName(n.Y)]; len(vs) == 1 {
				x.forEachArrayItem(vs[0], mapDepth, hopDepth+1, yield)
			}
		}
	case *js.CallExpr:
		d, ok := ungroup(n.X).(*js.DotExpr)
		if !ok {
			return
		}
		switch propName(d.Y) {
		case "filter", "slice", "reverse", "toReversed":
			x.forEachArrayItem(d.X, mapDepth, hopDepth+1, yield)
		case "map":
			if mapDepth >= 1 || len(n.Args.List) == 0 || n.Args.List[0].Rest || x.busy[n] {
				return
			}
			cb := ungroup(n.Args.List[0].Value)
			var key any = n
			params, body, isFn := fnParts(cb)
			if !isFn {
				var fv *js.Var
				fv, params, body, isFn = x.fnOf(cb)
				if !isFn || x.busy[fv] {
					return
				}
				key = fv
			}
			if len(params.List) == 0 {
				return
			}
			rets := returnsOf(body)
			if len(rets) == 0 || len(rets) > 2 {
				return
			}
			x.busy[n] = true
			if key != any(n) {
				x.busy[key] = true
			}
			defer func() {
				delete(x.busy, n)
				if key != any(n) {
					delete(x.busy, key)
				}
			}()
			total := 0
			x.forEachArrayItem(d.X, mapDepth+1, hopDepth+1, func(subEl js.IExpr) bool {
				var q []string
				undo := x.bindParams(params, []js.IExpr{subEl}, &q, mapDepth)
				cont := true
				for _, r := range rets {
					total++
					if total > maxAlts || !yield(ungroup(r)) {
						cont = false
						break
					}
				}
				undo()
				return cont
			})
		}
	}
}

// evalThis is what this.<name> may hold, from the assignments to it.
func (x *extractor) evalThis(name string, q *[]string, depth int) []string {
	vals := x.thisProps[name]
	key := "this." + name
	if len(vals) == 0 || len(vals) > maxAlts || x.busy[key] {
		return unk
	}
	x.busy[key] = true
	defer delete(x.busy, key)
	var out []string
	for _, e := range vals {
		out = union(out, x.eval(e, q, depth+1))
	}
	return out
}

// lookup is obj[key] for a key the code computes: each of the object's
// values that reads as a path ({original: "v1.0/oauth/token", ldap:
// "v1.0/ldap/oauth/token"}[this.loginType]).
func (x *extractor) lookup(obj *js.ObjectExpr, q *[]string, depth int) []string {
	if len(obj.List) > 4*maxAlts {
		return nil
	}
	var out []string
	for _, p := range obj.List {
		if p.Spread || p.Name == nil || p.Value == nil {
			continue
		}
		for _, s := range x.eval(p.Value, q, depth+1) {
			if s != unknown && strings.Contains(s, "/") {
				out = addAlt(out, s)
			}
		}
	}
	return out
}

// replace is s.replace(pattern, value) and replaceAll: "/roles/{id}"
// .replace("{id}", e.id) is "/roles/{}". A pattern it cannot read (a
// regexp with special characters) leaves the string as it is: the
// placeholder in it reads as {} too.
func (x *extractor) replace(n *js.CallExpr, d *js.DotExpr, q *[]string, depth int) []string {
	ss := x.eval(d.X, q, depth+1)
	if len(n.Args.List) < 2 {
		return ss
	}
	pat, global, ok := replacePattern(n.Args.List[0].Value)
	global = global || propName(d.Y) == "replaceAll"
	reps := x.eval(n.Args.List[1].Value, q, depth+1)
	var out []string
	for _, s := range ss {
		if !ok || pat == "" || !strings.Contains(s, pat) {
			out = addAlt(out, s)
			continue
		}
		for _, r := range reps {
			if global {
				out = addAlt(out, strings.ReplaceAll(s, pat, r))
			} else {
				out = addAlt(out, strings.Replace(s, pat, r, 1))
			}
		}
	}
	return out
}

// replacePattern reads the pattern of a replace: a string, or a regexp
// that is a plain text (/report-vehicle/g).
func replacePattern(e js.IExpr) (pat string, global, ok bool) {
	if s, ok := literalString(e); ok {
		return s, false, true
	}
	l, isLit := e.(*js.LiteralExpr)
	if !isLit || l.TokenType != js.RegExpToken {
		return "", false, false
	}
	raw := string(l.Data)
	end := strings.LastIndexByte(raw, '/')
	if end <= 0 {
		return "", false, false
	}
	body, flags := raw[1:end], raw[end+1:]
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == '\\' && i+1 < len(body) && !isAlnum(body[i+1]):
			i++
			b.WriteByte(body[i])
		case strings.IndexByte(`\.^$*+?()[]{}|`, c) >= 0:
			return "", false, false
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), strings.Contains(flags, "g"), true
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// maxReturns is how many return statements a function evaluated at its
// call may have: more is code, not a URL's helper.
const maxReturns = 8

// evalCall is what a call to a function of the app's own returns, its
// parameters bound to what the call gives them: function fe(){return
// "/openapi.yaml"}, function Ys(){const e="https://…".trim();return
// e?e.replace(/\/+$/,""):""}, a query string helper. An empty string
// beside other values is the guard's fallback, not a value.
func (x *extractor) evalCall(c *js.CallExpr, q *[]string, depth int) []string {
	// An imported call is marked only in the request's own URL: inside
	// a function the URL calls, its value is unknown as before (a marker
	// there would read as a known argument).
	if x.deferring {
		x.deferring = false
		defer func() { x.deferring = true }()
	}
	// A function's returns may call others, whose returns call more: the
	// work grows as a power of the depth. Two levels, a budget for the
	// whole script, and one evaluation of a function without parameters.
	if x.calls == 0 {
		x.rootEvals = 0 // a new expression read from the top: its own budget
	}
	if x.calls >= maxCallDepth || x.callBudget >= maxCallEvals || x.rootEvals >= maxRootEvals {
		return nil
	}
	key, v, params, body, ok := x.calleeFn(c)
	if !ok || x.busy[key] {
		return nil
	}
	// A method (n.conversations.sendUrl(e)) or a function a caller gives
	// (e.buildSendUrl(n)): its own path says what it makes, whatever it is
	// given.
	viaMethod := v == nil || key != any(v)
	if len(params.List) == 0 && v != nil && !viaMethod {
		if out, ok := x.noArgs[v]; ok {
			return out
		}
		defer func(v *js.Var) { x.noArgs[v] = x.lastCall }(v)
		x.lastCall = nil
	}
	x.callBudget++
	x.rootEvals++
	if !viaMethod {
		// A method or a function a caller gives is a step of the same
		// expression (ctx.conversations.sendUrl(e) → r(…)): only the
		// script's functions count toward the depth.
		x.calls++
		defer func() { x.calls-- }()
	}
	rets := returnsOf(body)
	if len(rets) == 0 || len(rets) > maxReturns {
		return nil
	}
	as := args(&c.Args)
	// Bound to nothing it knows (withBase(e) inside a helper, e its own
	// parameter), the function only says what it adds to the unknown:
	// helpers' plumbing, not a URL.
	vals := make([][]string, len(as))
	known := len(params.List) == 0
	for i, a := range as {
		vals[i] = x.eval(a, q, depth+1)
		if !(len(vals[i]) == 1 && vals[i][0] == unknown) {
			known = true
		}
	}
	x.busy[key] = true
	defer delete(x.busy, key)
	type saved struct {
		v           *js.Var
		old         []string
		had         bool
		wasOmitted  bool
		wasSupplied bool
	}
	var restore []saved
	for i, b := range params.List {
		p, isVar := b.Binding.(*js.Var)
		if !isVar {
			continue
		}
		p = root(p)
		old, had := x.bind[p]
		restore = append(restore, saved{p, old, had, x.omitted[p], x.supplied[p]})
		if i < len(as) {
			x.bind[p] = vals[i]
			if ov, ok := unwrapEnumGroup(as[i]).(*js.Var); ok && x.omitted[root(ov)] {
				x.omitted[p] = true
				delete(x.supplied, p)
			} else if !x.isNullishOrEmptyArg(as[i]) {
				delete(x.omitted, p)
				x.supplied[p] = true
			} else {
				delete(x.omitted, p)
				delete(x.supplied, p)
			}
		} else if b.Default != nil {
			x.bind[p] = x.eval(b.Default, q, depth+1)
			delete(x.omitted, p)
			delete(x.supplied, p)
		} else {
			x.bind[p] = unk
			x.omitted[p] = true
			delete(x.supplied, p)
		}
	}
	defer func() {
		for _, r := range restore {
			if r.had {
				x.bind[r.v] = r.old
			} else {
				delete(x.bind, r.v)
			}
			if r.wasOmitted {
				x.omitted[r.v] = true
			} else {
				delete(x.omitted, r.v)
			}
			if r.wasSupplied {
				x.supplied[r.v] = true
			} else {
				delete(x.supplied, r.v)
			}
		}
	}()
	var out []string
	for _, r := range rets {
		out = union(out, x.eval(r, q, depth+1))
	}
	if len(out) > 1 {
		out = slices.DeleteFunc(out, func(s string) bool { return s == "" })
	}
	if len(out) == 1 && out[0] == unknown {
		out = nil
	}
	isQuery := false
	if qi := x.queryParam(v, params, body); qi >= 0 && qi < len(as) && (len(out) == 0 || queryOnly(nonEmpty(out))) {
		// wr({lastEventId: t}), wr building "?k=v" from its object's
		// entries: the object's fields are the query.
		if ks := x.keys(as[qi], "", 0); len(ks) > 0 {
			*q = append(*q, ks...)
			out, isQuery = []string{""}, true
		}
	}
	if q != nil && len(out) > 0 {
		hasQMark := false
		for _, s := range out {
			if strings.Contains(s, "?") {
				hasQMark = true
				break
			}
		}
		if hasQMark {
			if lks := x.localQueryKeys(key, params, body); len(lks) > 0 {
				*q = append(*q, lks...)
			}
		}
	}
	if ownPath(out) {
		if viaMethod {
			known = true
		} else if _, _, isBuilder := x.builderParts(c.X); !isBuilder && namedAfterSlot(out) {
			known = true
		}
	}
	if !known && !queryOnly(out) && !isQuery {
		// Bound to nothing it knows (withBase(e) inside a helper, e its
		// own parameter), the function only says what it adds to the
		// unknown: helpers' plumbing, not a URL. One that makes a query
		// string ("?" + params, or "") is read all the same.
		out = nil
	}
	x.lastCall = out
	return out
}

// queryParam is the parameter of a function whose entries make its query
// string (Object.entries(e), Object.keys(e), new URLSearchParams(e), for
// (k in e)); -1 for none.
func (x *extractor) queryParam(v *js.Var, params js.Params, body *js.BlockStmt) int {
	if i, ok := x.qparams[v]; ok {
		return i
	}
	idx := map[*js.Var]int{}
	for i, b := range params.List {
		if p, ok := b.Binding.(*js.Var); ok {
			idx[root(p)] = i
		}
	}
	found := -1
	param := func(e js.IExpr) {
		if pv, ok := e.(*js.Var); ok && found < 0 {
			if i, ok := idx[root(pv)]; ok {
				found = i
			}
		}
	}
	if len(idx) > 0 {
		js.Walk(walker(func(n js.INode) {
			switch n := n.(type) {
			case *js.CallExpr:
				if d, ok := n.X.(*js.DotExpr); ok && isGlobal(d.X, "Object") && len(n.Args.List) > 0 {
					if p := propName(d.Y); p == "entries" || p == "keys" {
						param(n.Args.List[0].Value)
					}
				}
			case *js.NewExpr:
				if globalName(n.X) == "URLSearchParams" && n.Args != nil && len(n.Args.List) > 0 {
					param(n.Args.List[0].Value)
				}
			case *js.ForInStmt:
				param(n.Value)
			}
		}), body)
	}
	x.qparams[v] = found
	return found
}

// localQueryKeys extracts static query parameter names built into a local
// object inside a URL-builder helper (`const D = {sort, size, page};
// t && (D.projection = t); return P + "?" + Object.keys(D).map(...)`).
func (x *extractor) localQueryKeys(fnKey any, params js.Params, body *js.BlockStmt) []string {
	if fnKey != nil && x.localQDone[fnKey] {
		return x.localQKeys[fnKey]
	}
	if fnKey != nil {
		x.localQDone[fnKey] = true
	}
	if body == nil {
		return nil
	}
	isParam := map[*js.Var]bool{}
	for _, b := range params.List {
		if p, ok := b.Binding.(*js.Var); ok {
			isParam[root(p)] = true
		}
	}
	qObjs := map[*js.Var]bool{}
	noteObj := func(e js.IExpr) {
		if v, ok := ungroup(e).(*js.Var); ok {
			rv := root(v)
			if !isParam[rv] {
				qObjs[rv] = true
			}
		}
	}
	js.Walk(walker(func(n js.INode) {
		switch n := n.(type) {
		case *js.CallExpr:
			if d, ok := n.X.(*js.DotExpr); ok && isGlobal(d.X, "Object") && len(n.Args.List) > 0 {
				if p := propName(d.Y); p == "entries" || p == "keys" {
					noteObj(n.Args.List[0].Value)
				}
			}
		case *js.NewExpr:
			if globalName(n.X) == "URLSearchParams" && n.Args != nil && len(n.Args.List) > 0 {
				noteObj(n.Args.List[0].Value)
			}
		case *js.ForInStmt:
			noteObj(n.Value)
		}
	}), body)
	if len(qObjs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	addKey := func(k string) {
		if isQueryKey(k) {
			seen[k] = true
		}
	}
	for ov := range qObjs {
		for _, def := range x.defs[ov] {
			if obj, ok := ungroup(def).(*js.ObjectExpr); ok && len(obj.List) <= 32 {
				for i := range obj.List {
					p := &obj.List[i]
					if !p.Spread && p.Name != nil {
						addKey(propKey(p))
					}
				}
			}
		}
	}
	js.Walk(walker(func(n js.INode) {
		b, ok := n.(*js.BinaryExpr)
		if !ok || b.Op != js.EqToken {
			return
		}
		d, ok := ungroup(b.X).(*js.DotExpr)
		if !ok {
			return
		}
		if v, ok := ungroup(d.X).(*js.Var); ok && qObjs[root(v)] {
			addKey(propName(d.Y))
		}
	}), body)
	if len(seen) == 0 {
		return nil
	}
	out := sortedKeys(seen)
	if fnKey != nil {
		x.localQKeys[fnKey] = out
	}
	return out
}

func nonEmpty(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// queryOnly reports whether every value is a query string: "?…".
func queryOnly(vals []string) bool {
	for _, v := range vals {
		if !strings.HasPrefix(v, "?") {
			return false
		}
	}
	return len(vals) > 0
}

// maxCallDepth is how many calls evalCall goes into, one in another;
// maxCallEvals, how many it makes for a script.
const (
	maxCallDepth = 2
	maxCallEvals = 50000
	maxRootEvals = 300
)

// returnsOf is what a function's return statements return, those of the
// functions inside it aside.
func returnsOf(body *js.BlockStmt) []js.IExpr {
	var out []js.IExpr
	js.Walk(returnFinder{out: &out}, body)
	return out
}

type returnFinder struct{ out *[]js.IExpr }

func (f returnFinder) Enter(n js.INode) js.IVisitor {
	switch n := n.(type) {
	case *js.FuncDecl, *js.ArrowFunc, *js.MethodDecl, *js.ClassDecl:
		return nil
	case *js.ReturnStmt:
		if n.Value != nil {
			*f.out = append(*f.out, n.Value)
		}
	}
	return f
}

func (returnFinder) Exit(js.INode) {}

// builder reads a query builder's chain: new B(url).ctx(e).sortBy("x")
// .toRequest() is the URL it was given, with more query.
func (x *extractor) builder(n *js.CallExpr, q *[]string, depth int) []string {
	var e js.IExpr = n
	for i := 0; i < 16; i++ {
		switch c := e.(type) {
		case *js.CallExpr:
			d, ok := c.X.(*js.DotExpr)
			if !ok {
				return nil
			}
			e = d.X
			continue
		case *js.NewExpr:
			if globalName(c.X) != "" || c.Args == nil || len(c.Args.List) == 0 {
				return nil // a browser's own class: URL, Date, RegExp…
			}
			var out []string
			for _, s := range x.eval(c.Args.List[0].Value, q, depth+1) {
				if looksLikePath(cleanURL(s), call) {
					out = addAlt(out, s)
				}
			}
			return out
		}
		return nil
	}
	return nil
}

// templateText is a template literal's raw text between substitutions,
// without the backticks and ${ }.
func templateText(raw []byte, first, last bool) string {
	s := string(raw)
	if first {
		s = strings.TrimPrefix(s, "`")
	} else {
		s = strings.TrimPrefix(s, "}")
	}
	if last {
		s = strings.TrimSuffix(s, "`")
	} else {
		s = strings.TrimSuffix(s, "${")
	}
	return unescape(s)
}

// origin reports whether an expression is the page's own origin or host.
func origin(d *js.DotExpr) bool {
	switch propName(d.Y) {
	case "origin", "host":
	default:
		return false
	}
	switch o := d.X.(type) {
	case *js.Var:
		return root(o).Decl == js.NoDecl && string(o.Data) == "location"
	case *js.DotExpr:
		return propName(o.Y) == "location" && isGlobal(o.X, "window", "self", "document", "globalThis")
	}
	return false
}

// baseSlashGlobal reports whether d is a standard root base-path global
// (`window.BASE_PATH`, `window.__BASE_PATH__`, `import.meta.env.BASE_URL`)
// whose runtime default on the page's origin is "/".
func baseSlashGlobal(d *js.DotExpr) bool {
	switch globalName(d) {
	case "BASE_PATH", "__BASE_PATH__":
		return true
	}
	if propName(d.Y) == "BASE_URL" {
		if envDot, ok := d.X.(*js.DotExpr); ok && propName(envDot.Y) == "env" {
			if metaDot, ok := envDot.X.(*js.DotExpr); ok && propName(metaDot.Y) == "meta" {
				return true
			}
		}
	}
	return false
}

// reactiveArg unwraps a single-argument state/computed wrapper call (`ref(x)`,
// `reactive(x)`, `computed(() => x)`, or their minified 1-arg equivalents).
func (x *extractor) reactiveArg(e js.IExpr) (js.IExpr, bool) {
	e = unwrapEnumGroup(e)
	if v, ok := e.(*js.Var); ok {
		e = unwrapEnumGroup(x.constant(v))
	}
	if ce, ok := e.(*js.CallExpr); ok && len(ce.Args.List) == 1 && !ce.Args.List[0].Rest {
		return unwrapEnumGroup(ce.Args.List[0].Value), true
	}
	return nil, false
}

func singleReturnExpr(e js.IExpr) js.IExpr {
	e = ungroup(e)
	var params js.Params
	var body *js.BlockStmt
	switch f := e.(type) {
	case *js.ArrowFunc:
		params, body = f.Params, &f.Body
	case *js.FuncDecl:
		params, body = f.Params, &f.Body
	case *js.MethodDecl:
		if f.Set {
			return nil
		}
		params, body = f.Params, &f.Body
	default:
		return nil
	}
	if len(params.List) != 0 {
		return nil
	}
	rets := returnsOf(body)
	if len(rets) != 1 {
		return nil
	}
	return unwrapEnumGroup(rets[0])
}

// unwrapReactiveExpr unwraps an auto-unwrapped reactive ref/computed value
// (e.g. Pinia setup stores returning `{ restUrl: computed(() => ...) }`).
func (x *extractor) unwrapReactiveExpr(e js.IExpr) js.IExpr {
	arg, ok := x.reactiveArg(e)
	if !ok {
		return nil
	}
	if ret := singleReturnExpr(arg); ret != nil {
		return ret
	}
	if _, isStr := literalString(arg); isStr {
		return arg
	}
	return nil
}

// object finds the object literal an expression stands for: a literal,
// or a constant set to one.
func (x *extractor) object(e js.IExpr) (*js.ObjectExpr, bool) {
	return x.objectN(e, 0)
}

func isJSONParse(e js.IExpr) bool {
	d, ok := ungroup(e).(*js.DotExpr)
	return ok && isGlobal(d.X, "JSON") && propName(d.Y) == "parse"
}

func (x *extractor) jsonParsedObject(ce *js.CallExpr) (*js.ObjectExpr, bool) {
	if ce == nil || len(ce.Args.List) != 1 || ce.Args.List[0].Rest || !isJSONParse(ce.X) {
		return nil, false
	}
	if obj, seen := x.jsonObjs[ce]; seen {
		return obj, obj != nil
	}
	x.jsonObjs[ce] = nil
	raw, ok := literalString(ce.Args.List[0].Value)
	if !ok || len(raw) < 2 || len(raw) > 65536 {
		return nil, false
	}
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' || !json.Valid([]byte(trimmed)) {
		return nil, false
	}
	ast, err := js.Parse(parse.NewInputBytes([]byte("("+trimmed+")")), js.Options{})
	if err != nil || len(ast.BlockStmt.List) != 1 {
		return nil, false
	}
	es, ok := ast.BlockStmt.List[0].(*js.ExprStmt)
	if !ok {
		return nil, false
	}
	obj, ok := ungroup(es.Value).(*js.ObjectExpr)
	if !ok {
		return nil, false
	}
	x.jsonObjs[ce] = obj
	return obj, true
}

func unwrapFrozenObject(ce *js.CallExpr) (*js.ObjectExpr, bool) {
	if ce == nil || len(ce.Args.List) != 1 || ce.Args.List[0].Rest {
		return nil, false
	}
	d, ok := ungroup(ce.X).(*js.DotExpr)
	if !ok || globalName(d.X) != "Object" {
		return nil, false
	}
	switch propName(d.Y) {
	case "freeze", "seal":
		if obj, isObj := ungroup(ce.Args.List[0].Value).(*js.ObjectExpr); isObj {
			return obj, true
		}
	}
	return nil, false
}

// objectN is object, through at most 16 parameters bound to one another
// (helpers passing {body: n} on, or calling each other back).
func (x *extractor) objectN(e js.IExpr, depth int) (*js.ObjectExpr, bool) {
	switch n := ungroup(e).(type) {
	case *js.ObjectExpr:
		return n, true
	case *js.CallExpr:
		if obj, ok := unwrapFrozenObject(n); ok {
			return obj, true
		}
		if obj, ok := x.jsonParsedObject(n); ok {
			return obj, true
		}
		if obj, ok := x.wpDefaultObject(n, depth); ok {
			return obj, true
		}
	case *js.Var:
		if a, ok := x.args[root(n)]; ok {
			if a == nil || a == js.IExpr(n) || depth >= 16 {
				return nil, false
			}
			return x.objectN(a, depth+1)
		}
		if c := x.constOrSingleExpr(n); c != nil {
			switch cv := ungroup(c).(type) {
			case *js.ObjectExpr:
				return cv, true
			case *js.CallExpr:
				if obj, ok := unwrapFrozenObject(cv); ok {
					return obj, true
				}
				if obj, ok := x.jsonParsedObject(cv); ok {
					return obj, true
				}
				if obj, ok := x.wpDefaultObject(cv, depth); ok {
					return obj, true
				}
			case *js.Var, *js.DotExpr:
				if depth < 16 && cv != js.IExpr(n) {
					return x.objectN(cv, depth+1)
				}
			}
			return nil, false
		}
		if obj, ok := x.wpDefaultObject(n, depth); ok {
			return obj, true
		}
		if depth < 16 {
			if src := x.destructFrom[root(n)]; src != nil && x.propOf[root(n)] != "" {
				if obj, ok := x.objectN(src, depth+1); ok {
					if val := objectValue(obj, x.propOf[root(n)]); val != nil {
						return x.objectN(val, depth+1)
					}
				}
			}
		}
	case *js.DotExpr:
		if depth < 16 {
			if m, ok := x.memberN(n, depth+1); ok {
				return x.objectN(m, depth+1)
			}
			if x.isThis(n.X) {
				if f := x.thisFieldExpr(n.Y); f != nil {
					return x.objectN(f, depth+1)
				}
				if obj := x.thisPropObject(propName(n.Y), depth+1); obj != nil {
					return obj, true
				}
			}
			if propName(n.Y) == "value" {
				if arg, ok := x.reactiveArg(n.X); ok {
					if o, isObj := arg.(*js.ObjectExpr); isObj {
						return o, true
					}
					if o := returnedObject(arg); o != nil {
						return o, true
					}
				}
			}
		}
	}
	return nil, false
}

func (x *extractor) thisPropObject(name string, depth int) *js.ObjectExpr {
	if name == "" || depth >= 16 {
		return nil
	}
	if x.thisObjDone[name] {
		return x.thisObjCache[name]
	}
	vs := x.thisProps[name]
	if len(vs) == 0 || len(vs) > 256 {
		x.thisObjDone[name] = true
		return nil
	}
	// Mark done before recursion so cyclic self-references cannot loop.
	x.thisObjDone[name] = true
	obj0, ok := x.objectN(vs[0], depth+1)
	if !ok || obj0 == nil {
		return nil
	}
	for _, v := range vs[1:] {
		obji, oki := x.objectN(v, depth+1)
		if !oki || obji != obj0 {
			return nil
		}
	}
	x.thisObjCache[name] = obj0
	return obj0
}

func unwrapEnumGroup(e js.IExpr) js.IExpr {
	for {
		if g, ok := e.(*js.GroupExpr); ok {
			e = g.X
			continue
		}
		return e
	}
}

func (x *extractor) setEnumProp(target *js.Var, key string, val js.IExpr) {
	if target == nil || key == "" || val == nil {
		return
	}
	m := x.enumProps[target]
	if m == nil {
		m = map[string]js.IExpr{}
		x.enumProps[target] = m
	}
	if obj, ok := val.(*js.ObjectExpr); ok && len(obj.List) == 0 && m[key] != nil {
		return
	}
	m[key] = val
}

// registerEnumIIFE detects TypeScript enum and namespace IIFEs emitted by
// esbuild/tsc (((E2) => { E2.A = ... })(E || (E = {})) or (B = A2.B || ...))
// and maps the inner parameter variable E2 back to target E.
func (x *extractor) registerEnumIIFE(ce *js.CallExpr, lhs *js.Var) {
	if ce == nil || len(ce.Args.List) != 1 || ce.Args.List[0].Rest {
		return
	}
	var param0 *js.Var
	switch fn := unwrapEnumGroup(ce.X).(type) {
	case *js.ArrowFunc:
		if len(fn.Params.List) == 1 && fn.Params.Rest == nil {
			param0, _ = fn.Params.List[0].Binding.(*js.Var)
		}
	case *js.FuncDecl:
		if len(fn.Params.List) == 1 && fn.Params.Rest == nil {
			param0, _ = fn.Params.List[0].Binding.(*js.Var)
		}
	}
	if param0 == nil {
		return
	}
	var target *js.Var
	arg0 := unwrapEnumGroup(ce.Args.List[0].Value)
	isInitOr := func(op js.TokenType) bool {
		return op == js.OrToken || op == js.OrEqToken || op == js.NullishToken || op == js.NullishEqToken
	}
	if be, ok := arg0.(*js.BinaryExpr); ok {
		switch {
		case isInitOr(be.Op):
			switch lhsOr := unwrapEnumGroup(be.X).(type) {
			case *js.Var:
				target = root(lhsOr)
			case *js.DotExpr:
				if pv, ok := lhsOr.X.(*js.Var); ok {
					if outer := x.enumParamTarget[root(pv)]; outer != nil {
						sub := &js.Var{}
						x.setEnumProp(outer, propName(lhsOr.Y), sub)
						target = sub
					}
				}
			}
		case be.Op == js.EqToken:
			// Nested namespace: (V1 = Api2.V1 || (Api2.V1 = {})) or (V1 = Api2.V1 ||= {})
			if vr, ok := unwrapEnumGroup(be.X).(*js.Var); ok {
				target = root(vr)
				if orExpr, ok := unwrapEnumGroup(be.Y).(*js.BinaryExpr); ok && isInitOr(orExpr.Op) {
					if d, ok := unwrapEnumGroup(orExpr.X).(*js.DotExpr); ok {
						if pv, ok := d.X.(*js.Var); ok {
							if outer := x.enumParamTarget[root(pv)]; outer != nil {
								x.setEnumProp(outer, propName(d.Y), vr)
							}
						}
					}
				}
			}
		}
	}
	if target == nil {
		target = lhs
	}
	if target != nil {
		x.enumParamTarget[root(param0)] = target
	}
}

func (x *extractor) enumVar(e js.IExpr, depth int) *js.Var {
	if depth >= 8 || e == nil {
		return nil
	}
	switch n := ungroup(e).(type) {
	case *js.Var:
		v := root(n)
		if x.enumProps[v] != nil {
			return v
		}
		if a, ok := x.args[v]; ok && a != nil && a != js.IExpr(n) {
			return x.enumVar(a, depth+1)
		}
		if c := x.constOrSingleExpr(v); c != nil && c != js.IExpr(n) {
			return x.enumVar(c, depth+1)
		}
	case *js.DotExpr:
		if m, ok := x.memberN(n, depth+1); ok {
			return x.enumVar(m, depth+1)
		}
		if x.isThis(n.X) {
			if ev := x.thisPropEnum(propName(n.Y), depth+1); ev != nil {
				return ev
			}
		}
	}
	return nil
}

func (x *extractor) thisPropEnum(name string, depth int) *js.Var {
	if name == "" || depth >= 8 {
		return nil
	}
	if x.thisEnumDone[name] {
		return x.thisEnumCache[name]
	}
	vs := x.thisProps[name]
	if len(vs) == 0 || len(vs) > 256 {
		x.thisEnumDone[name] = true
		return nil
	}
	x.thisEnumDone[name] = true
	ev0 := x.enumVar(vs[0], depth+1)
	if ev0 == nil {
		return nil
	}
	for _, v := range vs[1:] {
		if x.enumVar(v, depth+1) != ev0 {
			return nil
		}
	}
	x.thisEnumCache[name] = ev0
	return ev0
}

// member is the value of obj.prop when obj is a constant object literal or
// TypeScript enum/namespace IIFE.
func (x *extractor) member(d *js.DotExpr) (js.IExpr, bool) {
	return x.memberN(d, 0)
}

func (x *extractor) memberN(d *js.DotExpr, depth int) (js.IExpr, bool) {
	if depth >= 16 || d == nil {
		return nil, false
	}
	if v, ok := x.wpMember(d, depth); ok {
		return v, true
	}
	if ev := x.enumVar(d.X, depth); ev != nil {
		if v := x.enumProps[ev][propName(d.Y)]; v != nil {
			return v, true
		}
	}
	if cls := x.classOfExprAt(d.X, depth+1); cls != nil {
		if v, ok := x.classStaticField(cls, propName(d.Y)); ok {
			return v, true
		}
	}
	if obj, ok := x.objectN(d.X, depth); ok {
		if v := x.objectValueSpread(obj, propName(d.Y), depth); v != nil {
			return v, true
		}
	}
	if propName(d.Y) == "value" {
		if arg, ok := x.reactiveArg(d.X); ok {
			if ret := singleReturnExpr(arg); ret != nil {
				return ret, true
			}
			if _, isStr := literalString(arg); isStr {
				return arg, true
			}
		}
	}
	return nil, false
}

func objectValue(obj *js.ObjectExpr, key string) js.IExpr {
	for _, p := range obj.List {
		if p.Name != nil && !p.Spread && propName(p.Name) == key {
			return p.Value
		}
	}
	return nil
}

// propName is the name of a property: an identifier, a string, or a
// number as written.
func propName(n js.INode) string {
	switch n := n.(type) {
	case *js.PropertyName:
		if n.Computed != nil {
			if s, ok := literalString(n.Computed); ok {
				return s
			}
			return ""
		}
		return propName(&n.Literal)
	case *js.LiteralExpr:
		return propName(*n)
	case js.LiteralExpr:
		// A DotExpr's property is a LiteralExpr value.
		if n.TokenType == js.StringToken {
			return unquote(n.Data)
		}
		return string(n.Data)
	case *js.Var:
		return string(n.Data)
	}
	return ""
}

func literalString(e js.IExpr) (string, bool) {
	switch n := e.(type) {
	case *js.LiteralExpr:
		if n.TokenType == js.StringToken {
			return unquote(n.Data), true
		}
	case *js.TemplateExpr:
		if n.Tag == nil && len(n.List) == 0 {
			return templateText(n.Tail, true, true), true
		}
	}
	return "", false
}

// globalName is the name of an undeclared variable (a browser global), or
// of window.X and the like.
func globalName(e js.IExpr) string {
	switch n := e.(type) {
	case *js.Var:
		if root(n).Decl == js.NoDecl {
			return string(n.Data)
		}
	case *js.DotExpr:
		if isGlobal(n.X, "window", "self", "globalThis") {
			return propName(n.Y)
		}
	case *js.GroupExpr:
		return globalName(n.X)
	}
	return ""
}

func isGlobal(e js.IExpr, names ...string) bool {
	v, ok := e.(*js.Var)
	if !ok || root(v).Decl != js.NoDecl {
		return false
	}
	for _, n := range names {
		if string(v.Data) == n {
			return true
		}
	}
	return false
}

// --- parameter names ---

type iterDepthKey int

func (x *extractor) isClientRequestCallee(callee js.IExpr) bool {
	callee = ungroup(callee)
	switch n := callee.(type) {
	case *js.Var:
		r := root(n)
		if x.clients[r] {
			return true
		}
		if im, ok := x.esImports[r]; ok && strings.EqualFold(im[0], "axios") {
			return true
		}
		return strings.EqualFold(string(n.Data), "axios")
	case *js.DotExpr:
		if propName(n.Y) == "request" {
			return x.isClientObj(n.X) || x.isThis(n.X)
		}
	}
	return false
}

func (x *extractor) isStoreNewVar(e js.IExpr) bool {
	v, ok := ungroup(e).(*js.Var)
	if !ok {
		return false
	}
	ne, ok := ungroup(x.constant(v)).(*js.NewExpr)
	if !ok {
		return false
	}
	switch globalName(ne.X) {
	case "Map", "Set", "WeakMap", "WeakSet", "Headers", "URLSearchParams", "FormData":
		return true
	}
	return false
}

func (x *extractor) isPointFreeRequestFn(fn js.IExpr) bool {
	if x.fetchLike(fn) || x.isClientRequestCallee(fn) {
		return true
	}
	switch n := fn.(type) {
	case *js.DotExpr:
		if m := clientMethods[propName(n.Y)]; m != "" && !storeLike(n.X, nil) && !x.isStoreNewVar(n.X) && !x.requestMethod(n, 1) {
			return true
		}
		if propName(n.Y) == "sendBeacon" && isGlobal(n.X, "navigator") {
			return true
		}
		return x.summaryOf(n, 1) != nil
	case *js.Var:
		if x.sseParam(n) == 0 {
			return true
		}
		return x.summaryOf(n, 1) != nil
	}
	return false
}

func hasIterCallTarget(body *js.BlockStmt) bool {
	found := false
	js.Walk(nodeVisitor(func(n js.INode) bool {
		if found {
			return false
		}
		switch t := n.(type) {
		case *js.CallExpr, *js.NewExpr:
			found = true
			return false
		case *js.BinaryExpr:
			if t.Op == js.EqToken && isLocation(t.X) {
				found = true
				return false
			}
		}
		return true
	}), body)
	return found
}

type iterBodyVisitor struct{ x *extractor }

func (v iterBodyVisitor) Enter(n js.INode) js.IVisitor {
	switch n.(type) {
	case *js.ClassDecl, *js.FuncDecl, *js.MethodDecl:
		v.x.thisStack = append(v.x.thisStack, n)
	}
	switch n := n.(type) {
	case *js.FuncDecl, *js.MethodDecl, *js.ArrowFunc:
		v.x.fnStack = append(v.x.fnStack, n)
	case *js.CallExpr:
		var made []string
		saved := v.x.made
		v.x.made = &made
		v.x.call(n)
		v.x.made = saved
		if len(made) > 0 {
			v.x.inst[n] = append(v.x.inst[n], made...)
		}
		if d, ok := ungroup(n.X).(*js.DotExpr); ok {
			switch propName(d.Y) {
			case "map", "forEach", "flatMap":
				if len(n.Args.List) >= 1 && len(n.Args.List) <= 2 && !n.Args.List[0].Rest {
					return nil
				}
			}
		}
	case *js.NewExpr:
		v.x.construct(n)
	case *js.BinaryExpr:
		if n.Op == js.EqToken && isLocation(n.X) {
			v.x.add(n.Y, Endpoint{Method: "GET", Kind: "navigation"}, nil, sure)
		}
	}
	return v
}

func (v iterBodyVisitor) Exit(n js.INode) {
	switch n.(type) {
	case *js.FuncDecl, *js.MethodDecl, *js.ArrowFunc:
		v.x.fnStack = v.x.fnStack[:len(v.x.fnStack)-1]
	}
	switch n.(type) {
	case *js.ClassDecl, *js.FuncDecl, *js.MethodDecl:
		v.x.thisStack = v.x.thisStack[:len(v.x.thisStack)-1]
	}
}

func (x *extractor) arrayIterCall(recv, cb js.IExpr) bool {
	if x.busy[iterDepthKey(1)] {
		return false
	}
	cb = ungroup(cb)
	if bc, ok := cb.(*js.CallExpr); ok {
		if bd, ok := ungroup(bc.X).(*js.DotExpr); ok && propName(bd.Y) == "bind" && len(bc.Args.List) == 1 && !bc.Args.List[0].Rest {
			cb = ungroup(bd.X)
		}
	}
	lvl := iterDepthKey(0)
	if x.busy[lvl] {
		lvl = iterDepthKey(1)
	}
	switch fn := cb.(type) {
	case *js.ArrowFunc, *js.FuncDecl:
		params, body, _ := fnParts(fn)
		if len(params.List) == 0 || !hasIterCallTarget(body) {
			return true
		}
		x.busy[lvl] = true
		defer delete(x.busy, lvl)
		x.fnStack = append(x.fnStack, fn)
		if _, isFD := fn.(*js.FuncDecl); isFD {
			x.thisStack = append(x.thisStack, fn)
		}
		defer func() {
			x.fnStack = x.fnStack[:len(x.fnStack)-1]
			if _, isFD := fn.(*js.FuncDecl); isFD {
				x.thisStack = x.thisStack[:len(x.thisStack)-1]
			}
		}()
		var log []*js.LiteralExpr
		savedLog, before := x.usedLog, len(x.eps)
		x.usedLog = &log
		defer func() {
			x.usedLog = savedLog
			if len(x.eps) == before {
				for _, l := range log {
					delete(x.used, l)
				}
			} else if savedLog != nil {
				*savedLog = append(*savedLog, log...)
			}
		}()
		count := 0
		x.forEachArrayItem(recv, 0, 0, func(el js.IExpr) bool {
			var q []string
			undo := x.bindParams(params, []js.IExpr{el}, &q, 0)
			js.Walk(iterBodyVisitor{x: x}, body)
			undo()
			count++
			return count < maxAlts
		})
		return true
	case *js.DotExpr, *js.Var:
		if !x.isPointFreeRequestFn(fn) {
			return false
		}
		x.busy[lvl] = true
		defer delete(x.busy, lvl)
		var log []*js.LiteralExpr
		savedLog, before := x.usedLog, len(x.eps)
		x.usedLog = &log
		defer func() {
			x.usedLog = savedLog
			if len(x.eps) == before {
				for _, l := range log {
					delete(x.used, l)
				}
			} else if savedLog != nil {
				*savedLog = append(*savedLog, log...)
			}
		}()
		count := 0
		x.forEachArrayItem(recv, 0, 0, func(el js.IExpr) bool {
			sc := &js.CallExpr{
				X:    fn,
				Args: js.Args{List: []js.Arg{{Value: el}}},
			}
			x.call(sc)
			count++
			return count < maxAlts
		})
		return true
	}
	return false
}
