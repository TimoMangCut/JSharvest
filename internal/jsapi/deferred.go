package jsapi

// This file: deferred URLs (round 27A): a request whose URL calls a
// function another module exports (Sf.patch(`${Qi(n.collection)}/${k}`),
// Qi imported from a shared chunk that defines MT(e){ return e in jT ?
// jT[e] : NC(e) ? `/${e.substring(9)}` : `/items/${e}` }). The caller's
// script records the request with the call's place and its arguments
// (Deferred); the exporting script records its URL builders (Builder); the
// catalog, which sees every script, evaluates the builder with the
// arguments given (EvalBuilder) and puts the values in place.

import (
	"strconv"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// Builder is a function a module exports that makes a URL of what it is
// given.
type Builder struct {
	Name   string `json:"name"`
	Local  string `json:"local,omitempty"`
	Params int    `json:"params"`
}

// Deferred is a request whose URL calls a function another module
// exports. URL has DeferredSlot where the call's value goes.
type Deferred struct {
	Method  string     `json:"method,omitempty"`
	Kind    string     `json:"kind"`
	URL     string     `json:"url"`
	Module  string     `json:"module"`
	Name    string     `json:"name"`
	Args    [][]string `json:"args"`
	Query   []string   `json:"query,omitempty"`
	Body    []string   `json:"body,omitempty"`
	Headers []string   `json:"headers,omitempty"`
	// Pre are the prefixes of the client the request is made with
	// (axios.create({baseURL: "/api"})): put before the URL when the
	// builder's value makes it a path of the page's origin.
	Pre     []string `json:"pre,omitempty"`
	Line    int      `json:"line,omitempty"`
	Col     int      `json:"col,omitempty"`
	Snippet string   `json:"snippet,omitempty"`
}

// DeferredSlot marks, in a Deferred's URL, the place of the imported
// call's value.
const DeferredSlot = "{import}"

// deferCall is an imported call met while a request's URL is read.
type deferCall struct {
	module, name string
	args         [][]string
}

// The marker an imported call's value is while a request's URL is read:
// no URL's character.
const (
	deferOpen  = "\x02"
	deferClose = "\x03"
)

const (
	maxBuilderParams = 4
	maxBuilderCombos = 16
	maxBuilderValues = 16
)

// noteBuilder records an exported function that makes a URL: one taking
// one to maxBuilderParams parameters whose returns write a path ("/items/").
func (x *extractor) noteBuilder(name, local string, v *js.Var) {
	_, params, body, ok := x.fnOf(v)
	if !ok || body == nil || params.Rest != nil || len(params.List) == 0 || len(params.List) > maxBuilderParams {
		return
	}
	rets := returnsOf(body)
	if len(rets) == 0 || len(rets) > maxReturns || !writesPath(rets) {
		return
	}
	b := Builder{Name: name, Params: len(params.List)}
	if local != name {
		b.Local = local
	}
	x.builders = append(x.builders, b)
}

// writesPath reports whether returns write a path of their own: a string or
// template text with a slash and a word of three letters or more.
func writesPath(rets []js.IExpr) bool {
	found := false
	for _, r := range rets {
		js.Walk(mentionVisitor{func(n js.INode) {
			if found {
				return
			}
			var texts []string
			switch n := n.(type) {
			case *js.LiteralExpr:
				if s, ok := literalString(n); ok {
					texts = append(texts, s)
				}
			case *js.TemplateExpr:
				for i, p := range n.List {
					texts = append(texts, templateText(p.Value, i == 0, false))
				}
				texts = append(texts, templateText(n.Tail, len(n.List) == 0, true))
			}
			for _, t := range texts {
				if strings.Contains(t, "/") && ownPath([]string{t}) {
					found = true
				}
			}
		}}, r)
	}
	return found
}

// deferImported marks a call to an imported function in a request's URL:
// its arguments' values are read (without marking calls in them), and its
// value is a marker the catalog replaces.
func (x *extractor) deferImported(c *js.CallExpr, depth int) ([]string, bool) {
	mod, name, ok := x.imported(c.X)
	if !ok || mod == "" || name == "" || len(x.deferCalls) >= 256 {
		return nil, false
	}
	x.deferring = false
	defer func() { x.deferring = true }()
	var vals [][]string
	for _, a := range c.Args.List {
		if a.Rest {
			return nil, false
		}
		var q []string
		v := x.eval(a.Value, &q, depth+1)
		if len(v) == 0 || len(v) > maxAlts {
			v = unk
		}
		vals = append(vals, v)
	}
	x.deferCalls = append(x.deferCalls, deferCall{mod, name, vals})
	return []string{deferOpen + strconv.Itoa(len(x.deferCalls)-1) + deferClose}, true
}

// addDeferred records a request whose URL holds one imported call's marker,
// and adds the request as it would be without (the call's value unknown):
// what the catalog cannot join is no worse than before.
func (x *extractor) addDeferred(t string, ep Endpoint, q []string, at js.INode, lv level) string {
	plain := t
	var call *deferCall
	n := 0
	for {
		i := strings.Index(plain, deferOpen)
		if i < 0 {
			break
		}
		j := strings.Index(plain[i:], deferClose)
		if j < 0 {
			break
		}
		idx, err := strconv.Atoi(plain[i+len(deferOpen) : i+j])
		if err == nil && idx < len(x.deferCalls) {
			call = &x.deferCalls[idx]
		}
		n++
		if n == 1 {
			t = plain[:i] + DeferredSlot + plain[i+j+len(deferClose):]
		}
		plain = plain[:i] + unknown + plain[i+j+len(deferClose):]
	}
	if n == 1 && call != nil && ep.Method != "" {
		d := Deferred{Method: ep.Method, Kind: ep.Kind, URL: t, Module: call.module, Name: call.name, Args: call.args,
			Query: append(ep.Query, q...), Body: ep.Body, Headers: ep.Headers}
		if strings.HasPrefix(t, DeferredSlot) && len(x.pre) > 0 {
			d.Pre = append([]string(nil), x.pre...)
		}
		if c, ok := at.(*js.CallExpr); ok {
			var loc Endpoint
			x.locateCall(&loc, c)
			d.Line, d.Col, d.Snippet = loc.Line, loc.Col, loc.Snippet
		}
		x.deferred = append(x.deferred, d)
	}
	return x.addOne(cleanURL(plain), ep, q, at, lv)
}

// Module is a module's source read for evaluating what it defines: parsed
// once (lowered as Extract does when the parser fails), its definitions
// read, then any number of evaluations. Not for concurrent use.
type Module struct {
	x *extractor
}

// PrepareModule reads a module for EvalBuilder; nil when it cannot be
// parsed.
func PrepareModule(src []byte) *Module {
	x, _ := prepared(src)
	if x == nil {
		return nil
	}
	x.noMarkUsed = true
	return &Module{x}
}

// EvalBuilder evaluates the function the module exports under a name with
// the arguments given (each a set of values; unknown is {}), at most
// maxBuilderValues values, evaluated once for each combination of the
// arguments' values, so that its tests (e in table, startsWith, substring)
// see one value each.
func (m *Module) EvalBuilder(name string, args [][]string) (out []string) {
	x := m.x
	defer func() {
		if r := recover(); r != nil {
			out = nil
		}
	}()
	v := x.exportVars[name]
	if v == nil {
		return nil
	}
	_, params, body, ok := x.fnOf(v)
	if !ok || body == nil {
		return nil
	}
	rets := returnsOf(body)
	if len(rets) == 0 || len(rets) > maxReturns {
		return nil
	}
	combos := [][]string{{}}
	for i := range params.List {
		vals := unk
		if i < len(args) && len(args[i]) > 0 {
			vals = args[i]
		}
		var next [][]string
		for _, c := range combos {
			for _, v := range vals {
				if len(next) >= maxBuilderCombos {
					break
				}
				next = append(next, append(append([]string(nil), c...), v))
			}
		}
		combos = next
	}
	var bound []*js.Var
	for _, b := range params.List {
		if p, ok := b.Binding.(*js.Var); ok {
			bound = append(bound, root(p))
		}
	}
	defer func() {
		for _, p := range bound {
			delete(x.bind, p)
		}
	}()
	for _, c := range combos {
		// Each evaluation its own budget: a module read once serves many.
		x.callBudget, x.rootEvals, x.calls = 0, 0, 0
		known := true
		for i, b := range params.List {
			if p, ok := b.Binding.(*js.Var); ok {
				x.bind[root(p)] = []string{c[i]}
			}
			known = known && !strings.Contains(c[i], unknown)
		}
		var vals []string
		for _, r := range rets {
			var q []string
			for _, s := range x.eval(r, &q, 0) {
				vals = addAlt(vals, s)
			}
		}
		if known && len(vals) > 1 {
			// Every argument known, and still more than one way: a test
			// the evaluation could not decide. Taking every side would
			// name URLs the code never makes for these arguments.
			continue
		}
		for _, v := range vals {
			if len(out) < maxBuilderValues {
				out = addAlt(out, v)
			}
		}
	}
	return out
}

// prepared parses a module and reads its definitions (the passes before
// the calls pass), for evaluating what it defines.
func prepared(src []byte) (x *extractor, ast *js.AST) {
	defer func() {
		if r := recover(); r != nil {
			x, ast = nil, nil
		}
	}()
	code := src
	a, err := js.Parse(parse.NewInputBytes(code), js.Options{})
	if err != nil {
		lowered, _, ok := transformJSLower(src)
		if !ok {
			return nil, nil
		}
		if a, err = js.Parse(parse.NewInputBytes(lowered), js.Options{}); err != nil {
			return nil, nil
		}
		code = lowered
	}
	x = newExtractor(code, nil, nil, false)
	x.prepare(a)
	return x, a
}

// CleanURL is a URL as the extractor writes an endpoint's: its parts
// joined, placeholders as {}.
func CleanURL(s string) string { return cleanURL(s) }

// NamedPath reports whether a URL a call makes is an endpoint's: a path
// that reads as one, with a word of its own (not /{}/{}).
func NamedPath(u string) bool {
	return looksLikePath(u, call) && ownPath([]string{u})
}
