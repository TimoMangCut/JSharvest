package jsapi

import (
	"slices"
	"strconv"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

// --- calls across a bundler's modules (Turbopack, webpack) ---

// A request helper and its caller are often in two chunks: one module
// exports (e,t) => l(e).verifyMfa(t), whose client posts its argument to
// /v1/auth/mfa/verify; another imports it (H = e.i(21666)) and calls
// (0,H.$)(cfg.AUTH_API_URL, {mfa_token, code}). Each script records its
// side; the catalog joins them by module and name, for the body (and the
// setting naming the base) only the caller has.

// Export is a module's exported function that makes a request with what
// it is given: either a fixed/template URL, a parameterized request
// wrapper (URLArg >= 0), or a multi-module wrapper delegating to an
// imported helper (Via != nil).
type Export struct {
	Module string `json:"module"`
	Name   string `json:"name"`
	Local  string `json:"local,omitempty"`
	Method string `json:"method"`
	URL    string `json:"url"`
	// QueryArg, BodyArg and BaseArg are the arguments that are the
	// request's query, body, and the base its client is made with; -1 for none.
	QueryArg int `json:"query_arg"`
	BodyArg  int `json:"body_arg"`
	BaseArg  int `json:"base_arg"`
	// ParamURL and ParamMethod mark parameterized wrapper exports whose URL
	// path or HTTP method is supplied by URLArg / MethodArg at the call site.
	ParamURL    bool       `json:"param_url,omitempty"`
	URLArg      int        `json:"url_arg,omitempty"`
	URLProp     string     `json:"url_prop,omitempty"`
	URLPrefix   string     `json:"url_prefix,omitempty"`
	ParamMethod bool       `json:"param_method,omitempty"`
	MethodArg   int        `json:"method_arg,omitempty"`
	MethodProp  string     `json:"method_prop,omitempty"`
	BodyProp    string     `json:"body_prop,omitempty"`
	QueryProp   string     `json:"query_prop,omitempty"`
	BaseProp    string     `json:"base_prop,omitempty"`
	HasDynBase  bool       `json:"has_dyn_base,omitempty"`
	HeaderNames string     `json:"headers,omitempty"`
	Factory     string     `json:"factory,omitempty"`
	Via         *ExportVia `json:"via,omitempty"`
}

func newExport() Export {
	return Export{QueryArg: -1, BodyArg: -1, BaseArg: -1}
}

// ExportVia describes an exported helper that delegates to an imported
// function in another module (File A -> File B -> File C).
type ExportVia struct {
	Module string   `json:"module"`
	Name   string   `json:"name"`
	Args   []ViaArg `json:"args,omitempty"`
}

type ViaArg struct {
	Param    int               `json:"param"`
	Prop     string            `json:"prop,omitempty"`
	Prefix   string            `json:"prefix,omitempty"`
	Suffix   string            `json:"suffix,omitempty"`
	Values   []string          `json:"values,omitempty"`
	Keys     []string          `json:"keys,omitempty"`
	BaseKey  string            `json:"base_key,omitempty"`
	ObjProps map[string]ViaArg `json:"obj_props,omitempty"`
}

// ReExport is an ES module re-export (`export { a as b } from "./x"` or
// `export * from "./x"`).
type ReExport struct {
	Module string `json:"module"`
	Name   string `json:"name,omitempty"`
	Target string `json:"target,omitempty"`
	All    bool   `json:"all,omitempty"`
}

// Factory is a function that makes a client of the base it is given and
// returns its methods (l = e => {let t = o(e); return {verifyMfa…,
// enrollTotp…}}): one base for all its requests, exported or not.
type Factory struct {
	ID string `json:"id"`
	// Endpoints are its methods' requests: "METHOD URL".
	Endpoints []string `json:"endpoints"`
	// Settings are those it is given in this script (a(e.CLIENT_API_URL)).
	Settings []string `json:"settings,omitempty"`
}

// Import is a call to a function another module exports.
type Import struct {
	Module  string `json:"module"`
	Name    string `json:"name"`
	Line    int    `json:"line,omitempty"`
	Col     int    `json:"col,omitempty"`
	Snippet string `json:"snippet,omitempty"`
	// Args are what the call gives: an object's fields, evaluated URL/method
	// values, or the setting an argument reads (cfg.AUTH_API_URL), by position.
	Args []ImportArg `json:"args"`
}

type ImportArg struct {
	Keys         []string            `json:"keys,omitempty"`
	Values       []string            `json:"values,omitempty"`
	Query        []string            `json:"query,omitempty"`
	Setting      string              `json:"setting,omitempty"`
	BaseKey      string              `json:"base_key,omitempty"`
	PropValues   map[string][]string `json:"prop_values,omitempty"`
	PropKeys     map[string][]string `json:"prop_keys,omitempty"`
	PropBaseKeys map[string]string   `json:"prop_base_keys,omitempty"`
}

// moduleVisitor finds the exports (M.s([...], id)) and the calls to
// imported functions ((0, H.name)(…), H = M.i(id)).
type moduleVisitor struct{ x *extractor }

func (v moduleVisitor) Enter(n js.INode) js.IVisitor {
	c, ok := n.(*js.CallExpr)
	if !ok {
		return v
	}
	x := v.x
	as := args(&c.Args)
	if d, ok := c.X.(*js.DotExpr); ok && propName(d.Y) == "s" && len(as) == 2 {
		if arr, ok := as[0].(*js.ArrayExpr); ok {
			if id, ok := moduleID(as[1]); ok {
				x.exportsOf(id, arr)
			}
		}
		return v
	}
	if _, isVar := c.X.(*js.Var); isVar && len(as) > 0 {
		// a(e.CLIENT_API_URL) or a(client.authServer): a factory of this script's, given its base.
		if f := x.factoryOf(c.X); f != nil {
			for _, a := range as {
				if d, ok := a.(*js.DotExpr); ok && propName(d.Y) != "" {
					if !slices.Contains(f.Settings, propName(d.Y)) {
						f.Settings = append(f.Settings, propName(d.Y))
					}
					break
				}
			}
		}
	}
	if mod, name, ok := x.imported(c.X); ok && !jsxNames[name] && len(as) > 0 && !x.viaCalls[c] {
		im := Import{Module: mod, Name: name}
		some := false
		x.lits = x.lits[:0]
		for _, a := range as {
			var ia ImportArg
			if bks := x.baseKeysOf(a, true, 0); len(bks) > 0 {
				ia.BaseKey = bks[0]
				some = true
			}
			if d, ok := a.(*js.DotExpr); ok && isBaseName(propName(d.Y)) {
				ia.Setting = propName(d.Y)
				if ia.BaseKey == "" {
					ia.BaseKey = "prop:" + propName(d.Y)
				}
				some = true
			} else if obj, isObj := x.object(a); isObj {
				ia.Keys = uniq(x.keys(a, "", 0))
				some = some || len(ia.Keys) > 0
				if len(obj.List) <= 16 {
					for _, p := range obj.List {
						k := propKey(&p)
						if k == "" || p.Value == nil {
							continue
						}
						switch k {
						case "method", "type", "url", "endpoint", "uri", "pathname", "baseURL", "baseUrl":
							if pbk := x.baseKeysOf(p.Value, true, 0); len(pbk) > 0 {
								if ia.PropBaseKeys == nil {
									ia.PropBaseKeys = map[string]string{}
								}
								ia.PropBaseKeys[k] = pbk[0]
								some = true
							}
							if s, ok := x.argString(p.Value); ok && s != "" {
								cu := cleanURL(s)
								val := s
								if !httpMethods[strings.ToUpper(s)] && cu != "" {
									val = cu
								}
								if ia.PropValues == nil {
									ia.PropValues = map[string][]string{}
								}
								ia.PropValues[k] = []string{val}
								if l, isLit := p.Value.(*js.LiteralExpr); isLit {
									x.lits = append(x.lits, l.Data)
								}
								some = true
							} else {
								var pq []string
								var clean []string
								for _, v := range x.eval(p.Value, &pq, 0) {
									cu := cleanURL(v)
									if httpMethods[strings.ToUpper(v)] || (cu != "" && cu != unknown && (schemeRe.MatchString(cu) || looksLikePath(cu, call))) {
										clean = addAlt(clean, cu)
									}
								}
								if len(clean) > 0 {
									if ia.PropValues == nil {
										ia.PropValues = map[string][]string{}
									}
									ia.PropValues[k] = uniq(clean)
									ia.Query = uniq(append(ia.Query, pq...))
									some = true
								}
							}
						case "data", "body", "json", "form":
							if ks := uniq(x.keys(p.Value, "", 0)); len(ks) > 0 {
								if ia.PropKeys == nil {
									ia.PropKeys = map[string][]string{}
								}
								ia.PropKeys[k] = ks
								some = true
							}
						case "params", "query", "queries", "searchParams", "headers":
							if ks := uniq(x.keys(p.Value, "", 2)); len(ks) > 0 {
								if ia.PropKeys == nil {
									ia.PropKeys = map[string][]string{}
								}
								ia.PropKeys[k] = ks
								some = true
							}
						}
					}
				}
			} else if s, ok := x.argString(a); ok {
				cu := cleanURL(s)
				if httpMethods[strings.ToUpper(s)] || schemeRe.MatchString(cu) || looksLikePath(cu, call) {
					ia.Values = []string{cu}
					if l, isLit := a.(*js.LiteralExpr); isLit {
						x.lits = append(x.lits, l.Data)
					}
					some = true
				}
			} else {
				var aq []string
				var clean []string
				for _, v := range x.eval(a, &aq, 0) {
					cu := cleanURL(v)
					if httpMethods[strings.ToUpper(v)] || (cu != "" && cu != unknown && (schemeRe.MatchString(cu) || looksLikePath(cu, call))) {
						clean = addAlt(clean, cu)
					}
				}
				if len(clean) > 0 {
					ia.Values = uniq(clean)
					ia.Query = uniq(aq)
					some = true
				} else if ks := uniq(x.keys(a, "", 0)); len(ks) > 0 {
					ia.Keys = ks
					some = true
				}
			}
			im.Args = append(im.Args, ia)
		}
		if some && len(x.imports) < maxImports {
			var loc Endpoint
			if len(x.lits) > 0 {
				x.locate(&loc, x.lits)
			}
			if loc.Line == 0 {
				x.locateCall(&loc, c)
			}
			if loc.Line == 0 && len(x.src) > 0 {
				pos := min(x.cursor, len(x.src)-1)
				x.place(&loc, pos, min(pos+1, len(x.src)))
			}
			im.Line, im.Col, im.Snippet = loc.Line, loc.Col, loc.Snippet
			x.imports = append(x.imports, im)
		}
	}
	return v
}

func (moduleVisitor) Exit(js.INode) {}

// jsxNames are a JSX runtime's: an element's props are no request's.
var jsxNames = map[string]bool{"jsx": true, "jsxs": true, "jsxDEV": true, "createElement": true, "cloneElement": true, "Fragment": true}

// maxImports is how many calls to imported functions a script records.
const maxImports = 4000

func moduleID(e js.IExpr) (string, bool) {
	l, ok := e.(*js.LiteralExpr)
	if !ok || l.TokenType != js.DecimalToken && l.TokenType != js.IntegerToken {
		return "", false
	}
	return string(l.Data), true
}

// scanESModules records top-level ES module imports and exports (Vite/Rollup)
// before moduleVisitor walks call expressions.
func (x *extractor) scanESModules(ast *js.AST) {
	topVars := map[string]*js.Var{}
	for _, v := range ast.BlockStmt.Scope.Declared {
		topVars[string(v.Data)] = root(v)
	}
	for _, v := range ast.BlockStmt.Scope.Undeclared {
		if _, ok := topVars[string(v.Data)]; !ok {
			topVars[string(v.Data)] = root(v)
		}
	}
	for _, stmt := range ast.BlockStmt.List {
		switch s := stmt.(type) {
		case *js.ImportStmt:
			mod := unquote(s.Module)
			if mod == "" {
				continue
			}
			if len(s.Default) > 0 {
				if v := topVars[string(s.Default)]; v != nil {
					x.esImports[v] = [2]string{mod, "default"}
				}
			}
			for _, al := range s.List {
				local := string(al.Binding)
				if local == "" {
					continue
				}
				v := topVars[local]
				if v == nil {
					continue
				}
				if len(al.Name) == 1 && al.Name[0] == '*' {
					x.esNSImports[v] = mod
					continue
				}
				expName := local
				if len(al.Name) > 0 {
					expName = string(al.Name)
				}
				x.esImports[v] = [2]string{mod, expName}
			}
		case *js.ExportStmt:
			if s.Module != nil {
				mod := unquote(s.Module)
				if mod == "" {
					continue
				}
				if len(s.List) == 1 && s.List[0].Name == nil && len(s.List[0].Binding) == 1 && s.List[0].Binding[0] == '*' {
					x.reExports = append(x.reExports, ReExport{Module: mod, All: true})
					continue
				}
				for _, al := range s.List {
					expName := string(al.Binding)
					if expName == "" {
						continue
					}
					target := expName
					if len(al.Name) > 0 {
						target = string(al.Name)
					}
					x.reExports = append(x.reExports, ReExport{Module: mod, Name: expName, Target: target})
				}
				continue
			}
			if s.Decl != nil {
				if s.Default {
					if ex, ok := x.exported(s.Decl); ok {
						ex.Module, ex.Name = "", "default"
						x.exports = append(x.exports, ex)
					}
					continue
				}
				switch d := s.Decl.(type) {
				case *js.FuncDecl:
					if d.Name != nil {
						x.exportVars[string(d.Name.Data)] = root(d.Name)
						if ex, ok := x.exported(d); ok {
							ex.Module, ex.Name = "", string(d.Name.Data)
							x.exports = append(x.exports, ex)
						} else {
							x.noteBuilder(string(d.Name.Data), "", root(d.Name))
						}
					}
				case *js.VarDecl:
					for _, b := range d.List {
						if vr, ok := b.Binding.(*js.Var); ok && b.Default != nil {
							x.exportVars[string(vr.Data)] = root(vr)
							if ex, ok := x.exported(b.Default); ok {
								ex.Module, ex.Name = "", string(vr.Data)
								x.exports = append(x.exports, ex)
							} else {
								x.noteBuilder(string(vr.Data), "", root(vr))
							}
						}
					}
				}
				continue
			}
			for _, al := range s.List {
				expName := string(al.Binding)
				if expName == "" {
					continue
				}
				local := expName
				if len(al.Name) > 0 {
					local = string(al.Name)
				}
				if v := topVars[local]; v != nil {
					x.exportVars[expName] = v
					if ex, ok := x.exported(v); ok {
						ex.Module, ex.Name = "", expName
						if local != expName {
							ex.Local = local
						}
						x.exports = append(x.exports, ex)
					} else {
						x.noteBuilder(expName, local, v)
					}
				}
			}
		}
	}
}

// imported reads a callee (0, H.name), H.name, H = M.i(id), or an ES module
// imported binding Z(…): the module and the name it calls.
func (x *extractor) imported(callee js.IExpr) (string, string, bool) {
	for {
		switch c := callee.(type) {
		case *js.GroupExpr:
			callee = c.X
			continue
		case *js.CommaExpr:
			if len(c.List) > 0 {
				callee = c.List[len(c.List)-1]
				continue
			}
		}
		break
	}
	if v, ok := callee.(*js.Var); ok {
		if im, ok := x.esImports[root(v)]; ok {
			return im[0], im[1], true
		}
		return "", "", false
	}
	d, ok := callee.(*js.DotExpr)
	if !ok {
		return "", "", false
	}
	h, ok := d.X.(*js.Var)
	if !ok {
		return "", "", false
	}
	if mod, ok := x.esNSImports[root(h)]; ok {
		return mod, propName(d.Y), true
	}
	ic, ok := x.constant(h).(*js.CallExpr)
	if !ok || len(ic.Args.List) != 1 {
		return "", "", false
	}
	if id, ok := moduleID(ic.Args.List[0].Value); ok {
		if dd, ok := ic.X.(*js.DotExpr); ok && propName(dd.Y) == "i" {
			return id, propName(d.Y), true
		}
	}
	return "", "", false
}

// exportsOf reads M.s(["name", 0, fn, "other", 0, fn2…], id).
func (x *extractor) exportsOf(id string, arr *js.ArrayExpr) {
	for i := 0; i < len(arr.List); i++ {
		name, ok := literalString(arr.List[i].Value)
		if !ok {
			continue
		}
		j := i + 1
		if j < len(arr.List) {
			if l, ok := arr.List[j].Value.(*js.LiteralExpr); ok && (l.TokenType == js.DecimalToken || l.TokenType == js.IntegerToken) {
				j++
			}
		}
		if j >= len(arr.List) {
			break
		}
		if ex, ok := x.exported(arr.List[j].Value); ok {
			ex.Module, ex.Name = id, name
			x.exports = append(x.exports, ex)
		}
		i = j
	}
}

// exported reads an exported function that calls a method of an object a
// factory makes ((e,t) => l(e).verifyMfa(t)), summarizes an intra-module
// HTTP helper chain (request/makeRestApiRequest/get/post/streamRequest),
// directly calls fetch/client.<verb>, or delegates to an imported helper (Via).
func (x *extractor) exported(fn js.IExpr) (Export, bool) {
	savedDyn := x.dynBase
	defer func() { x.dynBase = savedDyn }()
	if v, ok := fn.(*js.Var); ok {
		fn = x.constant(v)
	}
	var params js.Params
	var body *js.BlockStmt
	switch f := fn.(type) {
	case *js.ArrowFunc:
		params, body = f.Params, &f.Body
	case *js.FuncDecl:
		params, body = f.Params, &f.Body
	default:
		return Export{}, false
	}
	param := paramIndex(params)
	var out Export
	found := false
	js.Walk(fetchFinder(func(c *js.CallExpr) {
		if found {
			return
		}
		d, ok := c.X.(*js.DotExpr)
		if !ok {
			return
		}
		mk, ok := d.X.(*js.CallExpr) // l(e)
		if !ok {
			return
		}
		m, ok := x.factoryMethod(mk.X, propName(d.Y))
		if !ok {
			return
		}
		out = newExport()
		out.Method, out.URL = m.method, m.url
		if f := x.factoryOf(mk.X); f != nil {
			out.Factory = f.ID
		}
		if ma := args(&c.Args); m.bodyParam >= 0 && m.bodyParam < len(ma) {
			out.BodyArg = param(ma[m.bodyParam])
		}
		if fa := args(&mk.Args); len(fa) > 0 {
			out.BaseArg = param(fa[0])
		}
		found = true
	}), body)
	if found {
		return out, true
	}
	if ex, ok := x.exportedFromSummary(params, body); ok {
		if ex.ParamURL {
			if via, hasVia := x.exportedVia(params, body); hasVia {
				ex.Via = via.Via
			}
		}
		return ex, true
	}
	js.Walk(fetchFinder(func(c *js.CallExpr) {
		if found {
			return
		}
		as := args(&c.Args)
		if len(as) == 0 {
			return
		}
		if globalName(c.X) == "fetch" {
			u := x.methodURL(as[0])
			if u == "" {
				return
			}
			hm, qArg, bArg := "GET", -1, -1
			if len(as) > 1 {
				if obj, ok := x.object(as[1]); ok {
					if m, ok := literalString(objectValue(obj, "method")); ok && m != "" {
						hm = strings.ToUpper(m)
					}
					if b := objectValue(obj, "body"); b != nil {
						bArg = paramOrSpread(param, b)
					}
				}
			}
			if qArg >= 0 || bArg >= 0 {
				out = newExport()
				out.Method, out.URL, out.QueryArg, out.BodyArg = hm, u, qArg, bArg
				found = true
			}
			return
		}
		d, isDot := c.X.(*js.DotExpr)
		if !isDot {
			return
		}
		hm, isClient := clientMethods[propName(d.Y)]
		if !isClient || storeLike(d.X, as) {
			return
		}
		u := x.methodURL(as[0])
		if u == "" {
			return
		}
		if pre := x.prefixesOf(d.X); len(pre) == 1 && pre[0] != "" && !strings.HasPrefix(pre[0], unknown) && !x.ownPrefix(pre, u) {
			u = strings.TrimRight(pre[0], "/") + u
		}
		qArg, bArg := -1, -1
		cfgIdx := 1
		if hm == "POST" || hm == "PUT" || hm == "PATCH" {
			if len(as) > 1 {
				bArg = paramOrSpread(param, as[1])
			}
			cfgIdx = 2
		}
		if len(as) > cfgIdx {
			if obj, ok := x.object(as[cfgIdx]); ok {
				for _, pk := range []string{"params", "query", "queries", "searchParams"} {
					if pe := objectValue(obj, pk); pe != nil {
						if qArg = paramOrSpread(param, pe); qArg >= 0 {
							break
						}
					}
				}
				if bArg < 0 {
					for _, bk := range []string{"data", "body", "json"} {
						if be := objectValue(obj, bk); be != nil {
							if bArg = paramOrSpread(param, be); bArg >= 0 {
								break
							}
						}
					}
				}
			}
		}
		if qArg >= 0 || bArg >= 0 {
			out = newExport()
			out.Method, out.URL, out.QueryArg, out.BodyArg = hm, u, qArg, bArg
			found = true
		}
	}), body)
	if found {
		return out, true
	}
	return x.exportedVia(params, body)
}

// exportedFromSummary derives a unified Export (fixed URL or parameterized
// wrapper) by walking an intra-module summary chain (up to depth 8) with
// parameters bound at each step and tracing leaf expressions back to outerParams.
func (x *extractor) exportedFromSummary(outerParams js.Params, body *js.BlockStmt) (Export, bool) {
	s := x.summarize(outerParams, body)
	if s == nil || s.nested {
		return Export{}, false
	}
	var undos []func()
	defer func() {
		for i := len(undos) - 1; i >= 0; i-- {
			undos[i]()
		}
	}()
	var q []string
	cur := s
	for step := 0; cur.sub != nil && step < 8; step++ {
		callArgs := args(&cur.via.Args)
		undos = append(undos, x.bindParams(cur.sub.params, callArgs, &q, step))
		cur = cur.sub
	}
	if cur.sub != nil {
		return Export{}, false
	}
	l := cur.leaf
	if l.url == nil {
		return Export{}, false
	}
	out := newExport()
	var o opts
	hasOpt := false
	if l.opts != nil {
		o, hasOpt = x.options(l.opts)
	}
	hm := l.method
	if l.methodExpr != nil {
		if m, ok := x.argString(l.methodExpr); ok && httpMethods[strings.ToUpper(m)] {
			hm = strings.ToUpper(m)
		} else if mIdx, mProp := x.paramOrigin(outerParams, l.methodExpr, 0); mIdx >= 0 {
			out.ParamMethod, out.MethodArg, out.MethodProp, hm = true, mIdx, mProp, ""
		}
	}
	if hasOpt {
		if o.method != "" {
			hm = o.method
			out.ParamMethod, out.MethodArg, out.MethodProp = false, 0, ""
		} else if hm == "" && !out.ParamMethod && o.methodExpr != nil {
			if m, ok := x.argString(o.methodExpr); ok && httpMethods[strings.ToUpper(m)] {
				hm = strings.ToUpper(m)
			} else if mIdx, mProp := x.paramOrigin(outerParams, o.methodExpr, 0); mIdx >= 0 {
				out.ParamMethod, out.MethodArg, out.MethodProp = true, mIdx, mProp
			}
		}
	}
	out.Method = hm

	optBase := l.base
	if hasOpt && o.base != nil {
		optBase = o.base
	}
	if optBase != nil {
		if bIdx, bProp := x.paramOrigin(outerParams, optBase, 0); bIdx >= 0 {
			out.BaseArg, out.BaseProp, out.HasDynBase = bIdx, bProp, true
		} else {
			pre, isClient := x.optBasePre(optBase)
			if isClient {
				if len(pre) == 1 && pre[0] != "" && !strings.Contains(pre[0], unknown) {
					out.URLPrefix = strings.TrimRight(pre[0], "/")
				} else {
					out.HasDynBase = true
				}
			}
		}
	}
	if len(l.client) == 1 && l.client[0] != "" {
		if strings.Contains(l.client[0], unknown) {
			out.HasDynBase = true
		} else if out.URLPrefix == "" && !x.ownPrefix(l.client, "/x") {
			out.URLPrefix = strings.TrimRight(l.client[0], "/")
		}
	} else if l.isClient && out.URLPrefix == "" && len(l.client) == 0 {
		// e.g. splitBaseAndPath(`${ctx.baseUrl}${path}`) or axios instance with dynamic base
		if optBase != nil {
			out.HasDynBase = true
		}
	}

	bodyExpr := l.body
	if bodyExpr == nil && hasOpt {
		bodyExpr = o.bodyExpr
	}
	var queryExpr js.IExpr
	if hasOpt {
		queryExpr = o.queryExpr
	}
	if bodyExpr != nil {
		if bIdx, bProp := x.paramOrigin(outerParams, bodyExpr, 0); bIdx >= 0 {
			out.BodyArg, out.BodyProp = bIdx, bProp
		}
	}
	if queryExpr != nil {
		if qIdx, qProp := x.paramOrigin(outerParams, queryExpr, 0); qIdx >= 0 {
			out.QueryArg, out.QueryProp = qIdx, qProp
		}
	}
	if (out.Method == "GET" || out.Method == "HEAD") && out.BodyArg >= 0 && out.QueryArg < 0 {
		out.QueryArg, out.QueryProp = out.BodyArg, out.BodyProp
		out.BodyArg, out.BodyProp = -1, ""
	}
	if (out.Method == "POST" || out.Method == "PUT" || out.Method == "PATCH") && out.BodyArg >= 0 && out.BodyArg == out.QueryArg && out.BodyProp == out.QueryProp {
		out.QueryArg, out.QueryProp = -1, ""
	}
	if hasOpt && len(o.headers) > 0 {
		out.HeaderNames = strings.Join(uniq(o.headers), ",")
	}

	if !hasLiteral(l.url) {
		if uIdx, uProp := x.paramOrigin(outerParams, l.url, 0); uIdx >= 0 {
			out.ParamURL, out.URLArg, out.URLProp = true, uIdx, uProp
			return out, true
		}
		directParam := func(e js.IExpr) int {
			idx, prop := x.paramOrigin(outerParams, e, 0)
			if prop == "" {
				return idx
			}
			return -1
		}
		if uIdx := paramIn(l.url, directParam); uIdx >= 0 {
			out.ParamURL, out.URLArg = true, uIdx
			if pre := x.builderPath(l.url, &q, 0); len(pre) == 1 && strings.HasPrefix(pre[0], unknown+"/") {
				out.HasDynBase = true
				out.URLPrefix = strings.TrimRight(strings.TrimPrefix(pre[0], unknown), "/")
			}
			return out, true
		}
	}

	u := x.methodURL(l.url)
	if u == "" {
		return Export{}, false
	}
	if out.URLPrefix != "" && !strings.HasPrefix(u, out.URLPrefix+"/") {
		u = out.URLPrefix + u
		out.URLPrefix = ""
	}
	out.URL = u
	if out.QueryArg >= 0 || out.BodyArg >= 0 || out.BaseArg >= 0 {
		return out, true
	}
	return Export{}, false
}

// exportedVia records an Export.Via link when an exported function delegates
// to an imported helper in another module (File A -> File B -> File C).
func (x *extractor) exportedVia(params js.Params, body *js.BlockStmt) (Export, bool) {
	if len(params.List) == 0 {
		return Export{}, false
	}
	var out Export
	found := false
	nf := &nestFinder{}
	nf.f = func(c *js.CallExpr) {
		if found || nf.depth > 0 {
			return
		}
		mod, name, ok := x.imported(c.X)
		if !ok || jsxNames[name] {
			return
		}
		as := args(&c.Args)
		if len(as) == 0 {
			return
		}
		via := &ExportVia{Module: mod, Name: name, Args: make([]ViaArg, 0, len(as))}
		forwardsParam := false
		prefixWrapper := false
		for _, a := range as {
			va, fw, pw := x.buildViaArg(params, a)
			if fw {
				forwardsParam = true
			}
			if pw {
				prefixWrapper = true
			}
			via.Args = append(via.Args, va)
		}
		if !forwardsParam {
			return
		}
		if prefixWrapper || (viaHasMethodLiteral(via) && !viaHasConcretePath(via)) {
			x.viaCalls[c] = true
		}
		out = newExport()
		out.Via = via
		found = true
	}
	js.Walk(nf, body)
	return out, found
}

func viaHasMethodLiteral(via *ExportVia) bool {
	if via == nil {
		return false
	}
	var check func(va ViaArg) bool
	check = func(va ViaArg) bool {
		for _, v := range va.Values {
			if httpMethods[strings.ToUpper(v)] {
				return true
			}
		}
		for _, sub := range va.ObjProps {
			if check(sub) {
				return true
			}
		}
		return false
	}
	for _, a := range via.Args {
		if check(a) {
			return true
		}
	}
	return false
}

func viaHasConcretePath(via *ExportVia) bool {
	if via == nil {
		return false
	}
	var check func(va ViaArg) bool
	check = func(va ViaArg) bool {
		for _, v := range va.Values {
			if !httpMethods[strings.ToUpper(v)] && (strings.HasPrefix(v, "/") && len(v) > 1 || schemeRe.MatchString(v)) {
				return true
			}
		}
		if va.Prefix != "" && strings.HasSuffix(va.Prefix, "/") && len(va.Prefix) > 1 {
			return true
		}
		for _, sub := range va.ObjProps {
			if check(sub) {
				return true
			}
		}
		return false
	}
	for _, a := range via.Args {
		if check(a) {
			return true
		}
	}
	return false
}

func (x *extractor) buildViaArg(params js.Params, a js.IExpr) (va ViaArg, forwardsParam, prefixWrapper bool) {
	va.Param = -1
	if idx, prop := x.paramOrigin(params, a, 0); idx >= 0 {
		va.Param, va.Prop = idx, prop
		return va, true, false
	}
	if pfx, idx, sfx, ok := x.affixParam(params, a); ok {
		va.Param, va.Prefix, va.Suffix = idx, pfx, sfx
		isPrefixWrap := sfx == "" && pfx != "" && !strings.HasSuffix(pfx, "/")
		return va, true, isPrefixWrap
	}
	if obj, isObj := x.object(a); isObj && len(obj.List) <= 16 {
		for _, p := range obj.List {
			k := propKey(&p)
			if k == "" || p.Value == nil {
				continue
			}
			sub, fw, pw := x.buildViaArg(params, p.Value)
			if fw || len(sub.Values) > 0 || len(sub.Keys) > 0 || sub.BaseKey != "" {
				if va.ObjProps == nil {
					va.ObjProps = map[string]ViaArg{}
				}
				va.ObjProps[k] = sub
				forwardsParam = forwardsParam || fw
				prefixWrapper = prefixWrapper || pw
			}
		}
		if len(va.ObjProps) > 0 {
			return va, forwardsParam, prefixWrapper
		}
	}
	if bks := x.baseKeysOf(a, true, 0); len(bks) > 0 {
		va.BaseKey = bks[0]
	}
	if s, ok := x.argString(a); ok && s != "" {
		va.Values = []string{cleanURL(s)}
		return va, false, false
	}
	var q []string
	var vals []string
	for _, v := range x.eval(a, &q, 0) {
		cu := cleanURL(v)
		if httpMethods[strings.ToUpper(v)] || (cu != "" && cu != unknown && (schemeRe.MatchString(cu) || looksLikePath(cu, call))) {
			vals = addAlt(vals, cu)
		}
	}
	if len(vals) > 0 {
		va.Values = uniq(vals)
	} else if ks := uniq(x.keys(a, "", 0)); len(ks) > 0 {
		va.Keys = ks
	}
	return va, false, false
}

// affixParam decomposes `"/v1" + path` or `` `/v1/${id}/items` `` when a single
// parameter of `params` is embedded between literal prefix/suffix text.
func (x *extractor) affixParam(params js.Params, e js.IExpr) (prefix string, paramIdx int, suffix string, ok bool) {
	e = unwrapEnumGroup(e)
	switch n := e.(type) {
	case *js.BinaryExpr:
		if n.Op == js.AddToken {
			if pfx, isLit := literalString(n.X); isLit {
				if idx, prop := x.paramOrigin(params, n.Y, 0); idx >= 0 && prop == "" {
					return pfx, idx, "", true
				}
			}
		}
	case *js.TemplateExpr:
		if n.Tag == nil && len(n.List) == 1 {
			if idx, prop := x.paramOrigin(params, n.List[0].Expr, 0); idx >= 0 && prop == "" {
				pfx := templateText(n.List[0].Value, true, false)
				sfx := templateText(n.Tail, false, true)
				if pfx != "" || sfx != "" {
					return pfx, idx, sfx, true
				}
			}
		}
	}
	return "", -1, "", false
}

// paramOrSpread returns the function parameter index passed directly as e,
// via JSON.stringify(e), or spread inside an object literal ({...e}).
func paramOrSpread(param func(js.IExpr) int, e js.IExpr) int {
	for {
		if g, ok := e.(*js.GroupExpr); ok {
			e = g.X
			continue
		}
		break
	}
	if i := param(e); i >= 0 {
		return i
	}
	if ce, ok := e.(*js.CallExpr); ok && len(ce.Args.List) == 1 {
		if i := param(ce.Args.List[0].Value); i >= 0 {
			return i
		}
	}
	if obj, ok := e.(*js.ObjectExpr); ok {
		for _, p := range obj.List {
			if p.Spread && p.Value != nil {
				if i := param(p.Value); i >= 0 {
					return i
				}
			}
		}
	}
	return -1
}

type method struct {
	method, url string
	bodyParam   int
}

// factoryMethod is the request a method of the object a factory returns
// makes: its HTTP method, its URL (a literal), and which of its
// parameters is the body.
func (x *extractor) factoryMethod(factory js.IExpr, name string) (method, bool) {
	_, _, body, ok := x.fnOf(factory)
	if !ok {
		return method{}, false
	}
	for _, r := range returnsOf(body) {
		obj, ok := r.(*js.ObjectExpr)
		if !ok {
			continue
		}
		for _, p := range obj.List {
			if propKey(&p) != name {
				continue
			}
			var mp js.Params
			var mb *js.BlockStmt
			switch f := p.Value.(type) {
			case *js.FuncDecl:
				mp, mb = f.Params, &f.Body
			case *js.ArrowFunc:
				mp, mb = f.Params, &f.Body
			case *js.MethodDecl:
				mp, mb = f.Params, &f.Body
			default:
				continue
			}
			param := paramIndex(mp)
			var out method
			ok := false
			js.Walk(fetchFinder(func(c *js.CallExpr) {
				if ok {
					return
				}
				d, isDot := c.X.(*js.DotExpr)
				if !isDot {
					return
				}
				hm, isClient := clientMethods[propName(d.Y)]
				as := args(&c.Args)
				if !isClient || len(as) == 0 {
					return
				}
				u := x.methodURL(as[0])
				if u == "" {
					return
				}
				out = method{method: hm, url: u, bodyParam: -1}
				if (hm == "POST" || hm == "PUT" || hm == "PATCH") && len(as) > 1 {
					out.bodyParam = param(as[1])
				}
				ok = true
			}), mb)
			return out, ok
		}
	}
	return method{}, false
}

// methodURL is the path a client's method is called with: a literal, or a
// template of its parameters (`/v1/auth/social/${e}/start`,
// `/v1/auth/sessions/refresh${r}`, r a query string).
func (x *extractor) methodURL(e js.IExpr) string {
	if u, ok := literalString(e); ok {
		if strings.HasPrefix(u, "/") {
			return strings.SplitN(u, "?", 2)[0]
		}
		return ""
	}
	var q []string
	for _, v := range x.eval(e, &q, 0) {
		u, _, _ := strings.Cut(cleanURL(v), "?")
		if strings.HasPrefix(u, "/") && len(u) > 1 && strings.Trim(u, "/{}") != "" {
			return u
		}
	}
	return ""
}

// factoryOf is the client factory a callee is: a function of the app's
// returning an object whose methods make requests of a client.
func (x *extractor) factoryOf(callee js.IExpr) *Factory {
	v, _, body, ok := x.fnOf(callee)
	if !ok {
		return nil
	}
	if f, ok := x.factories[v]; ok {
		return f
	}
	x.factories[v] = nil // a factory's methods may call it again
	var eps []string
	for _, r := range returnsOf(body) {
		obj, ok := r.(*js.ObjectExpr)
		if !ok {
			continue
		}
		for _, p := range obj.List {
			if propKey(&p) == "" {
				continue
			}
			if m, ok := x.factoryMethod(callee, propKey(&p)); ok {
				if ep := m.method + " " + m.url; !slices.Contains(eps, ep) {
					eps = append(eps, ep)
				}
			}
		}
	}
	if len(eps) == 0 {
		return nil
	}
	f := &Factory{ID: "f" + strconv.Itoa(len(x.factoryList)+1), Endpoints: eps}
	x.factories[v] = f
	x.factoryList = append(x.factoryList, f)
	return f
}

// --- intra-bundle Webpack / Rspack / CJS module exports ---

type wpFactoryEntry struct {
	modID                  string
	modVar, expVar, reqVar *js.Var
	body                   *js.BlockStmt
}

func wpFactoryParts(e js.IExpr) (modVar, expVar, reqVar *js.Var, body *js.BlockStmt, ok bool) {
	e = ungroup(e)
	var params js.Params
	switch fn := e.(type) {
	case *js.ArrowFunc:
		params, body = fn.Params, &fn.Body
	case *js.FuncDecl:
		params, body = fn.Params, &fn.Body
	case *js.MethodDecl:
		if fn.Get || fn.Set || fn.Static {
			return nil, nil, nil, nil, false
		}
		params, body = fn.Params, &fn.Body
	default:
		return nil, nil, nil, nil, false
	}
	if body == nil || params.Rest != nil || len(params.List) == 0 || len(params.List) > 3 {
		return nil, nil, nil, nil, false
	}
	paramAt := func(idx int) *js.Var {
		if idx >= len(params.List) {
			return nil
		}
		if v, isVar := params.List[idx].Binding.(*js.Var); isVar {
			return root(v)
		}
		return nil
	}
	modVar, expVar, reqVar = paramAt(0), paramAt(1), paramAt(2)
	if modVar == nil && expVar == nil && reqVar == nil {
		return nil, nil, nil, nil, false
	}
	return modVar, expVar, reqVar, body, true
}

func isRootVar(e js.IExpr, target *js.Var) bool {
	if target == nil || e == nil {
		return false
	}
	v, ok := ungroup(e).(*js.Var)
	return ok && root(v) == target
}

func wpGetterExpr(e js.IExpr) js.IExpr {
	if e == nil {
		return nil
	}
	if ret := singleReturnExpr(e); ret != nil {
		return ret
	}
	if m, ok := e.(*js.MethodDecl); ok && m.Get && len(m.Params.List) == 0 {
		if rets := returnsOf(&m.Body); len(rets) == 1 {
			return unwrapEnumGroup(rets[0])
		}
	}
	switch ungroup(e).(type) {
	case *js.ArrowFunc, *js.FuncDecl, *js.MethodDecl:
		return nil
	}
	return unwrapEnumGroup(e)
}

type wpBodyVisitor struct {
	fn func(js.INode)
}

func (w wpBodyVisitor) Enter(n js.INode) js.IVisitor {
	switch n.(type) {
	case *js.FuncDecl, *js.ArrowFunc, *js.MethodDecl, *js.ClassDecl:
		return nil
	}
	w.fn(n)
	return w
}

func (wpBodyVisitor) Exit(js.INode) {}

func hasWPFactoryMarker(modVar, expVar, reqVar *js.Var, body *js.BlockStmt) bool {
	found := false
	js.Walk(wpBodyVisitor{fn: func(n js.INode) {
		if found {
			return
		}
		switch s := n.(type) {
		case *js.CallExpr:
			d, isDot := s.X.(*js.DotExpr)
			if !isDot {
				return
			}
			as := args(&s.Args)
			switch propName(d.Y) {
			case "d":
				if reqVar != nil && expVar != nil && isRootVar(d.X, reqVar) && len(as) >= 2 && isRootVar(as[0], expVar) {
					found = true
				}
			case "r":
				if reqVar != nil && expVar != nil && isRootVar(d.X, reqVar) && len(as) == 1 && isRootVar(as[0], expVar) {
					found = true
				}
			case "defineProperty":
				if expVar != nil && isGlobal(d.X, "Object") && len(as) >= 2 && isRootVar(as[0], expVar) {
					if k, ok := literalString(as[1]); ok && k == "__esModule" {
						found = true
					}
				}
			}
		case *js.BinaryExpr:
			if s.Op != js.EqToken {
				return
			}
			if d, isDot := ungroup(s.X).(*js.DotExpr); isDot {
				if modVar != nil && isRootVar(d.X, modVar) && propName(d.Y) == "exports" {
					found = true
					return
				}
				if dd, isDD := d.X.(*js.DotExpr); isDD && modVar != nil && isRootVar(dd.X, modVar) && propName(dd.Y) == "exports" {
					found = true
					return
				}
			}
		}
	}}, body)
	return found
}

func (x *extractor) setWPExport(modID, expName string, val js.IExpr) {
	if modID == "" || expName == "" || val == nil {
		return
	}
	m := x.wpModExports[modID]
	if m == nil {
		m = map[string]js.IExpr{}
		x.wpModExports[modID] = m
	}
	m[expName] = val
}

func (x *extractor) scanWPFactory(e wpFactoryEntry) {
	if e.reqVar != nil {
		x.wpReqVars[e.reqVar] = true
	}
	js.Walk(wpBodyVisitor{fn: func(n js.INode) {
		switch s := n.(type) {
		case *js.CallExpr:
			d, isDot := s.X.(*js.DotExpr)
			if !isDot {
				return
			}
			as := args(&s.Args)
			switch propName(d.Y) {
			case "d":
				if e.reqVar == nil || e.expVar == nil || !isRootVar(d.X, e.reqVar) || len(as) < 2 || !isRootVar(as[0], e.expVar) {
					return
				}
				if len(as) == 2 {
					if obj, ok := ungroup(as[1]).(*js.ObjectExpr); ok {
						for i := range obj.List {
							p := &obj.List[i]
							if p.Spread || p.Name == nil {
								continue
							}
							if k := propKey(p); k != "" {
								x.setWPExport(e.modID, k, wpGetterExpr(p.Value))
							}
						}
					}
				} else if len(as) >= 3 {
					if k, ok := literalString(as[1]); ok && k != "" {
						x.setWPExport(e.modID, k, wpGetterExpr(as[2]))
					}
				}
			case "defineProperty":
				if e.expVar == nil || !isGlobal(d.X, "Object") || len(as) < 3 || !isRootVar(as[0], e.expVar) {
					return
				}
				k, ok := literalString(as[1])
				if !ok || k == "" || k == "__esModule" {
					return
				}
				if desc, ok := ungroup(as[2]).(*js.ObjectExpr); ok {
					if g := objectValue(desc, "get"); g != nil {
						x.setWPExport(e.modID, k, wpGetterExpr(g))
					} else if val := objectValue(desc, "value"); val != nil {
						x.setWPExport(e.modID, k, unwrapEnumGroup(val))
					}
				}
			}
		case *js.BinaryExpr:
			if s.Op != js.EqToken {
				return
			}
			switch lhs := ungroup(s.X).(type) {
			case *js.DotExpr:
				pname := propName(lhs.Y)
				if pname == "" {
					return
				}
				if e.modVar != nil && isRootVar(lhs.X, e.modVar) && pname == "exports" {
					rhs := unwrapEnumGroup(s.Y)
					x.wpModDefault[e.modID] = rhs
					if obj, ok := rhs.(*js.ObjectExpr); ok {
						for i := range obj.List {
							p := &obj.List[i]
							if !p.Spread && p.Name != nil {
								if k := propKey(p); k != "" {
									x.setWPExport(e.modID, k, p.Value)
								}
							}
						}
					}
					return
				}
				if dd, isDD := lhs.X.(*js.DotExpr); isDD && e.modVar != nil && isRootVar(dd.X, e.modVar) && propName(dd.Y) == "exports" {
					x.setWPExport(e.modID, pname, unwrapEnumGroup(s.Y))
					return
				}
				if e.expVar != nil && isRootVar(lhs.X, e.expVar) && pname != "__esModule" {
					x.setWPExport(e.modID, pname, unwrapEnumGroup(s.Y))
				}
			case *js.IndexExpr:
				if e.expVar != nil && isRootVar(lhs.X, e.expVar) {
					if k, ok := literalString(lhs.Y); ok && k != "" && k != "__esModule" {
						x.setWPExport(e.modID, k, unwrapEnumGroup(s.Y))
					}
				}
			}
		}
	}}, e.body)
}

func (x *extractor) indexWebpackModuleObject(obj *js.ObjectExpr) {
	if obj == nil || len(obj.List) == 0 {
		return
	}
	var entries []wpFactoryEntry
	confirmed := false
	for i := range obj.List {
		p := &obj.List[i]
		if p.Spread || p.Name == nil || p.Value == nil {
			continue
		}
		modID := propKey(p)
		if modID == "" {
			continue
		}
		modVar, expVar, reqVar, body, ok := wpFactoryParts(p.Value)
		if !ok {
			continue
		}
		entries = append(entries, wpFactoryEntry{modID: modID, modVar: modVar, expVar: expVar, reqVar: reqVar, body: body})
		if !confirmed && hasWPFactoryMarker(modVar, expVar, reqVar, body) {
			confirmed = true
		}
	}
	if !confirmed {
		return
	}
	for _, e := range entries {
		x.scanWPFactory(e)
	}
}

func (x *extractor) indexWebpackModuleArray(arr *js.ArrayExpr) {
	if arr == nil || len(arr.List) == 0 {
		return
	}
	var entries []wpFactoryEntry
	confirmed := false
	for idx := range arr.List {
		el := &arr.List[idx]
		if el.Spread || el.Value == nil {
			continue
		}
		modVar, expVar, reqVar, body, ok := wpFactoryParts(el.Value)
		if !ok {
			continue
		}
		modID := strconv.Itoa(idx)
		entries = append(entries, wpFactoryEntry{modID: modID, modVar: modVar, expVar: expVar, reqVar: reqVar, body: body})
		if !confirmed && hasWPFactoryMarker(modVar, expVar, reqVar, body) {
			confirmed = true
		}
	}
	if !confirmed {
		return
	}
	for _, e := range entries {
		x.scanWPFactory(e)
	}
}

func wpModKey(e js.IExpr) (string, bool) {
	e = ungroup(e)
	if id, ok := moduleID(e); ok {
		return id, true
	}
	if s, ok := literalString(e); ok && s != "" && len(s) <= 128 {
		return s, true
	}
	return "", false
}

func (x *extractor) wpRequireModID(e js.IExpr, depth int) (string, bool) {
	if depth >= 8 || e == nil || len(x.wpReqVars) == 0 {
		return "", false
	}
	switch n := ungroup(e).(type) {
	case *js.CallExpr:
		as := args(&n.Args)
		if len(as) == 1 {
			if rv, ok := ungroup(n.X).(*js.Var); ok && x.wpReqVars[root(rv)] {
				return wpModKey(as[0])
			}
			if d, ok := ungroup(n.X).(*js.DotExpr); ok && propName(d.Y) == "n" {
				if rv, ok := ungroup(d.X).(*js.Var); ok && x.wpReqVars[root(rv)] {
					return x.wpRequireModID(as[0], depth+1)
				}
			}
		} else if len(as) == 0 {
			if cv, ok := ungroup(n.X).(*js.Var); ok {
				return x.wpRequireModID(cv, depth+1)
			}
		}
	case *js.Var:
		if c := x.constant(n); c != nil {
			return x.wpRequireModID(c, depth+1)
		}
		if cs := x.chains[root(n)]; len(cs) == 1 && len(cs[0]) == 1 && cs[0][0].op == 's' && cs[0][0].expr != nil {
			return x.wpRequireModID(cs[0][0].expr, depth+1)
		}
	}
	return "", false
}

func (x *extractor) wpMember(d *js.DotExpr, depth int) (js.IExpr, bool) {
	if d == nil || depth >= 16 || len(x.wpReqVars) == 0 {
		return nil, false
	}
	modID, ok := x.wpRequireModID(d.X, 0)
	if !ok {
		return nil, false
	}
	prop := propName(d.Y)
	if prop == "" {
		return nil, false
	}
	if exp := x.wpModExports[modID][prop]; exp != nil {
		return exp, true
	}
	if def := x.wpModDefault[modID]; def != nil {
		if obj, isObj := x.objectN(def, depth+1); isObj {
			if v := x.objectValueSpread(obj, prop, depth+1); v != nil {
				return v, true
			}
			if prop == "a" || prop == "default" {
				return def, true
			}
		} else if prop == "a" || prop == "default" {
			return def, true
		}
	}
	return nil, false
}

func (x *extractor) wpDefaultObject(e js.IExpr, depth int) (*js.ObjectExpr, bool) {
	if depth >= 16 || len(x.wpReqVars) == 0 {
		return nil, false
	}
	modID, ok := x.wpRequireModID(e, 0)
	if !ok {
		return nil, false
	}
	if def := x.wpModDefault[modID]; def != nil {
		return x.objectN(def, depth+1)
	}
	return nil, false
}
