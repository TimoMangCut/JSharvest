package jsapi

// This file: definitions: the visitor that records what names hold, assignment chains, the bases properties hold.

import (
	"regexp"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

// propDef is obj.name = value.
type propDef struct {
	obj   js.IExpr
	name  string
	value js.IExpr
}

// step is one assignment of a variable's chain.
type step struct {
	expr js.IExpr       // nil: something no URL (i++)
	node *js.BinaryExpr // assignment expression that added this step
	op   byte           // 's' starts the chain, '+' appends (+=), '=' builds on the variable's value
	// keep: the step is made under a condition the declaration is not,
	// so the value before it stays possible.
	keep   bool
	uncond bool // assigned unconditionally at the same function scope as declaration
	// forks are the branches (of an if, a ?:, a switch) the step is in:
	// a step in another branch of one the step before it is in builds on
	// what that one built on, not on it.
	forks []fork
}

type fork struct {
	node   js.INode
	branch int
}

// sibling reports whether b is in another branch of a fork a is in, the
// same forks around both.
func sibling(a, b step) bool {
	for i := 0; i < len(a.forks) && i < len(b.forks); i++ {
		if a.forks[i].node != b.forks[i].node {
			return false
		}
		if a.forks[i].branch != b.forks[i].branch {
			return true
		}
	}
	return false
}

type chain []step

// --- pass 1: what variables hold ---

type assignScope struct {
	vr      *js.Var
	fnDepth int
}

type defsVisitor struct {
	x       *extractor
	cond    int           // the conditions (if, ?:, &&, loops) around the node
	forks   []fork        // the forks around it, and the branch it is in
	fnDepth int           // nested function depth
	assigns []assignScope // active LHS variables being assigned in enclosing expressions
}

func (v *defsVisitor) inAssign(vr *js.Var) bool {
	for i := len(v.assigns) - 1; i >= 0; i-- {
		if v.assigns[i].fnDepth != v.fnDepth {
			break
		}
		if v.assigns[i].vr == vr {
			return true
		}
	}
	return false
}

func forking(n js.INode) bool {
	switch n.(type) {
	case *js.IfStmt, *js.CondExpr, *js.SwitchStmt:
		return true
	}
	return false
}

// branchOf is which branch of a fork a child of it is: 0 for its
// condition.
func branchOf(f js.INode, child js.INode) int {
	switch f := f.(type) {
	case *js.IfStmt:
		if child == js.INode(f.Body) {
			return 1
		}
		if f.Else != nil && child == js.INode(f.Else) {
			return 2
		}
	case *js.CondExpr:
		if child == js.INode(f.X) {
			return 1
		}
		if child == js.INode(f.Y) {
			return 2
		}
	case *js.SwitchStmt:
		for i := range f.List {
			if child == js.INode(&f.List[i]) {
				return i + 1
			}
		}
	}
	return 0
}

// here is a step's forks: those it is in a branch of.
func (v *defsVisitor) here() []fork {
	var out []fork
	for _, f := range v.forks {
		if f.branch > 0 {
			out = append(out, f)
		}
	}
	return out
}

func conditional(n js.INode) bool {
	switch n := n.(type) {
	case *js.IfStmt, *js.CondExpr, *js.ForStmt, *js.ForInStmt, *js.ForOfStmt, *js.WhileStmt, *js.DoWhileStmt, *js.SwitchStmt:
		return true
	case *js.BinaryExpr:
		return n.Op == js.AndToken || n.Op == js.OrToken || n.Op == js.NullishToken
	}
	return false
}

func (v *defsVisitor) Enter(n js.INode) js.IVisitor {
	if k := len(v.forks); k > 0 {
		if b := branchOf(v.forks[k-1].node, n); b > 0 {
			v.forks[k-1].branch = b
		}
	}
	if forking(n) {
		v.forks = append(v.forks, fork{node: n})
	}
	if conditional(n) {
		v.cond++
	}
	switch n.(type) {
	case *js.FuncDecl, *js.ArrowFunc, *js.MethodDecl:
		v.fnDepth++
	}
	x := v.x
	switch n := n.(type) {
	case *js.VarDecl:
		for _, b := range n.List {
			if bo, ok := b.Binding.(*js.BindingObject); ok {
				for _, it := range bo.List {
					if vr, ok := it.Value.Binding.(*js.Var); ok && it.Key != nil {
						x.propOf[root(vr)] = propName(it.Key)
						if b.Default != nil {
							x.destructFrom[root(vr)] = b.Default
						}
					}
				}
			}
			if vr, ok := b.Binding.(*js.Var); ok {
				r := root(vr)
				x.defs[r] = append(x.defs[r], b.Default)
				x.declDepth[r] = v.cond
				x.declFnDepth[r] = v.fnDepth
				if b.Default != nil {
					x.chains[r] = append(x.chains[r], chain{{expr: b.Default, op: 's', uncond: true}})
					if ce, ok := unwrapEnumGroup(b.Default).(*js.CallExpr); ok {
						x.registerEnumIIFE(ce, r)
					}
				}
			}
		}
	case *js.UnaryExpr:
		// i++ in for (let i = 0; …; i++): a loop's counter is no constant.
		switch n.Op {
		case js.PreIncrToken, js.PreDecrToken, js.PostIncrToken, js.PostDecrToken:
			if vr, ok := n.X.(*js.Var); ok {
				vr = root(vr)
				x.defs[vr] = append(x.defs[vr], nil)
				x.chains[vr] = append(x.chains[vr], chain{{op: 's'}})
			}
		case js.AwaitToken:
			inner := n.X
			for {
				if g, ok := inner.(*js.GroupExpr); ok {
					inner = g.X
					continue
				}
				break
			}
			if ce, ok := inner.(*js.CallExpr); ok {
				x.awaited[ce] = true
			}
		}
	case *js.FuncDecl:
		if n.Name != nil {
			vr := root(n.Name)
			x.defs[vr] = append(x.defs[vr], n)
		}
		if x.hasVueRenderHint {
			fnName := ""
			if n.Name != nil {
				fnName = string(n.Name.Data)
			}
			x.indexVueRenderFn(n.Params, &n.Body, fnName)
		}
	case *js.ArrowFunc:
		if x.hasVueRenderHint {
			x.indexVueRenderFn(n.Params, &n.Body, "")
		}
	case *js.MethodDecl:
		if x.hasVueRenderHint && !n.Get && !n.Set {
			x.indexVueRenderFn(n.Params, &n.Body, propName(&n.Name.PropertyName))
		}
	case *js.CallExpr:
		x.registerEnumIIFE(n, nil)
		if d, ok := n.X.(*js.DotExpr); ok {
			switch propName(d.Y) {
			case "then", "catch", "finally":
				if ce, ok := d.X.(*js.CallExpr); ok {
					x.awaited[ce] = true
				}
			}
		}
		// p.set("search", …), p.append("tag", …): a URLSearchParams' keys.
		if d, ok := n.X.(*js.DotExpr); ok && (propName(d.Y) == "set" || propName(d.Y) == "append") && len(n.Args.List) > 0 {
			if pv, ok := d.X.(*js.Var); ok {
				if k, ok := literalString(n.Args.List[0].Value); ok && k != "" && len(k) < 64 {
					x.qset[root(pv)] = append(x.qset[root(pv)], k)
					// headers.set("X-CSRF-Token", token): a client's header.
					if headerNameRe.MatchString(k) && len(n.Args.List) > 1 && headerValue(n.Args.List[1].Value) {
						x.headers = append(x.headers, propDef{name: k, value: n.Args.List[1].Value})
					}
				}
			}
		}
	case *js.TemplateExpr:
		if n.Tag == nil && len(n.List) >= 2 {
			if d0, ok0 := n.List[0].Expr.(*js.DotExpr); ok0 && isBaseRootProp(propName(d0.Y)) {
				if d1, ok1 := n.List[1].Expr.(*js.DotExpr); ok1 {
					if sep := templateText(n.List[1].Value, false, false); (sep == "" || sep == "/") && propName(d1.Y) != "" {
						x.joinedSeg[propName(d1.Y)] = true
					}
				}
			}
		}
	case *js.BinaryExpr:
		if n.Op == js.AddToken {
			if d0, ok0 := n.X.(*js.DotExpr); ok0 && isBaseRootProp(propName(d0.Y)) {
				if d1, ok1 := n.Y.(*js.DotExpr); ok1 && propName(d1.Y) != "" {
					x.joinedSeg[propName(d1.Y)] = true
				}
			}
		}
		if !isAssign(n.Op) {
			break
		}
		switch t := ungroup(n.X).(type) {
		case *js.Var:
			// A second assignment: the variable is not a constant.
			vr := root(t)
			nested := v.inAssign(vr)
			v.assigns = append(v.assigns, assignScope{vr: vr, fnDepth: v.fnDepth})
			if nested {
				break
			}
			x.defs[vr] = append(x.defs[vr], n.Y, nil)
			keep := v.cond > x.declDepth[vr]
			uncond := !keep && v.fnDepth == x.declFnDepth[vr]
			switch {
			case n.Op == js.AddEqToken:
				x.extend(vr, step{expr: n.Y, node: n, op: '+', keep: keep, forks: v.here()})
			case n.Op == js.EqToken && refers(n.Y, vr):
				x.extend(vr, step{expr: n.Y, node: n, op: '=', keep: keep, forks: v.here()})
			case n.Op == js.EqToken:
				x.chains[vr] = append(x.chains[vr], chain{{expr: n.Y, node: n, op: 's', keep: keep, uncond: uncond}})
			default:
				x.chains[vr] = append(x.chains[vr], chain{{node: n, op: 's', keep: keep}})
			}
		case *js.DotExpr:
			if n.Op != js.EqToken {
				break
			}
			if pv, ok := t.X.(*js.Var); ok {
				if target := x.enumParamTarget[root(pv)]; target != nil {
					if k := propName(t.Y); k != "" {
						x.setEnumProp(target, k, n.Y)
					}
				}
			}
			if headersObj(t.X) {
				x.headers = append(x.headers, propDef{name: propName(t.Y), value: n.Y})
			} else {
				pname := propName(t.Y)
				if rv, ok := t.X.(*js.Var); ok && (pname == "d" || pname == "r" || pname == "n") {
					switch ungroup(n.Y).(type) {
					case *js.ArrowFunc, *js.FuncDecl:
						x.wpReqVars[root(rv)] = true
					}
				}
				if keyName(pname) {
					x.keyExpr(pname, n.Y)
				}
				if pname != "" && !skipAssignBaseProp(pname) && mayEvalToBase(n.Y) {
					x.propBaseDefs = append(x.propBaseDefs, propDef{name: pname, value: n.Y})
				}
				if isBaseName(pname) {
					// this.customerProfileBaseUrl = Ys(), window.API_URL = "…"
					x.baseValue(n.Y)
				} else {
					x.props = append(x.props, propDef{obj: t.X, name: pname, value: n.Y})
				}
			}
		case *js.IndexExpr:
			if n.Op == js.EqToken {
				if pv, ok := t.X.(*js.Var); ok {
					if target := x.enumParamTarget[root(pv)]; target != nil {
						if k, ok := literalString(t.Y); ok && k != "" {
							x.setEnumProp(target, k, n.Y)
						}
					}
				}
			}
			// config.headers["X-A"] = v; h["X-CSRF-Token"] = token
			if k, ok := literalString(t.Y); ok && n.Op == js.EqToken && (headersObj(t.X) || headerNameRe.MatchString(k) && headerValue(n.Y)) {
				x.headers = append(x.headers, propDef{name: k, value: n.Y})
			}
		}
	case *js.Property:
		if n.Name == nil {
			break
		}
		switch name := propName(n.Name); {
		case isBaseName(name):
			x.baseValue(n.Value)
			x.segProps[name] = append(x.segProps[name], n.Value)
			// window.__ENV__ = {VITE_OPENAPI_BASE_URL: "https://…"} or
			// axios.create({baseURL: "/rest"}): a setting named by its property.
			if v, ok := literalString(n.Value); ok && (strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") || schemeRe.MatchString(v)) {
				x.settings[name+"\x00"+strings.TrimRight(v, "/")] = true
			}
		case headerNameRe.MatchString(name) && headerValue(n.Value):
			// {Authorization: `Bearer ${t}`, "X-CSRF-Token": e}: headers a
			// request is given; not {"X-AXIS": 48}, a chart's constant.
			x.headers = append(x.headers, propDef{name: name, value: n.Value})
		case keyName(name):
			x.keyExpr(name, n.Value)
		case name == "data":
			// A Vue component's data(): what this.<name> starts as.
			if o := returnedObject(n.Value); o != nil {
				x.dataObjs = append(x.dataObjs, o)
			}
		case name == "computed":
			// Vue component computed getters: computed: { PERMISSION() { return o.a } }.
			if co, ok := ungroup(n.Value).(*js.ObjectExpr); ok && len(co.List) <= 64 {
				for i := range co.List {
					cp := &co.List[i]
					if cp.Spread || cp.Value == nil {
						continue
					}
					cname := propKey(cp)
					if cname == "" {
						continue
					}
					val := singleReturnExpr(cp.Value)
					if val == nil {
						if goObj, isObj := ungroup(cp.Value).(*js.ObjectExpr); isObj {
							if g := objectValue(goObj, "get"); g != nil {
								val = singleReturnExpr(g)
							}
						}
					}
					if val != nil && !emptyValue(val) {
						x.thisProps[cname] = append(x.thisProps[cname], val)
					}
				}
			}
		}
	case *js.ClassDecl:
		for i := range n.List {
			el := &n.List[i]
			if el.Method == nil && el.StaticBlock == nil && el.Field.Init != nil {
				fname := strings.TrimPrefix(memberName(&el.Field.Name), "#")
				if keyName(fname) {
					x.keyExpr(fname, el.Field.Init)
				}
			}
		}
	case *js.ArrayExpr:
		x.indexWebpackModuleArray(n)
	case *js.ObjectExpr:
		x.indexWebpackModuleObject(n)
		hasReqOpt, hasRoute := false, false
		for _, p := range n.List {
			if p.Spread || p.Name == nil {
				continue
			}
			k := propName(p.Name)
			if httpOptKeys[k] && k != "baseURL" && k != "baseUrl" {
				hasReqOpt = true
			}
			if k == "component" || k == "components" || k == "children" {
				hasRoute = true
			}
		}
		for _, p := range n.List {
			if p.Spread || p.Name == nil {
				continue
			}
			k := propName(p.Name)
			if k == "" || jsonPointerProps[k] || k == "path" || k == "redirect" || k == "alias" || k == "to" {
				continue
			}
			if hasRoute && (k == "url" || k == "href") {
				continue
			}
			if hasReqOpt && (k == "url" || k == "uri" || k == "endpoint" || k == "pathname") {
				continue
			}
			if mayEvalToBase(p.Value) {
				x.propBaseDefs = append(x.propBaseDefs, propDef{name: k, value: p.Value})
			}
		}
	}
	return v
}

// baseValue takes a base URL's value: a literal now, the rest once every
// variable is known.
func (x *extractor) baseValue(e js.IExpr) {
	if s, ok := literalString(e); ok {
		if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "http") {
			x.addBase(s)
			if l, ok := e.(*js.LiteralExpr); ok {
				x.used[l] = true
			}
		}
	} else if e != nil {
		x.baseExprs = append(x.baseExprs, e)
	}
}

func (v *defsVisitor) Exit(n js.INode) {
	if be, ok := n.(*js.BinaryExpr); ok && isAssign(be.Op) {
		if _, isVar := ungroup(be.X).(*js.Var); isVar {
			v.assigns = v.assigns[:len(v.assigns)-1]
		}
	}
	switch n.(type) {
	case *js.FuncDecl, *js.ArrowFunc, *js.MethodDecl:
		v.fnDepth--
	}
	if conditional(n) {
		v.cond--
	}
	if forking(n) {
		v.forks = v.forks[:len(v.forks)-1]
	}
}

// extend adds a step that builds on a variable's value to its last chain.
func (x *extractor) extend(v *js.Var, s step) {
	cs := x.chains[v]
	if len(cs) == 0 {
		x.chains[v] = []chain{{s}}
		return
	}
	cs[len(cs)-1] = append(cs[len(cs)-1], s)
}

// refers reports whether an expression uses a variable.
func refers(e js.IExpr, v *js.Var) bool {
	found := false
	js.Walk(varFinder{v: v, found: &found}, e)
	return found
}

type varFinder struct {
	v     *js.Var
	found *bool
}

func (f varFinder) Enter(n js.INode) js.IVisitor {
	if *f.found {
		return nil
	}
	if vr, ok := n.(*js.Var); ok && root(vr) == f.v {
		*f.found = true
		return nil
	}
	return f
}

func (varFinder) Exit(js.INode) {}

// headersObj reports whether an expression is a request's or a client's
// headers: config.headers, defaults.headers.common and the like.
func headersObj(e js.IExpr) bool {
	d, ok := e.(*js.DotExpr)
	if !ok {
		return false
	}
	switch propName(d.Y) {
	case "headers":
		return true
	case "common", "get", "post", "put", "patch", "delete":
		if dd, ok := d.X.(*js.DotExpr); ok {
			return propName(dd.Y) == "headers"
		}
	}
	return false
}

// returnedObject is the object literal a function returns: data() {
// return {…} }, data: () => ({…}), or Terser's data: (function(){ return {…} }).
func returnedObject(e js.IExpr) *js.ObjectExpr {
	e = ungroup(e)
	var body *js.BlockStmt
	switch f := e.(type) {
	case *js.FuncDecl:
		body = &f.Body
	case *js.ArrowFunc:
		body = &f.Body
	case *js.MethodDecl:
		body = &f.Body
	default:
		return nil
	}
	for _, s := range body.List {
		if r, ok := s.(*js.ReturnStmt); ok && r.Value != nil {
			v := r.Value
			for {
				g, ok := v.(*js.GroupExpr)
				if !ok {
					break
				}
				v = g.X
			}
			o, _ := v.(*js.ObjectExpr)
			return o
		}
	}
	return nil
}

func isPrototypeExpr(e js.IExpr) bool {
	d, ok := ungroup(e).(*js.DotExpr)
	return ok && propName(d.Y) == "prototype"
}

// settle reads, once every variable's assignments are known, what pass 1
// put aside: the values of this.<name> (including X.prototype.<name>), and
// the baseURLs that are no literal.
func (x *extractor) settle() {
	for _, p := range x.props {
		if p.name != "" && (x.isThis(p.obj) || isPrototypeExpr(p.obj)) && !emptyValue(p.value) {
			x.thisProps[p.name] = append(x.thisProps[p.name], p.value)
		}
	}
	for _, o := range x.dataObjs {
		for _, p := range o.List {
			if p.Name != nil && !p.Spread && !emptyValue(p.Value) {
				name := propName(p.Name)
				x.thisProps[name] = append(x.thisProps[name], p.Value)
			}
		}
	}
	for _, e := range x.baseExprs {
		var q []string
		ok := false
		for _, s := range x.eval(e, &q, 0) {
			if s = cleanURL(s); !strings.HasPrefix(s, unknown) && (strings.HasPrefix(s, "/") || schemeRe.MatchString(s)) {
				x.addBase(s)
				ok = true
			}
		}
		if !ok {
			x.dynBase = true
		}
	}
	for prop := range x.joinedSeg {
		for _, e := range x.segProps[prop] {
			var q []string
			for _, s := range x.eval(e, &q, 0) {
				if s = strings.Trim(cleanURL(s), "/"); apiRootSegRe.MatchString(s) {
					x.addBase("/" + s)
				}
			}
		}
	}
	x.settlePropBases()
}

var propRelBaseRe = regexp.MustCompile(`^/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){0,2}$`)

func skipAssignBaseProp(name string) bool {
	switch name {
	case "href", "src", "action", "pathname", "path", "redirect", "innerHTML", "outerHTML", "textContent", "className":
		return true
	}
	return false
}

func mayEvalToBase(e js.IExpr) bool {
	for {
		if g, ok := e.(*js.GroupExpr); ok {
			e = g.X
			continue
		}
		break
	}
	switch n := e.(type) {
	case nil, *js.ObjectExpr, *js.ArrayExpr, *js.FuncDecl, *js.ArrowFunc, *js.ClassDecl, *js.UnaryExpr:
		return false
	case *js.LiteralExpr:
		if n.TokenType != js.StringToken || len(n.Data) <= 3 {
			return false
		}
		s := unquote(n.Data)
		return strings.HasPrefix(s, "/") || schemeRe.MatchString(s)
	case *js.BinaryExpr:
		return n.Op == js.AddToken || n.Op == js.OrToken || n.Op == js.NullishToken || n.Op == js.AndToken || n.Op == js.EqToken || n.Op == js.AddEqToken
	}
	return true
}

func cleanPropBase(raw string) (string, bool) {
	s := cleanURL(raw)
	if s == "" || s == "/" || len(s) > 512 || strings.Contains(s, unknown) || strings.ContainsAny(s, " \t\r\n?#<>\"'`\\") {
		return "", false
	}
	if strings.Contains(s, "www.w3.org/") || strings.HasPrefix(s, "data:") || strings.HasPrefix(s, "blob:") {
		return "", false
	}
	if schemeRe.MatchString(s) {
		if !looksLikePath(s, weak) {
			return "", false
		}
		return strings.TrimRight(s, "/"), true
	}
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		trimmed := strings.TrimRight(s, "/")
		if trimmed == "" || assetRe.MatchString(trimmed) || toolFileRe.MatchString(trimmed) || !propRelBaseRe.MatchString(trimmed) {
			return "", false
		}
		return trimmed, true
	}
	return "", false
}

func (x *extractor) settlePropBases() {
	if len(x.propBaseDefs) == 0 {
		return
	}
	savedLits := len(x.lits)
	savedBudget := x.callBudget
	x.noMarkUsed = true
	defer func() {
		x.noMarkUsed = false
		x.lits = x.lits[:savedLits]
		x.callBudget = savedBudget
	}()
	nonMethodCalls := 0
	for _, pd := range x.propBaseDefs {
		if pd.name == "" || pd.value == nil {
			continue
		}
		if s, ok := literalString(pd.value); ok {
			if b, ok := cleanPropBase(s); ok {
				x.propBases[pd.name+"\x00"+b] = true
				if isBaseName(pd.name) {
					x.settings[pd.name+"\x00"+b] = true
				}
			}
			continue
		}
		target := pd.value
		if unwrapped := x.unwrapReactiveExpr(target); unwrapped != nil {
			target = unwrapped
		}
		if ce, isCall := unwrapEnumGroup(target).(*js.CallExpr); isCall {
			isStrMethod := false
			if d, ok := ce.X.(*js.DotExpr); ok {
				switch propName(d.Y) {
				case "concat", "replace", "replaceAll", "trim", "toString", "valueOf":
					isStrMethod = true
				}
			}
			if !isStrMethod {
				if nonMethodCalls >= 64 {
					continue
				}
				nonMethodCalls++
			}
		}
		var q []string
		for _, v := range x.eval(target, &q, 0) {
			if b, ok := cleanPropBase(v); ok {
				x.propBases[pd.name+"\x00"+b] = true
				if isBaseName(pd.name) {
					x.settings[pd.name+"\x00"+b] = true
				}
			}
		}
	}
}

var apiRootSegRe = regexp.MustCompile(`^(?i)(?:rest|api|apis|graphql|gql|v\d+(?:\.\d+)*)$`)

func isBaseRootProp(name string) bool {
	switch name {
	case "baseUrl", "baseURL", "basePath", "BASE_PATH":
		return true
	}
	return false
}

// emptyValue is a value that is no URL nor fields: "", null, a number, a
// function.
func emptyValue(e js.IExpr) bool {
	switch n := e.(type) {
	case nil:
		return true
	case *js.LiteralExpr:
		return n.TokenType != js.StringToken || len(n.Data) <= 2
	case *js.ArrayExpr, *js.FuncDecl, *js.ArrowFunc, *js.UnaryExpr:
		return true
	}
	return false
}

// isThis reports whether an expression is this, a variable set to it
// (var e = this), or a compiled Vue 2/3 render-context parameter (_ctx, _vm).
func (x *extractor) isThis(e js.IExpr) bool {
	switch n := ungroup(e).(type) {
	case *js.LiteralExpr:
		return n.TokenType == js.ThisToken
	case *js.Var:
		rv := root(n)
		if x.renderCtxVars[rv] {
			return true
		}
		if l, ok := ungroup(x.constOrSingleExpr(rv)).(*js.LiteralExpr); ok && l.TokenType == js.ThisToken {
			return true
		}
		return loweredThis(n)
	}
	return false
}

func (x *extractor) indexVueRenderFn(params js.Params, body *js.BlockStmt, fnName string) {
	if body == nil || len(params.List) == 0 || len(params.List) > 6 {
		return
	}
	p0, ok := params.List[0].Binding.(*js.Var)
	if !ok || p0 == nil {
		return
	}
	r0 := root(p0)
	if fnName == "_sfc_render" || string(p0.Data) == "_ctx" {
		x.renderCtxVars[r0] = true
		if len(params.List) >= 4 {
			if p3, ok3 := params.List[3].Binding.(*js.Var); ok3 && p3 != nil {
				x.renderCtxVars[root(p3)] = true
			}
		}
		return
	}
	hasCreate, hasC, hasHelper := false, false, false
	js.Walk(wpBodyVisitor{fn: func(n js.INode) {
		if hasCreate || (hasC && hasHelper) {
			return
		}
		d, isDot := n.(*js.DotExpr)
		if !isDot || !isRootVar(d.X, r0) {
			return
		}
		switch propName(d.Y) {
		case "$createElement", "_self":
			hasCreate = true
		case "_c":
			hasC = true
		case "_v", "_s", "_e", "_l", "$can", "$cannot":
			hasHelper = true
		}
	}}, body)
	if hasCreate || (hasC && hasHelper) {
		x.renderCtxVars[r0] = true
	}
}

// loweredThisRe is the name esbuild gives the this an arrow function it
// lowers captures (_this, _this2).
var loweredThisRe = regexp.MustCompile(`^_this[0-9]*$`)

// loweredThis reports whether a variable is the this of a class field's
// arrow function the arrow lowering (transformJSLower) turned into a
// function: esbuild refers to _this there, and declares it nowhere (a
// field initialiser has no function to declare it in). Undeclared, the
// name is nothing else.
func loweredThis(v *js.Var) bool {
	v = root(v)
	return v.Decl == js.NoDecl && loweredThisRe.Match(v.Data)
}

func isAssign(op js.TokenType) bool {
	switch op {
	case js.EqToken, js.AddEqToken, js.SubEqToken, js.MulEqToken, js.ExpEqToken, js.DivEqToken, js.ModEqToken,
		js.LtLtEqToken, js.GtGtEqToken, js.GtGtGtEqToken, js.BitAndEqToken, js.BitOrEqToken, js.BitXorEqToken,
		js.AndEqToken, js.OrEqToken, js.NullishEqToken:
		return true
	}
	return false
}

// root is the variable a use refers to: a use in a nested scope is its own
// Var, linked to the declared one.
func root(v *js.Var) *js.Var {
	for i := 0; v.Link != nil && i < 64; i++ {
		v = v.Link
	}
	return v
}

// constant returns what a variable is set to when it is set exactly once.
func (x *extractor) constant(v *js.Var) js.IExpr {
	d := x.defs[root(v)]
	if len(d) != 1 || d[0] == nil {
		return nil
	}
	return d[0]
}

// constOrSingleExpr returns constant(v) or the single unconditional top-scope
// initializer of a hoisted variable (`var r; r = {...}`).
func (x *extractor) constOrSingleExpr(v *js.Var) js.IExpr {
	if v == nil {
		return nil
	}
	rv := root(v)
	if c := x.constant(rv); c != nil {
		return c
	}
	if cs := x.chains[rv]; len(cs) == 1 && len(cs[0]) == 1 && cs[0][0].op == 's' && cs[0][0].uncond && cs[0][0].expr != nil {
		return cs[0][0].expr
	}
	return nil
}

// --- evaluating URL expressions ---
