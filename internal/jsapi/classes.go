package jsapi

// This file: classes: requests made through class instances (round 26A):
// the members a class has and inherits (methods, function fields, #private
// ones), what its fields hold (field initialisers, this.x = … in its
// constructor), the instance a call is read in (its constructor's and each
// super(…)'s parameters bound), and a URL object whose pathname is set.

import (
	"slices"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

// classInfo is what a class declares.
type classInfo struct {
	decl *js.ClassDecl
	ctor *js.MethodDecl
	// superArgs are the arguments its constructor gives super(…);
	// hasSuper whether it calls it.
	superArgs []js.IExpr
	hasSuper  bool
	// members are the functions it has by name (#private ones with their
	// #): methods, and fields set to a function.
	members map[string][]js.IExpr
	// fields are the values it gives a name: a field's initialiser, an
	// assignment this.x = … in its constructor.
	fields map[string][]js.IExpr
	// later are the values its other methods give a field.
	later map[string][]js.IExpr
	// staticFields and staticMembers hold ES2022 static fields/getters/methods
	// and post-declaration ClassName.PROP = … assignments; facFn holds ɵfac.
	staticFields  map[string]js.IExpr
	staticMembers map[string][]js.IExpr
	facFn         js.IExpr
}

func normClassMetaName(name string) string {
	if strings.Contains(name, `\u0275`) || strings.Contains(name, `\U0275`) {
		name = strings.ReplaceAll(strings.ReplaceAll(name, `\u0275`, "ɵ"), `\U0275`, "ɵ")
	}
	return name
}

func isIvyFacName(name string) bool {
	return normClassMetaName(name) == "ɵfac"
}

func isFrameworkClassMeta(name string) bool {
	nm := normClassMetaName(name)
	if strings.HasPrefix(nm, "ɵ") {
		return true
	}
	switch nm {
	case "ctorParameters", "propDecorators", "decorators", "contextType", "propTypes", "defaultProps", "displayName":
		return true
	}
	return false
}

// memberName is a class element's name, a #private one with its #.
func memberName(n *js.ClassElementName) string {
	if n.Private != nil {
		return string(n.Private.Data)
	}
	return propName(&n.PropertyName)
}

// classVisitor indexes the script's classes, the instances it makes of
// them, and the URL objects whose parts it sets (u.pathname = …).
type classVisitor struct {
	x             *extractor
	news          *[]*js.NewExpr
	staticAssigns *[]propDef
}

func (v classVisitor) Enter(n js.INode) js.IVisitor {
	x := v.x
	switch n := n.(type) {
	case *js.ClassDecl:
		x.indexClass(n)
		if n.Name != nil {
			x.classByVar[root(n.Name)] = n
		}
	case *js.VarDecl:
		for _, b := range n.List {
			if bv, ok := b.Binding.(*js.Var); ok {
				if c, ok := ungroup(b.Default).(*js.ClassDecl); ok {
					x.classByVar[root(bv)] = c // const X = (class Y {…})
				}
			}
		}
	case *js.NewExpr:
		*v.news = append(*v.news, n)
	case *js.BinaryExpr:
		if n.Op != js.EqToken {
			break
		}
		if v, ok := n.X.(*js.Var); ok {
			if c, ok := ungroup(n.Y).(*js.ClassDecl); ok {
				x.classByVar[root(v)] = c // X = class {…}
			}
		}
		if d, ok := ungroup(n.X).(*js.DotExpr); ok {
			if u, ok := ungroup(d.X).(*js.Var); ok {
				p := propName(d.Y)
				switch p {
				case "pathname", "search", "hash":
					x.urlSets[root(u)] = append(x.urlSets[root(u)], urlSet{p, n.Y})
				}
				if p != "" && v.staticAssigns != nil {
					*v.staticAssigns = append(*v.staticAssigns, propDef{obj: u, name: p, value: n.Y})
				}
			}
		}
	}
	return v
}

func (classVisitor) Exit(js.INode) {}

// urlSet is an assignment to a part of a URL object.
type urlSet struct {
	prop string
	val  js.IExpr
}

func (x *extractor) indexClasses(ast js.INode) {
	var news []*js.NewExpr
	var staticAssigns []propDef
	js.Walk(classVisitor{x, &news, &staticAssigns}, ast)
	// In the order the script declares its classes, never a map's: which
	// instances a call is read in (instanceSites, at most eight) must not
	// change from run to run.
	for _, c := range x.classOrder {
		if v := x.classOf[c]; v != nil {
			if _, ok := x.classByVar[v]; !ok {
				x.classByVar[v] = c
			}
		}
	}
	for _, sa := range staticAssigns {
		cls := x.classOfExpr(sa.obj)
		if cls == nil {
			continue
		}
		info := x.classes[cls]
		if info == nil {
			continue
		}
		if isIvyFacName(sa.name) {
			if info.facFn == nil {
				info.facFn = ungroup(sa.value)
			}
			continue
		}
		if strings.HasPrefix(sa.name, "#") || isFrameworkClassMeta(sa.name) {
			continue
		}
		switch fn := ungroup(sa.value).(type) {
		case *js.ArrowFunc, *js.FuncDecl:
			info.staticMembers[sa.name] = append(info.staticMembers[sa.name], fn)
			x.ownerOf[fn] = cls
		default:
			if _, exists := info.staticFields[sa.name]; !exists {
				info.staticFields[sa.name] = unwrapEnumGroup(sa.value)
			}
		}
	}
	for _, c := range x.classOrder {
		if p := x.parentOf(c); p != nil {
			x.subclasses[p] = append(x.subclasses[p], c)
		}
	}
	for _, ne := range news {
		if c := x.classOfExpr(ne.X); c != nil {
			x.newSites[c] = append(x.newSites[c], ne)
		}
	}
}

func (x *extractor) indexClass(c *js.ClassDecl) {
	info := &classInfo{
		decl:          c,
		members:       map[string][]js.IExpr{},
		fields:        map[string][]js.IExpr{},
		later:         map[string][]js.IExpr{},
		staticFields:  map[string]js.IExpr{},
		staticMembers: map[string][]js.IExpr{},
	}
	x.classes[c] = info
	x.classOrder = append(x.classOrder, c)
	for i := range c.List {
		el := &c.List[i]
		switch {
		case el.Method != nil:
			if pv := el.Method.Name.Private; pv != nil {
				x.privOwner[root(pv)] = c
			}
			name := memberName(&el.Method.Name)
			if name == "constructor" && !el.Method.Static {
				info.ctor = el.Method
				continue
			}
			if el.Method.Static {
				if isIvyFacName(name) {
					info.facFn = el.Method
					continue
				}
				if el.Method.Get && len(el.Method.Params.List) == 0 && name != "" && !strings.HasPrefix(name, "#") && !isFrameworkClassMeta(name) {
					if rets := returnsOf(&el.Method.Body); len(rets) == 1 {
						info.staticFields[name] = unwrapEnumGroup(rets[0])
					}
				} else if !el.Method.Get && !el.Method.Set && name != "" && !strings.HasPrefix(name, "#") && !isFrameworkClassMeta(name) {
					info.staticMembers[name] = append(info.staticMembers[name], el.Method)
					x.ownerOf[el.Method] = c
				}
				continue
			}
			if el.Method.Get || el.Method.Set {
				continue
			}
			info.members[name] = append(info.members[name], el.Method)
			x.ownerOf[el.Method] = c
		case el.StaticBlock != nil:
			walkThisScope(el.StaticBlock, func(n js.INode) {
				b, ok := n.(*js.BinaryExpr)
				if !ok || b.Op != js.EqToken {
					return
				}
				d, ok := ungroup(b.X).(*js.DotExpr)
				if !ok {
					return
				}
				if !isThisLit(ungroup(d.X)) {
					if cv, isVar := ungroup(d.X).(*js.Var); !isVar || c.Name == nil || root(cv) != root(c.Name) {
						return
					}
				}
				pname := propName(d.Y)
				if pname == "" {
					return
				}
				if isIvyFacName(pname) {
					info.facFn = ungroup(b.Y)
					return
				}
				if strings.HasPrefix(pname, "#") || isFrameworkClassMeta(pname) {
					return
				}
				switch fn := ungroup(b.Y).(type) {
				case *js.ArrowFunc, *js.FuncDecl:
					info.staticMembers[pname] = append(info.staticMembers[pname], fn)
					x.ownerOf[fn] = c
				default:
					info.staticFields[pname] = unwrapEnumGroup(b.Y)
				}
			})
		case el.StaticBlock == nil && el.Field.Static:
			name := memberName(&el.Field.Name)
			if name == "" || el.Field.Init == nil {
				continue
			}
			if isIvyFacName(name) {
				info.facFn = ungroup(el.Field.Init)
				continue
			}
			if strings.HasPrefix(name, "#") || isFrameworkClassMeta(name) {
				continue
			}
			switch f := ungroup(el.Field.Init).(type) {
			case *js.ArrowFunc, *js.FuncDecl:
				info.staticMembers[name] = append(info.staticMembers[name], f)
				x.ownerOf[f] = c
			default:
				info.staticFields[name] = unwrapEnumGroup(el.Field.Init)
			}
		case el.StaticBlock == nil && !el.Field.Static:
			if pv := el.Field.Name.Private; pv != nil {
				x.privOwner[root(pv)] = c
			}
			name := memberName(&el.Field.Name)
			if name == "" || el.Field.Init == nil {
				continue
			}
			switch f := el.Field.Init.(type) {
			case *js.ArrowFunc, *js.FuncDecl:
				info.members[name] = append(info.members[name], f)
				x.ownerOf[f] = c
				if el.Field.Name.Private == nil {
					x.methodDefs[name] = append(x.methodDefs[name], methodDef{f, c})
				}
			default:
				info.fields[name] = append(info.fields[name], f)
			}
		}
	}
	// What other methods set (init(cfg) { this.baseUrl = … }): values a
	// field takes after the constructor's, in the order of the source.
	for i := range c.List {
		el := &c.List[i]
		var m js.IExpr
		var name string
		switch {
		case el.Method != nil && el.Method != info.ctor && !el.Method.Static:
			m, name = el.Method, memberName(&el.Method.Name)
		case el.Method == nil && el.StaticBlock == nil && !el.Field.Static && el.Field.Init != nil:
			switch f := el.Field.Init.(type) {
			case *js.ArrowFunc, *js.FuncDecl:
				m, name = f, memberName(&el.Field.Name)
			}
		}
		if m == nil {
			continue
		}
		{
			_, body, _ := fnParts(m)
			if body == nil {
				continue
			}
			walkThisScope(body, func(n js.INode) {
				if b, ok := n.(*js.BinaryExpr); ok && b.Op == js.EqToken {
					if d, ok := b.X.(*js.DotExpr); ok && isThisLit(d.X) {
						if f := propName(d.Y); f != "" && f != name {
							info.later[f] = append(info.later[f], b.Y)
						}
					}
				}
			})
		}
	}
	if info.ctor == nil {
		return
	}
	walkThisScope(&info.ctor.Body, func(n js.INode) {
		switch n := n.(type) {
		case *js.CallExpr:
			if l, ok := n.X.(*js.LiteralExpr); ok && l.TokenType == js.SuperToken && !info.hasSuper {
				info.hasSuper, info.superArgs = true, args(&n.Args)
			}
		case *js.BinaryExpr:
			if n.Op != js.EqToken {
				return
			}
			if d, ok := n.X.(*js.DotExpr); ok && isThisLit(d.X) {
				if name := propName(d.Y); name != "" {
					info.fields[name] = append(info.fields[name], n.Y)
				}
			}
		}
	})
}

// walkThisScope visits the nodes of a body whose this is the body's own:
// arrow functions in it share it; other functions and classes do not.
func walkThisScope(body js.INode, f func(js.INode)) {
	js.Walk(&thisScopeWalker{f: f}, body)
}

type thisScopeWalker struct {
	f     func(js.INode)
	inner int
}

func (w *thisScopeWalker) Enter(n js.INode) js.IVisitor {
	switch n.(type) {
	case *js.FuncDecl, *js.MethodDecl, *js.ClassDecl:
		w.inner++
	}
	if w.inner == 0 {
		w.f(n)
	}
	return w
}

func (w *thisScopeWalker) Exit(n js.INode) {
	switch n.(type) {
	case *js.FuncDecl, *js.MethodDecl, *js.ClassDecl:
		w.inner--
	}
}

func isThisLit(e js.IExpr) bool {
	l, ok := e.(*js.LiteralExpr)
	return ok && l.TokenType == js.ThisToken
}

// classOfExpr is the class an expression names: a class expression, a
// variable holding one, or a bundler class IIFE ((() => { class C {} return C; })()).
func (x *extractor) classOfExpr(e js.IExpr) *js.ClassDecl {
	return x.classOfExprAt(e, 0)
}

func (x *extractor) classOfExprAt(e js.IExpr, depth int) *js.ClassDecl {
	if depth > 4 || e == nil {
		return nil
	}
	for {
		g, ok := e.(*js.GroupExpr)
		if !ok {
			break
		}
		e = g.X
	}
	switch n := e.(type) {
	case *js.ClassDecl:
		return n
	case *js.Var:
		if c := x.classByVar[root(n)]; c != nil {
			return c
		}
		if k := x.constOrSingleExpr(n); k != nil && k != e {
			return x.classOfExprAt(k, depth+1)
		}
	case *js.CallExpr:
		if len(n.Args.List) == 0 {
			if _, body, ok := fnParts(n.X); ok && body != nil {
				if rets := returnsOf(body); len(rets) == 1 {
					return x.classOfExprAt(rets[0], depth+1)
				}
			}
		}
	}
	return nil
}

func (x *extractor) classStaticField(c *js.ClassDecl, name string) (js.IExpr, bool) {
	if name == "" {
		return nil, false
	}
	for i := 0; c != nil && i < maxClassChain; i++ {
		if info := x.classes[c]; info != nil {
			if v, ok := info.staticFields[name]; ok && v != nil {
				return v, true
			}
		}
		c = x.parentOf(c)
	}
	return nil, false
}

// maxClassChain is how many classes up an extends chain is read.
const maxClassChain = 8

// parentOf is the class a class extends, when the script has it.
func (x *extractor) parentOf(c *js.ClassDecl) *js.ClassDecl {
	if c.Extends == nil {
		return nil
	}
	return x.classOfExpr(c.Extends)
}

// lookupClass is the class whose members a property of this is looked up
// in: for a #private name, the class that declares it, whatever class
// the instance is (za's this.#e is za's own, though a subclass declares
// an #e of its own); the instance's class otherwise.
func (x *extractor) lookupClass(c *js.ClassDecl, y js.IExpr) *js.ClassDecl {
	if v, ok := y.(*js.Var); ok {
		if o := x.privOwner[root(v)]; o != nil {
			return o
		}
	}
	return c
}

// classMember is the function a class has, or inherits, under a name: the
// one its nearest class declares, when that one declares only one.
func (x *extractor) classMember(c *js.ClassDecl, name string) js.IExpr {
	for i := 0; c != nil && i < maxClassChain; i++ {
		if info := x.classes[c]; info != nil {
			if ms := info.members[name]; len(ms) > 0 {
				if len(ms) == 1 {
					return ms[0]
				}
				return nil
			}
		}
		c = x.parentOf(c)
	}
	return nil
}

// classField is what a class gives a field, or what a class it extends
// does: the nearest class's values; with what its methods set it to later
// (an init(cfg) after the constructor), the constructor's placeholders
// ("", null, void 0, false, 0) left out.
func (x *extractor) classField(c *js.ClassDecl, name string) []js.IExpr {
	for i := 0; c != nil && i < maxClassChain; i++ {
		if info := x.classes[c]; info != nil {
			fs, later := info.fields[name], info.later[name]
			if len(fs)+len(later) > 0 {
				if len(later) == 0 {
					return fs
				}
				var out []js.IExpr
				for _, f := range fs {
					if !placeholder(f) {
						out = append(out, f)
					}
				}
				for _, f := range later {
					if !placeholder(f) {
						out = append(out, f)
					}
				}
				if len(out) == 0 {
					return fs
				}
				return out
			}
		}
		c = x.parentOf(c)
	}
	return nil
}

// placeholder reports whether a value is one a field is given until it is
// set for real: "", null, undefined (void 0), false (!1), 0.
func placeholder(e js.IExpr) bool {
	switch n := e.(type) {
	case *js.LiteralExpr:
		switch n.TokenType {
		case js.NullToken, js.FalseToken:
			return true
		case js.StringToken:
			return len(n.Data) <= 2
		case js.IntegerToken, js.DecimalToken:
			return string(n.Data) == "0"
		}
	case *js.Var:
		return string(n.Data) == "undefined" && root(n).Decl == js.NoDecl
	case *js.UnaryExpr:
		if l, ok := n.X.(*js.LiteralExpr); ok {
			return n.Op == js.VoidToken || n.Op == js.NotToken && l.TokenType == js.IntegerToken && string(l.Data) == "1"
		}
	}
	return false
}

// selfClass is the class this is an instance of where the function being
// read is (a method or a field's function of a class); the instance being
// read, when one is (x.self).
func (x *extractor) selfClass() *js.ClassDecl {
	if n := len(x.self); n > 0 {
		return x.self[n-1]
	}
	return x.ownerClass()
}

// ownerClass is the class whose instance this is in the code being read:
// that of the innermost function summarized (a method, a function field;
// a plain function has a this of its own), or, at a call the call pass
// reads, the one it worked out from the classes and functions around it
// (x.entryClass: a field initialiser's, a method's). Arrow functions share
// the this around them.
func (x *extractor) ownerClass() *js.ClassDecl {
	for i := len(x.fnStack) - 1; i >= x.fnBase && i >= 0; i-- {
		switch o := x.ownerOf[x.fnStack[i]].(type) {
		case *js.ClassDecl:
			return o
		case nil:
			if _, arrow := x.fnStack[i].(*js.ArrowFunc); arrow {
				continue
			}
			return nil
		default:
			return nil
		}
	}
	return x.entryClass
}

// instanceOf is the class, and the constructor's arguments, of the value
// an expression is: new C(…), through constants and the fields of this.
// read: while a call is read, through the parameters bound to what it was
// given too, and this being the instance read (x.self); otherwise what the
// code says itself, the same at every call (what a summary may keep).
func (x *extractor) instanceOf(e js.IExpr, read bool, depth int) (*js.ClassDecl, []js.IExpr) {
	if depth > 8 || e == nil {
		return nil, nil
	}
	switch n := e.(type) {
	case *js.GroupExpr:
		return x.instanceOf(n.X, read, depth+1)
	case *js.NewExpr:
		if c := x.classOfExpr(n.X); c != nil {
			var as []js.IExpr
			if n.Args != nil {
				as = args(n.Args)
			}
			return c, as
		}
	case *js.Var:
		if a, ok := x.args[root(n)]; ok && read {
			if a == js.IExpr(n) {
				return nil, nil
			}
			return x.instanceOf(a, read, depth+1)
		}
		if c := x.constant(n); c != nil {
			return x.instanceOf(c, read, depth+1)
		}
	case *js.DotExpr:
		var c *js.ClassDecl
		if x.isThis(n.X) {
			c = x.ownerClass()
			if read {
				c = x.selfClass()
			}
		} else {
			// sdk.raw: an object's property; api.users: a field of an
			// instance.
			if m, ok := x.member(n); ok {
				return x.instanceOf(m, read, depth+1)
			}
			c, _ = x.instanceOf(n.X, read, depth+1)
		}
		if c != nil {
			if fs := x.classField(x.lookupClass(c, n.Y), propName(n.Y)); len(fs) == 1 {
				return x.instanceOf(fs[0], read, depth+1)
			}
		}
	}
	return nil, nil
}

// classCallee is the function a call on this or on a field of this calls,
// in a class: this.makeRequest(…), a method or function field the class
// has or inherits; this.#transport.request(…), a method of the class the
// field is an instance of (new Transport(…) in the class, or one it
// extends). What the code says itself (a summary keeps it): a field set
// to what the constructor is given is read at the call (lazyCallee).
func (x *extractor) classCallee(d *js.DotExpr, n int) js.IExpr {
	var c *js.ClassDecl
	switch {
	case x.isThis(d.X):
		c = x.ownerClass()
	default:
		// this.#transport.request(…), sdk.raw.send(…): the class of the
		// instance the receiver is, as the code says it.
		c, _ = x.instanceOf(d.X, false, 0)
	}
	if c == nil {
		return nil
	}
	fn := x.classMember(x.lookupClass(c, d.Y), propName(d.Y))
	if fn == nil || !x.takesFn(fn, n) {
		return nil
	}
	return fn
}

// thisFieldCall reports whether a call is on a field of this
// (this.http.send(…)): one to read at the call when the field's class is
// only known then.
func (x *extractor) thisFieldCall(c *js.CallExpr) bool {
	d, ok := c.X.(*js.DotExpr)
	if !ok {
		return false
	}
	r, ok := d.X.(*js.DotExpr)
	return ok && x.isThis(r.X) && x.ownerClass() != nil
}

// readCallee is, while a call is read, the function a call on a field of
// this calls, and the instance it is called on: the field's value with the
// parameters bound (this.http, the constructor given new ApiClient(…)).
func (x *extractor) readCallee(d *js.DotExpr, n int) (js.IExpr, *js.ClassDecl, []js.IExpr) {
	r, ok := d.X.(*js.DotExpr)
	if !ok || !x.isThis(r.X) {
		return nil, nil, nil
	}
	c, as := x.instanceOf(r, true, 0)
	if c == nil {
		return nil, nil, nil
	}
	fn := x.classMember(x.lookupClass(c, d.Y), propName(d.Y))
	if fn == nil || !x.takesFn(fn, n) {
		return nil, nil, nil
	}
	return fn, c, as
}

// bindInstance binds the parameters of a class's constructor to the
// arguments an instance is made with, and those of each class it extends
// to what super(…) gives them (a class without a constructor hands its
// arguments on): what the instance's fields are set from. The instance is
// the one this is, until undone.
func (x *extractor) bindInstance(c *js.ClassDecl, as []js.IExpr, q *[]string, depth int) func() {
	var undos []func()
	cur, cas := c, as
	for i := 0; cur != nil && i < maxClassChain; i++ {
		info := x.classes[cur]
		if info == nil {
			break
		}
		next := x.parentOf(cur)
		if info.ctor == nil {
			cur = next
			continue
		}
		undos = append(undos, x.bindParams(info.ctor.Params, cas, q, depth))
		if !info.hasSuper {
			break
		}
		cur, cas = next, info.superArgs
	}
	x.self = append(x.self, c)
	return func() {
		x.self = x.self[:len(x.self)-1]
		for i := len(undos) - 1; i >= 0; i-- {
			undos[i]()
		}
	}
}

// maxInstanceSites is how many of the instances the script makes of a
// class a call in it is read in.
const maxInstanceSites = 8

// instanceSite is a class an instance is made of, and its arguments.
type instanceSite struct {
	cls  *js.ClassDecl
	args []js.IExpr
}

// instanceSites are the instances the script makes of a class or of the
// classes extending it (a base class may be made only through those,
// each with its own super(…)): at most maxInstanceSites; one with no
// arguments (unknown) when the script makes none (a class whose new C(…)
// is in another chunk).
func (x *extractor) instanceSites(c *js.ClassDecl) []instanceSite {
	var out []instanceSite
	seen := map[*js.ClassDecl]bool{}
	var walk func(k *js.ClassDecl, depth int)
	walk = func(k *js.ClassDecl, depth int) {
		if seen[k] || depth > maxClassChain {
			return
		}
		seen[k] = true
		for _, ne := range x.newSites[k] {
			if len(out) >= maxInstanceSites {
				return
			}
			var as []js.IExpr
			if ne.Args != nil {
				as = args(ne.Args)
			}
			out = append(out, instanceSite{k, as})
		}
		for _, sub := range x.subclasses[k] {
			walk(sub, depth+1)
		}
	}
	walk(c, 0)
	if len(out) == 0 {
		out = append(out, instanceSite{c, nil})
	}
	return out
}

// callInInstances reads a call the call pass meets: in a class (a method,
// a field's initialiser or function) a call that reads this is read in
// each instance the script makes of the class (instanceSites); any other,
// once.
func (x *extractor) callInInstances(c *js.CallExpr) {
	cls := x.entryClass
	if cls == nil || len(x.self) > 0 || !x.readsThis(c) || x.forwardsPath(c) {
		x.call(c)
		return
	}
	for _, site := range x.instanceSites(cls) {
		var q []string
		// A read that finds nothing uses no literal: what it evaluated on
		// the way (a config object's collector URL) stays the strings
		// pass's.
		var log []*js.LiteralExpr
		saved, before := x.usedLog, len(x.eps)
		x.usedLog = &log
		undo := x.bindInstance(site.cls, site.args, &q, 0)
		x.call(c)
		undo()
		x.usedLog = saved
		if len(x.eps) == before {
			for _, l := range log {
				delete(x.used, l)
			}
		} else if saved != nil {
			*saved = append(*saved, log...)
		}
	}
}

// readsThis reports whether a call reads this (or the lowering's _this),
// in its callee or its arguments, outside functions of their own; or
// through the local constants it uses (const url = new URL(this.base))
// and the parts set on them (url.pathname = …).
func (x *extractor) readsThis(c *js.CallExpr) bool {
	seen := map[*js.Var]bool{}
	var reads func(n js.INode, depth int) bool
	reads = func(n js.INode, depth int) bool {
		found := false
		walkThisScope(n, func(m js.INode) {
			if found {
				return
			}
			switch m := m.(type) {
			case *js.LiteralExpr:
				found = m.TokenType == js.ThisToken
			case *js.Var:
				r := root(m)
				if loweredThis(m) {
					found = true
					return
				}
				if depth >= 3 || seen[r] || r.Decl == js.ArgumentDecl {
					return
				}
				seen[r] = true
				if k := x.constant(r); k != nil && reads(k, depth+1) {
					found = true
					return
				}
				for _, set := range x.urlSets[r] {
					if reads(set.val, depth+1) {
						found = true
						return
					}
				}
			}
		})
		return found
	}
	return reads(c, 0)
}

// thisFieldValues is what this.<name> holds in the instance being read
// (the class's own field, or one it inherits), evaluated with its
// constructor's parameters bound; ok false outside an instance, or for a
// name the class does not set.
func (x *extractor) thisFieldValues(y js.IExpr, q *[]string, depth int) ([]string, bool) {
	if len(x.self) == 0 {
		return nil, false
	}
	name := propName(y)
	fs := x.classField(x.lookupClass(x.self[len(x.self)-1], y), name)
	if len(fs) == 0 || len(fs) > maxAlts {
		return nil, false
	}
	key := "self." + name
	if x.busy[key] {
		return unk, true
	}
	x.busy[key] = true
	defer delete(x.busy, key)
	var out []string
	for _, f := range fs {
		out = union(out, x.eval(f, q, depth+1))
	}
	return out, true
}

// thisFieldExpr is the one value this.<name> is given in the instance
// being read, for reading the object it is.
func (x *extractor) thisFieldExpr(y js.IExpr) js.IExpr {
	if len(x.self) == 0 {
		return nil
	}
	if fs := x.classField(x.lookupClass(x.self[len(x.self)-1], y), propName(y)); len(fs) == 1 {
		return fs[0]
	}
	return nil
}

// evalURLObject is what a URL object a function makes is once its parts
// are set (const u = new URL(base); u.pathname = join(u.pathname, p)):
// the base's origin, and the path it is given, reading u.pathname as the
// base's path. ok false for a variable that is no such object.
func (x *extractor) evalURLObject(v *js.Var, q *[]string, depth int) ([]string, bool) {
	sets := x.urlSets[v]
	if len(sets) == 0 {
		return nil, false
	}
	ne, ok := x.constant(v).(*js.NewExpr)
	if !ok || globalName(ne.X) != "URL" || x.busy[v] {
		return nil, false
	}
	x.busy[v] = true
	defer delete(x.busy, v)
	var path js.IExpr
	var search []js.IExpr
	for _, s := range sets {
		switch s.prop {
		case "pathname":
			if path != nil {
				return nil, false // set twice: which one a request sees depends on the flow
			}
			path = s.val
		case "search":
			search = append(search, s.val)
		}
	}
	bases := x.eval(ne, q, depth+1)
	var out []string
	for _, b := range bases {
		org, p := splitOrigin(b)
		vals := []string{b}
		if path != nil {
			x.urlPath[v] = []string{p}
			vals = cat([]string{org}, x.eval(path, q, depth+1))
			delete(x.urlPath, v)
		}
		for _, s := range search {
			x.eval(s, q, depth+1) // its keys: URLSearchParams(…).toString()
		}
		for _, s := range vals {
			out = addAlt(out, s)
		}
	}
	return out, true
}

// splitOrigin splits a URL into its origin and its path: unknown when the
// URL is ({}), "" when it has no path.
func splitOrigin(u string) (string, string) {
	if u == unknown || strings.HasPrefix(u, unknown) {
		return unknown, strings.TrimPrefix(u, unknown)
	}
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return u[:i+3+j], rest[j:]
		}
		return u, ""
	}
	if strings.HasPrefix(u, "{origin}") {
		return "{origin}", strings.TrimPrefix(u, "{origin}")
	}
	return "", u
}

// objectValueSpread is an object's value for a key, through the objects
// it spreads ({client, ...settings}): the last one written wins.
func (x *extractor) objectValueSpread(obj *js.ObjectExpr, key string, depth int) js.IExpr {
	if key == "" {
		return nil
	}
	for i := len(obj.List) - 1; i >= 0; i-- {
		p := obj.List[i]
		if p.Spread {
			if depth >= 16 {
				continue
			}
			if o, ok := x.objectN(p.Value, depth+1); ok && o != obj {
				if v := x.objectValueSpread(o, key, depth+1); v != nil {
					return v
				}
			}
			continue
		}
		if p.Name != nil && propName(p.Name) == key {
			return p.Value
		}
	}
	return nil
}

// templateArg is the template a call parses: the string argument of the
// call a receiver is (parseTemplate(t)), or of the one a constant holds.
func (x *extractor) templateArg(e js.IExpr) js.IExpr {
	for i := 0; i < 4; i++ {
		switch n := e.(type) {
		case *js.GroupExpr:
			e = n.X
			continue
		case *js.Var:
			c := x.constant(n)
			if c == nil {
				return nil
			}
			e = c
			continue
		case *js.CallExpr:
			if as := args(&n.Args); len(as) >= 1 {
				return as[0]
			}
		}
		return nil
	}
	return nil
}

// condTruth tells which side of a ?: a known string takes: s.endsWith("/"),
// s.startsWith("/"), s.includes("?"), the string's one value known.
func (x *extractor) condTruth(cond js.IExpr, q *[]string, depth int) (bool, bool) {
	for {
		g, ok := cond.(*js.GroupExpr)
		if !ok {
			break
		}
		cond = g.X
	}
	if u, ok := cond.(*js.UnaryExpr); ok && u.Op == js.NotToken {
		t, ok := x.condTruth(u.X, q, depth)
		return !t, ok
	}
	switch n := cond.(type) {
	case *js.LiteralExpr:
		// !1, !0, true, null: the code's own constants.
		switch n.TokenType {
		case js.TrueToken:
			return true, true
		case js.FalseToken, js.NullToken:
			return false, true
		case js.IntegerToken, js.DecimalToken:
			return strings.Trim(string(n.Data), "0.") != "", true
		}
		return false, false
	case *js.CondExpr:
		// a ? b : c, a decided: the side it takes.
		if depth < 8 {
			if t, ok := x.condTruth(n.Cond, q, depth+1); ok {
				if t {
					return x.condTruth(n.X, q, depth+1)
				}
				return x.condTruth(n.Y, q, depth+1)
			}
		}
		return false, false
	}
	if c, ok := cond.(*js.CallExpr); ok {
		// list.includes(e), list the code's own strings (MC =
		// jC.data.map(e => e.collection)).
		if d, ok := c.X.(*js.DotExpr); ok && propName(d.Y) == "includes" && len(c.Args.List) == 1 {
			if list, ok := x.stringList(d.X, 0); ok {
				if v, ok := x.knownString(c.Args.List[0].Value, q, depth+1); ok {
					return slices.Contains(list, v), true
				}
				return false, false
			}
		}
	}
	if v, ok := cond.(*js.Var); ok {
		// const e = "https://…".trim(); e ? e.replace(…) : "": a constant
		// made of literals alone is "" or it is not. (A query string built
		// at run time reads as "" here, its keys aside: not decided.)
		if c := x.constant(v); c != nil && literalOnly(c) {
			if s, ok := x.knownString(c, q, depth); ok {
				return s != "", true
			}
		}
		return false, false
	}
	if b, ok := cond.(*js.BinaryExpr); ok && (b.Op == js.OrToken || b.Op == js.AndToken) && depth < 8 {
		// a || b, a && b: as JavaScript reads them, the right side only
		// when the left one does not decide.
		l, lok := x.condTruth(b.X, q, depth+1)
		if !lok {
			return false, false // the left side undecided: the whole is
		}
		if l == (b.Op == js.OrToken) {
			return l, true
		}
		return x.condTruth(b.Y, q, depth+1)
	}
	if b, ok := cond.(*js.BinaryExpr); ok && b.Op == js.InToken {
		// e in table: a known key, an object literal the code writes in
		// full (no spread).
		k, kok := x.knownString(b.X, q, depth)
		obj, ook := x.object(b.Y)
		if !kok || !ook {
			return false, false
		}
		for _, p := range obj.List {
			if p.Spread {
				return false, false
			}
		}
		return objectValue(obj, k) != nil, true
	}
	if c, ok := cond.(*js.CallExpr); ok && depth < 8 {
		// NC(e), NC = e => e.startsWith("directus_"): the test the
		// function makes of what it is given.
		if _, params, body, isFn := x.fnOf(c.X); isFn && body != nil && params.Rest == nil {
			if rets := returnsOf(body); len(rets) == 1 && len(params.List) == len(c.Args.List) {
				var restore []func()
				known := true
				for i, b := range params.List {
					p, isVar := b.Binding.(*js.Var)
					if c.Args.List[i].Rest {
						known = false // f(...xs): which value goes where is unknown
						break
					}
					s, sok := x.knownString(c.Args.List[i].Value, q, depth+1)
					if !isVar || !sok {
						known = false
						break
					}
					p = root(p)
					old, had := x.bind[p]
					x.bind[p] = []string{s}
					restore = append(restore, func() {
						if had {
							x.bind[p] = old
						} else {
							delete(x.bind, p)
						}
					})
				}
				var t, ok bool
				if known {
					t, ok = x.condTruth(rets[0], q, depth+1)
				}
				for i := len(restore) - 1; i >= 0; i-- {
					restore[i]()
				}
				if ok {
					return t, true
				}
			}
		}
	}
	if b, ok := cond.(*js.BinaryExpr); ok {
		// api.charAt(api.length - 1) === "/": both sides known.
		var eq bool
		switch b.Op {
		case js.EqEqEqToken, js.EqEqToken:
			eq = true
		case js.NotEqEqToken, js.NotEqToken:
		default:
			return false, false
		}
		l, lok := x.knownString(b.X, q, depth)
		r, rok := x.knownString(b.Y, q, depth)
		if !lok || !rok {
			return false, false
		}
		return (l == r) == eq, true
	}
	c, ok := cond.(*js.CallExpr)
	if !ok {
		return false, false
	}
	d, ok := c.X.(*js.DotExpr)
	if !ok {
		return false, false
	}
	as := args(&c.Args)
	if len(as) != 1 {
		return false, false
	}
	arg, ok := literalString(as[0])
	if !ok {
		return false, false
	}
	var test func(string, string) bool
	switch propName(d.Y) {
	case "endsWith":
		test = strings.HasSuffix
	case "startsWith":
		test = strings.HasPrefix
	case "includes":
		test = strings.Contains
	default:
		return false, false
	}
	if !x.stableExpr(d.X, 0) {
		return false, false
	}
	saved := x.noMarkUsed
	x.noMarkUsed = true // a test reads the string, it does not use it
	vals := x.eval(d.X, q, depth+1)
	x.noMarkUsed = saved
	if len(vals) != 1 || strings.Contains(vals[0], unknown) || strings.Contains(vals[0], "{origin}") {
		return false, false
	}
	return test(vals[0], arg), true
}

// knownString is the one value an expression has, when it has one and it
// is all known: a literal, or s.charAt(i) of a known string at a known
// index. Read without marking the literals used.
func (x *extractor) knownString(e js.IExpr, q *[]string, depth int) (string, bool) {
	if s, ok := literalString(e); ok {
		return s, true
	}
	saved := x.noMarkUsed
	x.noMarkUsed = true
	defer func() { x.noMarkUsed = saved }()
	if c, ok := e.(*js.CallExpr); ok {
		if d, ok := c.X.(*js.DotExpr); ok && propName(d.Y) == "charAt" {
			as := args(&c.Args)
			s, sok := x.knownString(d.X, q, depth+1)
			if len(as) != 1 || !sok {
				return "", false
			}
			i, iok := x.intValue(as[0], q, depth+1)
			if !iok || i < 0 || i >= len(s) {
				return "", iok && sok // out of range: ""
			}
			return s[i : i+1], true
		}
	}
	if !x.stableExpr(e, 0) {
		return "", false
	}
	vals := x.eval(e, q, depth+1)
	if len(vals) != 1 || strings.Contains(vals[0], unknown) || strings.Contains(vals[0], "{origin}") {
		return "", false
	}
	return vals[0], true
}

// stableExpr reports whether an expression's value is the code's, not the
// page's state at run time: literals, variables (a constant, a parameter a
// call binds), a template or sum of those, a field of the instance being
// read. Not x.value (a reactive ref's first value), nor a property read
// off an object the page changes: a test of those picks no side of a ?:.
func (x *extractor) stableExpr(e js.IExpr, depth int) bool {
	if depth > 8 {
		return false
	}
	if _, call := e.(*js.CallExpr); call && literalOnly(e) {
		return true // "https://…".trim()
	}
	switch n := e.(type) {
	case *js.LiteralExpr:
		return n.TokenType == js.StringToken || n.TokenType == js.IntegerToken
	case *js.Var:
		return true
	case *js.GroupExpr:
		return x.stableExpr(n.X, depth+1)
	case *js.TemplateExpr:
		if n.Tag != nil {
			return false
		}
		for _, p := range n.List {
			if !x.stableExpr(p.Expr, depth+1) {
				return false
			}
		}
		return true
	case *js.BinaryExpr:
		return n.Op == js.AddToken && x.stableExpr(n.X, depth+1) && x.stableExpr(n.Y, depth+1)
	case *js.DotExpr:
		return x.isThis(n.X) && len(x.self) > 0 && len(x.classField(x.lookupClass(x.self[len(x.self)-1], n.Y), propName(n.Y))) > 0
	case *js.CallExpr:
		if d, ok := n.X.(*js.DotExpr); ok && propName(d.Y) == "charAt" {
			return x.stableExpr(d.X, depth+1)
		}
	}
	return false
}

// intValue is an integer an expression is: a literal, s.length of a known
// string, and either plus or minus a literal.
func (x *extractor) intValue(e js.IExpr, q *[]string, depth int) (int, bool) {
	if n, ok := intLiteral(e); ok {
		return n, true
	}
	switch n := e.(type) {
	case *js.GroupExpr:
		return x.intValue(n.X, q, depth+1)
	case *js.DotExpr:
		if propName(n.Y) == "length" && depth < 12 {
			if s, ok := x.knownString(n.X, q, depth+1); ok {
				return len(s), true
			}
		}
	case *js.BinaryExpr:
		if n.Op != js.AddToken && n.Op != js.SubToken {
			break
		}
		a, aok := x.intValue(n.X, q, depth+1)
		b, bok := x.intValue(n.Y, q, depth+1)
		if !aok || !bok {
			break
		}
		if n.Op == js.SubToken {
			return a - b, true
		}
		return a + b, true
	}
	return 0, false
}

// sliceString is s.slice(a, b) of a known string, a and b numbers.
func (x *extractor) sliceString(c *js.CallExpr, d *js.DotExpr, q *[]string, depth int) ([]string, bool) {
	as := args(&c.Args)
	if len(as) == 0 || len(as) > 2 {
		return nil, false
	}
	nums := make([]int, len(as))
	for i, a := range as {
		n, ok := intLiteral(a)
		if !ok {
			return nil, false
		}
		nums[i] = n
	}
	vals := x.eval(d.X, q, depth+1)
	var out []string
	for _, v := range vals {
		if strings.Contains(v, unknown) || strings.Contains(v, "{origin}") {
			return nil, false
		}
		at := func(i int) int {
			if i < 0 {
				i += len(v)
			}
			return max(0, min(i, len(v)))
		}
		from, to := at(nums[0]), len(v)
		if len(nums) == 2 {
			to = at(nums[1])
		}
		if from > to {
			from = to
		}
		out = addAlt(out, v[from:to])
	}
	return out, len(out) > 0
}

// intLiteral is an integer literal, negative ones too.
func intLiteral(e js.IExpr) (int, bool) {
	neg := false
	if u, ok := e.(*js.UnaryExpr); ok && u.Op == js.NegToken {
		neg, e = true, u.X
	}
	l, ok := e.(*js.LiteralExpr)
	if !ok || l.TokenType != js.IntegerToken {
		return 0, false
	}
	n := 0
	for _, c := range l.Data {
		if c < '0' || c > '9' || n > 1<<20 {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	return n, true
}

// readVia reads the call a helper makes through another (its parameters
// bound already): a call on a field of this is read in the instance the
// field holds (this.#transport.request(…): new Transport({…}), made with
// the constructor's parameters of the instance being read bound), its
// arguments evaluated first, in the instance they are written in.
func (x *extractor) readVia(s *summary, q *[]string, depth int) helperCall {
	sub := s.sub
	var cls *js.ClassDecl
	var cas []js.IExpr
	if d, ok := s.via.X.(*js.DotExpr); ok {
		fn, c, as := x.readCallee(d, nargsOf(s.via))
		if c != nil && (s.lazy || sub != nil && x.fnSummary(fn) == sub) {
			cls, cas = c, as
			if s.lazy {
				sub = x.fnSummary(fn)
			}
		}
	}
	if sub == nil {
		return helperCall{}
	}
	if cls == nil {
		return x.readCall(sub, args(&s.via.Args), q, depth+1)
	}
	if depth+1 > maxHelperDepth {
		return helperCall{}
	}
	restore := x.bindParams(sub.params, args(&s.via.Args), q, depth+1)
	undo := x.bindInstance(cls, cas, q, depth+1)
	defer func() {
		undo()
		restore()
	}()
	// Its own parameters are bound: read it as readCall would, without
	// binding them again.
	return x.readBound(sub, q, depth+1)
}

// fnSummary is the summary of a method or function field, read once.
func (x *extractor) fnSummary(fn js.IExpr) *summary {
	if fn == nil {
		return nil
	}
	if s, ok := x.msums[fn]; ok {
		return s
	}
	x.msums[fn] = nil
	params, body, _ := fnParts(fn)
	if body == nil {
		return nil
	}
	x.fnStack = append(x.fnStack, fn)
	s := x.summarize(params, body)
	x.fnStack = x.fnStack[:len(x.fnStack)-1]
	x.msums[fn] = s
	return s
}

// readsSelfField reports whether an expression reads a field the instance
// being read sets (this.prefix + path): its value is the whole
// expression's, not that of the parameter in it.
func (x *extractor) readsSelfField(e js.IExpr) bool {
	if len(x.self) == 0 {
		return false
	}
	c := x.self[len(x.self)-1]
	found := false
	walkThisScope(e, func(n js.INode) {
		if d, ok := n.(*js.DotExpr); ok && !found && x.isThis(d.X) && len(x.classField(x.lookupClass(c, d.Y), propName(d.Y))) > 0 {
			found = true
		}
	})
	return found
}

// instanceField is what a field of another instance holds (this.http.base,
// the field http set to new Http("https://…")): read in that instance,
// its constructor's parameters bound.
func (x *extractor) instanceField(d *js.DotExpr, q *[]string, depth int) ([]string, bool) {
	if depth > 8 || len(x.self) > 2*maxClassChain {
		return nil, false
	}
	c, as := x.instanceOf(d.X, true, 0)
	if c == nil || len(x.classField(x.lookupClass(c, d.Y), propName(d.Y))) == 0 {
		return nil, false
	}
	undo := x.bindInstance(c, as, q, depth+1)
	defer undo()
	return x.thisFieldValues(d.Y, q, depth+1)
}

// requestMethod reports whether a method call is to a class's own method
// that makes a request: one with a summary, known now or at the call.
func (x *extractor) requestMethod(d *js.DotExpr, n int) bool {
	fn := x.classCallee(d, n)
	if fn == nil && len(x.self) > 0 {
		fn, _, _ = x.readCallee(d, n)
	}
	return fn != nil && x.fnSummary(fn) != nil
}

// forwardsPath reports whether a call's URL hands on a parameter of the
// function it is in as its path (this.request("GET", e), fetch(`${this.
// baseUrl}${t}`), or a local constant made so): a helper's frame, whose
// endpoints are its callers'; read in an instance it would be one
// endpoint per instance, the path unknown (/console-api{}). A parameter
// after a "/" (… + "/" + id), or as a query's value, is a segment of an
// endpoint, not the path.
func (x *extractor) forwardsPath(c *js.CallExpr) bool {
	for _, a := range x.urlArgs(c) {
		if x.pathForwardVia(a, 0) {
			return true
		}
	}
	return false
}

// urlArgs are the arguments of a call that are its URL, not its options or
// body (create(payload) { return fetch(this.base + "/items", payload) }):
// fetch's and a client method's first; for a helper with a summary, the
// arguments it takes as its whole path (pathParams: none when its path is
// its own, "/items", or the arguments are segments of it, "/items/" + id),
// never a guess; otherwise (a call read only at the call) the first that
// is neither an object nor a method's name ("GET"), and the url, uri,
// endpoint, path or pathname an options object gives.
func (x *extractor) urlArgs(c *js.CallExpr) []js.IExpr {
	as := args(&c.Args)
	if len(as) == 0 {
		return nil
	}
	if x.fetchLike(c.X) {
		return as[:1]
	}
	if d, ok := c.X.(*js.DotExpr); ok {
		if _, client := clientMethods[propName(d.Y)]; client && !x.requestMethod(d, len(as)) {
			return as[:1]
		}
	}
	if s := x.summaryOf(c.X, nargsOf(c)); s != nil && !s.lazy {
		var out []js.IExpr
		for _, i := range x.pathParams(s, 0) {
			if i < len(as) {
				out = append(out, x.urlOf(as[i])...)
			}
		}
		return out
	}
	var out []js.IExpr
	first := true
	for _, a := range as {
		if o, ok := x.object(a); ok {
			out = append(out, urlValues(o)...)
			continue
		}
		if m, ok := literalString(a); ok && httpMethods[strings.ToUpper(m)] {
			continue
		}
		if first {
			out, first = append(out, a), false
		}
	}
	return out
}

// urlOf is the URL an argument gives: itself, or an options object's url.
func (x *extractor) urlOf(a js.IExpr) []js.IExpr {
	if o, ok := a.(*js.ObjectExpr); ok {
		return urlValues(o)
	}
	return []js.IExpr{a}
}

func urlValues(o *js.ObjectExpr) []js.IExpr {
	var out []js.IExpr
	for _, k := range []string{"url", "uri", "endpoint", "path", "pathname"} {
		if v := objectValue(o, k); v != nil {
			out = append(out, v)
		}
	}
	return out
}

// pathParams are the parameters a helper takes as its whole path (or URL):
// those its summary says are the URL as given (s.urls); the path of a
// request whose base it splits off (fetch(base + path), path its own
// parameter); and those it hands on, as given, to another helper's.
func (x *extractor) pathParams(s *summary, depth int) []int {
	if s == nil || depth > maxHelperDepth {
		return nil
	}
	out := slices.Clone(s.urls)
	idx := paramIndex(s.params)
	add := func(i int) {
		if i >= 0 && !slices.Contains(out, i) {
			out = append(out, i)
		}
	}
	switch {
	case s.sub != nil:
		vas := args(&s.via.Args)
		for _, i := range x.pathParams(s.sub, depth+1) {
			if i < len(vas) {
				add(idx(ungroup(vas[i])))
			}
		}
	case !s.lazy:
		// fetch(base + path), path its own; fetch(c), c a constant
		// `${this.baseUrl}${t}${q}`: the parameters in the URL as a path.
		if s.leaf.base != nil {
			add(idx(ungroup(s.leaf.url)))
		}
		for _, v := range x.forwardVarsVia(s.leaf.url, 0) {
			add(idx(v))
		}
	}
	slices.Sort(out)
	return out
}

// pathForwardVia reports whether an expression, or the local constant it
// is (const c = `${this.baseUrl}${t}${s}`; fetch(c, u)), forwards a
// parameter as a whole path.
func (x *extractor) pathForwardVia(e js.IExpr, depth int) bool {
	return len(x.forwardVarsVia(e, depth)) > 0
}

// forwardVarsVia are the parameters an expression hands on as a whole
// path (forwardVars), through the local constants it is made of.
func (x *extractor) forwardVarsVia(e js.IExpr, depth int) []*js.Var {
	var out []*js.Var
	forwardVars(e, 0, &out)
	if v, ok := ungroup(e).(*js.Var); ok && depth < 3 && root(v).Decl != js.ArgumentDecl {
		if k := x.constant(v); k != nil {
			out = append(out, x.forwardVarsVia(k, depth+1)...)
		}
	}
	return out
}

// forwardVars are the parameters a URL expression takes as a whole path:
// the parameter alone, or after a base or text not ending in "/" (base +
// p, "/api" + p); in either side of a ?:, the whole's or a part's.
func forwardVars(e js.IExpr, depth int, out *[]*js.Var) {
	if depth > 8 {
		return
	}
	switch n := e.(type) {
	case *js.GroupExpr:
		forwardVars(n.X, depth+1, out)
		return
	case *js.CondExpr:
		forwardVars(n.X, depth+1, out)
		forwardVars(n.Y, depth+1, out)
		return
	}
	parts := urlParts(e, nil, 0)
	for i, p := range parts {
		p = ungroup(p)
		if ce, ok := p.(*js.CondExpr); ok {
			// `${t.startsWith("http") ? t : `${base}${t}`}${s}`
			forwardVars(ce.X, depth+1, out)
			forwardVars(ce.Y, depth+1, out)
			continue
		}
		v, ok := p.(*js.Var)
		if !ok || root(v).Decl != js.ArgumentDecl {
			continue
		}
		if i == 0 {
			// The URL is the parameter, or starts with it: when the rest
			// is known text, it is the parameter's path then a suffix.
			if len(parts) == 1 {
				*out = append(*out, v)
			}
			continue
		}
		prev, ok := literalString(parts[i-1])
		if !ok || prev == "" || !strings.HasSuffix(prev, "/") && !strings.HasSuffix(prev, "=") {
			*out = append(*out, v) // base + p, "/api" + p
		}
	}
}

// urlParts are the pieces a URL expression joins: a sum's terms, a
// template's text and expressions (text as string literals).
func urlParts(e js.IExpr, out []js.IExpr, depth int) []js.IExpr {
	if depth > 16 {
		return append(out, e)
	}
	switch n := e.(type) {
	case *js.GroupExpr:
		return urlParts(n.X, out, depth+1)
	case *js.BinaryExpr:
		if n.Op == js.AddToken {
			out = urlParts(n.X, out, depth+1)
			return urlParts(n.Y, out, depth+1)
		}
	case *js.TemplateExpr:
		if n.Tag != nil {
			break
		}
		for i, p := range n.List {
			if t := templateText(p.Value, i == 0, false); t != "" {
				out = append(out, &js.LiteralExpr{TokenType: js.StringToken, Data: []byte(quoteLit(t))})
			}
			out = urlParts(p.Expr, out, depth+1)
		}
		if t := templateText(n.Tail, len(n.List) == 0, true); t != "" {
			out = append(out, &js.LiteralExpr{TokenType: js.StringToken, Data: []byte(quoteLit(t))})
		}
		return out
	}
	return append(out, e)
}

func quoteLit(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// literalOnly reports whether an expression is made of literals alone, no
// variable or this in it ("https://…".trim()).
func literalOnly(e js.IExpr) bool {
	ok := true
	js.Walk(literalOnlyVisitor{&ok}, e)
	return ok
}

type literalOnlyVisitor struct{ ok *bool }

func (v literalOnlyVisitor) Enter(n js.INode) js.IVisitor {
	switch n := n.(type) {
	case *js.Var:
		*v.ok = false
	case *js.LiteralExpr:
		if n.TokenType == js.ThisToken {
			*v.ok = false
		}
	case *js.FuncDecl, *js.ArrowFunc, *js.ClassDecl:
		*v.ok = false
	}
	if !*v.ok {
		return nil
	}
	return v
}

func (literalOnlyVisitor) Exit(js.INode) {}

// arrayJoin is [a, b, …].join(sep) of an array literal: its elements'
// values joined.
func (x *extractor) arrayJoin(c *js.CallExpr, d *js.DotExpr, q *[]string, depth int) ([]string, bool) {
	arr, ok := d.X.(*js.ArrayExpr)
	if !ok || len(arr.List) == 0 || len(arr.List) > 16 {
		return nil, false
	}
	sep, ok := x.joinSep(c, q, depth)
	if !ok {
		return nil, false
	}
	var parts []js.IExpr
	for _, el := range arr.List {
		if el.Spread || el.Value == nil {
			return nil, false
		}
		parts = append(parts, el.Value)
	}
	return x.joinValues(parts, sep, false, q, depth), true
}

// joinSep is the separator a join(sep) call is given: a known string; ","
// when none is.
func (x *extractor) joinSep(c *js.CallExpr, q *[]string, depth int) (string, bool) {
	as := args(&c.Args)
	switch len(as) {
	case 0:
		return ",", true
	case 1:
		return x.knownString(as[0], q, depth+1)
	}
	return "", false
}

// joinCall reads a call to a function joining the paths it is given
// (function g0(...e) { return e.map(…).join("/") }, urlJoin(...parts)):
// its arguments joined with the separator; where the function maps them
// with a callback that reads the separator (trimming it off each part's
// ends), the separators at each join are one.
func (x *extractor) joinCall(c *js.CallExpr, q *[]string, depth int) ([]string, bool) {
	_, _, params, body, ok := x.calleeFn(c)
	if !ok || body == nil || len(params.List) != 0 || params.Rest == nil {
		return nil, false
	}
	rest, ok := params.Rest.(*js.Var)
	if !ok {
		return nil, false
	}
	rets := returnsOf(body)
	if len(rets) != 1 {
		return nil, false
	}
	jc, ok := rets[0].(*js.CallExpr)
	if !ok {
		return nil, false
	}
	jd, ok := jc.X.(*js.DotExpr)
	if !ok || propName(jd.Y) != "join" {
		return nil, false
	}
	sep, ok := x.joinSep(jc, q, depth)
	if !ok || sep == "" {
		return nil, false
	}
	// rest.map(cb).join(SEP), with a filter (dropping the empty parts)
	// before or after the map.
	normalize, filtered := false, false
	recv := jd.X
	for step := 0; step < 3; step++ {
		mc, ok := recv.(*js.CallExpr)
		if !ok {
			break
		}
		md, ok := mc.X.(*js.DotExpr)
		mas := args(&mc.Args)
		if !ok || len(mas) == 0 {
			return nil, false
		}
		switch propName(md.Y) {
		case "filter":
			filtered = true
		case "map":
			if normalize || !x.mentionsSep(mas[0], sep, q, depth) {
				return nil, false // a map that does something else
			}
			normalize = true
		default:
			return nil, false
		}
		recv = md.X
	}
	if v, ok := recv.(*js.Var); !ok || root(v) != root(rest) {
		return nil, false
	}
	parts := args(&c.Args)
	if len(parts) == 0 || len(parts) > 16 {
		return nil, false
	}
	for _, a := range c.Args.List {
		if a.Rest {
			return nil, false
		}
	}
	if filtered {
		// filter(Boolean): the parts known to be "" are left out.
		var kept []js.IExpr
		for _, p := range parts {
			if v, ok := literalString(p); ok && v == "" {
				continue
			}
			kept = append(kept, p)
		}
		if len(kept) == 0 {
			return nil, false
		}
		parts = kept
	}
	return x.joinValues(parts, sep, normalize, q, depth), true
}

// mentionsSep reports whether a callback reads the separator: the literal,
// or a constant set to it.
func (x *extractor) mentionsSep(cb js.IExpr, sep string, q *[]string, depth int) bool {
	found := false
	js.Walk(mentionVisitor{func(n js.INode) {
		if found {
			return
		}
		switch n := n.(type) {
		case *js.LiteralExpr:
			if s, ok := literalString(n); ok && s == sep {
				found = true
			}
		case *js.Var:
			if c := x.constant(n); c != nil {
				if s, ok := literalString(c); ok && s == sep {
					found = true
				}
			}
		}
	}}, cb)
	return found
}

type mentionVisitor struct{ f func(js.INode) }

func (v mentionVisitor) Enter(n js.INode) js.IVisitor { v.f(n); return v }
func (mentionVisitor) Exit(js.INode)                  {}

// joinValues joins the values of parts with a separator; normalize: one
// separator where two parts meet, whatever ends they had.
func (x *extractor) joinValues(parts []js.IExpr, sep string, normalize bool, q *[]string, depth int) []string {
	out := x.eval(parts[0], q, depth+1)
	for i, p := range parts[1:] {
		vals := x.eval(p, q, depth+1)
		var next []string
		for _, l := range out {
			for _, r := range vals {
				if normalize {
					l2 := strings.TrimSuffix(l, sep)
					r2 := r
					if i < len(parts)-2 {
						r2 = strings.TrimSuffix(r2, sep)
					}
					next = addAlt(next, l2+sep+strings.TrimPrefix(r2, sep))
				} else {
					next = addAlt(next, l+sep+r)
				}
				if len(next) >= maxAlts {
					break
				}
			}
		}
		out = next
	}
	return out
}

// ungroup is an expression without the parentheses around it.
func ungroup(e js.IExpr) js.IExpr {
	for {
		g, ok := e.(*js.GroupExpr)
		if !ok {
			return e
		}
		e = g.X
	}
}

// stringList is the strings a list the code writes holds: an array of
// string literals; a constant, a property set to one; arr.map(e => e.key)
// of an array of object literals. ok false when a part is not the code's.
func (x *extractor) stringList(e js.IExpr, depth int) ([]string, bool) {
	if depth > 8 {
		return nil, false
	}
	switch n := ungroup(e).(type) {
	case *js.ArrayExpr:
		var out []string
		for _, el := range n.List {
			s, ok := literalString(el.Value)
			if el.Spread || !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	case *js.Var:
		if c := x.constant(n); c != nil {
			return x.stringList(c, depth+1)
		}
	case *js.DotExpr:
		if m, ok := x.member(n); ok {
			return x.stringList(m, depth+1)
		}
	case *js.CallExpr:
		d, ok := n.X.(*js.DotExpr)
		if !ok || propName(d.Y) != "map" || len(n.Args.List) != 1 {
			return nil, false
		}
		f, ok := n.Args.List[0].Value.(*js.ArrowFunc)
		if !ok || len(f.Params.List) != 1 {
			return nil, false
		}
		p, ok := f.Params.List[0].Binding.(*js.Var)
		rets := returnsOf(&f.Body)
		if !ok || len(rets) != 1 {
			return nil, false
		}
		pd, ok := rets[0].(*js.DotExpr)
		if !ok {
			return nil, false
		}
		if pv, ok := pd.X.(*js.Var); !ok || root(pv) != root(p) {
			return nil, false
		}
		key := propName(pd.Y)
		arr, ok := x.arrayOf(d.X, depth+1)
		if !ok {
			return nil, false
		}
		var out []string
		for _, el := range arr.List {
			o, ok := el.Value.(*js.ObjectExpr)
			if el.Spread || !ok {
				return nil, false
			}
			if v := objectValue(o, key); v != nil {
				if s, ok := literalString(v); ok {
					out = append(out, s)
				}
			}
		}
		return out, true
	}
	return nil, false
}

// arrayOf is the array literal an expression is: itself, a constant, a
// property set to one.
func (x *extractor) arrayOf(e js.IExpr, depth int) (*js.ArrayExpr, bool) {
	if depth > 8 {
		return nil, false
	}
	switch n := ungroup(e).(type) {
	case *js.ArrayExpr:
		return n, true
	case *js.Var:
		if c := x.constant(n); c != nil {
			return x.arrayOf(c, depth+1)
		}
	case *js.DotExpr:
		if m, ok := x.member(n); ok {
			return x.arrayOf(m, depth+1)
		}
	}
	return nil, false
}
