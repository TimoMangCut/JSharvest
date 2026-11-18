package jsapi

import (
	"slices"
	"sort"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

const (
	maxRouteDepth      = 12
	maxRoutesPerScript = 2000
)

// RouteEntry is a normalized route from a client-side SPA router tree,
// with any static redirect and guard metadata attached to it.
type RouteEntry struct {
	Path         string   `json:"path"`
	Redirect     string   `json:"redirect,omitempty"`
	AuthRequired *bool    `json:"auth_required,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	Line         int      `json:"line,omitempty"`
}

type routeMeta struct {
	authReq    *bool
	roles      []string
	perms      []string
	unresolved []UnresolvedRoutePerm
}

var routerStructuralKeys = map[string]bool{
	"children":         true,
	"component":        true,
	"components":       true,
	"redirect":         true,
	"redirectTo":       true,
	"loadChildren":     true,
	"loadComponent":    true,
	"element":          true,
	"errorElement":     true,
	"ErrorBoundary":    true,
	"lazy":             true,
	"beforeEnter":      true,
	"canActivate":      true,
	"canActivateChild": true,
	"canMatch":         true,
	"meta":             true,
	"index":            true,
	"loader":           true,
	"beforeLoad":       true,
}

var routerFactoryNames = map[string]bool{
	"createRouter":        true,
	"createBrowserRouter": true,
	"createHashRouter":    true,
	"createMemoryRouter":  true,
	"provideRouter":       true,
}

func (x *extractor) routerNew(n *js.NewExpr) {
	if n == nil {
		return
	}
	as := args(n.Args)
	if len(as) == 0 {
		return
	}
	ident, prop := calleeIdentOrProp(n.X)
	if ident == "VueRouter" || prop == "VueRouter" {
		x.walkRouterRootArg(as[0])
		return
	}
	if obj, ok := x.object(as[0]); ok && isRouterOptionsObject(obj) {
		if rv := objectValue(obj, "routes"); rv != nil {
			x.walkRouteListExpr(rv, "", routeMeta{}, 0, map[js.INode]bool{})
		}
	}
}

func (x *extractor) routerCall(c *js.CallExpr) bool {
	if c == nil {
		return false
	}
	as := args(&c.Args)
	if len(as) == 0 {
		return false
	}
	ident, prop := calleeIdentOrProp(c.X)
	if routerFactoryNames[ident] || routerFactoryNames[prop] {
		x.walkRouterRootArg(as[0])
		x.routeCalls[c] = true
		return true
	}
	if d, ok := unwrapCallee(c.X).(*js.DotExpr); ok {
		mName := propName(d.Y)
		switch mName {
		case "forRoot", "forChild":
			recvIdent, recvProp := calleeIdentOrProp(d.X)
			if recvIdent == "RouterModule" || recvProp == "RouterModule" || x.looksLikeRouteList(as[0], 0) {
				x.walkRouteListExpr(as[0], "", routeMeta{}, 0, map[js.INode]bool{})
				x.routeCalls[c] = true
				return true
			}
		case "when":
			if len(as) >= 2 && x.isAngularWhenCall(d.X, as[0], as[1]) {
				// Walk chained $routeProvider.when(...).when(...)
				if inner, ok := unwrapEnumGroup(d.X).(*js.CallExpr); ok {
					x.routerCall(inner)
				}
				if p, line, ok := x.routePathValue(as[0], false); ok && strings.HasPrefix(p, "/") {
					redir := ""
					if cfgObj, ok := x.object(as[1]); ok {
						if r, _, rok := x.routePathValue(objectValue(cfgObj, "redirectTo"), true); rok && r != "" {
							redir = joinRoutePath("", r)
						}
					}
					x.recordRouteEntry(RouteEntry{Path: cleanRoutePath(p), Redirect: redir, Line: line})
				}
				x.routeCalls[c] = true
				return true
			}
		}
	}
	return false
}

func (x *extractor) isAngularWhenCall(recv, pathArg, cfgArg js.IExpr) bool {
	s, ok := literalString(pathArg)
	if !ok || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return false
	}
	rIdent, rProp := calleeIdentOrProp(recv)
	if strings.HasSuffix(strings.ToLower(rIdent), "routeprovider") || strings.HasSuffix(strings.ToLower(rProp), "routeprovider") {
		return true
	}
	cfg, ok := x.object(cfgArg)
	if !ok {
		return false
	}
	for _, p := range cfg.List {
		if p.Spread || p.Name == nil {
			continue
		}
		switch propName(p.Name) {
		case "template", "templateUrl", "controller", "redirectTo":
			return true
		}
	}
	return false
}

func (x *extractor) routerObject(obj *js.ObjectExpr) {
	if obj == nil || x.routeObjs[obj] {
		return
	}
	if isRouterOptionsObject(obj) {
		if rv := objectValue(obj, "routes"); rv != nil {
			x.routeObjs[obj] = true
			x.walkRouteListExpr(rv, "", routeMeta{}, 0, map[js.INode]bool{})
			return
		}
	}
	pVal := objectValue(obj, "path")
	if pVal == nil {
		return
	}
	hasStructKey := hasRouterStructuralKey(obj)
	p, line, ok := x.routePathValue(pVal, hasStructKey)
	if !ok || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return
	}
	// Root object without explicit router factory: require either a structural
	// router key (which also permits path: "/") or looksLikePath(p, weak) for
	// backward compatibility with `{path: "/settings"}`.
	if !hasStructKey && !looksLikePath(p, weak) {
		return
	}
	x.walkRouteObject(obj, "", routeMeta{}, false, 0, map[js.INode]bool{obj: true})
	_ = line
}

func isRouterOptionsObject(obj *js.ObjectExpr) bool {
	if obj == nil || objectValue(obj, "routes") == nil {
		return false
	}
	for _, p := range obj.List {
		if p.Spread || p.Name == nil {
			continue
		}
		switch propName(p.Name) {
		case "mode", "history", "scrollBehavior", "linkActiveClass", "linkExactActiveClass", "parseQuery", "stringifyQuery", "fallback":
			return true
		}
	}
	return false
}

func hasRouterStructuralKey(obj *js.ObjectExpr) bool {
	for _, p := range obj.List {
		if !p.Spread && p.Name != nil && routerStructuralKeys[propName(p.Name)] {
			return true
		}
	}
	return false
}

func (x *extractor) walkRouterRootArg(arg js.IExpr) {
	if arg == nil {
		return
	}
	if obj, ok := x.object(arg); ok {
		if rv := objectValue(obj, "routes"); rv != nil {
			x.routeObjs[obj] = true
			x.walkRouteListExpr(rv, "", routeMeta{}, 0, map[js.INode]bool{})
			return
		}
	}
	x.walkRouteListExpr(arg, "", routeMeta{}, 0, map[js.INode]bool{})
}

func (x *extractor) looksLikeRouteList(e js.IExpr, depth int) bool {
	if e == nil || depth > 4 {
		return false
	}
	switch n := unwrapEnumGroup(e).(type) {
	case *js.ArrayExpr:
		for _, el := range n.List {
			if el.Spread {
				if x.looksLikeRouteList(el.Value, depth+1) {
					return true
				}
				continue
			}
			if obj, ok := x.object(el.Value); ok && hasRouterStructuralKey(obj) && (objectValue(obj, "path") != nil || objectValue(obj, "redirectTo") != nil) {
				return true
			}
		}
	case *js.Var:
		for _, def := range x.defs[root(n)] {
			if def != nil && x.looksLikeRouteList(def, depth+1) {
				return true
			}
		}
	}
	return false
}

func (x *extractor) walkRouteListExpr(e js.IExpr, parentPath string, inherited routeMeta, depth int, visiting map[js.INode]bool) {
	if e == nil || depth > maxRouteDepth || len(x.routeOrder) >= maxRoutesPerScript {
		return
	}
	e = unwrapEnumGroup(e)
	if e == nil {
		return
	}
	if v, isVar := e.(*js.Var); isVar {
		rv := root(v)
		if visiting[rv] {
			return
		}
		visiting[rv] = true
		defer delete(visiting, rv)
		for _, def := range x.defs[rv] {
			if def != nil {
				x.walkRouteListExpr(def, parentPath, inherited, depth+1, visiting)
			}
		}
		return
	}
	if visiting[e] {
		return
	}
	visiting[e] = true
	defer delete(visiting, e)

	switch n := e.(type) {
	case *js.ArrayExpr:
		for _, el := range n.List {
			if len(x.routeOrder) >= maxRoutesPerScript {
				return
			}
			if el.Value == nil {
				continue
			}
			if el.Spread {
				x.walkRouteListExpr(el.Value, parentPath, inherited, depth+1, visiting)
				continue
			}
			x.walkRouteItemExpr(el.Value, parentPath, inherited, depth, visiting)
		}
	case *js.DotExpr:
		if m, ok := x.member(n); ok {
			x.walkRouteListExpr(m, parentPath, inherited, depth+1, visiting)
		}
	case *js.CallExpr:
		if d, ok := unwrapEnumGroup(n.X).(*js.DotExpr); ok {
			switch propName(d.Y) {
			case "concat":
				x.walkRouteListExpr(d.X, parentPath, inherited, depth+1, visiting)
				for _, a := range n.Args.List {
					if a.Value != nil {
						x.walkRouteListOrItemExpr(a.Value, parentPath, inherited, depth+1, visiting)
					}
				}
				return
			case "filter", "slice", "flat":
				x.walkRouteListExpr(d.X, parentPath, inherited, depth+1, visiting)
				return
			}
		}
		// Babel spread helper inside concat/array: _toConsumableArray(subRoutes) / Object(r.a)(subRoutes)
		if len(n.Args.List) == 1 && !n.Args.List[0].Rest {
			x.walkRouteListExpr(n.Args.List[0].Value, parentPath, inherited, depth+1, visiting)
		}
	case *js.CondExpr:
		x.walkRouteListExpr(n.X, parentPath, inherited, depth+1, visiting)
		x.walkRouteListExpr(n.Y, parentPath, inherited, depth+1, visiting)
	case *js.BinaryExpr:
		switch n.Op {
		case js.OrToken, js.NullishToken:
			x.walkRouteListExpr(n.X, parentPath, inherited, depth+1, visiting)
			x.walkRouteListExpr(n.Y, parentPath, inherited, depth+1, visiting)
		case js.AndToken:
			x.walkRouteListExpr(n.Y, parentPath, inherited, depth+1, visiting)
		}
	case *js.ObjectExpr:
		x.walkRouteObject(n, parentPath, inherited, true, depth, visiting)
	}
}

func (x *extractor) walkRouteListOrItemExpr(e js.IExpr, parentPath string, inherited routeMeta, depth int, visiting map[js.INode]bool) {
	if obj, ok := unwrapEnumGroup(e).(*js.ObjectExpr); ok {
		if visiting[obj] {
			return
		}
		visiting[obj] = true
		x.walkRouteObject(obj, parentPath, inherited, true, depth, visiting)
		delete(visiting, obj)
		return
	}
	x.walkRouteListExpr(e, parentPath, inherited, depth, visiting)
}

func (x *extractor) walkRouteItemExpr(e js.IExpr, parentPath string, inherited routeMeta, depth int, visiting map[js.INode]bool) {
	if e == nil || depth > maxRouteDepth || len(x.routeOrder) >= maxRoutesPerScript {
		return
	}
	e = unwrapEnumGroup(e)
	switch n := e.(type) {
	case *js.ObjectExpr:
		if visiting[n] {
			return
		}
		visiting[n] = true
		x.walkRouteObject(n, parentPath, inherited, true, depth, visiting)
		delete(visiting, n)
	case *js.Var:
		rv := root(n)
		if visiting[rv] {
			return
		}
		visiting[rv] = true
		for _, def := range x.defs[rv] {
			if def != nil {
				x.walkRouteItemExpr(def, parentPath, inherited, depth+1, visiting)
			}
		}
		delete(visiting, rv)
	case *js.CondExpr:
		x.walkRouteItemExpr(n.X, parentPath, inherited, depth+1, visiting)
		x.walkRouteItemExpr(n.Y, parentPath, inherited, depth+1, visiting)
	case *js.BinaryExpr:
		if n.Op == js.AndToken {
			x.walkRouteItemExpr(n.Y, parentPath, inherited, depth+1, visiting)
		} else if n.Op == js.OrToken || n.Op == js.NullishToken {
			x.walkRouteItemExpr(n.X, parentPath, inherited, depth+1, visiting)
			x.walkRouteItemExpr(n.Y, parentPath, inherited, depth+1, visiting)
		}
	}
}

func (x *extractor) walkRouteObject(obj *js.ObjectExpr, parentPath string, inherited routeMeta, inTree bool, depth int, visiting map[js.INode]bool) {
	if obj == nil || depth > maxRouteDepth || len(x.routeOrder) >= maxRoutesPerScript {
		return
	}
	x.routeObjs[obj] = true

	pVal := objectValue(obj, "path")
	hasPath := pVal != nil
	rawPath := ""
	line := 0
	if hasPath {
		var ok bool
		rawPath, line, ok = x.routePathValue(pVal, inTree || hasRouterStructuralKey(obj))
		if !ok {
			return
		}
		if strings.HasPrefix(rawPath, "//") || schemeRe.MatchString(rawPath) {
			return
		}
	} else if !inTree {
		return
	}

	var curPath string
	isIndex, _ := boolValue(objectValue(obj, "index"))
	if !hasPath {
		// Pathless layout route (`{ element: <Guard/>, children: [...] }`) or `{ index: true }`.
		if parentPath == "" {
			curPath = "/"
		} else {
			curPath = parentPath
		}
	} else {
		curPath = joinRoutePath(parentPath, rawPath)
	}

	own := x.extractRouteMeta(obj)
	eff := mergeRouteMeta(inherited, own)

	redir := x.extractRedirect(obj, parentPath, curPath, hasPath && rawPath != "")
	if redir != "" && looksLikePath(redir, weak) {
		x.routes[redir] = true
	}

	if line == 0 {
		line = x.objectLine(obj)
	}

	// Emit RouteEntry for concrete/parameterized routes (skipping pure pathless
	// wrapper layouts that have neither `path` nor `index: true`, and skipping
	// bare root catch-all `/*`).
	if (hasPath || isIndex) && curPath != "/*" && !strings.HasSuffix(curPath, "/*") {
		if curPath != "/" || redir != "" || eff.authReq != nil || len(eff.roles) > 0 || len(eff.perms) > 0 || len(eff.unresolved) > 0 {
			x.recordRouteEntry(RouteEntry{
				Path:         curPath,
				Redirect:     redir,
				AuthRequired: eff.authReq,
				Roles:        eff.roles,
				Permissions:  eff.perms,
				Line:         line,
			})
			for _, u := range eff.unresolved {
				u.Path = curPath
				x.addUnresolvedRoutePerm(u)
			}
		} else if looksLikePath(curPath, weak) {
			x.routes[curPath] = true
		}
	}

	if ch := objectValue(obj, "children"); ch != nil {
		x.walkRouteListExpr(ch, curPath, eff, depth+1, visiting)
	}
}

func (x *extractor) recordRouteEntry(re RouteEntry) {
	if re.Path == "" || !strings.HasPrefix(re.Path, "/") || strings.HasPrefix(re.Path, "//") {
		return
	}
	if looksLikePath(re.Path, weak) {
		x.routes[re.Path] = true
	}
	if existing, ok := x.routeMap[re.Path]; ok {
		if existing.Redirect == "" && re.Redirect != "" {
			existing.Redirect = re.Redirect
		}
		if existing.AuthRequired == nil && re.AuthRequired != nil {
			v := *re.AuthRequired
			existing.AuthRequired = &v
		}
		if len(re.Roles) > 0 {
			existing.Roles = uniq(append(existing.Roles, re.Roles...))
		}
		if len(re.Permissions) > 0 {
			existing.Permissions = uniq(append(existing.Permissions, re.Permissions...))
		}
		if existing.Line == 0 && re.Line > 0 {
			existing.Line = re.Line
		}
		return
	}
	if len(x.routeOrder) >= maxRoutesPerScript {
		return
	}
	cp := re
	if re.AuthRequired != nil {
		v := *re.AuthRequired
		cp.AuthRequired = &v
	}
	cp.Roles = uniq(slices.Clone(re.Roles))
	cp.Permissions = uniq(slices.Clone(re.Permissions))
	x.routeMap[cp.Path] = &cp
	x.routeOrder = append(x.routeOrder, cp.Path)
}

func joinRoutePath(parentPath, childPath string) string {
	childPath = strings.TrimSpace(childPath)
	if childPath == "" {
		if parentPath == "" {
			return "/"
		}
		return cleanRoutePath(parentPath)
	}
	if strings.HasPrefix(childPath, "/") {
		return cleanRoutePath(childPath)
	}
	base := strings.TrimRight(parentPath, "/")
	if base == "" {
		return cleanRoutePath("/" + childPath)
	}
	return cleanRoutePath(base + "/" + childPath)
}

func cleanRoutePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
		if p == "" {
			return "/"
		}
	}
	return p
}

func (x *extractor) routePathValue(e js.IExpr, allowEval bool) (string, int, bool) {
	if e == nil {
		return "", 0, false
	}
	e = unwrapEnumGroup(e)
	if l, ok := e.(*js.LiteralExpr); ok && l.TokenType == js.StringToken {
		s := unquote(l.Data)
		if !x.noMarkUsed {
			x.used[l] = true
		}
		return s, x.litLine(l.Data), true
	}
	if t, ok := e.(*js.TemplateExpr); ok && t.Tag == nil && len(t.List) == 0 {
		return templateText(t.Tail, true, true), x.litLine(t.Tail), true
	}
	if !allowEval {
		return "", 0, false
	}
	var q []string
	savedLits := len(x.lits)
	vals := x.eval(e, &q, 0)
	var line int
	if len(x.lits) > savedLits {
		line = x.litLine(x.lits[savedLits])
	}
	x.lits = x.lits[:savedLits]
	if len(vals) == 1 && !strings.Contains(vals[0], unknown) {
		return vals[0], line, true
	}
	return "", 0, false
}

func (x *extractor) extractRedirect(obj *js.ObjectExpr, parentPath, curPath string, hasOwnSeg bool) string {
	rv := objectValue(obj, "redirect")
	isAngularRedirectTo := false
	if rv == nil {
		rv = objectValue(obj, "redirectTo")
		isAngularRedirectTo = rv != nil
	}
	if rv == nil {
		return ""
	}
	rv = unwrapEnumGroup(rv)
	if ro, ok := x.object(rv); ok {
		rv = objectValue(ro, "path")
	} else if fnBody := singleReturnExpr(rv); fnBody != nil {
		rv = fnBody
	}
	s, _, ok := x.routePathValue(rv, true)
	if !ok || s == "" || strings.HasPrefix(s, "//") || schemeRe.MatchString(s) {
		return ""
	}
	if strings.HasPrefix(s, "/") {
		return cleanRoutePath(s)
	}
	base := curPath
	if isAngularRedirectTo && !hasOwnSeg {
		base = parentPath
	}
	return joinRoutePath(base, s)
}

func (x *extractor) extractRouteMeta(obj *js.ObjectExpr) routeMeta {
	var m routeMeta
	for _, key := range []string{"meta", "data"} {
		mv := objectValue(obj, key)
		if mv == nil {
			continue
		}
		mo, ok := x.object(mv)
		if !ok {
			continue
		}
		x.readMetaObject(mo, &m)
	}
	if m.authReq == nil {
		for _, gk := range []string{"canActivate", "canActivateChild", "canMatch"} {
			gv := objectValue(obj, gk)
			if gv == nil {
				continue
			}
			if arr, ok := unwrapEnumGroup(gv).(*js.ArrayExpr); ok {
				if len(arr.List) > 0 {
					t := true
					m.authReq = &t
					break
				}
				continue
			}
			t := true
			m.authReq = &t
			break
		}
	}
	return m
}

func (x *extractor) readMetaObject(mo *js.ObjectExpr, m *routeMeta) {
	for _, p := range mo.List {
		if p.Spread {
			if so, ok := x.object(p.Value); ok {
				x.readMetaObject(so, m)
			}
			continue
		}
		if p.Name == nil || p.Value == nil {
			continue
		}
		switch propName(p.Name) {
		case "authRequired", "requiresAuth", "requireAuth", "auth", "isAuth", "authenticated", "protected", "private":
			if b, ok := boolValue(p.Value); ok {
				m.authReq = &b
			}
		case "public", "isPublic", "guest", "anonymous", "allowAnonymous":
			if b, ok := boolValue(p.Value); ok && b {
				f := false
				m.authReq = &f
			}
		case "roles", "role", "authority", "authorities", "allowedRoles", "requiredRoles":
			rs := x.metaStrings(p.Value)
			m.roles = append(m.roles, rs...)
			m.unresolved = append(m.unresolved, x.metaUnresolvedRoles(p.Value)...)
		case "permissions", "permission", "perms", "perm", "privilege", "privileges":
			ps, up := x.metaPermValuesWithRefs(p.Value, 0)
			m.perms = append(m.perms, ps...)
			m.unresolved = append(m.unresolved, up...)
		}
	}
}

func mergeRouteMeta(parent, own routeMeta) routeMeta {
	var out routeMeta
	if own.authReq != nil {
		v := *own.authReq
		out.authReq = &v
	} else if parent.authReq != nil && *parent.authReq {
		t := true
		out.authReq = &t
	}
	if own.authReq != nil && !*own.authReq {
		out.roles = uniq(slices.Clone(own.roles))
		out.perms = uniq(slices.Clone(own.perms))
		out.unresolved = slices.Clone(own.unresolved)
		return out
	}
	out.roles = uniq(append(slices.Clone(parent.roles), own.roles...))
	out.perms = uniq(append(slices.Clone(parent.perms), own.perms...))
	out.unresolved = append(slices.Clone(parent.unresolved), own.unresolved...)
	return out
}

func (x *extractor) metaUnresolvedRoles(e js.IExpr) []UnresolvedRoutePerm {
	if e == nil {
		return nil
	}
	e = unwrapEnumGroup(e)
	if arr, ok := e.(*js.ArrayExpr); ok {
		var out []UnresolvedRoutePerm
		for _, el := range arr.List {
			if !el.Spread && el.Value != nil {
				out = append(out, x.metaUnresolvedRoles(el.Value)...)
			}
		}
		return out
	}
	if vals := x.metaStrings(e); len(vals) > 0 {
		return nil
	}
	if ref, ok := x.extractConstRef(e); ok {
		return []UnresolvedRoutePerm{{IsRole: true, Action: ref}}
	}
	return nil
}

func (x *extractor) resolveMetaAuthz(e js.IExpr, allowArray bool) ([]string, bool) {
	savedNoMark := x.noMarkUsed
	x.noMarkUsed = true
	vals, ok := resolveAuthzStrings(x, e, allowArray)
	x.noMarkUsed = savedNoMark
	return vals, ok
}

func (x *extractor) metaAuthzTokens(e js.IExpr) []string {
	if e == nil {
		return nil
	}
	if vals, ok := x.resolveMetaAuthz(e, true); ok && len(vals) > 0 {
		return vals
	}
	return x.metaStrings(e)
}

func (x *extractor) metaPermValues(e js.IExpr, depth int) []string {
	ps, _ := x.metaPermValuesWithRefs(e, depth)
	return ps
}

func (x *extractor) metaPermValuesWithRefs(e js.IExpr, depth int) ([]string, []UnresolvedRoutePerm) {
	if e == nil || depth > 4 {
		return nil, nil
	}
	e = unwrapEnumGroup(e)
	if arr, ok := e.(*js.ArrayExpr); ok {
		var out []string
		var uout []UnresolvedRoutePerm
		for _, el := range arr.List {
			if !el.Spread && el.Value != nil {
				ps, us := x.metaPermValuesWithRefs(el.Value, depth+1)
				out = append(out, ps...)
				uout = append(uout, us...)
			}
		}
		return out, uout
	}
	if po, ok := x.object(e); ok {
		return x.extractMetaPermObject(po, depth, map[js.INode]bool{})
	}
	toks := x.metaAuthzTokens(e)
	if len(toks) > 0 {
		return toks, nil
	}
	if ref, ok := x.extractConstRef(e); ok {
		return nil, []UnresolvedRoutePerm{{Action: ref}}
	}
	return nil, nil
}

func (x *extractor) extractMetaPermObject(po *js.ObjectExpr, depth int, visiting map[js.INode]bool) ([]string, []UnresolvedRoutePerm) {
	var actions, subjects, nested, named []string
	var actRefs, subjRefs, namedRefs []*ConstRef
	var nestedUnres []UnresolvedRoutePerm
	x.collectMetaPermFields(po, depth, visiting, &actions, &subjects, &nested, &named, &actRefs, &subjRefs, &namedRefs, &nestedUnres)

	var out []string
	var uout []UnresolvedRoutePerm
	switch {
	case len(actions) > 0 && len(subjects) > 0:
		for _, a := range uniq(actions) {
			for _, s := range uniq(subjects) {
				tok := a + ":" + s
				if isValidRouteToken(tok) {
					out = append(out, tok)
					if len(out) >= 16 {
						break
					}
				}
			}
			if len(out) >= 16 {
				break
			}
		}
	case (len(actions) > 0 || len(actRefs) > 0) && (len(subjects) > 0 || len(subjRefs) > 0):
		for _, ar := range actRefs {
			for _, sr := range subjRefs {
				uout = append(uout, UnresolvedRoutePerm{Action: ar, Subject: sr})
			}
			for _, s := range uniq(subjects) {
				uout = append(uout, UnresolvedRoutePerm{Action: ar, SubjectLit: s})
			}
		}
		for _, a := range uniq(actions) {
			for _, sr := range subjRefs {
				uout = append(uout, UnresolvedRoutePerm{ActionLit: a, Subject: sr})
			}
		}
	case len(actions) > 0:
		out = append(out, actions...)
	case len(subjects) > 0:
		out = append(out, subjects...)
	case len(actRefs) > 0:
		for _, ar := range actRefs {
			uout = append(uout, UnresolvedRoutePerm{Action: ar})
		}
	case len(subjRefs) > 0:
		for _, sr := range subjRefs {
			uout = append(uout, UnresolvedRoutePerm{Subject: sr})
		}
	}
	out = append(out, nested...)
	uout = append(uout, nestedUnres...)
	if len(out) == 0 && len(uout) == 0 {
		out = append(out, named...)
		for _, nr := range namedRefs {
			uout = append(uout, UnresolvedRoutePerm{Action: nr})
		}
	}
	return out, uout
}

func (x *extractor) collectMetaPermFields(
	po *js.ObjectExpr,
	depth int,
	visiting map[js.INode]bool,
	actions, subjects, nested, named *[]string,
	actRefs, subjRefs, namedRefs *[]*ConstRef,
	nestedUnres *[]UnresolvedRoutePerm,
) {
	if po == nil || depth > 4 || visiting[po] {
		return
	}
	visiting[po] = true
	defer delete(visiting, po)

	collectRefs := func(val js.IExpr, dst *[]*ConstRef) {
		val = unwrapEnumGroup(val)
		if arr, ok := val.(*js.ArrayExpr); ok {
			for _, el := range arr.List {
				if !el.Spread && el.Value != nil {
					if r, rok := x.extractConstRef(el.Value); rok {
						*dst = append(*dst, r)
					}
				}
			}
			return
		}
		if r, rok := x.extractConstRef(val); rok {
			*dst = append(*dst, r)
		}
	}

	for _, p := range po.List {
		if p.Spread {
			if so, ok := x.object(p.Value); ok {
				x.collectMetaPermFields(so, depth+1, visiting, actions, subjects, nested, named, actRefs, subjRefs, namedRefs, nestedUnres)
			}
			continue
		}
		if p.Name == nil || p.Value == nil {
			continue
		}
		switch propName(p.Name) {
		case "action", "actions", "act", "I", "do":
			toks := x.metaAuthzTokens(p.Value)
			if len(toks) > 0 {
				*actions = append(*actions, toks...)
			} else {
				collectRefs(p.Value, actRefs)
			}
		case "object", "objects", "subject", "subjects", "resource", "resources", "entity", "entities", "target", "a", "this", "on":
			toks := x.metaAuthzTokens(p.Value)
			if len(toks) > 0 {
				*subjects = append(*subjects, toks...)
			} else {
				collectRefs(p.Value, subjRefs)
			}
		case "permissions", "permission", "perms", "perm", "privilege", "privileges":
			ps, us := x.metaPermValuesWithRefs(p.Value, depth+1)
			*nested = append(*nested, ps...)
			*nestedUnres = append(*nestedUnres, us...)
		case "code", "name", "key":
			if vals, ok := x.resolveMetaAuthz(p.Value, false); ok && len(vals) > 0 {
				*named = append(*named, vals...)
			} else {
				collectRefs(p.Value, namedRefs)
			}
		}
	}
}

func (x *extractor) metaStrings(e js.IExpr) []string {
	if e == nil {
		return nil
	}
	e = unwrapEnumGroup(e)
	switch n := e.(type) {
	case *js.ArrayExpr:
		var out []string
		for _, el := range n.List {
			if !el.Spread && el.Value != nil {
				out = append(out, x.metaStrings(el.Value)...)
			}
		}
		return out
	default:
		if vals, ok := x.resolveMetaAuthz(n, false); ok && len(vals) > 0 {
			return vals
		}
		s, _, ok := x.routePathValue(n, true)
		if ok && isValidRouteToken(s) {
			return []string{s}
		}
	}
	return nil
}

func isValidRouteToken(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	return !strings.ContainsAny(s, " \t\r\n<>\"'`\\{}")
}

func boolValue(e js.IExpr) (bool, bool) {
	if e == nil {
		return false, false
	}
	switch n := unwrapEnumGroup(e).(type) {
	case *js.LiteralExpr:
		switch n.TokenType {
		case js.TrueToken:
			return true, true
		case js.FalseToken:
			return false, true
		}
	case *js.UnaryExpr:
		// Terser minifies `true` -> `!0` and `false` -> `!1`.
		if n.Op == js.NotToken {
			if l, ok := unwrapEnumGroup(n.X).(*js.LiteralExpr); ok && (l.TokenType == js.DecimalToken || l.TokenType == js.IntegerToken) {
				switch string(l.Data) {
				case "0":
					return true, true
				case "1":
					return false, true
				}
			}
		}
	}
	return false, false
}

func (x *extractor) objectLine(obj *js.ObjectExpr) int {
	lits := collectNodeLits(obj)
	if len(lits) > 0 {
		return x.litLine(lits[0])
	}
	return 0
}

func unwrapCallee(e js.IExpr) js.IExpr {
	for e != nil {
		switch n := e.(type) {
		case *js.GroupExpr:
			e = n.X
			continue
		case *js.CommaExpr:
			if len(n.List) > 0 {
				e = n.List[len(n.List)-1]
				continue
			}
		case *js.CallExpr:
			// Webpack 4 ESM call wrapper: Object(r.createRouter)(...)
			if v, ok := n.X.(*js.Var); ok && string(v.Data) == "Object" && len(n.Args.List) == 1 && !n.Args.List[0].Rest {
				e = n.Args.List[0].Value
				continue
			}
		}
		break
	}
	return e
}

func calleeIdentOrProp(e js.IExpr) (ident, prop string) {
	switch n := unwrapCallee(e).(type) {
	case *js.Var:
		return string(n.Data), ""
	case *js.DotExpr:
		return "", propName(n.Y)
	}
	return "", ""
}

func (x *extractor) sortedRouteEntries() []RouteEntry {
	if len(x.routeOrder) == 0 {
		return nil
	}
	out := make([]RouteEntry, 0, len(x.routeOrder))
	for _, p := range x.routeOrder {
		if x.bases[strings.TrimRight(p, "/")] {
			continue
		}
		if re := x.routeMap[p]; re != nil {
			out = append(out, *re)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
