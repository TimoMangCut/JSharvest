package jsapi

// This file: the result: endpoints, bases, headers.

import (
	"bytes"
	"slices"
	"sort"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

func (x *extractor) result() Result {
	r := Result{Version: Version, Endpoints: []Endpoint{}}
	for _, k := range x.order {
		if x.frame(k) {
			continue
		}
		ep := *x.eps[k]
		ep.Query, ep.Body, ep.Headers, ep.Operations = uniq(ep.Query), uniq(ep.Body), uniq(ep.Headers), uniq(ep.Operations)
		r.Endpoints = append(r.Endpoints, ep)
	}
	for _, e := range r.Endpoints {
		delete(x.paths, e.URL)
	}
	if x.dynBase && len(x.bases) == 0 {
		// baseURL: e.getURL(…): the strings that read as an API's root,
		// but the pages' routes or endpoint paths, are the candidates.
		epPaths := map[string]bool{}
		for _, e := range r.Endpoints {
			if e.Method == "" {
				continue
			}
			epPaths[strings.TrimRight(e.URL, "/")] = true
			if rel := strings.TrimPrefix(e.URL, unknown); rel != e.URL && strings.HasPrefix(rel, "/") {
				epPaths[strings.TrimRight(rel, "/")] = true
			}
		}
		var cands, slash []string
		for c := range x.baseCands {
			p := strings.TrimRight(c, "/")
			if p == "" || epPaths[p] || x.routes[p] && !strings.HasSuffix(c, "/") {
				continue
			}
			cands = append(cands, p)
			if strings.HasSuffix(c, "/") {
				slash = append(slash, p)
			}
		}
		if len(cands) > 1 && len(slash) > 0 {
			cands = slash
		}
		if len(cands) <= 3 {
			for _, c := range cands {
				x.bases[c] = true
			}
		}
	}
	for b := range x.bases {
		for _, p := range []string{b, b + "/"} {
			delete(x.routes, p)
			delete(x.paths, p)
		}
	}
	// A base the code names without a call to it is no endpoint.
	r.Endpoints = slices.DeleteFunc(r.Endpoints, func(e Endpoint) bool {
		return e.Method == "" && (x.bases[strings.TrimRight(e.URL, "/")])
	})
	r.Routes = sortedKeys(x.routes)
	r.RouteEntries = x.sortedRouteEntries()
	r.Paths = sortedKeys(x.paths)
	r.Bases = sortedKeys(x.bases)
	r.ClientHeaders = x.clientHeaders()
	r.Cloud = sortedKeys(x.cloud)
	r.Keys = x.keys2
	r.Exports, r.Imports, r.ReExports = x.exports, x.imports, x.reExports
	r.Builders, r.Deferred = x.builders, x.deferred
	r.DocVars = x.docVarList()
	r.DocProd = uniq(x.docProd)
	for k, vs := range x.docDev {
		for _, v := range uniq(vs) {
			r.DocDev = append(r.DocDev, Header{Name: k, Value: v})
			if p := ProdOf(v, r.DocProd); p != "" && !slices.ContainsFunc(r.DocVars, func(h Header) bool { return h.Name == k }) {
				r.DocVars = append(r.DocVars, Header{Name: k, Value: p})
			}
		}
	}
	slices.SortFunc(r.DocDev, func(a, b Header) int { return strings.Compare(a.Name+a.Value, b.Name+b.Value) })
	for i := range r.Endpoints {
		// $SLINK_HOST set by another document of the same script.
		if b := r.Endpoints[i].Base; strings.HasPrefix(b, "$") {
			for _, v := range r.DocVars {
				if v.Name == b[1:] {
					r.Endpoints[i].Base = v.Value
				}
			}
		}
	}
	for _, f := range x.factoryList {
		used := len(f.Settings) > 0
		for _, ex := range x.exports {
			used = used || ex.Factory == f.ID
		}
		if used {
			r.Factories = append(r.Factories, *f)
		}
	}
	for _, k := range sortedKeys(x.settings) {
		n, v, _ := strings.Cut(k, "\x00")
		r.Settings = append(r.Settings, Header{Name: n, Value: v})
	}
	for _, k := range sortedKeys(x.propBases) {
		n, v, _ := strings.Cut(k, "\x00")
		r.PropBases = append(r.PropBases, Header{Name: n, Value: v})
	}
	for op := range x.ops {
		if !x.opsUsed[op] {
			r.Operations = append(r.Operations, op)
		}
	}
	sort.Strings(r.Operations)
	return r
}

func uniq(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := s[:0:0]
	for _, v := range s {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// clientHeaders reads the headers put aside in pass 1, with their values,
// once each.
func (x *extractor) clientHeaders() []Header {
	var out []Header
	seen := map[string]bool{}
	for _, h := range x.headers {
		if h.name == "" {
			continue
		}
		var q []string
		x.lits = x.lits[:0]
		v := x.eval(h.value, &q, 0)[0]
		if strings.EqualFold(h.name, "Authorization") && (v == "Basic {}" || v == "Basic {}:{}") && x.isGenericBasicAuth(h.value) {
			continue
		}
		if seen[h.name+"\x00"+v] {
			continue
		}
		seen[h.name+"\x00"+v] = true
		hd := Header{Name: h.name, Value: v}
		if l, ok := h.value.(*js.LiteralExpr); ok && len(l.Data) > 2 {
			if i := bytes.Index(x.src, l.Data); i >= 0 {
				hd.Line, _ = x.lineCol(i)
			}
		}
		out = append(out, hd)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// isGenericBasicAuth reports a bundled HTTP library's generic Basic auth
// serializer (e.g. Axios reading config.auth.username and config.auth.password)
// so it does not pollute client_headers with "Authorization: Basic {}" (ENH-08).
func (x *extractor) isGenericBasicAuth(e js.IExpr) bool {
	if e == nil {
		return false
	}
	hasConcreteVal := func(ex js.IExpr) bool {
		if ex == nil {
			return false
		}
		var dummy []string
		savedLits := len(x.lits)
		vals := x.eval(ex, &dummy, 0)
		x.lits = x.lits[:savedLits]
		for _, val := range vals {
			if val != "" && !strings.Contains(val, unknown) {
				return true
			}
		}
		return false
	}
	var hasUser, hasPass, hasConcrete bool
	seen := map[*js.Var]bool{}
	var inspect func(n js.INode, depth int)
	inspect = func(n js.INode, depth int) {
		if n == nil || depth > 5 || hasConcrete {
			return
		}
		js.Walk(nodeVisitor(func(nd js.INode) bool {
			if hasConcrete {
				return false
			}
			switch t := nd.(type) {
			case *js.DotExpr:
				switch propName(t.Y) {
				case "username", "user":
					hasUser = true
					if hasConcreteVal(t) {
						hasConcrete = true
					}
				case "password", "pass":
					hasPass = true
					if hasConcreteVal(t) {
						hasConcrete = true
					}
				}
			case *js.IndexExpr:
				if s, ok := literalString(t.Y); ok {
					switch s {
					case "username", "user":
						hasUser = true
						if hasConcreteVal(t) {
							hasConcrete = true
						}
					case "password", "pass":
						hasPass = true
						if hasConcreteVal(t) {
							hasConcrete = true
						}
					}
				}
			case *js.ObjectExpr:
				for _, k := range []string{"username", "user"} {
					if v := objectValue(t, k); v != nil {
						hasUser = true
						if hasConcreteVal(v) {
							hasConcrete = true
						}
					}
				}
				for _, k := range []string{"password", "pass"} {
					if v := objectValue(t, k); v != nil {
						hasPass = true
						if hasConcreteVal(v) {
							hasConcrete = true
						}
					}
				}
			case *js.LiteralExpr:
				if s, ok := literalString(t); ok {
					switch s {
					case "username":
						hasUser = true
					case "password":
						hasPass = true
					}
				}
			case *js.Var:
				rv := root(t)
				if x.destructFrom[rv] != nil {
					switch string(t.Data) {
					case "username", "user":
						hasUser = true
						if hasConcreteVal(t) {
							hasConcrete = true
						}
					case "password", "pass":
						hasPass = true
						if hasConcreteVal(t) {
							hasConcrete = true
						}
					}
				}
				if !seen[rv] {
					seen[rv] = true
					for _, def := range x.defs[rv] {
						inspect(def, depth+1)
					}
					if df := x.destructFrom[rv]; df != nil {
						inspect(df, depth+1)
					}
				}
			}
			return !hasConcrete
		}), n)
	}
	inspect(e, 0)
	return hasUser && hasPass && !hasConcrete
}

type nodeVisitor func(js.INode) bool

func (f nodeVisitor) Enter(n js.INode) js.IVisitor {
	if f(n) {
		return f
	}
	return nil
}

func (nodeVisitor) Exit(js.INode) {}

// addBase keeps a base URL, without its trailing slash; "/" alone is the
// page's own origin, no base.
func (x *extractor) addBase(s string) {
	if s = strings.TrimRight(s, "/"); s != "" {
		x.bases[s] = true
	}
}
