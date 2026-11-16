package jsapi

import (
	"regexp"
	"slices"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

// ParamSpec is what is known of one of an endpoint's parameters (QAL-03):
// where it goes, its type, and values the code, the spec or the document
// gives it. Query, Body and Headers keep the names alone.
type ParamSpec struct {
	Name string `json:"name"`
	In   string `json:"in"` // path, query, body, header
	// Position is a path parameter's slot: the n-th {} of the path, a
	// client's base before it ({}/…) not counted.
	Position int      `json:"position,omitempty"`
	Type     string   `json:"type,omitempty"`   // string, number, boolean, array, object
	Values   []string `json:"values,omitempty"` // up to 8: constants, enums, defaults, examples
	Required bool     `json:"required,omitempty"`
}

// maxValues is how many values a parameter keeps.
const maxValues = 8

// keyInfo is what an object literal's field holds: its type, its values,
// whether it is a constant.
type keyInfo struct {
	typ    string
	values []string
	fixed  bool
}

// typeOf reads what an expression is, for a field's type and values: a
// literal, a list, an object, a lookup table's values ({day: "daily",
// month: "monthly"}[x]), a constant set to one of those.
func (x *extractor) typeOf(e js.IExpr, depth int) keyInfo {
	if e == nil || depth > 3 {
		return keyInfo{}
	}
	switch n := e.(type) {
	case *js.LiteralExpr:
		switch n.TokenType {
		case js.StringToken:
			return keyInfo{"string", []string{unquote(n.Data)}, true}
		case js.IntegerToken, js.DecimalToken:
			return keyInfo{"number", []string{string(n.Data)}, true}
		case js.TrueToken, js.FalseToken:
			return keyInfo{"boolean", []string{string(n.Data)}, true}
		}
	case *js.TemplateExpr:
		if n.Tag == nil && len(n.List) == 0 {
			return keyInfo{"string", []string{string(templateText(n.Tail, true, true))}, true}
		}
		return keyInfo{typ: "string"}
	case *js.UnaryExpr:
		switch n.Op {
		case js.NotToken:
			if l, ok := n.X.(*js.LiteralExpr); ok && l.TokenType == js.IntegerToken {
				// !0, !1: minified true and false.
				v := "true"
				if string(l.Data) != "0" {
					v = "false"
				}
				return keyInfo{"boolean", []string{v}, true}
			}
			return keyInfo{typ: "boolean"}
		case js.NegToken:
			if in := x.typeOf(n.X, depth+1); in.typ == "number" {
				for i, v := range in.values {
					in.values[i] = "-" + v
				}
				return in
			}
		case js.TypeofToken:
			return keyInfo{typ: "string"}
		}
	case *js.ArrayExpr:
		return keyInfo{typ: "array"}
	case *js.ObjectExpr:
		return keyInfo{typ: "object"}
	case *js.CondExpr:
		a, b := x.typeOf(n.X, depth+1), x.typeOf(n.Y, depth+1)
		if a.typ == b.typ {
			return keyInfo{typ: a.typ, values: uniqLimit(append(a.values, b.values...))}
		}
	case *js.IndexExpr:
		// {day: "daily", month: "monthly"}[n]
		if obj, ok := x.object(n.X); ok {
			var vals []string
			for _, p := range obj.List {
				if s, ok := literalString(p.Value); ok && !p.Spread {
					vals = append(vals, s)
				} else {
					return keyInfo{}
				}
			}
			if len(vals) > 0 {
				return keyInfo{typ: "string", values: uniqLimit(vals)}
			}
		}
	case *js.CallExpr:
		if d, ok := n.X.(*js.DotExpr); ok {
			switch propName(d.Y) {
			case "map", "filter", "flatMap", "slice", "concat":
				return keyInfo{typ: "array"}
			case "toString", "toISOString", "trim", "join", "toUpperCase", "toLowerCase", "format":
				return keyInfo{typ: "string"}
			case "stringify":
				if isGlobal(d.X, "JSON") {
					return keyInfo{typ: "string"}
				}
			case "from":
				if isGlobal(d.X, "Array") {
					return keyInfo{typ: "array"}
				}
			}
		}
		switch globalName(n.X) {
		case "Number", "parseInt", "parseFloat":
			return keyInfo{typ: "number"}
		case "String", "encodeURIComponent":
			return keyInfo{typ: "string"}
		case "Boolean":
			return keyInfo{typ: "boolean"}
		}
	case *js.Var:
		if c := x.constant(n); c != nil {
			in := x.typeOf(c, depth+1)
			in.fixed = false
			return in
		}
	case *js.GroupExpr:
		return x.typeOf(n.X, depth+1)
	}
	return keyInfo{}
}

func uniqLimit(vals []string) []string {
	var out []string
	for _, v := range vals {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
		if len(out) == maxValues {
			break
		}
	}
	return out
}

// noteKey records what a field of an object literal the call being read
// gives holds.
func (x *extractor) noteKey(name string, v js.IExpr) {
	if x.keyInfo == nil {
		return
	}
	in := x.typeOf(v, 0)
	if in.typ == "" {
		return
	}
	if old, ok := x.keyInfo[name]; ok {
		if old.typ != in.typ {
			return
		}
		in.values = uniqLimit(append(old.values, in.values...))
		in.fixed = in.fixed && old.fixed
	}
	x.keyInfo[name] = in
}

// specsOf are the parameters of an endpoint the call being read adds: its
// body, query and header names with what their object literals hold, and
// its path's names (pathNames, by slot).
func (x *extractor) specsOf(ep *Endpoint, names []string) []ParamSpec {
	var out []ParamSpec
	for i, n := range names {
		if n != "" {
			out = append(out, ParamSpec{Name: n, In: "path", Position: i, Type: "string", Required: true})
		}
	}
	add := func(in string, keys []string) {
		for _, k := range uniq(slices.Clone(keys)) {
			info, ok := x.keyInfo[k]
			if !ok {
				continue
			}
			out = append(out, ParamSpec{Name: k, In: in, Type: info.typ, Values: info.values, Required: info.fixed})
		}
	}
	// files.content_type: files, the list holding it, too.
	parents := func(keys []string) []string {
		var out []string
		for _, k := range keys {
			for i := strings.LastIndexByte(k, '.'); i > 0; i = strings.LastIndexByte(k[:i], '.') {
				if info, ok := x.keyInfo[k[:i]]; ok && (info.typ == "array" || info.typ == "object") {
					out = append(out, k[:i])
				}
			}
		}
		return out
	}
	add("body", append(slices.Clone(ep.Body), parents(ep.Body)...))
	add("query", ep.Query)
	add("header", ep.Headers)
	return out
}

// mergeSpecs adds what b knows of a's parameters, and b's others.
func mergeSpecs(a, b []ParamSpec) []ParamSpec {
	for _, p := range b {
		i := slices.IndexFunc(a, func(q ParamSpec) bool { return q.Name == p.Name && q.In == p.In })
		if i < 0 {
			a = append(a, p)
			continue
		}
		q := &a[i]
		if q.Type == "" {
			q.Type = p.Type
		}
		if q.Type == p.Type || p.Type == "" {
			q.Values = uniqLimit(append(q.Values, p.Values...))
		}
		q.Required = q.Required || p.Required
	}
	return a
}

// MergeParams is mergeSpecs for the catalog.
func MergeParams(a, b []ParamSpec) []ParamSpec {
	return mergeSpecs(slices.Clone(a), b)
}

// minifiedName is a name a minifier makes (e, t, n…), which says nothing.
var minifiedName = regexp.MustCompile(`^[a-zA-Z_$][a-zA-Z0-9_$]?$`)

// exprName is the name a URL's part is given in the code: a variable's
// (tenantId), a property's (e.appSlug), what a function encoding it is
// given (encodeURIComponent(conversationId)).
func exprName(e js.IExpr, depth int) string {
	if depth > 3 {
		return ""
	}
	switch n := e.(type) {
	case *js.Var:
		if s := string(n.Data); !minifiedName.MatchString(s) {
			return s
		}
	case *js.DotExpr:
		if s := propName(n.Y); !minifiedName.MatchString(s) || s == "id" {
			return s
		}
	case *js.CallExpr:
		if len(n.Args.List) == 1 {
			return exprName(n.Args.List[0].Value, depth+1)
		}
	case *js.GroupExpr:
		return exprName(n.X, depth+1)
	}
	return ""
}

// pathNames are the names of a URL template's parts, by the slot each
// makes ({} in the path), the base a template starts with not counted: for
// `${base}/tenants/${tenantId}/apps/${e.appSlug}`, tenantId and appSlug.
// Nothing when the template is not found or names none.
func (x *extractor) pathNames(u js.IExpr) []string {
	var tpl *js.TemplateExpr
	for i := 0; i < 4 && tpl == nil; i++ {
		switch n := u.(type) {
		case *js.TemplateExpr:
			tpl = n
		case *js.Var:
			c := x.constant(n)
			if c == nil {
				return nil
			}
			u = c
		case *js.CallExpr:
			if len(n.Args.List) == 0 {
				return nil
			}
			u = n.Args.List[0].Value
		case *js.BinaryExpr:
			u = n.X
		case *js.GroupExpr:
			u = n.X
		default:
			return nil
		}
	}
	if tpl == nil || tpl.Tag != nil {
		return nil
	}
	var names []string
	any := false
	for i, p := range tpl.List {
		if i == 0 && len(templateText(p.Value, true, false)) == 0 {
			continue // `${base}/x`: the base, no parameter
		}
		n := exprName(p.Expr, 0)
		any = any || n != ""
		names = append(names, n)
	}
	if !any {
		return nil
	}
	return names
}

// pathSlots is how many parameters a path has: its {}, a base before it
// not counted.
func pathSlots(path string) int {
	return strings.Count(strings.TrimPrefix(path, unknown), unknown)
}

// byNameRe is a path's segment that names the one after it: by-slug/{}.
var byNameRe = regexp.MustCompile(`^by-([a-z][a-z0-9_]*)$`)

// slotNames fills the names the code does not give (a minified e) where
// the path itself says it: /apps/by-slug/{} is a slug.
func slotNames(path string, names []string) []string {
	n := pathSlots(path)
	if n == 0 {
		return names
	}
	if len(names) != n {
		names = make([]string, n)
	} else {
		names = slices.Clone(names)
	}
	segs := strings.Split(strings.TrimPrefix(path, unknown), "/")
	slot := 0
	for i, sg := range segs {
		if !strings.Contains(sg, unknown) {
			continue
		}
		if sg == unknown && i > 0 && names[slot] == "" {
			if m := byNameRe.FindStringSubmatch(segs[i-1]); m != nil {
				names[slot] = m[1]
			}
		}
		slot += strings.Count(sg, unknown)
	}
	return names
}
