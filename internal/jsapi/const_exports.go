package jsapi

import (
	"sort"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

const (
	maxConstDictsPerScript = 128
	maxConstKeysPerDict    = 1024
	maxUnresolvedPerScript = 512
)

// ConstDict holds static string/enum constants exported by a bundler or ES module
// so cross-chunk RBAC/permission references (e.g. `o.a.READ`, `e.PERMISSION.CREATE`)
// can be resolved cleanly during multi-script intelligence aggregation.
type ConstDict struct {
	Module string            `json:"module"`
	Export string            `json:"export"`
	Values map[string]string `json:"values,omitempty"`
	Scalar string            `json:"scalar,omitempty"`
}

// ConstRef identifies a symbolic member lookup into an imported module's export.
type ConstRef struct {
	Module string `json:"module"`
	Export string `json:"export"`
	Key    string `json:"key"`
}

// UnresolvedRoutePerm records a route role or permission expression whose
// constant dictionary lives in another chunk.
type UnresolvedRoutePerm struct {
	Path       string    `json:"path"`
	IsRole     bool      `json:"is_role,omitempty"`
	Action     *ConstRef `json:"action,omitempty"`
	ActionLit  string    `json:"action_lit,omitempty"`
	Subject    *ConstRef `json:"subject,omitempty"`
	SubjectLit string    `json:"subject_lit,omitempty"`
}

// UnresolvedAuthzRule records a client-side guard or CASL call whose action or
// subject references a constant dictionary in another chunk.
type UnresolvedAuthzRule struct {
	Kind       string    `json:"kind"` // "role", "perm", "rule"
	Action     *ConstRef `json:"action,omitempty"`
	ActionLit  string    `json:"action_lit,omitempty"`
	Subject    *ConstRef `json:"subject,omitempty"`
	SubjectLit string    `json:"subject_lit,omitempty"`
}

// SymConstPrefix marks a symbolic cross-module ConstRef embedded at the head of
// an exported constant string (e.g. `$jsh_const[77747|c|gateway]/svc-a/items`)
// so multi-hop constant dictionaries across chunks resolve transitively.
const SymConstPrefix = "$jsh_const["

// EncodeSymConst formats a ConstRef as a printable symbolic prefix token.
func EncodeSymConst(ref *ConstRef) string {
	if ref == nil || ref.Module == "" || ref.Export == "" {
		return ""
	}
	if strings.ContainsAny(ref.Module+ref.Export+ref.Key, "[]|\r\n\x00") {
		return ""
	}
	return SymConstPrefix + ref.Module + "|" + ref.Export + "|" + ref.Key + "]"
}

// DecodeSymConstPrefix parses a leading `$jsh_const[mod|exp|key]` prefix token
// and returns (mod, exp, key, suffixRest, true).
func DecodeSymConstPrefix(s string) (mod, exp, key, rest string, ok bool) {
	if !strings.HasPrefix(s, SymConstPrefix) {
		return "", "", "", "", false
	}
	body := s[len(SymConstPrefix):]
	end := strings.IndexByte(body, ']')
	if end <= 0 {
		return "", "", "", "", false
	}
	head := body[:end]
	p1 := strings.IndexByte(head, '|')
	if p1 <= 0 {
		return "", "", "", "", false
	}
	p2 := strings.IndexByte(head[p1+1:], '|')
	if p2 < 0 {
		return "", "", "", "", false
	}
	p2 += p1 + 1
	mod, exp, key = head[:p1], head[p1+1:p2], head[p2+1:]
	if mod == "" || exp == "" {
		return "", "", "", "", false
	}
	return mod, exp, key, body[end+1:], true
}

// IsValidAuthzToken reports whether s is a valid RBAC role or permission token
// (and not a URL or symbolic constant reference).
func IsValidAuthzToken(s string) bool {
	if strings.HasPrefix(s, SymConstPrefix) || strings.Contains(s, "://") || strings.HasPrefix(s, "/") {
		return false
	}
	return isValidAuthzToken(s)
}

func isConstURLOrPathScalar(s string) bool {
	if strings.HasPrefix(s, SymConstPrefix) || strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return !strings.ContainsAny(s, " \t")
	}
	return strings.HasPrefix(s, "/") && len(s) > 1 && !strings.HasPrefix(s, "//") && !strings.ContainsAny(s, " \t")
}

func isValidConstScalar(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	return !strings.ContainsAny(s, "\r\n\x00<>\"'`\\{}")
}

func (x *extractor) evalConstScalar(e js.IExpr) (string, bool) {
	if e == nil {
		return "", false
	}
	e = ungroup(e)
	if s, ok := literalString(e); ok {
		if isValidConstScalar(s) {
			return s, true
		}
		return "", false
	}
	if isLiteralNonString(e) {
		return "", false
	}
	savedNoMark := x.noMarkUsed
	savedSym := x.symConstMode
	x.noMarkUsed = true
	x.symConstMode = true
	vals := x.eval(e, nil, 0)
	x.symConstMode = savedSym
	x.noMarkUsed = savedNoMark
	if len(vals) == 1 && !strings.Contains(vals[0], unknown) && isValidConstScalar(vals[0]) {
		// Reject nested or mid-string symbolic tokens; allow at most one leading token.
		if idx := strings.Index(vals[0], SymConstPrefix); idx > 0 || (idx == 0 && strings.Contains(vals[0][len(SymConstPrefix):], SymConstPrefix)) {
			return "", false
		}
		return vals[0], true
	}
	return "", false
}

func (x *extractor) extractConstDictExpr(e js.IExpr) (vals map[string]string, scalar string, ok bool) {
	if e == nil {
		return nil, "", false
	}
	e = ungroup(e)
	if ev := x.enumVar(e, 0); ev != nil {
		em := x.enumProps[ev]
		if len(em) > 0 && len(em) <= maxConstKeysPerDict {
			out := map[string]string{}
			for k, ve := range em {
				if k == "" || len(out) >= maxConstKeysPerDict {
					continue
				}
				if s, sok := x.evalConstScalar(ve); sok {
					out[k] = s
				}
			}
			if len(out) > 0 {
				return out, "", true
			}
		}
	}
	if cls := x.classOfExpr(e); cls != nil {
		if info := x.classes[cls]; info != nil && len(info.staticFields) > 0 && len(info.staticFields) <= 4*maxConstKeysPerDict {
			ks := make([]string, 0, len(info.staticFields))
			for k := range info.staticFields {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			out := map[string]string{}
			for _, k := range ks {
				if k == "" || len(out) >= maxConstKeysPerDict {
					continue
				}
				ve := info.staticFields[k]
				if s, sok := x.evalConstScalar(ve); sok {
					out[k] = s
					continue
				}
				if subEv := x.enumVar(ve, 1); subEv != nil {
					subKeys := make([]string, 0, len(x.enumProps[subEv]))
					for sk := range x.enumProps[subEv] {
						subKeys = append(subKeys, sk)
					}
					sort.Strings(subKeys)
					for _, sk := range subKeys {
						if sk == "" || len(out) >= maxConstKeysPerDict {
							break
						}
						if s, sok := x.evalConstScalar(x.enumProps[subEv][sk]); sok {
							out[k+"."+sk] = s
						}
					}
					continue
				}
				if subObj, subOK := x.objectN(ve, 1); subOK && subObj != nil && !isSchemaOrUIDescriptor(subObj) && len(subObj.List) <= 64 {
					for j := range subObj.List {
						sp := &subObj.List[j]
						if sp.Spread || sp.Name == nil || sp.Value == nil || len(out) >= maxConstKeysPerDict {
							continue
						}
						sk := propKey(sp)
						if sk == "" {
							continue
						}
						if s, sok := x.evalConstScalar(sp.Value); sok {
							out[k+"."+sk] = s
						}
					}
				}
			}
			if len(out) > 0 {
				return out, "", true
			}
		}
	}
	if obj, isObj := x.objectN(e, 0); isObj && obj != nil && !isSchemaOrUIDescriptor(obj) && len(obj.List) > 0 && len(obj.List) <= maxConstKeysPerDict {
		out := map[string]string{}
		for i := range obj.List {
			p := &obj.List[i]
			if p.Spread || p.Name == nil || p.Value == nil || len(out) >= maxConstKeysPerDict {
				continue
			}
			k := propKey(p)
			if k == "" || k == "__esModule" {
				continue
			}
			if s, sok := x.evalConstScalar(p.Value); sok {
				out[k] = s
				continue
			}
			if subEv := x.enumVar(p.Value, 1); subEv != nil {
				for sk, sve := range x.enumProps[subEv] {
					if sk == "" || len(out) >= maxConstKeysPerDict {
						break
					}
					if s, sok := x.evalConstScalar(sve); sok {
						out[k+"."+sk] = s
					}
				}
				continue
			}
			if subObj, subOK := x.objectN(p.Value, 1); subOK && subObj != nil && !isSchemaOrUIDescriptor(subObj) && len(subObj.List) <= 64 {
				for j := range subObj.List {
					sp := &subObj.List[j]
					if sp.Spread || sp.Name == nil || sp.Value == nil || len(out) >= maxConstKeysPerDict {
						continue
					}
					sk := propKey(sp)
					if sk == "" {
						continue
					}
					if s, sok := x.evalConstScalar(sp.Value); sok {
						out[k+"."+sk] = s
					}
				}
			}
		}
		if len(out) > 0 {
			return out, "", true
		}
	}
	if s, sok := x.evalConstScalar(e); sok && (isValidAuthzToken(s) || isConstURLOrPathScalar(s)) {
		return nil, s, true
	}
	return nil, "", false
}

func (x *extractor) collectConstExports() []ConstDict {
	var out []ConstDict
	seen := map[[2]string]bool{}
	add := func(mod, exp string, expr js.IExpr) {
		if len(out) >= maxConstDictsPerScript || exp == "" || expr == nil {
			return
		}
		k := [2]string{mod, exp}
		if seen[k] {
			return
		}
		vals, scalar, ok := x.extractConstDictExpr(expr)
		if !ok {
			return
		}
		seen[k] = true
		out = append(out, ConstDict{Module: mod, Export: exp, Values: vals, Scalar: scalar})
	}

	modIDs := make([]string, 0, len(x.wpModExports)+len(x.wpModDefault))
	modSet := map[string]bool{}
	for m := range x.wpModExports {
		modSet[m] = true
	}
	for m := range x.wpModDefault {
		modSet[m] = true
	}
	for m := range modSet {
		modIDs = append(modIDs, m)
	}
	sort.Strings(modIDs)
	for _, mod := range modIDs {
		if em := x.wpModExports[mod]; len(em) > 0 {
			eks := make([]string, 0, len(em))
			for ek := range em {
				eks = append(eks, ek)
			}
			sort.Strings(eks)
			for _, ek := range eks {
				add(mod, ek, em[ek])
			}
		}
		if def := x.wpModDefault[mod]; def != nil {
			add(mod, "*", def)
		}
	}

	if len(x.turbopackConst) > 0 {
		tks := make([][2]string, 0, len(x.turbopackConst))
		for k := range x.turbopackConst {
			tks = append(tks, k)
		}
		sort.Slice(tks, func(i, j int) bool {
			if tks[i][0] != tks[j][0] {
				return tks[i][0] < tks[j][0]
			}
			return tks[i][1] < tks[j][1]
		})
		for _, k := range tks {
			add(k[0], k[1], x.turbopackConst[k])
		}
	}

	if len(x.esExports) > 0 {
		eks := make([]string, 0, len(x.esExports))
		for ek := range x.esExports {
			eks = append(eks, ek)
		}
		sort.Strings(eks)
		for _, ek := range eks {
			add("", ek, x.esExports[ek])
		}
	}
	return out
}

// importRootBinding resolves whether expr is an imported module namespace or
// imported export binding (`o = n("1234")`, `H = M.i(12)`, `import { P } from "./c.js"`).
func (x *extractor) importRootBinding(e js.IExpr, depth int) (mod, exp string, ok bool) {
	if depth >= 8 || e == nil {
		return "", "", false
	}
	e = ungroup(e)
	if modID, wok := x.wpRequireModID(e, 0); wok {
		return modID, "", true
	}
	switch n := e.(type) {
	case *js.Var:
		rv := root(n)
		if im, eok := x.esImports[rv]; eok {
			return im[0], im[1], true
		}
		if ns, nok := x.esNSImports[rv]; nok {
			return ns, "", true
		}
		if c := x.constOrSingleExpr(rv); c != nil && c != e {
			if ic, cok := ungroup(c).(*js.CallExpr); cok && len(ic.Args.List) == 1 {
				if id, iok := moduleID(ic.Args.List[0].Value); iok {
					if dd, dok := ungroup(ic.X).(*js.DotExpr); dok && propName(dd.Y) == "i" {
						return id, "", true
					}
				}
			}
			return x.importRootBinding(c, depth+1)
		}
	case *js.DotExpr:
		prop := propName(n.Y)
		if prop == "" {
			return "", "", false
		}
		if x.isThis(n.X) {
			if m, ex, tok := x.thisPropImportBinding(prop, depth+1); tok {
				return m, ex, true
			}
			return "", "", false
		}
		if m, ex, rok := x.importRootBinding(n.X, depth+1); rok && ex == "" {
			return m, prop, true
		}
	}
	return "", "", false
}

func (x *extractor) thisPropImportBinding(name string, depth int) (mod, exp string, ok bool) {
	if name == "" || depth >= 8 {
		return "", "", false
	}
	vs := x.thisProps[name]
	if len(vs) == 0 || len(vs) > 256 {
		return "", "", false
	}
	m0, e0, ok0 := x.importRootBinding(vs[0], depth+1)
	if !ok0 {
		return "", "", false
	}
	for _, v := range vs[1:] {
		mi, ei, oki := x.importRootBinding(v, depth+1)
		if !oki || mi != m0 || ei != e0 {
			return "", "", false
		}
	}
	return m0, e0, true
}

// extractConstRef inspects an unresolved member expression (`o.a.READ`,
// `o.READ`, `o.a.PERM.READ`, `PERM.READ`, or `this.PERMISSION.CREATE`) and
// returns a symbolic cross-chunk ConstRef when rooted at a module import.
func (x *extractor) extractConstRef(e js.IExpr) (*ConstRef, bool) {
	if e == nil {
		return nil, false
	}
	e = ungroup(e)
	if vr, ok := e.(*js.Var); ok {
		if im, eok := x.esImports[root(vr)]; eok && im[0] != "" && im[1] != "" {
			return &ConstRef{Module: im[0], Export: im[1]}, true
		}
		if c := x.constOrSingleExpr(vr); c != nil && c != e {
			e = ungroup(c)
		}
	}

	var tail []string
	cur := e
	for len(tail) < 3 {
		switch t := ungroup(cur).(type) {
		case *js.DotExpr:
			p := propName(t.Y)
			if p == "" {
				return nil, false
			}
			if m, ex, ok := x.importRootBinding(t.X, 0); ok {
				if ex == "" {
					if len(tail) == 0 {
						// Direct `o.READ` on CJS `o = n("1234")` -> Export "*", Key "READ".
						return &ConstRef{Module: m, Export: "*", Key: p}, true
					}
					// `o.a.READ` or `o.a.PERM.READ` -> Export "a", Key "READ" / "PERM.READ".
					reverseStrings(tail)
					return &ConstRef{Module: m, Export: p, Key: strings.Join(tail, ".")}, true
				}
				// `t.X` already named export `ex` (e.g. `import { PERM } from "./c"` or `this.PERMISSION` -> `o.a`).
				tail = append(tail, p)
				reverseStrings(tail)
				return &ConstRef{Module: m, Export: ex, Key: strings.Join(tail, ".")}, true
			}
			tail = append(tail, p)
			cur = t.X
			continue
		case *js.IndexExpr:
			k, kok := literalString(t.Y)
			if !kok || k == "" {
				return nil, false
			}
			if m, ex, ok := x.importRootBinding(t.X, 0); ok {
				if ex == "" {
					if len(tail) == 0 {
						return &ConstRef{Module: m, Export: "*", Key: k}, true
					}
					reverseStrings(tail)
					return &ConstRef{Module: m, Export: k, Key: strings.Join(tail, ".")}, true
				}
				tail = append(tail, k)
				reverseStrings(tail)
				return &ConstRef{Module: m, Export: ex, Key: strings.Join(tail, ".")}, true
			}
			tail = append(tail, k)
			cur = t.X
			continue
		}
		break
	}
	return nil, false
}

func reverseStrings(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func (x *extractor) addUnresolvedRoutePerm(u UnresolvedRoutePerm) {
	if len(x.unresolvedRoutePerms) >= maxUnresolvedPerScript || u.Path == "" {
		return
	}
	x.unresolvedRoutePerms = append(x.unresolvedRoutePerms, u)
}

func (x *extractor) addUnresolvedAuthzRule(u UnresolvedAuthzRule) {
	if len(x.unresolvedAuthzRules) >= maxUnresolvedPerScript {
		return
	}
	x.unresolvedAuthzRules = append(x.unresolvedAuthzRules, u)
}
