package jsapi

import (
	"bytes"
	"regexp"
	"sort"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

const maxAuthzPerScript = 1024

// AuthzRule is a client-side CASL / ABAC capability rule (action + optional subject).
type AuthzRule struct {
	Action  string `json:"action"`
	Subject string `json:"subject,omitempty"`
}

// ClientAuthz holds the client-side authorization surface statically extracted
// from one script's AST: roles, permissions, and CASL capability rules.
type ClientAuthz struct {
	Roles       []string    `json:"roles,omitempty"`
	Permissions []string    `json:"permissions,omitempty"`
	Rules       []AuthzRule `json:"rules,omitempty"`
}

var (
	guardCallRe     = regexp.MustCompile(`^(?:has|check|require|is)(?:Any|All)?(?:Permission|Role|Authority|Authorities|Scope|Privilege)s?$`)
	authzDictNameRe = regexp.MustCompile(`(?i)^(?:(?:USER_?)?ROLES?|(?:(?:APP|USER)_?)?PERMISSIONS?|AUTHORITIES)$`)
	upperDictNameRe = regexp.MustCompile(`^(?:(?:USER_)?ROLES?|(?:(?:APP|USER)_)?PERMISSIONS?|AUTHORITIES)$`)
)

// schemaOrUIKeys are object keys that indicate a Vue/React prop definition,
// JSON Schema property, or UI table column descriptor rather than a role/permission dictionary.
var schemaOrUIKeys = map[string]bool{
	"type": true, "required": true, "validator": true, "default": true,
	"render": true, "component": true, "dataIndex": true, "sortable": true,
	"placeholder": true, "className": true, "style": true, "$ref": true,
	"properties": true, "align": true, "width": true, "format": true,
	"title": true, "label": true,
}

var authzHintTokens = [][]byte{
	[]byte(".can"), []byte("$can"), []byte("cannot"), []byte("(can"),
	[]byte(`["can"]`), []byte(`['can']`), []byte("Can"), []byte("Ability"),
	[]byte("role"), []byte("Role"), []byte("ROLE"),
	[]byte("perm"), []byte("Perm"), []byte("PERM"),
	[]byte("authorit"), []byte("Authorit"), []byte("AUTHORIT"),
	[]byte("Auth"), []byte("AUTH"), []byte("Scope"), []byte("Privilege"),
}

func hasAuthzHint(src []byte, hasCanVar bool) bool {
	if hasCanVar {
		return true
	}
	for _, tok := range authzHintTokens {
		if bytes.Contains(src, tok) {
			return true
		}
	}
	return false
}

func hasAuthzPass1Hint(src []byte) bool {
	return bytes.Contains(src, []byte("Can")) ||
		bytes.Contains(src, []byte("Ability")) ||
		bytes.Contains(src, []byte("(can"))
}

func extractClientAuthz(ast *js.AST, x *extractor) *ClientAuthz {
	if ast == nil || x == nil {
		return nil
	}
	canVars := map[*js.Var]bool{}
	canCompVars := map[*js.Var]bool{}
	for v, prop := range x.propOf {
		if (prop == "can" || prop == "cannot") && isAbilityDestructSource(x.destructFrom[v]) {
			canVars[v] = true
		}
	}
	if !hasAuthzHint(x.src, len(canVars) > 0) {
		return nil
	}

	savedNoMark := x.noMarkUsed
	savedLits := len(x.lits)
	savedBudget := x.callBudget
	x.noMarkUsed = true
	defer func() {
		x.noMarkUsed = savedNoMark
		x.lits = x.lits[:savedLits]
		x.callBudget = savedBudget
	}()

	// Pass 1: index CASL callback builder variables (`defineAbility((can, cannot) => ...)`),
	// and `<Can>` component variables (`createContextualCan`, `resolveComponent("Can")`).
	if hasAuthzPass1Hint(x.src) {
		js.Walk(walker(func(n js.INode) {
			switch t := n.(type) {
			case *js.VarDecl:
				for _, b := range t.List {
					vr, ok := b.Binding.(*js.Var)
					if !ok || b.Default == nil {
						continue
					}
					if isCanCompInit(b.Default) {
						canCompVars[root(vr)] = true
					}
				}
			case *js.CallExpr:
				markCASLBuilderParams(t, canVars)
			}
		}), ast)
	}

	roles := map[string]bool{}
	perms := map[string]bool{}
	rules := map[AuthzRule]bool{}

	addRole := func(s string) {
		if len(roles) < maxAuthzPerScript && isValidAuthzToken(s) {
			roles[s] = true
		}
	}
	addPerm := func(s string) {
		if len(perms) < maxAuthzPerScript && isValidAuthzToken(s) {
			perms[s] = true
		}
	}
	addRule := func(action, subject string) {
		if len(rules) >= maxAuthzPerScript || !isValidAuthzToken(action) {
			return
		}
		if subject != "" && !isValidAuthzToken(subject) {
			return
		}
		rules[AuthzRule{Action: action, Subject: subject}] = true
	}
	addDictValue := func(dictName, val string) {
		if strings.Contains(strings.ToLower(dictName), "role") {
			addRole(val)
		} else {
			addPerm(val)
		}
	}

	// Pass 2: collect Sources A (CASL), B (Guard helpers), and C (Constant dictionaries / TS enums).
	js.Walk(walker(func(n js.INode) {
		switch t := n.(type) {
		case *js.CallExpr:
			extractCallAuthz(t, x, canVars, canCompVars, addRole, addPerm, addRule)
			extractEnumIIFEAuthz(t, addDictValue)
		case *js.VarDecl:
			for _, b := range t.List {
				vr, ok := b.Binding.(*js.Var)
				if !ok || b.Default == nil {
					continue
				}
				name := string(vr.Data)
				if !authzDictNameRe.MatchString(name) {
					continue
				}
				if obj := unwrapDictObject(b.Default); obj != nil {
					extractDictObjectValues(obj, 0, func(v string) { addDictValue(name, v) })
				}
			}
		case *js.BinaryExpr:
			if t.Op != js.EqToken {
				return
			}
			switch lhs := t.X.(type) {
			case *js.DotExpr:
				pname := propName(lhs.Y)
				if authzDictNameRe.MatchString(pname) {
					if obj := unwrapDictObject(t.Y); obj != nil {
						extractDictObjectValues(obj, 0, func(v string) { addDictValue(pname, v) })
						return
					}
				}
				if vr, ok := lhs.X.(*js.Var); ok && upperDictNameRe.Match(vr.Data) && !schemaOrUIKeys[pname] {
					if s, ok := literalString(t.Y); ok {
						addDictValue(string(vr.Data), s)
					}
				}
			case *js.IndexExpr:
				if vr, ok := lhs.X.(*js.Var); ok && upperDictNameRe.Match(vr.Data) {
					if key, ok := literalString(lhs.Y); ok && !schemaOrUIKeys[key] {
						if s, ok := literalString(t.Y); ok {
							addDictValue(string(vr.Data), s)
						}
					}
				}
			}
		case *js.Property:
			if t.Name == nil || t.Spread {
				return
			}
			pname := propName(t.Name)
			// Require uppercase-leading name inside object literals so Vue `props: { role: {...} }`
			// and JSON Schema `{ properties: { role: {...} } }` never match.
			if len(pname) >= 4 && pname[0] >= 'A' && pname[0] <= 'Z' && authzDictNameRe.MatchString(pname) {
				if obj := unwrapDictObject(t.Value); obj != nil {
					extractDictObjectValues(obj, 0, func(v string) { addDictValue(pname, v) })
				}
			}
		}
	}), ast)

	if len(roles) == 0 && len(perms) == 0 && len(rules) == 0 {
		return nil
	}
	out := &ClientAuthz{
		Roles:       sortedKeys(roles),
		Permissions: sortedKeys(perms),
	}
	if len(rules) > 0 {
		out.Rules = make([]AuthzRule, 0, len(rules))
		for r := range rules {
			out.Rules = append(out.Rules, r)
		}
		sort.Slice(out.Rules, func(i, j int) bool {
			if out.Rules[i].Action != out.Rules[j].Action {
				return out.Rules[i].Action < out.Rules[j].Action
			}
			return out.Rules[i].Subject < out.Rules[j].Subject
		})
	}
	return out
}

func extractCallAuthz(
	c *js.CallExpr,
	x *extractor,
	canVars, canCompVars map[*js.Var]bool,
	addRole, addPerm func(string),
	addRule func(string, string),
) {
	args := c.Args.List
	callee := unwrapCalleeExpr(c.X)

	// 1. Source A: CASL `<Can I="update" a="Order">` compiled JSX / Vue VNode call.
	if len(args) >= 2 && !args[0].Rest && !args[1].Rest {
		extractCanComponentAuthz(callee, args[0].Value, args[1].Value, x, canCompVars, addRule)
	}

	// 2. Source A: Direct call to CASL `can(action, subject)` from `defineAbility`,
	// `useAbility`, or `AbilityBuilder`.
	if vr, ok := callee.(*js.Var); ok && canVars[root(vr)] {
		if (len(args) == 2 || len(args) == 3) && !args[0].Rest && !args[1].Rest {
			actions, okA := resolveAuthzStrings(x, args[0].Value, true)
			subjects, okS := resolveAuthzStrings(x, args[1].Value, true)
			if okA && okS {
				for _, a := range actions {
					for _, s := range subjects {
						addRule(a, s)
					}
				}
			}
		}
		return
	}

	recv, name := splitCallee(callee)

	// 3. Source A: `.can`, `.cannot`, `.$can`, `.$cannot` method calls.
	if recv != nil {
		switch name {
		case "$can", "$cannot":
			if len(args) >= 1 && len(args) <= 3 && !args[0].Rest {
				actions, okA := resolveAuthzStrings(x, args[0].Value, true)
				if !okA {
					if ar, rok := x.extractConstRef(args[0].Value); rok {
						if len(args) >= 2 && !args[1].Rest {
							if subjects, okS := resolveAuthzStrings(x, args[1].Value, true); okS {
								for _, s := range subjects {
									x.addUnresolvedAuthzRule(UnresolvedAuthzRule{Kind: "rule", Action: ar, SubjectLit: s})
								}
							} else if sr, srok := x.extractConstRef(args[1].Value); srok {
								x.addUnresolvedAuthzRule(UnresolvedAuthzRule{Kind: "rule", Action: ar, Subject: sr})
							} else if !isLiteralNonString(args[1].Value) {
								x.addUnresolvedAuthzRule(UnresolvedAuthzRule{Kind: "rule", Action: ar})
							}
						} else {
							x.addUnresolvedAuthzRule(UnresolvedAuthzRule{Kind: "rule", Action: ar})
						}
					}
					return
				}
				if len(args) == 1 {
					for _, a := range actions {
						addRule(a, "")
					}
					return
				}
				if args[1].Rest {
					return
				}
				if s, isLit := literalString(args[1].Value); isLit && !isValidAuthzToken(s) {
					return
				}
				if subjects, okS := resolveAuthzStrings(x, args[1].Value, true); okS {
					for _, a := range actions {
						for _, s := range subjects {
							addRule(a, s)
						}
					}
				} else if sr, srok := x.extractConstRef(args[1].Value); srok {
					for _, a := range actions {
						x.addUnresolvedAuthzRule(UnresolvedAuthzRule{Kind: "rule", ActionLit: a, Subject: sr})
					}
				} else if !isLiteralNonString(args[1].Value) {
					for _, a := range actions {
						addRule(a, "")
					}
				}
			}
			return
		case "can", "cannot":
			if len(args) == 1 && !args[0].Rest {
				if isAbilityReceiver(recv) {
					if actions, okA := resolveAuthzStrings(x, args[0].Value, false); okA {
						for _, a := range actions {
							addRule(a, "")
						}
					} else if ar, rok := x.extractConstRef(args[0].Value); rok {
						x.addUnresolvedAuthzRule(UnresolvedAuthzRule{Kind: "rule", Action: ar})
					}
				}
				return
			}
			if (len(args) == 2 || (len(args) == 3 && isAbilityReceiver(recv))) && !args[0].Rest && !args[1].Rest {
				actions, okA := resolveAuthzStrings(x, args[0].Value, true)
				subjects, okS := resolveAuthzStrings(x, args[1].Value, true)
				if okA && okS {
					for _, a := range actions {
						for _, s := range subjects {
							addRule(a, s)
						}
					}
				} else {
					var ar, sr *ConstRef
					if !okA {
						ar, _ = x.extractConstRef(args[0].Value)
					}
					if !okS {
						sr, _ = x.extractConstRef(args[1].Value)
					}
					if ar != nil && sr != nil {
						x.addUnresolvedAuthzRule(UnresolvedAuthzRule{Kind: "rule", Action: ar, Subject: sr})
					} else if ar != nil && okS {
						for _, s := range subjects {
							x.addUnresolvedAuthzRule(UnresolvedAuthzRule{Kind: "rule", Action: ar, SubjectLit: s})
						}
					} else if okA && sr != nil {
						for _, a := range actions {
							x.addUnresolvedAuthzRule(UnresolvedAuthzRule{Kind: "rule", ActionLit: a, Subject: sr})
						}
					}
				}
			}
			return
		}
	}

	// 4. Source B: Explicit permission / role guard calls (`hasPermission`, `hasAnyRole`, `checkAuthority`...).
	if name != "" && guardCallRe.MatchString(name) {
		isRole := strings.Contains(name, "Role")
		kind := "perm"
		if isRole {
			kind = "role"
		}
		for _, a := range args {
			if a.Rest {
				continue
			}
			vals, ok := resolveAuthzStrings(x, a.Value, true)
			if !ok {
				if ref, rok := x.extractConstRef(a.Value); rok {
					x.addUnresolvedAuthzRule(UnresolvedAuthzRule{Kind: kind, Action: ref})
				}
				continue
			}
			for _, v := range vals {
				if isRole {
					addRole(v)
				} else {
					addPerm(v)
				}
			}
		}
	}
}

func extractCanComponentAuthz(
	callee, compArg, propsArg js.IExpr,
	x *extractor,
	canCompVars map[*js.Var]bool,
	addRule func(string, string),
) {
	propsObj := resolveObjectExpr(x, propsArg)
	if propsObj == nil {
		return
	}
	isExplicitCan := isCanComponentRef(compArg, canCompVars)
	if !isExplicitCan && !isVNodeFactory(callee) {
		return
	}
	for _, cand := range candidateCanPropObjects(x, propsObj, isExplicitCan) {
		actExpr := firstProp(cand, "I")
		if actExpr == nil && isExplicitCan {
			actExpr = firstProp(cand, "do")
		}
		if actExpr == nil {
			continue
		}
		subjExpr := firstProp(cand, "a")
		if subjExpr == nil {
			subjExpr = firstProp(cand, "this")
		}
		if subjExpr == nil && isExplicitCan {
			subjExpr = firstProp(cand, "on")
		}
		if !isExplicitCan && subjExpr == nil {
			continue
		}
		actions, okA := resolveAuthzStrings(x, actExpr, true)
		if !okA {
			continue
		}
		if subjExpr == nil {
			for _, a := range actions {
				addRule(a, "")
			}
			return
		}
		if subjects, okS := resolveAuthzStrings(x, subjExpr, true); okS {
			for _, a := range actions {
				for _, s := range subjects {
					addRule(a, s)
				}
			}
			return
		}
	}
}

func candidateCanPropObjects(x *extractor, propsObj *js.ObjectExpr, includeSubObjects bool) []*js.ObjectExpr {
	out := []*js.ObjectExpr{propsObj}
	if includeSubObjects {
		for _, k := range []string{"attrs", "props"} {
			if sub := resolveObjectExpr(x, objectValue(propsObj, k)); sub != nil {
				out = append(out, sub)
			}
		}
	}
	return out
}

func firstProp(obj *js.ObjectExpr, name string) js.IExpr {
	return objectValue(obj, name)
}

func resolveObjectExpr(x *extractor, e js.IExpr) *js.ObjectExpr {
	if e == nil {
		return nil
	}
	e = unwrapEnumGroup(e)
	if o, ok := e.(*js.ObjectExpr); ok {
		return o
	}
	if o, ok := x.object(e); ok {
		return o
	}
	return nil
}

func isCanComponentRef(e js.IExpr, canCompVars map[*js.Var]bool) bool {
	e = unwrapEnumGroup(e)
	if s, ok := literalString(e); ok {
		return s == "Can"
	}
	switch t := e.(type) {
	case *js.Var:
		name := string(t.Data)
		return name == "Can" || name == "_component_Can" || canCompVars[root(t)]
	case *js.DotExpr:
		return propName(t.Y) == "Can"
	case *js.CallExpr:
		return isResolveCanCall(t)
	}
	return false
}

func isCanCompInit(e js.IExpr) bool {
	ce, ok := unwrapEnumGroup(e).(*js.CallExpr)
	if !ok {
		return false
	}
	if isResolveCanCall(ce) {
		return true
	}
	_, name := splitCallee(unwrapCalleeExpr(ce.X))
	return name == "createContextualCan"
}

func isResolveCanCall(ce *js.CallExpr) bool {
	if len(ce.Args.List) < 1 || ce.Args.List[0].Rest {
		return false
	}
	_, name := splitCallee(unwrapCalleeExpr(ce.X))
	if name != "resolveComponent" && name != "_resolveComponent" {
		return false
	}
	s, ok := literalString(ce.Args.List[0].Value)
	return ok && s == "Can"
}

func isVNodeFactory(callee js.IExpr) bool {
	_, name := splitCallee(callee)
	switch name {
	case "jsx", "jsxs", "_jsx", "_jsxs", "jsxDEV", "_jsxDEV",
		"createElement", "$createElement", "_c", "h",
		"createVNode", "_createVNode", "createBlock", "_createBlock":
		return true
	}
	return false
}

func isAbilityDestructSource(e js.IExpr) bool {
	switch unwrapEnumGroup(e).(type) {
	case *js.CallExpr, *js.NewExpr:
		return true
	}
	return false
}

func markCASLBuilderParams(c *js.CallExpr, canVars map[*js.Var]bool) {
	_, calleeName := splitCallee(unwrapCalleeExpr(c.X))
	isDefineAbility := calleeName == "defineAbility"
	for i, a := range c.Args.List {
		if a.Rest {
			continue
		}
		params := funcParams(unwrapEnumGroup(a.Value))
		if len(params) == 0 {
			continue
		}
		p0, ok := params[0].Binding.(*js.Var)
		if !ok {
			continue
		}
		if (isDefineAbility && i == 0) || string(p0.Data) == "can" {
			canVars[root(p0)] = true
			if len(params) >= 2 {
				if p1, ok := params[1].Binding.(*js.Var); ok && (isDefineAbility || string(p1.Data) == "cannot") {
					canVars[root(p1)] = true
				}
			}
		}
	}
}

func funcParams(e js.IExpr) []js.BindingElement {
	switch fn := e.(type) {
	case *js.ArrowFunc:
		return fn.Params.List
	case *js.FuncDecl:
		return fn.Params.List
	}
	return nil
}

// extractEnumIIFEAuthz handles TypeScript enum IIFEs (`(function(Role){ Role["Admin"] = "admin"; })(Role || (Role = {}))`
// and Terser-minified CJS exports `!function(e){ e.Auditor = "AUDITOR"; }(r = exports.UserRole || (exports.UserRole = {}))`).
func extractEnumIIFEAuthz(ce *js.CallExpr, addDictValue func(dictName, val string)) {
	if ce == nil || len(ce.Args.List) != 1 || ce.Args.List[0].Rest {
		return
	}
	params := funcParams(unwrapEnumGroup(ce.X))
	if len(params) != 1 {
		return
	}
	param0, ok := params[0].Binding.(*js.Var)
	if !ok || param0 == nil {
		return
	}
	dictName := enumIIFETargetName(ce.Args.List[0].Value)
	if dictName == "" || !authzDictNameRe.MatchString(dictName) {
		return
	}
	pRoot := root(param0)
	js.Walk(walker(func(n js.INode) {
		be, ok := n.(*js.BinaryExpr)
		if !ok || be.Op != js.EqToken {
			return
		}
		val, ok := literalString(be.Y)
		if !ok {
			return
		}
		switch lhs := be.X.(type) {
		case *js.DotExpr:
			if vr, ok := lhs.X.(*js.Var); ok && root(vr) == pRoot && propName(lhs.Y) != "" {
				addDictValue(dictName, val)
			}
		case *js.IndexExpr:
			if vr, ok := lhs.X.(*js.Var); ok && root(vr) == pRoot {
				if k, ok := literalString(lhs.Y); ok && k != "" {
					addDictValue(dictName, val)
				}
			}
		}
	}), ce.X)
}

func enumIIFETargetName(arg js.IExpr) string {
	isInitOr := func(op js.TokenType) bool {
		return op == js.OrToken || op == js.OrEqToken || op == js.NullishToken || op == js.NullishEqToken
	}
	be, ok := unwrapEnumGroup(arg).(*js.BinaryExpr)
	if !ok {
		return ""
	}
	if be.Op == js.EqToken {
		if orExpr, ok := unwrapEnumGroup(be.Y).(*js.BinaryExpr); ok && isInitOr(orExpr.Op) {
			return exprIdentOrPropName(orExpr.X)
		}
		return exprIdentOrPropName(be.X)
	}
	if isInitOr(be.Op) {
		return exprIdentOrPropName(be.X)
	}
	return ""
}

func exprIdentOrPropName(e js.IExpr) string {
	switch t := unwrapEnumGroup(e).(type) {
	case *js.Var:
		return string(t.Data)
	case *js.DotExpr:
		return propName(t.Y)
	}
	return ""
}

func unwrapDictObject(e js.IExpr) *js.ObjectExpr {
	e = unwrapEnumGroup(e)
	if ce, ok := e.(*js.CallExpr); ok && len(ce.Args.List) == 1 && !ce.Args.List[0].Rest {
		if d, ok := unwrapEnumGroup(ce.X).(*js.DotExpr); ok && globalName(d.X) == "Object" && propName(d.Y) == "freeze" {
			e = unwrapEnumGroup(ce.Args.List[0].Value)
		}
	}
	o, _ := e.(*js.ObjectExpr)
	if o == nil || isSchemaOrUIDescriptor(o) {
		return nil
	}
	return o
}

func isSchemaOrUIDescriptor(o *js.ObjectExpr) bool {
	for _, p := range o.List {
		if !p.Spread && p.Name != nil && schemaOrUIKeys[propName(p.Name)] {
			return true
		}
	}
	return false
}

func extractDictObjectValues(o *js.ObjectExpr, depth int, emit func(string)) {
	if o == nil || depth > 2 || isSchemaOrUIDescriptor(o) {
		return
	}
	for _, p := range o.List {
		if p.Spread || p.Name == nil {
			continue
		}
		val := unwrapEnumGroup(p.Value)
		if s, ok := literalString(val); ok {
			emit(s)
			continue
		}
		if sub := unwrapDictObject(val); sub != nil {
			extractDictObjectValues(sub, depth+1, emit)
		}
	}
}

// unwrapCalleeExpr strips `(0, mod.fn)` and Webpack 4 `Object(mod.fn)` wrappers.
func unwrapCalleeExpr(e js.IExpr) js.IExpr {
	for {
		switch t := e.(type) {
		case *js.GroupExpr:
			e = t.X
			continue
		case *js.CommaExpr:
			if len(t.List) > 0 {
				e = t.List[len(t.List)-1]
				continue
			}
		case *js.CallExpr:
			if globalName(t.X) == "Object" && len(t.Args.List) == 1 && !t.Args.List[0].Rest {
				e = t.Args.List[0].Value
				continue
			}
		}
		return e
	}
}

func splitCallee(callee js.IExpr) (recv js.IExpr, name string) {
	switch t := callee.(type) {
	case *js.Var:
		return nil, string(t.Data)
	case *js.DotExpr:
		return t.X, propName(t.Y)
	case *js.IndexExpr:
		if s, ok := literalString(t.Y); ok {
			return t.X, s
		}
	}
	return nil, ""
}

func isAbilityReceiver(recv js.IExpr) bool {
	name := exprIdentOrPropName(recv)
	switch strings.ToLower(strings.TrimPrefix(name, "$")) {
	case "ability", "abilities", "acl", "casl":
		return true
	}
	return false
}

func isLiteralNonString(e js.IExpr) bool {
	l, ok := unwrapEnumGroup(e).(*js.LiteralExpr)
	return ok && l.TokenType != js.StringToken
}

func resolveAuthzStrings(x *extractor, e js.IExpr, allowArray bool) ([]string, bool) {
	if e == nil {
		return nil, false
	}
	e = unwrapEnumGroup(e)
	if s, ok := literalString(e); ok {
		if !isValidAuthzToken(s) {
			return nil, false
		}
		return []string{s}, true
	}
	if isLiteralNonString(e) {
		return nil, false
	}
	if allowArray {
		if arr := resolveArrayExpr(x, e); arr != nil && len(arr.List) > 0 && len(arr.List) <= 16 {
			var out []string
			for _, elem := range arr.List {
				if elem.Spread || elem.Value == nil {
					return nil, false
				}
				vals, ok := resolveAuthzStrings(x, elem.Value, false)
				if !ok {
					return nil, false
				}
				out = append(out, vals...)
			}
			return out, len(out) > 0
		}
	}
	// CASL `subject("Order", item)` / `an("Order", item)` instance subject helper.
	if ce, ok := e.(*js.CallExpr); ok && len(ce.Args.List) == 2 && !ce.Args.List[0].Rest {
		if _, cname := splitCallee(unwrapCalleeExpr(ce.X)); cname == "subject" || cname == "an" {
			return resolveAuthzStrings(x, ce.Args.List[0].Value, false)
		}
	}
	// Member lookup on an `Object.freeze({...})` constant dictionary (`ACTIONS.APPROVE`).
	switch t := e.(type) {
	case *js.DotExpr:
		if vr, ok := unwrapEnumGroup(t.X).(*js.Var); ok {
			if obj := unwrapDictObject(x.constOrSingleExpr(vr)); obj != nil {
				if v := objectValue(obj, propName(t.Y)); v != nil {
					return resolveAuthzStrings(x, v, false)
				}
			}
		}
	case *js.IndexExpr:
		if vr, ok := unwrapEnumGroup(t.X).(*js.Var); ok {
			if key, ok := literalString(t.Y); ok {
				if obj := unwrapDictObject(x.constOrSingleExpr(vr)); obj != nil {
					if v := objectValue(obj, key); v != nil {
						return resolveAuthzStrings(x, v, false)
					}
				}
			}
		}
	}
	// Constant variable or TypeScript enum member via `x.eval` (single value without `{}`).
	switch e.(type) {
	case *js.Var, *js.DotExpr, *js.IndexExpr:
		var q []string
		vals := x.eval(e, &q, 0)
		if len(vals) == 1 && !strings.Contains(vals[0], unknown) && isValidAuthzToken(vals[0]) {
			return []string{vals[0]}, true
		}
	}
	return nil, false
}

func resolveArrayExpr(x *extractor, e js.IExpr) *js.ArrayExpr {
	if arr, ok := e.(*js.ArrayExpr); ok {
		return arr
	}
	if vr, ok := e.(*js.Var); ok {
		if arr, ok := unwrapEnumGroup(x.constOrSingleExpr(vr)).(*js.ArrayExpr); ok {
			return arr
		}
	}
	return nil
}

// isValidAuthzToken enforces `^[A-Za-z0-9_:.*-]{2,64}$` (no slashes `/`, no
// spaces, no URLs, no pure numbers or JS literal keywords).
func isValidAuthzToken(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	first, last := s[0], s[len(s)-1]
	if first == ':' || first == '.' || first == '-' || last == ':' || last == '.' || last == '-' {
		return false
	}
	hasAlpha := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			hasAlpha = true
		case c >= '0' && c <= '9', c == '_', c == ':', c == '.', c == '*', c == '-':
		default:
			return false
		}
	}
	if !hasAlpha && s != "*:*" {
		return false
	}
	switch strings.ToLower(s) {
	case "true", "false", "null", "undefined", "nan", "infinity":
		return false
	}
	return true
}
