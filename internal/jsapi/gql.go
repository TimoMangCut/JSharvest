package jsapi

import (
	"bytes"
	"regexp"
	"slices"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

const maxGraphQLDocBytes = 8192

// GraphQLVar describes one typed variable declared in a GraphQL operation header.
type GraphQLVar struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// GraphQLDoc is a static GraphQL operation document extracted from gql`...`,
// graphql(`...`), or a compiled graphql-tag Document AST object.
type GraphQLDoc struct {
	Name  string       `json:"name"`
	Kind  string       `json:"kind"` // query, mutation, subscription
	Query string       `json:"query"`
	Vars  []GraphQLVar `json:"vars,omitempty"`
}

var (
	gqlOpHeadRe   = regexp.MustCompile(`\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?`)
	gqlFragHeadRe = regexp.MustCompile(`\bfragment\s+([A-Za-z_][A-Za-z0-9_]*)\s+on\s+[A-Za-z_][A-Za-z0-9_]*`)
	gqlSpreadRe   = regexp.MustCompile(`\.\.\.\s*([A-Za-z_][A-Za-z0-9_]*)\b`)
	gqlVarDefRe   = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(\[?[A-Za-z_][A-Za-z0-9_!]*\]?!?)`)
)

func hasGQLDocHint(src []byte) bool {
	return bytes.Contains(src, []byte("gql")) ||
		bytes.Contains(src, []byte("graphql")) ||
		((bytes.Contains(src, []byte(`"Document"`)) || bytes.Contains(src, []byte(`'Document'`))) &&
			bytes.Contains(src, []byte("loc")))
}

func extractGraphQLDocs(ast *js.AST, x *extractor) []GraphQLDoc {
	if ast == nil || x == nil || !hasGQLDocHint(x.src) {
		return nil
	}

	varText := map[*js.Var]string{}
	fragByName := map[string]string{}

	collectFrags := func(text string) {
		if len(text) > maxGraphQLDocBytes {
			return
		}
		for name, block := range extractGQLFragmentBlocks(text) {
			if _, exists := fragByName[name]; !exists {
				fragByName[name] = block
			}
		}
	}

	// Pass 1: resolve static fragment/document variables (`const Frag = gql`...``).
	js.Walk(walker(func(n js.INode) {
		vd, ok := n.(*js.VarDecl)
		if !ok {
			return
		}
		for _, b := range vd.List {
			vr, ok := b.Binding.(*js.Var)
			if !ok || b.Default == nil {
				continue
			}
			if txt, ok := resolveGQLExprText(b.Default, x, varText); ok && len(txt) <= maxGraphQLDocBytes {
				varText[root(vr)] = txt
				collectFrags(txt)
			}
		}
	}), ast)

	// Pass 2: extract GraphQL documents from tagged templates, gql()/graphql() calls, and Document AST objects.
	var rawTexts []string
	js.Walk(walker(func(n js.INode) {
		switch t := n.(type) {
		case *js.TemplateExpr:
			if t.Tag != nil && isGQLTag(t.Tag) {
				if txt, ok := evalGQLTemplate(t, x, varText); ok {
					collectFrags(txt)
					rawTexts = append(rawTexts, txt)
				}
			}
		case *js.CallExpr:
			_, fn := splitCallee(unwrapCalleeExpr(t.X))
			if isGQLTagName(fn) && len(t.Args.List) >= 1 && !t.Args.List[0].Rest {
				if txt, ok := resolveGQLExprText(t.Args.List[0].Value, x, varText); ok {
					collectFrags(txt)
					rawTexts = append(rawTexts, txt)
				}
			}
		case *js.ObjectExpr:
			if txt, ok := extractCompiledGQLDocument(t); ok {
				collectFrags(txt)
				rawTexts = append(rawTexts, txt)
			}
		}
	}), ast)

	seen := map[string]bool{}
	var out []GraphQLDoc
	for _, txt := range rawTexts {
		for _, doc := range parseGraphQLDocs(txt, fragByName) {
			key := doc.Kind + " " + doc.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, doc)
		}
	}
	return out
}

func isGQLTag(e js.IExpr) bool {
	_, name := splitCallee(unwrapCalleeExpr(e))
	return isGQLTagName(name)
}

func isGQLTagName(name string) bool {
	switch strings.ToLower(name) {
	case "gql", "graphql":
		return true
	}
	return false
}

func resolveGQLExprText(e js.IExpr, x *extractor, varText map[*js.Var]string) (string, bool) {
	e = unwrapEnumGroup(e)
	switch t := e.(type) {
	case *js.LiteralExpr:
		if t.TokenType == js.StringToken {
			s := unquote(t.Data)
			return s, len(s) <= maxGraphQLDocBytes
		}
	case *js.TemplateExpr:
		if t.Tag == nil || isGQLTag(t.Tag) {
			return evalGQLTemplate(t, x, varText)
		}
	case *js.CallExpr:
		_, fn := splitCallee(unwrapCalleeExpr(t.X))
		if isGQLTagName(fn) && len(t.Args.List) >= 1 && !t.Args.List[0].Rest {
			return resolveGQLExprText(t.Args.List[0].Value, x, varText)
		}
	case *js.ObjectExpr:
		return extractCompiledGQLDocument(t)
	case *js.Var:
		if s, ok := varText[root(t)]; ok {
			return s, true
		}
	}
	return "", false
}

func evalGQLTemplate(t *js.TemplateExpr, x *extractor, varText map[*js.Var]string) (string, bool) {
	var b strings.Builder
	for i, part := range t.List {
		b.WriteString(templateText(part.Value, i == 0, false))
		if b.Len() > maxGraphQLDocBytes {
			return "", false
		}
		if part.Expr != nil {
			sub, ok := resolveGQLInterpolation(part.Expr, x, varText)
			if !ok {
				return "", false
			}
			b.WriteByte('\n')
			b.WriteString(sub)
			b.WriteByte('\n')
			if b.Len() > maxGraphQLDocBytes {
				return "", false
			}
		}
	}
	b.WriteString(templateText(t.Tail, len(t.List) == 0, true))
	if b.Len() > maxGraphQLDocBytes {
		return "", false
	}
	return b.String(), true
}

func resolveGQLInterpolation(e js.IExpr, x *extractor, varText map[*js.Var]string) (string, bool) {
	e = unwrapEnumGroup(e)
	if vr, ok := e.(*js.Var); ok {
		if s, found := varText[root(vr)]; found {
			return s, true
		}
	}
	if s, ok := resolveGQLExprText(e, x, varText); ok {
		return s, true
	}
	vals := x.eval(e, nil, 0)
	if len(vals) == 1 && vals[0] != "" && vals[0] != unknown && len(vals[0]) <= maxGraphQLDocBytes {
		return vals[0], true
	}
	return "", false
}

// extractCompiledGQLDocument reads `{ kind: "Document", loc: { source: { body: "..." } } }`.
func extractCompiledGQLDocument(obj *js.ObjectExpr) (string, bool) {
	isDoc := false
	var locObj *js.ObjectExpr
	for _, p := range obj.List {
		if p.Name == nil || p.Value == nil {
			continue
		}
		switch propName(p.Name) {
		case "kind":
			if s, ok := literalString(unwrapEnumGroup(p.Value)); ok && s == "Document" {
				isDoc = true
			}
		case "loc":
			locObj, _ = unwrapEnumGroup(p.Value).(*js.ObjectExpr)
		}
	}
	if !isDoc || locObj == nil {
		return "", false
	}
	for _, p := range locObj.List {
		if p.Name == nil || propName(p.Name) != "source" || p.Value == nil {
			continue
		}
		srcObj, ok := unwrapEnumGroup(p.Value).(*js.ObjectExpr)
		if !ok {
			continue
		}
		for _, sp := range srcObj.List {
			if sp.Name != nil && propName(sp.Name) == "body" && sp.Value != nil {
				if s, ok := literalString(unwrapEnumGroup(sp.Value)); ok && len(s) <= maxGraphQLDocBytes {
					return s, true
				}
			}
		}
	}
	return "", false
}

func parseGraphQLDocs(raw string, fragByName map[string]string) []GraphQLDoc {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxGraphQLDocBytes {
		return nil
	}
	localFrags := extractGQLFragmentBlocks(raw)
	matches := gqlOpHeadRe.FindAllStringSubmatchIndex(raw, -1)
	var out []GraphQLDoc
	for _, m := range matches {
		kind := raw[m[2]:m[3]]
		name := raw[m[4]:m[5]]
		varsRaw := ""
		if m[6] >= 0 && m[7] >= 0 {
			varsRaw = raw[m[6]:m[7]]
		}
		block, ok := sliceBalancedBraces(raw, m[0], m[1])
		if !ok {
			continue
		}
		fullQuery := attachReferencedFragments(block, localFrags, fragByName)
		if len(fullQuery) > maxGraphQLDocBytes {
			continue
		}
		out = append(out, GraphQLDoc{
			Name:  name,
			Kind:  kind,
			Query: fullQuery,
			Vars:  parseGQLVars(varsRaw),
		})
	}
	return out
}

func parseGQLVars(varsRaw string) []GraphQLVar {
	if strings.TrimSpace(varsRaw) == "" {
		return nil
	}
	ms := gqlVarDefRe.FindAllStringSubmatch(varsRaw, -1)
	if len(ms) == 0 {
		return nil
	}
	out := make([]GraphQLVar, 0, len(ms))
	seen := map[string]bool{}
	for _, m := range ms {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, GraphQLVar{Name: m[1], Type: m[2]})
	}
	return out
}

func extractGQLFragmentBlocks(raw string) map[string]string {
	matches := gqlFragHeadRe.FindAllStringSubmatchIndex(raw, -1)
	if len(matches) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, m := range matches {
		name := raw[m[2]:m[3]]
		if block, ok := sliceBalancedBraces(raw, m[0], m[1]); ok {
			out[name] = block
		}
	}
	return out
}

func attachReferencedFragments(opBlock string, localFrags, globalFrags map[string]string) string {
	var parts []string
	parts = append(parts, strings.TrimSpace(opBlock))
	added := map[string]bool{}
	queue := spreadNames(opBlock)
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		if added[fn] {
			continue
		}
		frag, ok := localFrags[fn]
		if !ok {
			frag, ok = globalFrags[fn]
		}
		if !ok {
			continue
		}
		added[fn] = true
		parts = append(parts, strings.TrimSpace(frag))
		for _, sub := range spreadNames(frag) {
			if !added[sub] && !slices.Contains(queue, sub) {
				queue = append(queue, sub)
			}
		}
	}
	return strings.Join(parts, "\n")
}

func spreadNames(s string) []string {
	ms := gqlSpreadRe.FindAllStringSubmatch(s, -1)
	var out []string
	for _, m := range ms {
		if m[1] != "on" && !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	return out
}

// sliceBalancedBraces returns raw[headStart : closingBrace+1] for a GraphQL
// operation or fragment definition whose header ends at headEnd.
func sliceBalancedBraces(raw string, headStart, headEnd int) (string, bool) {
	i := headEnd
	for i < len(raw) && raw[i] != '{' {
		if raw[i] == '#' {
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			continue
		}
		i++
	}
	if i >= len(raw) || raw[i] != '{' {
		return "", false
	}
	depth := 0
	inStr := false
	for ; i < len(raw); i++ {
		c := raw[i]
		if inStr {
			if c == '\\' && i+1 < len(raw) {
				i++
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '#':
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return strings.TrimSpace(raw[headStart : i+1]), true
			}
		}
	}
	return "", false
}
