package resolve

import (
	"bytes"
	"maps"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
)

const (
	maxPlainChunks      = 128
	asyncAnchorWindow   = 1000
	maxAsyncContextSize = 256 << 10
)

// WebpackRuntime describes the chunk URL builder extracted from a Webpack 3, 4,
// or 5 bootstrap runtime.
type WebpackRuntime struct {
	PublicBase *url.URL
	Prefix     string
	NameMap    map[string]string
	Sep        string
	HashMap    map[string]string
	Suffix     string
	Named      map[string]string

	hasNamePart bool
	from        string
}

var (
	// Entry headers for Webpack 3, 4, and 5 chunk filename builders:
	//   1. Webpack 5: <req>.u = function(e){return ...  or  <req>.u = e => ...
	//   2. Webpack 3/4 standalone fn: function jsonpScriptSrc(e){return <req>.p + ...
	//   3. Webpack 4 inline .src IIFE: .src = function(e){return <req>.p + ...}(e)
	//   4. Arrow/assigned helper: fn = (e) => <req>.p + ...
	//   5. Webpack 3 / Terser-inlined direct .src: .src = <req>.p + ...
	webpackBuilderHeaderRe = regexp.MustCompile(
		`(?:([\w$]+)\s*)?\.u\s*=\s*(?:function\s*\(\s*([\w$]+)\s*\)\s*\{\s*return\b\s*|\(?\s*([\w$]+)\s*\)?\s*=>\s*)` +
			`|` +
			`function\s+[\w$]+\s*\(\s*([\w$]+)\s*\)\s*\{\s*return\s+([\w$]+)\.p\s*\+\s*` +
			`|` +
			`\.src\s*=\s*\(?(?:function\s*\(\s*([\w$]+)\s*\)\s*\{\s*return\s+|\(?\s*([\w$]+)\s*\)?\s*=>\s*)([\w$]+)\.p\s*\+\s*` +
			`|` +
			`(?:^|[^\w$.])[\w$]+\s*=\s*(?:function\s*\(\s*([\w$]+)\s*\)\s*\{\s*return\s+|\(?\s*([\w$]+)\s*\)?\s*=>\s*)([\w$]+)\.p\s*\+\s*` +
			`|` +
			`\.src\s*=\s*([\w$]+)\.p\s*\+\s*`,
	)

	webpackMapEntryRe = regexp.MustCompile(`([\w$]+|"[^"\r\n\\]+"|'[^'\r\n\\]+')\s*:\s*(?:"([^"\r\n\\]*)"|'([^'\r\n\\]*)')`)
	webpackFallbackP  = regexp.MustCompile(`\.p\s*=\s*(?:"([^"\r\n\\]*)"|'([^'\r\n\\]*)')`)

	// Explicit <req>.e(chunkId) calls, allowing optional Webpack banner comments.
	webpackLoadCallRe = regexp.MustCompile(`[\w$]\.e\(\s*(?:/\*[^*]*\*+(?:[^/*][^*]*\*+)*/\s*)?(\d+|"[^"\r\n\\]+"|'[^'\r\n\\]+')\s*\)`)

	// Async loader anchors emitted in webpackAsyncContext within <= 1000 bytes
	// after the context map literal:
	//   - ids.slice(1).map(t.e) / ids.slice(1).map(function(e){return t.e(e)}) / ids.slice(2).map(...)
	//   - t.e(ids[1]) / t.e(ids[2])
	webpackAsyncAnchorRe = regexp.MustCompile(
		`\.slice\(\s*([12])\s*\)\.map\(\s*(?:[\w$]+\.e\b|\(?(?:function\s*\(\s*[\w$]+\s*\)\s*\{\s*return\s+|\(?\s*[\w$]+\s*\)?\s*=>\s*(?:\{\s*return\s+)?)[\w$]+\.e\s*\()` +
			`|` +
			`[\w$]+\.e\(\s*[\w$]+(?:\[[\w$]+\])?\[\s*([12])\s*\]\s*\)`,
	)

	chunkIDRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// IsPlain reports whether rt builds unhashed chunk URLs from dynamic chunk IDs
// rather than from a closed HashMap.
func (rt *WebpackRuntime) IsPlain() bool {
	return rt != nil && len(rt.HashMap) == 0 && rt.hasNamePart && rt.Suffix != ""
}

// ExtractWebpackRuntime extracts a Webpack 3, 4, or 5 chunk URL runtime from
// src, resolving its static publicPath against scriptURL (falling back to
// pageURL). Runtimes with a computed ("auto") publicPath return nil.
func ExtractWebpackRuntime(src []byte, scriptURL, pageURL string) *WebpackRuntime {
	if !bytes.Contains(src, []byte(".p")) {
		return nil
	}
	base, err := url.Parse(scriptURL)
	if err != nil || base.Host == "" {
		base, err = url.Parse(pageURL)
		if err != nil || base.Host == "" {
			return nil
		}
	}
	s := string(src)
	matches := webpackBuilderHeaderRe.FindAllStringSubmatchIndex(s, -1)
	for _, m := range matches {
		reqVar, idVar, isU := headerVars(s, m)
		exprStart := m[1]
		if isU && reqVar != "" {
			// Tolerate custom .u bodies that still prepend <req>.p +.
			rest := strings.TrimLeft(s[exprStart:], " \t\r\n")
			if strings.HasPrefix(rest, reqVar+".p") {
				after := strings.TrimLeft(rest[len(reqVar)+2:], " \t\r\n")
				if strings.HasPrefix(after, "+") && !strings.HasPrefix(after, "++") && !strings.HasPrefix(after, "+=") {
					exprStart = len(s) - len(strings.TrimLeft(after[1:], " \t\r\n"))
				}
			}
		}
		exprEnd := scanExprEnd(s, exprStart)
		if exprEnd <= exprStart {
			continue
		}
		rt := parseBuilderExpr(s[exprStart:exprEnd], idVar)
		if rt == nil {
			continue
		}
		pubPath, ok := findPublicPath(s, m[0], reqVar)
		if !ok {
			continue
		}
		pubBase, prefix, named, ok := resolvePublicBase(base, pubPath, rt.Prefix, rt.Named)
		if !ok {
			continue
		}
		rt.PublicBase = pubBase
		rt.Prefix = prefix
		rt.Named = named
		rt.from = base.String()
		return rt
	}
	return nil
}

func headerVars(s string, m []int) (reqVar, idVar string, isU bool) {
	sub := func(group int) string {
		i, j := m[2*group], m[2*group+1]
		if i < 0 {
			return ""
		}
		return s[i:j]
	}
	switch {
	case m[4] >= 0 || m[6] >= 0: // Alt 1: .u =
		return sub(1), firstNonEmpty(sub(2), sub(3)), true
	case m[8] >= 0: // Alt 2: function fn(e){return req.p +
		return sub(5), sub(4), false
	case m[12] >= 0 || m[14] >= 0: // Alt 3: .src = function(e){return req.p +
		return sub(8), firstNonEmpty(sub(6), sub(7)), false
	case m[18] >= 0 || m[20] >= 0: // Alt 4: fn = (e) => req.p +
		return sub(11), firstNonEmpty(sub(9), sub(10)), false
	default: // Alt 5: .src = req.p +
		return sub(12), "", false
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// findPublicPath locates the static string assignment to <reqVar>.p closest to
// anchorPos. If the closest assignment to <reqVar>.p is non-constant (such as
// Webpack 5's computed "auto" publicPath), it returns false.
func findPublicPath(src string, anchorPos int, reqVar string) (string, bool) {
	if reqVar == "" {
		m := webpackFallbackP.FindStringSubmatch(src)
		if m == nil {
			return "", false
		}
		if m[1] != "" {
			return m[1], true
		}
		return m[2], true
	}
	needle := reqVar + ".p"
	bestIdx := -1
	bestDist := len(src) + 1
	for off := 0; off < len(src); {
		i := strings.Index(src[off:], needle)
		if i < 0 {
			break
		}
		pos := off + i
		off = pos + len(needle)
		if pos > 0 && isJSIdentOrDot(src[pos-1]) {
			continue
		}
		after := skipWSAndComments(src, pos+len(needle))
		if after >= len(src) || src[after] != '=' {
			continue
		}
		if after+1 < len(src) && src[after+1] == '=' {
			continue // comparison (== or ===), not assignment
		}
		dist := pos - anchorPos
		if dist < 0 {
			dist = -dist
		}
		if dist < bestDist {
			bestDist = dist
			bestIdx = after + 1
		}
	}
	if bestIdx < 0 {
		return "", false
	}
	rhs := skipWSAndComments(src, bestIdx)
	val, next, ok := parseJSStringLiteral(src, rhs)
	if !ok {
		return "", false
	}
	tail := skipWSAndComments(src, next)
	if tail < len(src) {
		switch src[tail] {
		case ';', ',', '}', ')', '\r', '\n':
		default:
			// Reject dynamic concatenations such as r.p = "/" + window.base.
			return "", false
		}
	}
	return val, true
}

func resolvePublicBase(base *url.URL, pubPath, prefix string, named map[string]string) (*url.URL, string, map[string]string, bool) {
	if pubPath == "" {
		cp := *base
		return &cp, prefix, named, true
	}
	// Preserve exact JS string concatenation (pubPath + rel) when pubPath does
	// not end with "/" by keeping the directory part on PublicBase and folding
	// any trailing segment onto prefix / named values.
	dirPart := pubPath
	tailPart := ""
	if !strings.HasSuffix(pubPath, "/") {
		if i := strings.LastIndexByte(pubPath, '/'); i >= 0 {
			dirPart = pubPath[:i+1]
			tailPart = pubPath[i+1:]
		} else {
			dirPart = ""
			tailPart = pubPath
		}
	}
	pub, err := base.Parse(dirPart)
	if err != nil || (pub.Scheme != "http" && pub.Scheme != "https") {
		return nil, "", nil, false
	}
	if tailPart != "" {
		prefix = tailPart + prefix
	} else if dirPart != "" && strings.HasPrefix(prefix, "/") {
		prefix = strings.TrimPrefix(prefix, "/")
	}
	if len(named) > 0 && (tailPart != "" || dirPart != "") {
		adj := make(map[string]string, len(named))
		for k, v := range named {
			if tailPart != "" {
				adj[k] = tailPart + v
			} else if strings.HasPrefix(v, "/") {
				adj[k] = strings.TrimPrefix(v, "/")
			} else {
				adj[k] = v
			}
		}
		named = adj
	}
	return pub, prefix, named, true
}

type builderTermKind int

const (
	termStr builderTermKind = iota
	termID
	termFallbackMap
	termDirectMap
)

type builderTerm struct {
	kind  builderTermKind
	str   string
	idMap map[string]string
}

func parseBuilderExpr(raw, idVar string) *WebpackRuntime {
	expr := trimOuterParens(raw)
	if expr == "" {
		return nil
	}
	named := map[string]string{}
	for {
		var key, val, rest string
		var ok bool
		key, val, rest, idVar, ok = peelLeadingChunkTernary(expr, idVar)
		if !ok {
			break
		}
		if isJSSuffix(val) {
			named[key] = val
		}
		expr = trimOuterParens(rest)
	}
	if expr == "" || expr == "void 0" || expr == "undefined" {
		if len(named) == 0 {
			return nil
		}
		return &WebpackRuntime{Named: named}
	}

	rawParts := splitTopLevelPlus(expr)
	if len(rawParts) == 0 {
		return nil
	}
	var terms []builderTerm
	for _, p := range rawParts {
		p = trimOuterParens(p)
		if p == "" {
			return nil
		}
		if s, end, ok := parseJSStringLiteral(p, 0); ok && skipWSAndComments(p, end) == len(p) {
			if len(terms) > 0 && terms[len(terms)-1].kind == termStr {
				terms[len(terms)-1].str += s
			} else {
				terms = append(terms, builderTerm{kind: termStr, str: s})
			}
			continue
		}
		if isValidJSIdent(p) {
			if idVar == "" {
				idVar = p
			}
			if p != idVar {
				return nil
			}
			terms = append(terms, builderTerm{kind: termID})
			continue
		}
		if m, fallback, v, ok := parseChunkMapTerm(p, idVar); ok {
			if idVar == "" {
				idVar = v
			}
			kind := termDirectMap
			if fallback {
				kind = termFallbackMap
			}
			terms = append(terms, builderTerm{kind: kind, idMap: m})
			continue
		}
		return nil
	}

	rt := assembleBuilderTerms(terms)
	if rt == nil {
		return nil
	}
	if len(named) > 0 {
		rt.Named = named
	}
	return rt
}

func assembleBuilderTerms(terms []builderTerm) *WebpackRuntime {
	idx := 0
	takeStr := func() string {
		if idx < len(terms) && terms[idx].kind == termStr {
			s := terms[idx].str
			idx++
			return s
		}
		return ""
	}

	prefix := takeStr()
	if idx >= len(terms) {
		return nil
	}
	first := terms[idx]
	idx++

	switch first.kind {
	case termID, termFallbackMap:
		var nameMap map[string]string
		if first.kind == termFallbackMap {
			nameMap = first.idMap
		}
		mid := takeStr()
		if idx == len(terms) {
			if !isJSSuffix(mid) {
				return nil
			}
			return &WebpackRuntime{
				Prefix:      prefix,
				NameMap:     nameMap,
				Suffix:      mid,
				hasNamePart: true,
			}
		}
		if terms[idx].kind != termDirectMap {
			return nil
		}
		hashMap := terms[idx].idMap
		idx++
		suffix := takeStr()
		if idx != len(terms) || len(hashMap) == 0 || !isJSSuffix(suffix) {
			return nil
		}
		return &WebpackRuntime{
			Prefix:      prefix,
			NameMap:     nameMap,
			Sep:         mid,
			HashMap:     hashMap,
			Suffix:      suffix,
			hasNamePart: true,
		}

	case termDirectMap:
		mid := takeStr()
		if idx == len(terms) {
			if len(first.idMap) == 0 || !isJSSuffix(mid) {
				return nil
			}
			return &WebpackRuntime{
				Prefix:      prefix,
				HashMap:     first.idMap,
				Suffix:      mid,
				hasNamePart: false,
			}
		}
		if terms[idx].kind != termDirectMap {
			return nil
		}
		hashMap := terms[idx].idMap
		idx++
		suffix := takeStr()
		if idx != len(terms) || len(hashMap) == 0 || !isJSSuffix(suffix) {
			return nil
		}
		return &WebpackRuntime{
			Prefix:      prefix,
			NameMap:     first.idMap,
			Sep:         mid,
			HashMap:     hashMap,
			Suffix:      suffix,
			hasNamePart: true,
		}
	}
	return nil
}

// peelLeadingChunkTernary matches `<idOrLit> === <idOrLit> ? "<file>" : <rest>`
// at depth 0 on the front of expr.
func peelLeadingChunkTernary(expr, idVar string) (key, val, rest, outIDVar string, ok bool) {
	qPos, cPos := findTopLevelTernary(expr)
	if qPos < 0 || cPos < 0 {
		return "", "", "", idVar, false
	}
	cond := trimOuterParens(expr[:qPos])
	conseq := trimOuterParens(expr[qPos+1 : cPos])
	fileStr, end, strOK := parseJSStringLiteral(conseq, 0)
	if !strOK || skipWSAndComments(conseq, end) != len(conseq) {
		return "", "", "", idVar, false
	}
	var lhs, rhs string
	if i := strings.Index(cond, "==="); i > 0 {
		lhs, rhs = strings.TrimSpace(cond[:i]), strings.TrimSpace(cond[i+3:])
	} else if i := strings.Index(cond, "=="); i > 0 && (i+2 >= len(cond) || cond[i+2] != '=') {
		lhs, rhs = strings.TrimSpace(cond[:i]), strings.TrimSpace(cond[i+2:])
	} else {
		return "", "", "", idVar, false
	}
	if k, v, matched := matchIDComparison(lhs, rhs, idVar); matched {
		return k, fileStr, expr[cPos+1:], v, true
	}
	if k, v, matched := matchIDComparison(rhs, lhs, idVar); matched {
		return k, fileStr, expr[cPos+1:], v, true
	}
	return "", "", "", idVar, false
}

func matchIDComparison(litSide, varSide, idVar string) (key, outIDVar string, ok bool) {
	if !isValidJSIdent(varSide) {
		return "", idVar, false
	}
	if idVar != "" && varSide != idVar {
		return "", idVar, false
	}
	if isDigits(litSide) {
		return litSide, varSide, true
	}
	if s, end, strOK := parseJSStringLiteral(litSide, 0); strOK && end == len(litSide) && validChunkID(s) {
		return s, varSide, true
	}
	return "", idVar, false
}

// parseChunkMapTerm parses `{...}[id]` or `({...}[id] || id)` (with optional
// parens around the object literal).
func parseChunkMapTerm(s, idVar string) (idMap map[string]string, fallback bool, outIDVar string, ok bool) {
	i := skipWSAndComments(s, 0)
	wrappedObj := false
	if i < len(s) && s[i] == '(' {
		closeParen := matchBalanced(s, i, '(', ')')
		if closeParen < 0 {
			return nil, false, idVar, false
		}
		inner := skipWSAndComments(s, i+1)
		if inner < closeParen && s[inner] == '{' {
			if innerEnd := matchBalanced(s, inner, '{', '}'); innerEnd > inner && skipWSAndComments(s, innerEnd+1) == closeParen {
				wrappedObj = true
				i = inner
			}
		}
	}
	if i >= len(s) || s[i] != '{' {
		return nil, false, idVar, false
	}
	objEnd := matchBalanced(s, i, '{', '}')
	if objEnd < 0 {
		return nil, false, idVar, false
	}
	objBody := s[i+1 : objEnd]
	pos := skipWSAndComments(s, objEnd+1)
	if wrappedObj {
		if pos >= len(s) || s[pos] != ')' {
			return nil, false, idVar, false
		}
		pos = skipWSAndComments(s, pos+1)
	}
	if pos >= len(s) || s[pos] != '[' {
		return nil, false, idVar, false
	}
	brkEnd := matchBalanced(s, pos, '[', ']')
	if brkEnd < 0 {
		return nil, false, idVar, false
	}
	idxVar := strings.TrimSpace(s[pos+1 : brkEnd])
	if !isValidJSIdent(idxVar) || (idVar != "" && idxVar != idVar) {
		return nil, false, idVar, false
	}
	pos = skipWSAndComments(s, brkEnd+1)
	if pos == len(s) {
		return parseIDMap(objBody), false, idxVar, true
	}
	if !strings.HasPrefix(s[pos:], "||") {
		return nil, false, idVar, false
	}
	orVar := strings.TrimSpace(s[pos+2:])
	if orVar != idxVar {
		return nil, false, idVar, false
	}
	return parseIDMap(objBody), true, idxVar, true
}

func parseIDMap(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range webpackMapEntryRe.FindAllStringSubmatch(s, -1) {
		k := strings.Trim(kv[1], `"'`)
		v := kv[2]
		if v == "" && kv[3] != "" {
			v = kv[3]
		}
		if validChunkID(k) {
			out[k] = v
		}
	}
	return out
}

func isJSSuffix(s string) bool {
	s, _, _ = strings.Cut(s, "?")
	s, _, _ = strings.Cut(s, "#")
	switch strings.ToLower(path.Ext("x" + s)) {
	case ".js", ".mjs", ".cjs":
		return true
	}
	return false
}

// StaticCandidates returns the candidates deterministically implied by rt's
// own tables (Named, HashMap, and any named entries in NameMap).
func (rt *WebpackRuntime) StaticCandidates() []Candidate {
	if rt == nil || rt.PublicBase == nil {
		return nil
	}
	var out []Candidate
	from := rt.from
	add := func(rel string) {
		if u, err := rt.PublicBase.Parse(rel); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			u.Fragment = ""
			out = append(out, Candidate{URL: u.String(), Method: "webpack-runtime", From: from})
		}
	}
	for _, k := range sortedKeys(rt.Named) {
		add(rt.Named[k])
	}
	if len(rt.HashMap) > 0 {
		for _, id := range sortedKeys(rt.HashMap) {
			hash := rt.HashMap[id]
			if rt.hasNamePart {
				name := id
				if n, ok := rt.NameMap[id]; ok {
					name = n
				}
				add(rt.Prefix + name + rt.Sep + hash + rt.Suffix)
			} else {
				add(rt.Prefix + hash + rt.Suffix)
			}
		}
		return out
	}
	if rt.IsPlain() && len(rt.NameMap) > 0 {
		count := 0
		for _, id := range sortedKeys(rt.NameMap) {
			if count >= maxPlainChunks {
				break
			}
			count++
			add(rt.Prefix + rt.NameMap[id] + rt.Suffix)
		}
	}
	return out
}

// ChunkCandidate resolves one dynamic chunk ID against a plain WebpackRuntime.
func (rt *WebpackRuntime) ChunkCandidate(id, from string) (Candidate, bool) {
	if !rt.IsPlain() || rt.PublicBase == nil || !validChunkID(id) {
		return Candidate{}, false
	}
	if from == "" {
		from = rt.from
	}
	rel := ""
	if namedRel, ok := rt.Named[id]; ok {
		rel = namedRel
	} else {
		name := id
		if n, ok := rt.NameMap[id]; ok {
			name = n
		}
		rel = rt.Prefix + name + rt.Suffix
	}
	u, err := rt.PublicBase.Parse(rel)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return Candidate{}, false
	}
	u.Fragment = ""
	return Candidate{URL: u.String(), Method: "webpack-runtime", From: from}, true
}

func webpackChunks(body []byte, scriptURL, pageURL string) []Candidate {
	rt := ExtractWebpackRuntime(body, scriptURL, pageURL)
	if rt == nil {
		return nil
	}
	out := rt.StaticCandidates()
	if !rt.IsPlain() {
		return out
	}
	seen := make(map[string]bool, len(rt.NameMap)+len(rt.Named))
	for k := range rt.Named {
		seen[k] = true
	}
	plainCount := 0
	for k := range rt.NameMap {
		if plainCount >= maxPlainChunks {
			break
		}
		seen[k] = true
		plainCount++
	}
	for _, id := range ExtractWebpackChunkIDs(body) {
		if plainCount >= maxPlainChunks {
			break
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if c, ok := rt.ChunkCandidate(id, rt.from); ok {
			plainCount++
			out = append(out, c)
		}
	}
	return out
}

// ExtractWebpackChunkIDs extracts validated chunk IDs from explicit <req>.e(...)
// calls and webpackAsyncContext module maps in src.
func ExtractWebpackChunkIDs(src []byte) []string {
	if !bytes.Contains(src, []byte(".e")) {
		return nil
	}
	s := string(src)
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		if !validChunkID(id) || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}

	for _, m := range webpackLoadCallRe.FindAllStringSubmatch(s, -1) {
		add(strings.Trim(m[1], `"'`))
	}

	seenMap := map[int]bool{}
	for _, loc := range webpackAsyncAnchorRe.FindAllStringSubmatchIndex(s, -1) {
		anchorStart := loc[0]
		sliceStart := 1
		if (loc[2] >= 0 && s[loc[2]:loc[3]] == "2") || (loc[4] >= 0 && s[loc[4]:loc[5]] == "2") {
			sliceStart = 2
		}
		winStart := max(0, anchorStart-asyncAnchorWindow)
		for closePos := anchorStart - 1; closePos >= winStart; closePos-- {
			if s[closePos] != '}' {
				continue
			}
			if !nonNegativeBraceDepth(s[closePos+1 : anchorStart]) {
				break // crossed out of the enclosing function/module
			}
			openPos, ok := findMatchingOpenBrace(s, closePos, maxAsyncContextSize)
			if !ok {
				continue
			}
			if seenMap[openPos] {
				break
			}
			firstTok := skipWSAndComments(s, openPos+1)
			if firstTok+3 >= closePos || (s[firstTok] != '"' && s[firstTok] != '\'') || s[firstTok+1] != '.' || s[firstTok+2] != '/' {
				continue
			}
			ids, ok := parseAsyncContextMap(s[openPos:closePos+1], sliceStart)
			if !ok {
				continue
			}
			seenMap[openPos] = true
			for _, id := range ids {
				add(id)
			}
			break
		}
	}
	return out
}

func validChunkID(id string) bool {
	return id != "." && id != ".." && chunkIDRe.MatchString(id)
}

// parseAsyncContextMap parses `{ "./a.json": [1476, 0], "./b.vue": [1502, 2, 5] }`
// and returns scalar elements at index >= sliceStart for entries whose array
// length exceeds sliceStart. Every key must start with "./" and every value
// must be an array literal.
func parseAsyncContextMap(lit string, sliceStart int) ([]string, bool) {
	if len(lit) < 2 || lit[0] != '{' || lit[len(lit)-1] != '}' {
		return nil, false
	}
	end := len(lit) - 1
	pos := skipWSAndComments(lit, 1)
	if pos >= end {
		return nil, false
	}
	var ids []string
	entries := 0
	for pos < end {
		key, next, ok := parseJSStringLiteral(lit, pos)
		if !ok || !strings.HasPrefix(key, "./") {
			return nil, false
		}
		pos = skipWSAndComments(lit, next)
		if pos >= end || lit[pos] != ':' {
			return nil, false
		}
		pos = skipWSAndComments(lit, pos+1)
		if pos >= end || lit[pos] != '[' {
			return nil, false
		}
		arrEnd := matchBalanced(lit, pos, '[', ']')
		if arrEnd < 0 || arrEnd >= end {
			return nil, false
		}
		elems, ok := parseContextArrayElems(lit[pos+1 : arrEnd])
		if !ok || len(elems) == 0 {
			return nil, false
		}
		entries++
		if len(elems) > sliceStart {
			for _, el := range elems[sliceStart:] {
				if el != "" && validChunkID(el) {
					ids = append(ids, el)
				}
			}
		}
		pos = skipWSAndComments(lit, arrEnd+1)
		if pos < end {
			if lit[pos] != ',' {
				return nil, false
			}
			pos = skipWSAndComments(lit, pos+1)
		}
	}
	if entries == 0 {
		return nil, false
	}
	return ids, true
}

// parseContextArrayElems splits `[1476, 0, "chunk-a"]` at bracket depth 0.
// Nested arrays (e.g. Webpack 5 deferred harmony exports `[59222, 7, [59222]]`)
// return "" at that position so module IDs inside nested arrays are never
// mistaken for chunk IDs.
func parseContextArrayElems(body string) ([]string, bool) {
	var elems []string
	pos := skipWSAndComments(body, 0)
	if pos == len(body) {
		return nil, false
	}
	for pos < len(body) {
		elemStart := pos
		depth := 0
		for pos < len(body) {
			c := body[pos]
			switch {
			case c == '"' || c == '\'':
				_, next, ok := parseJSStringLiteral(body, pos)
				if !ok {
					return nil, false
				}
				pos = next
				continue
			case c == '/' && pos+1 < len(body) && (body[pos+1] == '*' || body[pos+1] == '/'):
				pos = skipWSAndComments(body, pos)
				continue
			case c == '[' || c == '(' || c == '{':
				depth++
			case c == ']' || c == ')' || c == '}':
				depth--
				if depth < 0 {
					return nil, false
				}
			case c == ',' && depth == 0:
				goto gotElem
			}
			pos++
		}
	gotElem:
		raw := strings.TrimSpace(stripComments(body[elemStart:pos]))
		if raw == "" {
			return nil, false
		}
		switch {
		case isDigits(raw):
			elems = append(elems, raw)
		case raw[0] == '"' || raw[0] == '\'':
			s, end, ok := parseJSStringLiteral(raw, 0)
			if !ok || end != len(raw) {
				return nil, false
			}
			elems = append(elems, s)
		case raw[0] == '[':
			// Nested array metadata (never a scalar chunk ID).
			elems = append(elems, "")
		default:
			return nil, false
		}
		if pos < len(body) && body[pos] == ',' {
			pos = skipWSAndComments(body, pos+1)
		}
	}
	return elems, true
}

// --- Cross-script Webpack runtimeChunk linker ---

var trackerDomains = []string{
	"google-analytics.com",
	"googletagmanager.com",
	"doubleclick.net",
	"googlesyndication.com",
	"googleadservices.com",
	"facebook.net",
	"facebook.com",
	"hotjar.com",
	"clarity.ms",
	"segment.io",
	"segment.com",
	"mixpanel.com",
	"amplitude.com",
	"fullstory.com",
	"intercom.io",
	"intercomcdn.com",
	"hubspot.com",
	"hs-scripts.com",
	"hs-analytics.net",
	"newrelic.com",
	"nr-data.net",
	"datadoghq-browser-agent.com",
	"sentry-cdn.com",
	"bugsnag.com",
	"logrocket.io",
	"pendo.io",
	"optimizely.com",
	"criteo.com",
	"taboola.com",
	"outbrain.com",
}

func isTrackerURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h == "" {
		return false
	}
	for _, d := range trackerDomains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

type linkedRuntime struct {
	rt           *WebpackRuntime
	key          string
	scriptOrigin string
	publicOrigin string
	pageOrigin   string
	inline       bool
	emitted      map[string]bool
	plainCount   int
}

func (lr *linkedRuntime) emit(ids []string, from string) []Candidate {
	var out []Candidate
	for _, id := range ids {
		if lr.plainCount >= maxPlainChunks {
			break
		}
		if lr.emitted[id] {
			continue
		}
		c, ok := lr.rt.ChunkCandidate(id, from)
		if !ok {
			continue
		}
		lr.emitted[id] = true
		lr.plainCount++
		out = append(out, c)
	}
	return out
}

type linkedChunks struct {
	ids          []string
	from         string
	scriptOrigin string
	pageOrigin   string
	inline       bool
	thirdParty   bool
}

// WebpackLinker pairs unhashed WebpackRuntimes (e.g. runtime~main.js) with
// chunk IDs discovered in sibling non-tracker scripts of the same app (e.g.
// main.js, vendors.js, or resolved lazy chunks). A zero WebpackLinker is ready
// for concurrent use.
type WebpackLinker struct {
	mu       sync.Mutex
	runtimes []*linkedRuntime
	chunks   []linkedChunks
}

// Add inspects a script and returns any newly paired cross-script webpack-runtime
// candidates not already returned by single-file Static(body, scriptURL, pageURL).
func (l *WebpackLinker) Add(body []byte, scriptURL, pageURL string, inline, thirdParty bool) []Candidate {
	if isTrackerURL(scriptURL) {
		return nil
	}
	rt := ExtractWebpackRuntime(body, scriptURL, pageURL)
	ids := ExtractWebpackChunkIDs(body)
	plainRT := rt != nil && rt.IsPlain() && !thirdParty
	if !plainRT && len(ids) == 0 {
		return nil
	}

	scriptOrigin := urlOrigin(scriptURL)
	pageOrigin := urlOrigin(pageURL)
	if pageOrigin == "" {
		pageOrigin = scriptOrigin
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	var out []Candidate
	if plainRT {
		pubOrigin := urlOrigin(rt.PublicBase.String())
		rtKey := rt.PublicBase.String() + "|" + rt.Prefix + "|" + rt.Suffix + "|" + scriptOrigin + "|" + pageOrigin
		var lr *linkedRuntime
		for _, existing := range l.runtimes {
			if existing.key == rtKey {
				lr = existing
				break
			}
		}
		isNew := lr == nil
		if isNew {
			lr = &linkedRuntime{
				rt:           rt,
				key:          rtKey,
				scriptOrigin: scriptOrigin,
				publicOrigin: pubOrigin,
				pageOrigin:   pageOrigin,
				inline:       inline,
				emitted:      map[string]bool{},
			}
			for k := range rt.Named {
				lr.emitted[k] = true
			}
			for k := range rt.NameMap {
				if lr.plainCount < maxPlainChunks {
					lr.emitted[k] = true
					lr.plainCount++
				}
			}
		}
		// Mark chunk IDs present in this script's own body as already emitted by Static.
		for _, id := range ids {
			if !lr.emitted[id] && lr.plainCount < maxPlainChunks {
				lr.emitted[id] = true
				lr.plainCount++
			}
		}
		if isNew {
			l.runtimes = append(l.runtimes, lr)
			for _, lc := range l.chunks {
				if sameWebpackApp(lr, lc) {
					out = append(out, lr.emit(lc.ids, lc.from)...)
				}
			}
		}
	}

	if len(ids) > 0 {
		lc := linkedChunks{
			ids:          ids,
			from:         scriptURL,
			scriptOrigin: scriptOrigin,
			pageOrigin:   pageOrigin,
			inline:       inline,
			thirdParty:   thirdParty,
		}
		l.chunks = append(l.chunks, lc)
		for _, lr := range l.runtimes {
			if sameWebpackApp(lr, lc) {
				out = append(out, lr.emit(lc.ids, lc.from)...)
			}
		}
	}
	return dedupe(out)
}

func sameWebpackApp(lr *linkedRuntime, lc linkedChunks) bool {
	if lc.scriptOrigin != "" && !lc.inline && (lc.scriptOrigin == lr.publicOrigin || lc.scriptOrigin == lr.scriptOrigin) {
		return true
	}
	if lc.inline && lc.pageOrigin != "" && (lc.pageOrigin == lr.pageOrigin || lc.pageOrigin == lr.scriptOrigin) {
		return true
	}
	if lr.inline && !lc.thirdParty && lr.pageOrigin != "" && lc.pageOrigin == lr.pageOrigin {
		return true
	}
	return false
}

func urlOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// --- Lexical helpers ---

func scanExprEnd(s string, start int) int {
	pDepth, bDepth, kDepth := 0, 0, 0
	for i := start; i < len(s); {
		c := s[i]
		switch {
		case c == '"' || c == '\'' || c == '`':
			_, next, ok := skipQuoted(s, i)
			if !ok {
				return i
			}
			i = next
			continue
		case c == '/' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '/'):
			i = skipWSAndComments(s, i)
			continue
		case c == '(':
			pDepth++
		case c == ')':
			if pDepth == 0 && bDepth == 0 && kDepth == 0 {
				return i
			}
			pDepth--
		case c == '{':
			bDepth++
		case c == '}':
			if pDepth == 0 && bDepth == 0 && kDepth == 0 {
				return i
			}
			bDepth--
		case c == '[':
			kDepth++
		case c == ']':
			if kDepth == 0 {
				return i
			}
			kDepth--
		case (c == ';' || c == ',') && pDepth == 0 && bDepth == 0 && kDepth == 0:
			return i
		}
		i++
	}
	return len(s)
}

func trimOuterParens(s string) string {
	for {
		start := skipWSAndComments(s, 0)
		end := trimRightWS(s)
		if start >= end {
			return ""
		}
		s = s[start:end]
		if s[0] != '(' || s[len(s)-1] != ')' {
			return s
		}
		if matchBalanced(s, 0, '(', ')') != len(s)-1 {
			return s
		}
		s = s[1 : len(s)-1]
	}
}

func findTopLevelTernary(s string) (qPos, cPos int) {
	pDepth, bDepth, kDepth, qDepth := 0, 0, 0, 0
	qPos = -1
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"' || c == '\'' || c == '`':
			_, next, ok := skipQuoted(s, i)
			if !ok {
				return -1, -1
			}
			i = next
			continue
		case c == '/' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '/'):
			i = skipWSAndComments(s, i)
			continue
		case c == '(':
			pDepth++
		case c == ')':
			pDepth--
		case c == '{':
			bDepth++
		case c == '}':
			bDepth--
		case c == '[':
			kDepth++
		case c == ']':
			kDepth--
		case pDepth == 0 && bDepth == 0 && kDepth == 0:
			if c == '?' && (i+1 >= len(s) || (s[i+1] != '?' && s[i+1] != '.')) {
				if qPos < 0 {
					qPos = i
				} else {
					qDepth++
				}
			} else if c == ':' && qPos >= 0 {
				if qDepth == 0 {
					return qPos, i
				}
				qDepth--
			}
		}
		i++
	}
	return -1, -1
}

func splitTopLevelPlus(s string) []string {
	var parts []string
	pDepth, bDepth, kDepth := 0, 0, 0
	last := 0
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"' || c == '\'' || c == '`':
			_, next, ok := skipQuoted(s, i)
			if !ok {
				return nil
			}
			i = next
			continue
		case c == '/' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '/'):
			i = skipWSAndComments(s, i)
			continue
		case c == '(':
			pDepth++
		case c == ')':
			pDepth--
		case c == '{':
			bDepth++
		case c == '}':
			bDepth--
		case c == '[':
			kDepth++
		case c == ']':
			kDepth--
		case c == '+' && pDepth == 0 && bDepth == 0 && kDepth == 0:
			if i+1 < len(s) && (s[i+1] == '+' || s[i+1] == '=') {
				return nil
			}
			parts = append(parts, s[last:i])
			last = i + 1
		}
		i++
	}
	parts = append(parts, s[last:])
	return parts
}

func matchBalanced(s string, openIdx int, openCh, closeCh byte) int {
	if openIdx < 0 || openIdx >= len(s) || s[openIdx] != openCh {
		return -1
	}
	depth := 1
	for i := openIdx + 1; i < len(s); {
		c := s[i]
		switch {
		case c == '"' || c == '\'' || c == '`':
			_, next, ok := skipQuoted(s, i)
			if !ok {
				return -1
			}
			i = next
			continue
		case c == '/' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '/'):
			i = skipWSAndComments(s, i)
			continue
		case c == openCh:
			depth++
		case c == closeCh:
			depth--
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return -1
}

func nonNegativeBraceDepth(s string) bool {
	depth := 0
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"' || c == '\'' || c == '`':
			_, next, ok := skipQuoted(s, i)
			if !ok {
				return false
			}
			i = next
			continue
		case c == '/' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '/'):
			i = skipWSAndComments(s, i)
			continue
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth < 0 {
				return false
			}
		}
		i++
	}
	return true
}

func findMatchingOpenBrace(s string, closePos, maxSpan int) (int, bool) {
	limit := max(0, closePos-maxSpan)
	depth := 1
	for i := closePos - 1; i >= limit; i-- {
		c := s[i]
		if c == '"' || c == '\'' {
			q := c
			i--
			for i >= limit {
				if s[i] == '\n' || s[i] == '\r' {
					return 0, false
				}
				if s[i] == q {
					bs := 0
					for i-1-bs >= limit && s[i-1-bs] == '\\' {
						bs++
					}
					if bs%2 == 0 {
						break
					}
				}
				i--
			}
			if i < limit {
				return 0, false
			}
			continue
		}
		if c == '}' {
			depth++
		} else if c == '{' {
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// parseJSStringLiteral parses a plain single- or double-quoted string literal
// with no backslash escapes or raw newlines, returning the inner bytes.
func parseJSStringLiteral(s string, pos int) (val string, next int, ok bool) {
	if pos >= len(s) || (s[pos] != '"' && s[pos] != '\'') {
		return "", pos, false
	}
	q := s[pos]
	for i := pos + 1; i < len(s); i++ {
		switch s[i] {
		case '\\', '\r', '\n':
			return "", pos, false
		case q:
			return s[pos+1 : i], i + 1, true
		}
	}
	return "", pos, false
}

func skipQuoted(s string, pos int) (val string, next int, ok bool) {
	q := s[pos]
	for i := pos + 1; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if (q == '"' || q == '\'') && (s[i] == '\r' || s[i] == '\n') {
			return "", pos, false
		}
		if s[i] == q {
			return s[pos+1 : i], i + 1, true
		}
	}
	return "", pos, false
}

func skipWSAndComments(s string, pos int) int {
	for pos < len(s) {
		switch s[pos] {
		case ' ', '\t', '\r', '\n':
			pos++
		case '/':
			if pos+1 < len(s) && s[pos+1] == '*' {
				end := strings.Index(s[pos+2:], "*/")
				if end < 0 {
					return len(s)
				}
				pos += 2 + end + 2
				continue
			}
			if pos+1 < len(s) && s[pos+1] == '/' {
				end := strings.IndexByte(s[pos+2:], '\n')
				if end < 0 {
					return len(s)
				}
				pos += 2 + end + 1
				continue
			}
			return pos
		default:
			return pos
		}
	}
	return pos
}

func trimRightWS(s string) int {
	end := len(s)
	for end > 0 {
		switch s[end-1] {
		case ' ', '\t', '\r', '\n':
			end--
		default:
			return end
		}
	}
	return 0
}

func stripComments(s string) string {
	if !strings.Contains(s, "/") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			_, next, ok := skipQuoted(s, i)
			if !ok {
				b.WriteString(s[i:])
				break
			}
			b.WriteString(s[i:next])
			i = next
			continue
		}
		if s[i] == '/' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '/') {
			i = skipWSAndComments(s, i)
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isJSIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$'
}

func isJSIdentPart(c byte) bool {
	return isJSIdentStart(c) || (c >= '0' && c <= '9')
}

func isJSIdentOrDot(c byte) bool {
	return isJSIdentPart(c) || c == '.'
}

func isValidJSIdent(s string) bool {
	if s == "" || !isJSIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isJSIdentPart(s[i]) {
			return false
		}
	}
	switch s {
	case "return", "void", "undefined", "null", "true", "false", "function", "var", "let", "const":
		return false
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	ks := slices.Collect(maps.Keys(m))
	slices.Sort(ks)
	return ks
}
