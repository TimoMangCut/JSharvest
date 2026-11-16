package jsapi

import (
	"bytes"
	"encoding/json"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/evanw/esbuild/pkg/api"
)

// ExtractSource extracts API endpoints from a script or original source file
// (TypeScript, TSX/JSX, Vue/Svelte SFC). Plain valid JavaScript runs on the
// direct Extract fast path with zero preprocessing overhead; esbuild's pure-Go
// transform only runs when SFC masking or TypeScript/JSX syntax requires it.
func ExtractSource(src []byte, hint string) Result {
	if masked, spans, preferTSX, hasLangTS, ok := maskSFC(src, hint); ok {
		if !hasLangTS && !preferTSX {
			r := extractWithMap(masked, src, nil, false)
			if !strings.HasPrefix(r.Error, "parse") {
				return r
			}
		}
		if code, lm, tok := transformTS(masked, hint, preferTSX); tok {
			r := extractWithMap(code, src, lm, false)
			if !strings.HasPrefix(r.Error, "parse") {
				return r
			}
			if lcode, llm, lok := transformTSWithSupported(masked, hint, preferTSX, arrowLowered); lok {
				if r2 := extractWithMap(lcode, src, llm, false); !strings.HasPrefix(r2.Error, "parse") {
					r2.ASTLowered = true
					return r2
				}
			}
			return r
		}
		// Dual <script> + <script setup> blocks in a .vue SFC can both
		// import the same identifier; transform each block separately while
		// preserving original .vue line numbers.
		if len(spans) > 1 {
			if merged, mok := extractSFCSpans(src, spans, hint, preferTSX); mok {
				return merged
			}
		}
		return extractWithMap(masked, src, nil, false)
	}
	switch hintExt(hint) {
	case ".ts", ".tsx", ".mts", ".cts":
		if code, lm, ok := transformTS(src, hint, false); ok {
			r := extractWithMap(code, src, lm, false)
			if !strings.HasPrefix(r.Error, "parse") {
				return r
			}
			if lcode, llm, lok := transformTSWithSupported(src, hint, false, arrowLowered); lok {
				if r2 := extractWithMap(lcode, src, llm, false); !strings.HasPrefix(r2.Error, "parse") {
					r2.ASTLowered = true
					return r2
				}
			}
			return r
		}
	}
	r := extractWithMap(src, nil, nil, false)
	if !strings.HasPrefix(r.Error, "parse") {
		return r
	}
	if code, lm, ok := transformJSLower(src); ok {
		if r2 := extractWithMap(code, src, lm, false); !strings.HasPrefix(r2.Error, "parse") {
			r2.ASTLowered = true
			return r2
		}
	}
	if code, lm, ok := transformTS(src, hint, false); ok {
		r2 := extractWithMap(code, src, lm, false)
		if !strings.HasPrefix(r2.Error, "parse") {
			return r2
		}
		if lcode, llm, lok := transformTSWithSupported(src, hint, false, arrowLowered); lok {
			if r3 := extractWithMap(lcode, src, llm, false); !strings.HasPrefix(r3.Error, "parse") {
				r3.ASTLowered = true
				return r3
			}
		}
		return r2
	}
	return r
}

func extractSFCSpans(src []byte, spans [][2]int, hint string, preferTSX bool) (Result, bool) {
	out := Result{Version: Version}
	anyOK := false
	buf := make([]byte, len(src))
	for _, sp := range spans {
		for i, c := range src {
			if c == '\n' {
				buf[i] = '\n'
			} else {
				buf[i] = ' '
			}
		}
		copy(buf[sp[0]:sp[1]], src[sp[0]:sp[1]])
		r := extractWithMap(buf, src, nil, false)
		if strings.HasPrefix(r.Error, "parse") {
			code, lm, ok := transformTS(buf, hint, preferTSX)
			if !ok {
				continue
			}
			r = extractWithMap(code, src, lm, false)
			if strings.HasPrefix(r.Error, "parse") {
				if lcode, llm, lok := transformTSWithSupported(buf, hint, preferTSX, arrowLowered); lok {
					if r2 := extractWithMap(lcode, src, llm, false); !strings.HasPrefix(r2.Error, "parse") {
						r2.ASTLowered = true
						r = r2
					}
				}
			}
		}
		if r.Error != "" {
			continue
		}
		anyOK = true
		out.mergeSpan(r)
	}
	return out, anyOK
}

// mergeSpan adds what one <script> block of an SFC found. Every slice of
// Result goes here (TestMergeSpanCoversEverySlice).
func (out *Result) mergeSpan(r Result) {
	out.ASTLowered = out.ASTLowered || r.ASTLowered
	out.Endpoints = append(out.Endpoints, r.Endpoints...)
	out.Routes = append(out.Routes, r.Routes...)
	out.RouteEntries = append(out.RouteEntries, r.RouteEntries...)
	out.Bases = append(out.Bases, r.Bases...)
	out.Operations = append(out.Operations, r.Operations...)
	out.Paths = append(out.Paths, r.Paths...)
	out.ClientHeaders = append(out.ClientHeaders, r.ClientHeaders...)
	out.Cloud = append(out.Cloud, r.Cloud...)
	out.Keys = append(out.Keys, r.Keys...)
	out.Exports = append(out.Exports, r.Exports...)
	out.Imports = append(out.Imports, r.Imports...)
	out.ReExports = append(out.ReExports, r.ReExports...)
	out.Builders = append(out.Builders, r.Builders...)
	out.Deferred = append(out.Deferred, r.Deferred...)
	out.Settings = append(out.Settings, r.Settings...)
	out.PropBases = append(out.PropBases, r.PropBases...)
	out.DocVars = append(out.DocVars, r.DocVars...)
	out.DocProd = append(out.DocProd, r.DocProd...)
	out.DocDev = append(out.DocDev, r.DocDev...)
	out.Factories = append(out.Factories, r.Factories...)
	if r.ClientAuthz != nil {
		if out.ClientAuthz == nil {
			out.ClientAuthz = &ClientAuthz{}
		}
		out.ClientAuthz.Roles = uniq(append(out.ClientAuthz.Roles, r.ClientAuthz.Roles...))
		out.ClientAuthz.Permissions = uniq(append(out.ClientAuthz.Permissions, r.ClientAuthz.Permissions...))
		for _, rule := range r.ClientAuthz.Rules {
			if !slices.Contains(out.ClientAuthz.Rules, rule) {
				out.ClientAuthz.Rules = append(out.ClientAuthz.Rules, rule)
			}
		}
	}
}

// hintExt returns the lowercased file extension of a URL or sourcemap virtual
// path ("https://host/app.js#../../src/views/Home.vue?vue&type=script" -> ".vue").
func hintExt(hint string) string {
	if hint == "" {
		return ""
	}
	if _, frag, ok := strings.Cut(hint, "#"); ok && frag != "" {
		hint = frag
	}
	if p, _, ok := strings.Cut(hint, "?"); ok {
		hint = p
	}
	return strings.ToLower(path.Ext(hint))
}

// looksLikeHTMLDoc rejects full HTML/XML documents so they are never treated as
// SFC components or JSX expressions.
func looksLikeHTMLDoc(src []byte) bool {
	s := skipLeadingCommentsAndSpace(src)
	if len(s) < 5 || s[0] != '<' {
		return false
	}
	for _, p := range []string{"<!doctype", "<html", "<head", "<body", "<meta", "<title", "<?xml"} {
		if len(s) >= len(p) && strings.EqualFold(string(s[:len(p)]), p) {
			after := byte('>')
			if len(s) > len(p) {
				after = s[len(p)]
			}
			if after == '>' || after == ' ' || after == '\t' || after == '\r' || after == '\n' || after == '/' {
				return true
			}
		}
	}
	return false
}

func skipLeadingCommentsAndSpace(src []byte) []byte {
	s := src
	if bytes.HasPrefix(s, []byte{0xEF, 0xBB, 0xBF}) {
		s = s[3:]
	}
	for {
		s = bytes.TrimLeft(s, " \t\r\n")
		if bytes.HasPrefix(s, []byte("<!--")) {
			i := bytes.Index(s[4:], []byte("-->"))
			if i < 0 {
				return nil
			}
			s = s[4+i+3:]
			continue
		}
		return s
	}
}

func looksLikeSFC(src []byte) bool {
	s := skipLeadingCommentsAndSpace(src)
	if len(s) < 7 || s[0] != '<' {
		return false
	}
	for _, p := range []string{"<template", "<script", "<style"} {
		if len(s) > len(p) && strings.EqualFold(string(s[:len(p)]), p) {
			c := s[len(p)]
			if c == '>' || c == ' ' || c == '\t' || c == '\r' || c == '\n' {
				low := bytes.ToLower(s)
				return bytes.Contains(low, []byte("</script")) || bytes.Contains(low, []byte("</template"))
			}
		}
	}
	return false
}

// maskSFC replaces every non-newline byte outside top-level <script>...</script>
// bodies with ' ', keeping exact 1-to-1 byte offsets and line numbers with src.
func maskSFC(src []byte, hint string) (masked []byte, spans [][2]int, preferTSX bool, hasLangTS bool, ok bool) {
	if looksLikeHTMLDoc(src) {
		return nil, nil, false, false, false
	}
	ext := hintExt(hint)
	if ext != ".vue" && ext != ".svelte" && (ext != "" || !looksLikeSFC(src)) {
		return nil, nil, false, false, false
	}
	out := make([]byte, len(src))
	for i, c := range src {
		if c == '\n' {
			out[i] = '\n'
		} else {
			out[i] = ' '
		}
	}
	i := 0
	for i < len(src) {
		if bytes.HasPrefix(src[i:], []byte("<!--")) {
			if end := bytes.Index(src[i+4:], []byte("-->")); end >= 0 {
				i += 4 + end + 3
				continue
			}
			break
		}
		if hasTagOpen(src, i, "template") {
			i = skipNestedTag(src, i, "template")
			continue
		}
		if hasTagOpen(src, i, "style") {
			i = skipRawTag(src, i, "style")
			continue
		}
		if hasTagOpen(src, i, "script") {
			tagEnd, selfClose := scanTagOpenEnd(src, i+len("<script"))
			if tagEnd < 0 {
				break
			}
			if selfClose {
				i = tagEnd + 1
				continue
			}
			attrs := strings.ToLower(string(src[i : tagEnd+1]))
			if strings.Contains(attrs, `lang="tsx"`) || strings.Contains(attrs, `lang='tsx'`) ||
				strings.Contains(attrs, `lang="jsx"`) || strings.Contains(attrs, `lang='jsx'`) {
				preferTSX = true
			}
			if strings.Contains(attrs, `lang="ts"`) || strings.Contains(attrs, `lang='ts'`) {
				hasLangTS = true
			}
			contentStart := tagEnd + 1
			closeStart, closeEnd := findClosingTag(src, contentStart, "script")
			if closeStart < 0 {
				break
			}
			copy(out[contentStart:closeStart], src[contentStart:closeStart])
			spans = append(spans, [2]int{contentStart, closeStart})
			i = closeEnd
			continue
		}
		i++
	}
	return out, spans, preferTSX, hasLangTS, true
}

func hasTagOpen(src []byte, i int, tag string) bool {
	n := 1 + len(tag)
	if i+n >= len(src) || src[i] != '<' {
		return false
	}
	if !strings.EqualFold(string(src[i+1:i+n]), tag) {
		return false
	}
	c := src[i+n]
	return c == '>' || c == '/' || c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func hasTagClose(src []byte, i int, tag string) (int, bool) {
	n := 2 + len(tag)
	if i+n >= len(src) || src[i] != '<' || src[i+1] != '/' {
		return 0, false
	}
	if !strings.EqualFold(string(src[i+2:i+n]), tag) {
		return 0, false
	}
	j := i + n
	for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\r' || src[j] == '\n') {
		j++
	}
	if j < len(src) && src[j] == '>' {
		return j + 1, true
	}
	return 0, false
}

// scanTagOpenEnd scans HTML/SFC opening tag attributes from start until an
// unquoted '>', so generic="T extends Record<string, any>" does not end early.
func scanTagOpenEnd(src []byte, start int) (tagEnd int, selfClose bool) {
	var quote byte
	for i := start; i < len(src); i++ {
		c := src[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '>' {
			k := i - 1
			for k >= start && (src[k] == ' ' || src[k] == '\t' || src[k] == '\r' || src[k] == '\n') {
				k--
			}
			return i, k >= start && src[k] == '/'
		}
	}
	return -1, false
}

func findClosingTag(src []byte, start int, tag string) (closeStart, closeEnd int) {
	for i := start; i < len(src); i++ {
		if src[i] == '<' {
			if end, ok := hasTagClose(src, i, tag); ok {
				return i, end
			}
		}
	}
	return -1, -1
}

func skipRawTag(src []byte, i int, tag string) int {
	tagEnd, selfClose := scanTagOpenEnd(src, i+1+len(tag))
	if tagEnd < 0 {
		return len(src)
	}
	if selfClose {
		return tagEnd + 1
	}
	_, closeEnd := findClosingTag(src, tagEnd+1, tag)
	if closeEnd < 0 {
		return len(src)
	}
	return closeEnd
}

func skipNestedTag(src []byte, i int, tag string) int {
	tagEnd, selfClose := scanTagOpenEnd(src, i+1+len(tag))
	if tagEnd < 0 {
		return len(src)
	}
	if selfClose {
		return tagEnd + 1
	}
	depth := 1
	j := tagEnd + 1
	for j < len(src) && depth > 0 {
		if bytes.HasPrefix(src[j:], []byte("<!--")) {
			if end := bytes.Index(src[j+4:], []byte("-->")); end >= 0 {
				j += 4 + end + 3
				continue
			}
			return len(src)
		}
		if hasTagOpen(src, j, tag) {
			te, sc := scanTagOpenEnd(src, j+1+len(tag))
			if te < 0 {
				return len(src)
			}
			if !sc {
				depth++
			}
			j = te + 1
			continue
		}
		if end, ok := hasTagClose(src, j, tag); ok {
			depth--
			j = end
			continue
		}
		j++
	}
	return j
}

const legacyDecoratorsTSConfig = `{"compilerOptions":{"experimentalDecorators":true}}`

var arrowLowered = map[string]bool{"arrow": false}

// transformJSLower lowers arrow functions in valid standard JavaScript (not
// TypeScript/JSX) when tdewolff/parse fails on ES2015+ cover-grammar edge
// cases such as `({ a: b = 1 } = { a: 1 }) => b`.
func transformJSLower(src []byte) ([]byte, *esbuildLineMap, bool) {
	if len(src) == 0 || looksLikeHTMLDoc(src) {
		return nil, nil, false
	}
	res := api.Transform(string(src), api.TransformOptions{
		Loader:         api.LoaderJS,
		Target:         api.ESNext,
		Supported:      arrowLowered,
		Format:         api.FormatDefault,
		TreeShaking:    api.TreeShakingFalse,
		Sourcemap:      api.SourceMapExternal,
		SourcesContent: api.SourcesContentExclude,
		LogLevel:       api.LogLevelSilent,
	})
	if len(res.Errors) == 0 {
		return res.Code, decodeEsbuildMap(res.Map), true
	}
	return nil, nil, false
}

// transformTS strips TypeScript and JSX syntax using esbuild's pure-Go
// Transform API without tree-shaking or minifying, returning the generated JS
// and a decoded SourceMap v3 line mapper back to src.
func transformTS(src []byte, hint string, preferTSX bool) ([]byte, *esbuildLineMap, bool) {
	return transformTSWithSupported(src, hint, preferTSX, nil)
}

func transformTSWithSupported(src []byte, hint string, preferTSX bool, supported map[string]bool) ([]byte, *esbuildLineMap, bool) {
	if len(src) == 0 || looksLikeHTMLDoc(src) {
		return nil, nil, false
	}
	ext := hintExt(hint)
	loaders := []api.Loader{api.LoaderTS, api.LoaderTSX}
	if preferTSX || ext == ".tsx" || ext == ".jsx" {
		loaders = []api.Loader{api.LoaderTSX, api.LoaderTS}
	}
	input := string(src)
	for _, loader := range loaders {
		for _, tsconfig := range []string{legacyDecoratorsTSConfig, ""} {
			res := api.Transform(input, api.TransformOptions{
				Loader:         loader,
				Target:         api.ESNext,
				Supported:      supported,
				Format:         api.FormatDefault,
				TreeShaking:    api.TreeShakingFalse,
				Sourcemap:      api.SourceMapExternal,
				SourcesContent: api.SourcesContentExclude,
				TsconfigRaw:    tsconfig,
				LogLevel:       api.LogLevelSilent,
			})
			if len(res.Errors) == 0 {
				return res.Code, decodeEsbuildMap(res.Map), true
			}
		}
	}
	return nil, nil, false
}

type vlqSeg struct {
	genCol   int32 // 0-based UTF-16 column in generated JS
	origLine int32 // 1-based line in original source
	origCol  int32 // 1-based UTF-16 column in original source
}

type esbuildLineMap struct {
	segs    []vlqSeg
	lineOff []int32 // len == numLines+1; line g uses segs[lineOff[g]:lineOff[g+1]]
}

type rawSourceMap struct {
	Mappings string `json:"mappings"`
}

func extractMappingsField(raw []byte) string {
	const key = `"mappings":`
	idx := bytes.Index(raw, []byte(key))
	if idx >= 0 {
		j := idx + len(key)
		for j < len(raw) && (raw[j] == ' ' || raw[j] == '\t' || raw[j] == '\r' || raw[j] == '\n') {
			j++
		}
		if j < len(raw) && raw[j] == '"' {
			j++
			end := j
			escaped := false
			for end < len(raw) && raw[end] != '"' {
				if raw[end] == '\\' {
					escaped = true
					end += 2
					continue
				}
				end++
			}
			if end < len(raw) && !escaped {
				return string(raw[j:end])
			}
		}
	}
	var sm rawSourceMap
	if json.Unmarshal(raw, &sm) != nil {
		return ""
	}
	return sm.Mappings
}

func decodeEsbuildMap(raw []byte) *esbuildLineMap {
	if len(raw) == 0 {
		return nil
	}
	s := extractMappingsField(raw)
	if s == "" {
		return nil
	}
	nLines := strings.Count(s, ";") + 1
	m := &esbuildLineMap{
		segs:    make([]vlqSeg, 0, len(s)/4+4),
		lineOff: make([]int32, 0, nLines+1),
	}
	m.lineOff = append(m.lineOff, 0)
	var (
		origSrc  int
		origLine int
		origCol  int
		nameIdx  int
	)
	i := 0
	genCol := 0
	for i <= len(s) {
		if i == len(s) || s[i] == ';' {
			m.lineOff = append(m.lineOff, int32(len(m.segs)))
			genCol = 0
			i++
			continue
		}
		if s[i] == ',' {
			i++
			continue
		}
		var fields [5]int
		nf := 0
		ok := true
		for i < len(s) && s[i] != ',' && s[i] != ';' {
			v, next, vok := decodeVLQ(s, i)
			if !vok {
				ok = false
				break
			}
			if nf < len(fields) {
				fields[nf] = v
			}
			nf++
			i = next
		}
		if !ok {
			for i < len(s) && s[i] != ',' && s[i] != ';' {
				i++
			}
			continue
		}
		if nf >= 1 {
			genCol += fields[0]
		}
		if nf >= 4 {
			origSrc += fields[1]
			origLine += fields[2]
			origCol += fields[3]
			_ = origSrc
			m.segs = append(m.segs, vlqSeg{
				genCol:   int32(genCol),
				origLine: int32(origLine + 1),
				origCol:  int32(origCol + 1),
			})
		}
		if nf >= 5 {
			nameIdx += fields[4]
			_ = nameIdx
		}
	}
	if len(m.lineOff) <= 1 {
		return nil
	}
	return m
}

func decodeVLQ(s string, i int) (int, int, bool) {
	var val, shift int
	for i < len(s) {
		d := b64Val(s[i])
		if d < 0 || shift >= 30 {
			return 0, i, false
		}
		i++
		val |= (d & 31) << shift
		shift += 5
		if d&32 == 0 {
			if val&1 != 0 {
				return -(val >> 1), i, true
			}
			return val >> 1, i, true
		}
	}
	return 0, i, false
}

func b64Val(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c - 'a' + 26)
	case c >= '0' && c <= '9':
		return int(c - '0' + 52)
	case c == '+':
		return 62
	case c == '/':
		return 63
	}
	return -1
}

// lookup maps a 1-based generated line and 0-based UTF-16 column back to a
// 1-based (line, utf16Col) in the original source.
func (m *esbuildLineMap) lookup(genLine, genColUTF16 int) (int, int) {
	if m == nil || len(m.lineOff) <= 1 {
		return genLine, genColUTF16 + 1
	}
	nLines := len(m.lineOff) - 1
	gl := min(max(genLine-1, 0), nLines-1)
	lineSegs := func(l int) []vlqSeg {
		return m.segs[m.lineOff[l]:m.lineOff[l+1]]
	}
	target32 := int32(genColUTF16)
	if segs := lineSegs(gl); len(segs) > 0 {
		idx, found := slices.BinarySearchFunc(segs, target32, func(a vlqSeg, target int32) int {
			return int(a.genCol) - int(target)
		})
		if found {
			for idx+1 < len(segs) && segs[idx+1].genCol == target32 {
				idx++
			}
			return int(segs[idx].origLine), int(segs[idx].origCol)
		}
		if idx > 0 {
			return int(segs[idx-1].origLine), int(segs[idx-1].origCol)
		}
		return int(segs[0].origLine), int(segs[0].origCol)
	}
	for d := 1; d < nLines; d++ {
		if gl-d >= 0 {
			if segs := lineSegs(gl - d); len(segs) > 0 {
				last := segs[len(segs)-1]
				return int(last.origLine), int(last.origCol)
			}
		}
		if gl+d < nLines {
			if segs := lineSegs(gl + d); len(segs) > 0 {
				return int(segs[0].origLine), int(segs[0].origCol)
			}
		}
	}
	return genLine, genColUTF16 + 1
}

func utf16Cols(b []byte) int {
	n := 0
	for len(b) > 0 {
		r, sz := utf8.DecodeRune(b)
		b = b[sz:]
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func utf16ColToByteOffset(line []byte, col1 int) int {
	if col1 <= 1 {
		return 0
	}
	rem := col1 - 1
	off := 0
	for off < len(line) && rem > 0 {
		r, sz := utf8.DecodeRune(line[off:])
		off += sz
		if r > 0xFFFF {
			rem -= 2
		} else {
			rem--
		}
	}
	return off
}
