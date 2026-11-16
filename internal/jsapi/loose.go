package jsapi

import (
	"bytes"
	"regexp"
	"strings"
)

// The loose reading is for code the parser does not take: the original
// sources a source map carries are TypeScript, JSX or Vue as often as
// JavaScript. It finds calls by their shape in the text, and the strings
// that read as API paths; it is less sure than Extract, and says so in the
// kinds it gives (fetch and client calls, else string).

var (
	// fetch("/a"), axios.get('/a'), this.http.post(`/a/${id}`), api.delete("/a")
	looseCallRe = regexp.MustCompile("(?:\\b(fetch|axios|ky|request|\\$http|http|httpClient|api|client|instance|service)" +
		"(?:\\.(get|post|put|patch|delete|head|options|request))?)\\s*(?:<[^>()]{0,80}>)?\\(\\s*([\"'`])((?:/|https?://)[^\"'`\\s]{1,300}?)[\"'`]")
	// method: 'POST' near a fetch( or an options object.
	looseMethodRe = regexp.MustCompile(`(?i)method\s*:\s*["'](get|post|put|patch|delete|head|options)["']`)
	// A quoted path with at least two segments, or under /api: "/api/v1/users", '/admin/reports'.
	loosePathRe = regexp.MustCompile("[\"'`](/(?:[A-Za-z0-9_.~-]+|\\$\\{[^}]{1,60}\\}|:[A-Za-z_]\\w*)(?:/(?:[A-Za-z0-9_.~-]+|\\$\\{[^}]{1,60}\\}|:[A-Za-z_]\\w*)){1,12}/?)(?:\\?[^\"'`\\s]*)?[\"'`]")
	templateRe  = regexp.MustCompile(`\$\{[^}]*\}|/:[A-Za-z_]\w*`)
	staticExtRe = regexp.MustCompile(`(?i)\.(png|jpe?g|gif|svg|webp|ico|css|scss|less|woff2?|ttf|eot|map|md|html?|vue|tsx?|jsx?|mjs|json)$`)
)

// ExtractLoose finds the endpoints of code Extract cannot parse, by the
// shape of their calls and paths.
func ExtractLoose(src []byte) Result {
	res := Result{Version: Version}
	seen := map[string]int{}
	add := func(e Endpoint) {
		k := e.Method + " " + e.URL
		if i, ok := seen[k]; ok {
			if res.Endpoints[i].Kind == "string" && e.Kind != "string" {
				res.Endpoints[i] = e
			}
			return
		}
		seen[k] = len(res.Endpoints)
		res.Endpoints = append(res.Endpoints, e)
	}
	lineCol := func(off int) (int, int) {
		before := src[:off]
		line := bytes.Count(before, []byte("\n")) + 1
		col := off - (bytes.LastIndexByte(before, '\n') + 1)
		return line, col
	}
	snippet := func(a, b int) string {
		s := string(src[a:min(b, a+160)])
		return strings.Join(strings.Fields(s), " ")
	}
	called := map[int]bool{}
	for _, m := range looseCallRe.FindAllSubmatchIndex(src, -1) {
		callee := string(src[m[2]:m[3]])
		method := ""
		kind := "client"
		if m[4] >= 0 {
			method = strings.ToUpper(string(src[m[4]:m[5]]))
			if method == "REQUEST" {
				method = ""
			}
		}
		if callee == "fetch" {
			kind, method = "fetch", "GET"
			// The options object, if any, follows the URL.
			tail := src[m[1]:min(len(src), m[1]+300)]
			if end := bytes.IndexByte(tail, ')'); end >= 0 {
				tail = tail[:end]
			}
			if mm := looseMethodRe.FindSubmatch(tail); mm != nil {
				method = strings.ToUpper(string(mm[1]))
			}
		} else if method == "" {
			kind = "string"
		}
		raw := string(src[m[8]:m[9]])
		u, q := cutQuery(raw)
		line, col := lineCol(m[0])
		called[m[8]] = true
		add(Endpoint{Method: method, URL: templateRe.ReplaceAllStringFunc(u, holeFor), Query: q, Kind: kind, Line: line, Col: col, Snippet: snippet(m[0], m[1])})
	}
	for _, m := range loosePathRe.FindAllSubmatchIndex(src, -1) {
		if called[m[2]] {
			continue
		}
		raw := string(src[m[2]:m[3]])
		u, q := cutQuery(raw)
		if staticExtRe.MatchString(u) {
			continue // an asset or a module path, not an endpoint
		}
		line, col := lineCol(m[0])
		add(Endpoint{URL: templateRe.ReplaceAllStringFunc(u, holeFor), Query: q, Kind: "string", Line: line, Col: col, Snippet: snippet(m[0], m[1])})
	}
	return res
}

// holeFor keeps the slash of a ":id" parameter, and makes any hole {}.
func holeFor(s string) string {
	if strings.HasPrefix(s, "/") {
		return "/" + unknown
	}
	return unknown
}

func cutQuery(raw string) (string, []string) {
	u, q, ok := strings.Cut(raw, "?")
	if !ok {
		return u, nil
	}
	var names []string
	for _, kv := range strings.Split(q, "&") {
		k, _, _ := strings.Cut(kv, "=")
		if k != "" && !strings.Contains(k, "${") {
			names = append(names, k)
		}
	}
	return u, names
}
