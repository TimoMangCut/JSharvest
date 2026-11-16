package jsapi

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
)

// --- endpoints a documentation names ---

// A developer portal's pages are bundles of their text: Markdown tables
// (| `GET` | `/admin/v1/apps` |), code blocks ("POST /v1/feed/items"),
// curl commands (curl -X POST 'https://api…/x' -d '{…}'), code that calls
// fetch, diagrams ("A->>B: POST /promo-codes/validate"). The endpoints
// they name are the API's as much as a call is: kind "doc", with the
// query and body the document gives, and the base it exports
// (export SLINK_HOST="https://api…/v1", then "$SLINK_HOST/x").

var (
	// docLineRe is a method, then a path (with a base written as a
	// placeholder, a variable or a URL before it) and its query, where
	// text starts.
	docLineRe = regexp.MustCompile("(?:^|[\\s`|>\"'(\\[:])(GET|POST|PUT|PATCH|DELETE)\\s+((?:\\{[A-Za-z_][\\w.-]*\\}|\\$\\{?[A-Za-z_][\\w]*\\}?|https?://[A-Za-z0-9.-]+(?::\\d+)?)?/[A-Za-z0-9_\\-./{}:$%~]*[A-Za-z0-9_}](?:\\?[^\\s`'\"|)\\]]*)?)")
	// docTableRe is a Markdown table's row: | `GET` | `/path` |.
	docTableRe = regexp.MustCompile("\\|\\s*`?(GET|POST|PUT|PATCH|DELETE)`?\\s*\\|\\s*`?((?:https?://[A-Za-z0-9.-]+)?/[A-Za-z0-9_\\-./{}:$%~]*[A-Za-z0-9_}](?:\\?[^\\s`'\"|]*)?)`?\\s*\\|")
	// docCurlRe is where a curl command starts.
	docCurlRe = regexp.MustCompile("(?:^|[\\s;|&(`$])curl\\s")
	// docExportRe is a variable a document sets to a URL: export
	// SLINK_HOST="https://…", SLINK_HOST=https://….
	docExportRe = regexp.MustCompile(`(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=["']?(https?://[^"'\s]+)["']?\s*$`)
	// docFenceRe is a fenced block of JavaScript or TypeScript.
	docFenceRe = regexp.MustCompile("(?s)```(?:ts|tsx|js|jsx|javascript|typescript|mjs)\\s*\\n(.*?)```")
	// docVarRe is a placeholder of a document's: {app_id}, :appId, $WORKSPACE.
	docVarRe = regexp.MustCompile(`\{[A-Za-z_][\w.-]*\}|:[A-Za-z_]\w*|\$\{?[A-Za-z_]\w*\}?|<[A-Za-z_][\w-]*>`)
	docNumRe = regexp.MustCompile(`/\d{2,}(/|$)`)
	// docSampleRe is an example's version, code or id in a path:
	// /versions/1.0.0/, /items/SKU-001, /tasks/3fa85f64-5717-….
	docSampleRe = regexp.MustCompile(`/(?:v?\d+\.\d+(?:\.\d+)*|[A-Z]{2,}-\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/|$)`)
	// exampleHostRe is a host a document makes up: example.com, a test
	// domain, localhost.
	exampleHostRe = regexp.MustCompile(`(?i)(?:^|\.)(?:example\.(?:com|org|net)|example|test|invalid|localhost|test\.com)(?::\d+)?$`)
	// devHostRe is a host of a development environment: a document's
	// example of one is no base of the target's.
	devHostRe = regexp.MustCompile(`(?i)(?:^|[.-])(?:dev|develop|development|staging|stage|stg|sit|uat|qa|sandbox|local)(?:[.-]|$)`)
	// notDocRe precedes what an error says, not what a document names:
	// "Cannot GET /x" (express).
	notDocRe = regexp.MustCompile(`(?i)(cannot|can't|unable to|failed to|error)\s*$`)
)

// docEndpoints reads the endpoints a document's text names.
func (x *extractor) docEndpoints(s string) {
	if x.pendingBody != "" {
		x.pendingData(s)
	}
	if len(s) < 24 || len(s) > 1<<20 {
		return
	}
	curl := strings.Contains(s, "curl ")
	if !curl && !strings.Contains(s, "GET") && !strings.Contains(s, "POST") && !strings.Contains(s, "PUT") &&
		!strings.Contains(s, "PATCH") && !strings.Contains(s, "DELETE") && !strings.Contains(s, "fetch(") {
		return
	}
	env := docEnv(s)
	for k, v := range env {
		x.docVars[k] = append(x.docVars[k], v)
	}
	x.prdHosts(s)
	pre := sectionPrefixes(s)
	for _, re := range []*regexp.Regexp{docTableRe, docLineRe, docMethodsRe} {
		for _, m := range re.FindAllStringSubmatchIndex(s, 500) {
			if notDocRe.MatchString(s[max(0, m[0]-24):m[2]]) {
				continue
			}
			u := s[m[4]:m[5]]
			if clientRoute(s, m[0], u) {
				continue
			}
			u = prefixAt(pre, m[0], u)
			methods := []string{s[m[2]:m[3]]}
			if re == docMethodsRe {
				// `GET` / `POST /conversations`: each of them.
				methods = docMethodWordRe.FindAllString(s[m[2]:m[3]], -1)
			}
			for _, meth := range methods {
				x.docEndpoint(docCall{method: meth, url: u}, env)
			}
		}
	}
	if curl {
		for _, m := range docCurlRe.FindAllStringIndex(s, 200) {
			if noRoute(s[:m[1]]) {
				continue
			}
			if c, ok := parseCurl(s[m[1]-len("curl "):]); ok && !clientRoute(s, m[0], c.url) {
				x.docEndpoint(c, env)
			}
		}
	}
	x.httpBlocks(s, env)
	x.docCode(s, env)
}

// docMethodsRe is a table cell of several methods and a path: `GET` /
// `POST /conversations`.
var (
	docMethodsRe    = regexp.MustCompile("`" + `((?:GET|POST|PUT|PATCH|DELETE)` + "`" + `(?:\s*[/,]\s*` + "`" + `(?:GET|POST|PUT|PATCH|DELETE))+)\s+((?:\{[A-Za-z_][\w.-]*\})?/[A-Za-z0-9_\-./{}:$%~]*[A-Za-z0-9_}](?:\?[^\s'"|` + "`" + `]*)?)` + "`")
	docMethodWordRe = regexp.MustCompile(`GET|POST|PUT|PATCH|DELETE`)
	// docUnderRe says the paths of the table after it are under a base
	// and a path: "nằm dưới `{agentHub}/api/v1`", "under `/api/v1`".
	docUnderRe = regexp.MustCompile(`(?i)(?:dưới|under|relative to|prefixed with)\s+` + "`" + `((?:\{[A-Za-z_][\w.-]*\}|<[\w.-]+>|https?://[^/` + "`" + `]+)?(?:/[\w.-]+)+)` + "`")
)

// docPrefix is a path the table after a sentence is under, from where
// the table starts to where it ends.
type docPrefix struct {
	from, to int
	path     string
}

// sectionPrefixes reads the sentences that put the table after them under
// a base and a path.
func sectionPrefixes(s string) []docPrefix {
	if !strings.Contains(s, "\n|") {
		return nil
	}
	var out []docPrefix
	for _, m := range docUnderRe.FindAllStringSubmatchIndex(s, 50) {
		// The table: the lines starting with | right after the sentence's
		// paragraph.
		rest := s[m[1]:]
		start := strings.Index(rest, "\n|")
		if start < 0 || strings.Contains(rest[:start], "\n\n\n") || start > 200 {
			continue
		}
		end := start + 1
		for end < len(rest) {
			nl := strings.IndexByte(rest[end:], '\n')
			if nl < 0 {
				end = len(rest)
				break
			}
			if end+nl+1 >= len(rest) || rest[end+nl+1] != '|' {
				end += nl
				break
			}
			end += nl + 1
		}
		out = append(out, docPrefix{m[1] + start, m[1] + end, s[m[2]:m[3]]})
	}
	return out
}

// prefixAt puts a relative path of a table under its section's prefix.
func prefixAt(pre []docPrefix, at int, u string) string {
	if !strings.HasPrefix(u, "/") {
		return u
	}
	for _, p := range pre {
		if at >= p.from && at < p.to && !strings.HasPrefix(u, strings.TrimLeft(p.path, "{}<>")) {
			return p.path + u
		}
	}
	return u
}

// clientRouteRe is a route of the integrator's own app a document tells
// them to make (Next.js's ISR, draft and preview routes).
var (
	clientRouteRe = regexp.MustCompile(`^/api/(?:revalidate|draft|preview|exit-preview|disable-draft|enable-draft)(?:[/?]|$)`)
	// clientAppRe is text saying an app is the integrator's: Next.js,
	// ISR, "space app", "your app".
	clientAppRe = regexp.MustCompile(`(?i)next\.?js|\bISR\b|space app|ứng dụng của bạn|your (?:own )?(?:next\.js )?app|app router|pages router`)
)

// clientRoute reports whether a path a document names is a route of the
// integrator's own app: a Next.js convention, with the text around it
// about such an app (POST /api/revalidate?path=…, "Chờ hết cửa sổ ISR").
func clientRoute(s string, at int, u string) bool {
	if i := strings.Index(u, "://"); i > 0 {
		if _, p, ok := strings.Cut(u[i+3:], "/"); ok {
			u = "/" + p
		}
	}
	if !clientRouteRe.MatchString(u) {
		return false
	}
	return clientAppRe.MatchString(s[max(0, at-800):min(len(s), at+400)])
}

// noRouteRe is a comment saying the request after it goes to a route
// that does not exist (the example of a router's 404), not of a missing
// resource on a route that does ("route tồn tại, tài nguyên không").
var noRouteRe = regexp.MustCompile(`(?i)\b(?:route|endpoint|path|url|đường dẫn)\b[^\n]{0,12}?(?:(?:không|chưa)\s+tồn\s+tại|does\s*n[o']?t\s+exist|not\s+exist|is\s+not\s+found|unknown|nonexistent|non-existent)|\b(?:sai\s+đường\s+dẫn|unknown\s+route|wrong\s+path|invalid\s+path)\b`)

// noRoute reports whether the comment lines right above a command
// (# …, // …) say its route does not exist.
func noRoute(before string) bool {
	lines := strings.Split(before, "\n")
	lines = lines[:len(lines)-1] // the command's own line
	for i := len(lines) - 1; i >= 0 && i >= len(lines)-3; i-- {
		l := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "//") {
			break
		}
		if noRouteRe.MatchString(l) {
			return true
		}
	}
	return false
}

// docCall is a request a document writes out.
type docCall struct {
	method, url string
	query, body []string
	headers     []string
	specs       []ParamSpec
}

// docEnv are the variables a document sets to a URL, those of a
// development or made-up host aside.
func docEnv(s string) map[string]string {
	if !strings.Contains(s, "=") {
		return nil
	}
	env := map[string]string{}
	for _, m := range docExportRe.FindAllStringSubmatch(s, 50) {
		u := strings.TrimRight(m[2], "/")
		host, _, _ := strings.Cut(strings.SplitN(u, "://", 2)[1], "/")
		if exampleHostRe.MatchString(host) || devHostRe.MatchString(host) || strings.ContainsAny(host, "<>{}$") {
			continue
		}
		env[m[1]] = u
	}
	return env
}

// docCode reads the calls of the code a document shows (fetch(…, {method,
// body: JSON.stringify({…})})): a fenced block of JavaScript, or a string
// that is all code (an MDX page's <code> children).
func (x *extractor) docCode(s string, env map[string]string) {
	if x.nested || !strings.Contains(s, "fetch(") && !strings.Contains(s, "axios") {
		return
	}
	var blocks []string
	for _, m := range docFenceRe.FindAllStringSubmatch(s, 20) {
		blocks = append(blocks, m[1])
	}
	if blocks == nil && !strings.Contains(s, "```") && len(s) < 1<<16 {
		blocks = []string{s}
	}
	for _, b := range blocks {
		if !strings.Contains(b, "fetch(") && !strings.Contains(b, "axios") {
			continue
		}
		r := extract([]byte(b), true)
		if r.Error != "" {
			r = ExtractLoose([]byte(b))
		}
		for _, e := range r.Endpoints {
			switch e.Kind {
			case "navigation", "string", "doc":
				continue
			}
			x.docEndpoint(docCall{method: e.Method, url: e.URL, query: e.Query, body: e.Body}, env)
		}
	}
}

func (x *extractor) docEndpoint(c docCall, env map[string]string) string {
	p := strings.TrimRight(c.url, ".,;:")
	if c.method == "" || strings.Contains(p, "...") || strings.Contains(p, "…") || strings.Contains(p, "*") {
		return ""
	}
	raw := p
	// A base the document exports ($SLINK_HOST/x): the path goes under it.
	base := ""
	if strings.HasPrefix(p, "$") {
		name := strings.Trim(strings.SplitN(p[1:], "/", 2)[0], "{}")
		if v, ok := env[name]; ok {
			base = v
		} else if docVarNameRe.MatchString(name) {
			base = "$" + name // another page exports it
		}
	}
	// A base the document leaves to the reader (https://<open-platform-
	// host>/x, {base}/x, $HOST/x): the path is what it names, the same as
	// where it writes the path alone. A host it makes up
	// (my-space.example.com) says the path is someone else's.
	host := ""
	if i := strings.Index(p, "://"); i > 0 {
		rest := p[i+3:]
		h, path, _ := strings.Cut(rest, "/")
		if exampleHostRe.MatchString(h) {
			return ""
		}
		host, p = p[:i+3]+h, "/"+path
		if strings.ContainsAny(h, "<>{}$") {
			host = ""
			if base == "" {
				base = hostMark(h) // <auth-host>: a setting of the portal's
			}
		}
	} else if !strings.HasPrefix(p, "/") {
		first, after, ok := strings.Cut(p, "/")
		if ok {
			p = "/" + after
		}
		if base == "" {
			base = hostMark(first) // {agentHub}/auth/exchange
		}
	}
	p, rawQuery, _ := strings.Cut(p, "?")
	query := slices.Clone(c.query)
	for _, kv := range strings.Split(rawQuery, "&") {
		if k, _, _ := strings.Cut(kv, "="); k != "" && docKeyRe.MatchString(k) {
			query = append(query, k)
		}
	}
	var names []string
	for _, v := range docVarRe.FindAllString(p, -1) {
		names = append(names, strings.Trim(v, "{}:$<>"))
	}
	p = docVarRe.ReplaceAllString(p, unknown)
	p = docNumRe.ReplaceAllString(p, "/"+unknown+"${1}") // an example's id: /shortlinks/1042
	p = docSampleRe.ReplaceAllString(p, "/"+unknown+"${1}")
	p = cleanURL(p)
	// A path the document names is an API's when it has two segments
	// (one with a word of three letters), or a base before it.
	segs := strings.Split(strings.Trim(p, "/"), "/")
	word := false
	for _, sg := range segs {
		letters := 0
		for _, r := range sg {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
				letters++
			}
		}
		word = word || letters >= 3
	}
	if !word || len(segs) < 2 && host == "" && base == "" || assetRe.MatchString(p) {
		return ""
	}
	url := p
	if host != "" {
		url = host + p
	}
	specs := slices.Clone(c.specs)
	if len(names) == pathSlots(p) {
		for i, n := range names {
			if n != "" && !docVarNameRe.MatchString(n) || n == "" {
				continue
			}
			specs = append(specs, ParamSpec{Name: n, In: "path", Position: i, Type: "string", Required: true})
		}
	}
	for _, h := range c.headers {
		specs = append(specs, headerSpec(h))
	}
	headers := headerNamesOf(c.headers)
	key := c.method + " " + url + " doc"
	if old, ok := x.eps[key]; ok {
		// The table names it; the curl command below gives its query and
		// body.
		old.Query = append(old.Query, query...)
		old.Body = append(old.Body, c.body...)
		old.Headers = append(old.Headers, headers...)
		old.Params = mergeSpecs(old.Params, specs)
		if old.Base == "" || isMark(old.Base) && base != "" && !isMark(base) {
			old.Base = base
		}
		return key
	}
	ep := Endpoint{Method: c.method, URL: url, Kind: "doc", Client: !strings.Contains(url, "://"), Query: query, Body: slices.Clone(c.body),
		Headers: headers, Params: mergeSpecs(nil, specs), Base: base}
	lit := raw
	if i := strings.IndexAny(lit, "$`"); i > 0 {
		lit = lit[:i]
	}
	x.locate(&ep, [][]byte{[]byte(lit)})
	x.eps[key] = &ep
	x.order = append(x.order, key)
	return key
}

// docVarNameRe is a shell variable's name.
var docVarNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// DocVars are the variables a script's documents set to a URL (export
// SLINK_HOST=https://…), one value each: for the pages of the same
// portal that use them ($SLINK_HOST/shortlinks/{id}) without setting them.
func (x *extractor) docVarList() []Header {
	var out []Header
	for k, vs := range x.docVars {
		if vs = uniq(vs); len(vs) == 1 {
			out = append(out, Header{Name: k, Value: vs[0]})
		}
	}
	slices.SortFunc(out, func(a, b Header) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// docKeyRe is a parameter's name.
var docKeyRe = regexp.MustCompile(`^[A-Za-z_][\w.\[\]-]{0,63}$`)

// parseCurl reads a curl command (lines joined by a backslash): its
// method (-X, or what its options imply), its URL, and the names of its
// query (?k=, -G with -d or --data-urlencode) and its body (-d JSON's
// keys, k=v pairs, -F fields).
func parseCurl(s string) (docCall, bool) {
	args := shellWords(s, 4096)
	if len(args) < 2 || args[0] != "curl" {
		return docCall{}, false
	}
	var c docCall
	var data, form, urlenc []string
	get, head, upload := false, false, false
	takes := map[string]bool{"-o": true, "--output": true, "-w": true, "--write-out": true,
		"-u": true, "--user": true, "-A": true, "--user-agent": true, "-e": true, "--referer": true, "-b": true, "--cookie": true,
		"-c": true, "--cookie-jar": true, "-m": true, "--max-time": true, "--connect-timeout": true, "--retry": true,
		"-x": true, "--proxy": true, "--cacert": true, "--cert": true, "--key": true, "-K": true, "--config": true,
		"-r": true, "--range": true, "-D": true, "--dump-header": true, "--resolve": true, "--limit-rate": true, "-E": true}
	for i := 1; i < len(args); i++ {
		a := args[i]
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch {
		case a == "-X" || a == "--request":
			c.method = strings.ToUpper(next())
		case strings.HasPrefix(a, "-X") && len(a) > 2:
			c.method = strings.ToUpper(a[2:])
		case a == "-G" || a == "--get":
			get = true
		case a == "-I" || a == "--head":
			head = true
		case a == "-T" || a == "--upload-file":
			upload = true
			next()
		case a == "-d" || a == "--data" || a == "--data-raw" || a == "--data-binary" || a == "--data-ascii" || a == "--json":
			data = append(data, next())
		case a == "--data-urlencode":
			urlenc = append(urlenc, next())
		case a == "-F" || a == "--form" || a == "--form-string":
			form = append(form, next())
		case a == "-H" || a == "--header":
			c.addHeader(next())
		case a == "--url":
			if c.url == "" {
				c.url = next()
			}
		case takes[a]:
			next()
		case strings.HasPrefix(a, "-"):
			// -sS, -L, --compressed: flags.
		case c.url == "" && curlURLRe.MatchString(a):
			c.url = a
		}
	}
	if c.url == "" {
		return docCall{}, false
	}
	var keys []string
	var specs []ParamSpec
	for _, d := range data {
		keys = append(keys, dataKeys(d)...)
		specs = append(specs, dataSpecs(d)...)
	}
	for _, d := range urlenc {
		if k, _, ok := strings.Cut(d, "="); ok && docKeyRe.MatchString(k) {
			keys = append(keys, k)
		}
	}
	switch {
	case c.method != "":
	case head:
		c.method = "HEAD"
	case upload:
		c.method = "PUT"
	case get || len(keys) == 0 && len(form) == 0:
		c.method = "GET"
	default:
		c.method = "POST"
	}
	if !httpMethods[c.method] {
		return docCall{}, false
	}
	in := "body"
	if get || c.method == "GET" || c.method == "HEAD" {
		c.query, in = keys, "query"
	} else {
		c.body = keys
	}
	for _, s := range specs {
		s.In = in
		c.specs = append(c.specs, s)
	}
	for _, f := range form {
		if k, _, ok := strings.Cut(f, "="); ok && docKeyRe.MatchString(k) {
			c.body = append(c.body, k)
		}
	}
	return c, true
}

// curlURLRe is what a curl command's URL starts with: a scheme, a
// variable, a placeholder, a path.
var curlURLRe = regexp.MustCompile(`^(?:https?://|\$\{?[A-Za-z_]\w*\}?/|\{[A-Za-z_][\w.-]*\}/|<[\w.-]+>/|/)`)

// dataKeys are the names a request's data gives: a JSON object's keys
// (nested ones as a.b), or k=v pairs.
func dataKeys(d string) []string {
	d = strings.TrimSpace(d)
	if strings.HasPrefix(d, "@") {
		return nil // a file's
	}
	if strings.HasPrefix(d, "{") {
		var v map[string]any
		if json.Unmarshal([]byte(d), &v) == nil {
			return jsonKeys(v, "", 0)
		}
		// Placeholders the document leaves in (<token>, …): the keys as
		// written.
		var out []string
		for _, m := range jsonKeyRe.FindAllStringSubmatch(d, 100) {
			out = append(out, m[1])
		}
		return out
	}
	var out []string
	for _, kv := range strings.Split(d, "&") {
		if k, _, ok := strings.Cut(kv, "="); ok && docKeyRe.MatchString(k) {
			out = append(out, k)
		}
	}
	return out
}

var jsonKeyRe = regexp.MustCompile(`"([A-Za-z_][\w.-]{0,63})"\s*:`)

func jsonKeys(v map[string]any, prefix string, depth int) []string {
	var out []string
	for k, val := range v {
		switch t := val.(type) {
		case map[string]any:
			if sub := jsonKeys(t, prefix+k+".", depth+1); depth < 2 && len(sub) > 0 {
				out = append(out, sub...)
				continue
			}
		case []any:
			if len(t) > 0 {
				if m, ok := t[0].(map[string]any); ok && depth < 2 {
					if sub := jsonKeys(m, prefix+k+".", depth+1); len(sub) > 0 {
						out = append(out, sub...)
						continue
					}
				}
			}
		}
		out = append(out, prefix+k)
	}
	slices.Sort(out)
	return out
}

// shellWords splits a shell command into its words, as far as its end (a
// line break no backslash continues, a pipe, a semicolon, a backtick):
// quotes kept together, escapes read.
func shellWords(s string, limit int) []string {
	var out []string
	var b strings.Builder
	in := false
	flush := func() {
		if in {
			out = append(out, b.String())
			b.Reset()
			in = false
		}
	}
	for i := 0; i < len(s) && i < limit; i++ {
		ch := s[i]
		switch {
		case ch == '\\' && i+1 < len(s):
			if s[i+1] == '\n' || s[i+1] == '\r' {
				i++
				flush()
				continue
			}
			b.WriteByte(s[i+1])
			in = true
			i++
		case ch == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return out
			}
			b.WriteString(s[i+1 : i+1+j])
			in = true
			i += j + 1
		case ch == '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
			}
			b.WriteString(strings.ReplaceAll(s[i+1:min(j, len(s))], "\\\"", "\""))
			in = true
			i = j
		case ch == ' ' || ch == '\t':
			flush()
		case ch == '\n' || ch == '|' || ch == ';' || ch == '`' || ch == '&':
			flush()
			return out
		default:
			b.WriteByte(ch)
			in = true
		}
	}
	flush()
	return out
}
