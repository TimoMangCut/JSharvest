package jsapi

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// --- what documents say beyond a method and a path (QAL-03, QAL-04) ---

// docHeaderKeep is a header a document gives that says how to call the
// API: credentials and the API's own (X-*, *-Key, *-Token, a tenant's);
// docHeaderDrop, HTTP's generic ones.
var (
	docHeaderKeep = regexp.MustCompile(`(?i)^(?:authorization|x-[\w-]+|[\w-]*-(?:key|token|secret|signature)|[\w-]*tenant[\w-]*|[\w-]*org[\w-]*|[\w-]+-language)$`)
	docHeaderDrop = regexp.MustCompile(`(?i)^(?:content-type|content-length|accept(?:-[\w-]+)?|user-agent|cache-control|host|origin|referer|connection|cookie|x-request-id|x-axis)$`)
	// placeholderValRe is a value a document leaves to the reader.
	placeholderValRe = regexp.MustCompile(`(?i)^<.*>$|^\$|^\{.*\}$|your[_-]|^x{3,}$|\.\.\.|…|^\*+$|^\[.*\]$|^(?:token|secret|string|value)$`)
)

// addHeader reads a header a curl command or an HTTP block gives.
func (c *docCall) addHeader(h string) {
	name, val, ok := strings.Cut(h, ":")
	name, val = strings.TrimSpace(name), strings.TrimSpace(val)
	if !ok || !docKeyRe.MatchString(name) || docHeaderDrop.MatchString(name) || !docHeaderKeep.MatchString(name) {
		return
	}
	c.headers = append(c.headers, name+":"+val)
}

// headerNamesOf are the names of headers read as name:value.
func headerNamesOf(hs []string) []string {
	var out []string
	for _, h := range hs {
		n, _, _ := strings.Cut(h, ":")
		out = append(out, n)
	}
	return out
}

// headerSpec is a header's parameter: its value, when the document gives
// one (Authorization's scheme, Bearer).
func headerSpec(h string) ParamSpec {
	n, v, _ := strings.Cut(h, ":")
	ps := ParamSpec{Name: n, In: "header", Type: "string", Required: true}
	if strings.EqualFold(n, "authorization") {
		if scheme, _, ok := strings.Cut(v, " "); ok && scheme != "" {
			ps.Values = []string{scheme}
		}
		return ps
	}
	if v != "" && !placeholderValRe.MatchString(v) {
		ps.Values = []string{v}
	}
	return ps
}

// dataSpecs are the parameters a request's data gives, with their types
// and the example's values (a placeholder's aside).
func dataSpecs(d string) []ParamSpec {
	d = strings.TrimSpace(d)
	if strings.HasPrefix(d, "{") {
		var v map[string]any
		if json.Unmarshal([]byte(d), &v) == nil {
			return jsonSpecs(v, "", 0)
		}
		return nil
	}
	var out []ParamSpec
	for _, kv := range strings.FieldsFunc(d, func(r rune) bool { return r == '&' || r == '\n' }) {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || !docKeyRe.MatchString(k) {
			continue
		}
		ps := ParamSpec{Name: k, Type: "string"}
		if v != "" && !placeholderValRe.MatchString(v) {
			ps.Values = []string{v}
		}
		out = append(out, ps)
	}
	return out
}

func jsonSpecs(v map[string]any, prefix string, depth int) []ParamSpec {
	var out []ParamSpec
	for k, val := range v {
		ps := ParamSpec{Name: prefix + k}
		switch t := val.(type) {
		case map[string]any:
			if sub := jsonSpecs(t, prefix+k+".", depth+1); depth < 2 && len(sub) > 0 {
				out = append(out, sub...)
				continue
			}
			ps.Type = "object"
		case []any:
			ps.Type = "array"
			if len(t) > 0 {
				if m, ok := t[0].(map[string]any); ok && depth < 2 {
					if sub := jsonSpecs(m, prefix+k+".", depth+1); len(sub) > 0 {
						out = append(out, sub...)
						continue
					}
				}
			}
		case string:
			ps.Type = "string"
			if !placeholderValRe.MatchString(t) && t != "" {
				ps.Values = []string{t}
			}
		case float64:
			ps.Type, ps.Values = "number", []string{fmt.Sprint(t)}
		case bool:
			ps.Type, ps.Values = "boolean", []string{fmt.Sprint(t)}
		}
		out = append(out, ps)
	}
	slices.SortFunc(out, func(a, b ParamSpec) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// genericHost names a placeholder host that says nothing of which API it
// is: {base}, <host>, {domain}.
var genericHost = regexp.MustCompile(`(?i)^(?:base|base[-_]?url|host|domain|api|url|server|gateway|your[-_]\w+|example)$`)

// hostMark is the mark of a placeholder host a document writes
// (<auth-host>, {agentHub}): endpoints.Build reads it as the setting of
// the portal it names. Nothing for a generic one.
func hostMark(h string) string {
	name := strings.Trim(h, "<>{}")
	if name == h || name == "" || strings.ContainsAny(name, "<>{}$/ ") || genericHost.MatchString(name) {
		return ""
	}
	return "<" + name + ">"
}

// isMark reports whether a document's base is a name still to resolve:
// $SLINK_HOST, <auth-host>.
func isMark(b string) bool {
	return strings.HasPrefix(b, "$") || strings.HasPrefix(b, "<")
}

// docProdRe is a row of a table of environments naming production's host:
// | prd | `https://api.ecom.example.services` |.
var docProdRe = regexp.MustCompile("(?im)^\\|\\s*`?(?:prd|prod|production|live)`?\\s*\\|\\s*`?(https?://[A-Za-z0-9.-]+(?::\\d+)?)`?\\s*\\|")

// prdHosts records the production hosts a document's tables name, and the
// variables it sets to a development host (export CMS_HOST=https://api.
// ecom-dev…): production's host stands for such a variable (ProdOf).
func (x *extractor) prdHosts(s string) {
	if !strings.Contains(s, "| ") && !strings.Contains(s, "export ") && !strings.Contains(s, "=http") {
		return
	}
	for _, m := range docProdRe.FindAllStringSubmatch(s, 10) {
		x.docProd = append(x.docProd, strings.ToLower(m[1]))
	}
	if !strings.Contains(s, "=") {
		return
	}
	for _, m := range docExportRe.FindAllStringSubmatch(s, 50) {
		u := strings.TrimRight(m[2], "/")
		host, _, _ := strings.Cut(strings.SplitN(u, "://", 2)[1], "/")
		if devHostRe.MatchString(host) && !exampleHostRe.MatchString(host) {
			x.docDev[m[1]] = append(x.docDev[m[1]], u)
		}
	}
}

// envTokenRe is a development environment's token in a host.
var envTokenRe = regexp.MustCompile(`(?i)[.-](?:dev|develop|development|staging|stage|stg|sit|uat|qa|sandbox)(?:\d*)(?:[.-])`)

// ProdOf is production's URL for a development URL a document exports: its
// host without the environment's token, when a table of environments
// names that host (prod). Nothing otherwise.
func ProdOf(dev string, prod []string) string {
	scheme, rest, ok := strings.Cut(dev, "://")
	if !ok {
		return ""
	}
	host, path, _ := strings.Cut(rest, "/")
	p := envTokenRe.ReplaceAllStringFunc(host, func(t string) string { return t[len(t)-1:] })
	if p == host {
		return ""
	}
	if !slices.Contains(prod, strings.ToLower(scheme+"://"+p)) {
		return ""
	}
	if path != "" {
		return scheme + "://" + p + "/" + path
	}
	return scheme + "://" + p
}

// docHTTPRe is a fenced block of HTTP (```http); docDataRe the block of data
// that may follow it in its section (```json, ```text).
var (
	docHTTPRe = regexp.MustCompile("(?s)```http\\s*\\n(.*?)```")
	docDataRe = regexp.MustCompile("(?s)^\\s*(?:[^#`\\n][^\\n]*\\n){0,3}?\\s*```(?:json|text|x-www-form-urlencoded|form)?\\s*\\n(.*?)```")
	// docReqLineRe is an HTTP request's first line.
	docReqLineRe = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE|HEAD)\s+(\S+)(?:\s+HTTP/[\d.]+)?\s*$`)
)

// httpBlocks reads the HTTP requests a document writes out: a ```http
// block's request line, its headers, its body (in the block, or the block
// of data after it). A page compiled to strings (MDX) has the block alone
// in a string: its body is the string of data after it.
func (x *extractor) httpBlocks(s string, env map[string]string) {
	if !strings.Contains(s, "```http") && (len(s) >= 4000 || !docReqLineRe.MatchString(firstLine(strings.TrimSpace(s)))) {
		return
	}
	var blocks []string
	var after []string
	for _, m := range docHTTPRe.FindAllStringSubmatchIndex(s, 20) {
		blocks = append(blocks, s[m[2]:m[3]])
		after = append(after, s[m[1]:min(len(s), m[1]+800)])
	}
	whole := false
	if blocks == nil && !strings.Contains(s, "```") && len(s) < 4000 {
		first, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
		if docReqLineRe.MatchString(strings.TrimSpace(first)) {
			blocks, after, whole = []string{strings.TrimSpace(s)}, []string{""}, true
		}
	}
	for i, b := range blocks {
		c, body, ok := parseHTTP(b)
		if !ok {
			continue
		}
		if body == "" && c.method != "GET" && c.method != "HEAD" {
			// The block of data after it, its body: not a response's.
			if m := docDataRe.FindStringSubmatchIndex(after[i]); m != nil && !docResponseRe.MatchString(after[i][:m[2]]) {
				body = after[i][m[2]:m[3]]
			}
		}
		x.dataInto(&c, body)
		key := x.docEndpoint(c, env)
		if key != "" && body == "" && whole && c.method != "GET" {
			x.pendingBody, x.pendingLeft = key, 4
		}
	}
}

// docResponseRe is text saying the block after it is a response's.
var docResponseRe = regexp.MustCompile(`(?i)response|phản hồi|trả về|kết quả|returns?\b|output`)

// parseHTTP reads a request a document writes: its first line, its
// headers, and the body after a blank line.
func parseHTTP(b string) (docCall, string, bool) {
	lines := strings.Split(strings.ReplaceAll(b, "\r", ""), "\n")
	if len(lines) == 0 {
		return docCall{}, "", false
	}
	m := docReqLineRe.FindStringSubmatch(strings.TrimSpace(lines[0]))
	if m == nil {
		return docCall{}, "", false
	}
	c := docCall{method: m[1], url: m[2]}
	i := 1
	for ; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			break
		}
		c.addHeader(l)
	}
	return c, strings.TrimSpace(strings.Join(lines[min(i, len(lines)):], "\n")), true
}

// dataInto gives a request the data a document shows it with.
func (x *extractor) dataInto(c *docCall, body string) {
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}
	keys, specs := dataKeys(body), dataSpecs(body)
	if strings.Contains(body, "\n") && !strings.HasPrefix(body, "{") {
		keys = nil
		for _, s := range specs {
			keys = append(keys, s.Name)
		}
	}
	in := "body"
	if c.method == "GET" || c.method == "HEAD" {
		in = "query"
		c.query = append(c.query, keys...)
	} else {
		c.body = append(c.body, keys...)
	}
	for _, s := range specs {
		s.In = in
		c.specs = append(c.specs, s)
	}
}

// docBodyRe is a string that is all a request's data: a JSON object, or
// k=v lines.
var docBodyRe = regexp.MustCompile(`^(?:\{[\s\S]*\}|(?:[A-Za-z_][\w.-]*=[^\n]*\n?)+)$`)

// pendingData gives a request a page compiled to strings writes alone
// (POST https://<auth-host>/v1/oauth/token) the data of a string right
// after it (grant_type=client_credentials\nclient_id=<client_id>…).
func (x *extractor) pendingData(s string) {
	t := strings.TrimSpace(s)
	if len(t) < 3 {
		return // the line breaks between a page's blocks
	}
	key := x.pendingBody
	if x.pendingLeft--; x.pendingLeft <= 0 {
		x.pendingBody = ""
	}
	if !docBodyRe.MatchString(t) || docResponseRe.MatchString(t) && strings.HasPrefix(t, "{") && strings.Contains(t, "access_token") {
		return
	}
	x.pendingBody = ""
	ep := x.eps[key]
	if ep == nil {
		return
	}
	c := docCall{method: ep.Method}
	x.dataInto(&c, t)
	ep.Query = append(ep.Query, c.query...)
	ep.Body = append(ep.Body, c.body...)
	ep.Params = mergeSpecs(ep.Params, c.specs)
}
