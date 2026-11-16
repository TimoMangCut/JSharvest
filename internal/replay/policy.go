package replay

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// Kind is what sending a request again may do.
type Kind string

const (
	Read        Kind = "read"
	Write       Kind = "write"       // only with -allow-write
	Destructive Kind = "destructive" // only replay of one flow, with -allow-destructive
	Never       Kind = "never"       // a session's end, a login flow: never sent
	Excluded    Kind = "excluded"    // OPTIONS: nothing to learn
)

// Policy classifies requests for sending. It is stricter than the guard:
// the guard keeps a browser's page working, a replay may send anything.
type Policy struct {
	ReadAllow *regexp.Regexp // POSTs that only read (a search)
	AuthAllow *regexp.Regexp // login-flow URLs the user lets through
}

// authFlowRe names the endpoints of a login flow: sending one again may
// rotate or end the recorded session.
var authFlowRe = regexp.MustCompile(`(?i)log[-_]?in|sign[-_]?in|sign[-_]?on|log[-_]?on|auth(enticate|orize)?|token|refresh|oauth2?|openid|sso|saml|cas|password|passwd|mfa|2fa|otp|totp|webauthn|passkey|impersonat(e|ion)|switch[-_]?(account|user|role)|sudo`)

// sessionEndRe names a session's end: never sent, whatever the flags.
var sessionEndRe = regexp.MustCompile(`(?i)log[-_]?out|log[-_]?off|sign[-_]?out|end[-_]?session|wsignout|revoke|expire`)

type Decision struct {
	Kind   Kind
	Reason string
}

// Classify says what sending a recorded request again may do. held says
// the crawl's guard held it back, in any role.
func (p Policy) Classify(e traffic.Entry, held bool) Decision {
	u, err := url.Parse(e.URL)
	if err != nil {
		return Decision{Never, "bad URL"}
	}
	path := decode(u.EscapedPath())
	query := decode(u.RawQuery)
	if r := e.Response; r != nil {
		if header(r.Headers, "clear-site-data") != "" {
			return Decision{Never, "its response cleared the site's data"}
		}
	}
	if word(sessionEndRe, path+"?"+query) {
		return Decision{Never, "ends a session"}
	}
	if word(authFlowRe, path) && (p.AuthAllow == nil || !p.AuthAllow.MatchString(e.URL)) {
		return Decision{Never, "a login flow (-allow-auth to send it)"}
	}
	ct := header(e.Headers, "content-type")
	method := guard.EffectiveMethod(e.Method, guard.OverrideHeader(lowerKeys(e.Headers)), e.URL, ct, e.Body.Body)
	if method == "OPTIONS" {
		return Decision{Excluded, "OPTIONS"}
	}

	// What the request names: its path and query, the values of its body,
	// its operations.
	names := []string{path, query}
	body := e.Body.Body
	if e.BodyBase64 {
		body = ""
	}
	gql := graphQL(body, u)
	if gql.unknown {
		return Decision{Destructive, "a GraphQL operation that cannot be read (a persisted query)"}
	}
	names = append(names, gql.names...)
	names = append(names, bodyValues(body, ct)...)
	for _, n := range names {
		if guard.NamesDestructive(n) {
			return Decision{Destructive, "names a destructive action: " + clip(n)}
		}
	}
	switch {
	case method == "DELETE":
		return Decision{Destructive, "DELETE"}
	case method != "GET" && method != "HEAD":
		if p.ReadAllow != nil && p.ReadAllow.MatchString(e.URL) && !gql.write {
			return Decision{Read, "-read-allow"}
		}
		if gql.query && !gql.write {
			return Decision{Read, "a GraphQL query"}
		}
		return Decision{Write, method}
	case gql.write:
		return Decision{Write, "a GraphQL mutation"}
	case held:
		return Decision{Write, "the guard held it back"}
	}
	for _, n := range names {
		if guard.NamesAction(n) {
			return Decision{Write, "a GET that names an action: " + clip(n)}
		}
	}
	return Decision{Read, method}
}

type gqlInfo struct {
	query, write, unknown bool
	names                 []string // operation names and root fields
}

var (
	gqlOpRe   = regexp.MustCompile(`^\s*(query|mutation|subscription)\b\s*([_A-Za-z]\w*)?`)
	gqlNameRe = regexp.MustCompile(`^[_A-Za-z]\w*`)
)

// graphQL reads a GraphQL request, one or a batch: whether it writes, and
// the names of its operations and of their root fields (a mutation named
// SaveThing may run deleteUser).
func graphQL(body string, u *url.URL) gqlInfo {
	var docs []map[string]any
	t := strings.TrimSpace(body)
	switch {
	case strings.HasPrefix(t, "["):
		var batch []map[string]any
		if json.Unmarshal([]byte(t), &batch) != nil {
			return gqlInfo{}
		}
		docs = batch
	case strings.HasPrefix(t, "{"):
		var one map[string]any
		if json.Unmarshal([]byte(t), &one) != nil {
			return gqlInfo{}
		}
		docs = []map[string]any{one}
	}
	if q := u.Query(); q.Get("query") != "" || q.Get("extensions") != "" {
		docs = append(docs, map[string]any{"query": q.Get("query"), "operationName": q.Get("operationName"), "extensions": q.Get("extensions")})
	}
	var g gqlInfo
	for _, d := range docs {
		q, _ := d["query"].(string)
		name, _ := d["operationName"].(string)
		_, persisted := d["extensions"]
		if ext, ok := d["extensions"].(string); ok && ext == "" {
			persisted = false
		}
		if q == "" {
			if persisted {
				g.unknown = true
			}
			continue
		}
		g.query = true
		doc := stripGQLComments(q)
		if name != "" {
			g.names = append(g.names, name)
		}
		if m := gqlOpRe.FindStringSubmatch(doc); m != nil {
			if m[1] != "query" {
				g.write = true
			}
			if m[2] != "" {
				g.names = append(g.names, m[2])
			}
		}
		g.names = append(g.names, rootFields(doc)...)
	}
	return g
}

// rootFields are the field names at the first depth of a GraphQL
// document's selection sets.
func rootFields(doc string) []string {
	var out []string
	depth, paren := 0, 0
	for i := 0; i < len(doc); i++ {
		switch c := doc[i]; {
		case c == '"':
			for i++; i < len(doc) && doc[i] != '"'; i++ {
				if doc[i] == '\\' {
					i++
				}
			}
		case c == '(':
			paren++
		case c == ')':
			paren--
		case c == '{':
			depth++
		case c == '}':
			depth--
		case depth == 1 && paren == 0:
			if m := gqlNameRe.FindString(doc[i:]); m != "" && (i == 0 || !isNameByte(doc[i-1])) {
				if m != "on" && m != "fragment" {
					out = append(out, m)
				}
				i += len(m) - 1
			}
		}
	}
	return out
}

func isNameByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func stripGQLComments(doc string) string {
	var b strings.Builder
	for _, line := range strings.Split(doc, "\n") {
		if i := strings.Index(line, "#"); i >= 0 && !strings.Contains(line[:i], `"`) {
			line = line[:i]
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// bodyValues are the string values of a form or JSON body: JSON-RPC's
// "method", an "action" field, a value naming what to do.
func bodyValues(body, ct string) []string {
	t := strings.TrimSpace(body)
	var out []string
	switch {
	case strings.HasPrefix(t, "{") || strings.HasPrefix(t, "["):
		var v any
		if json.Unmarshal([]byte(t), &v) == nil {
			walk(v, func(k, s string) {
				if k != "query" { // a GraphQL document: read as one
					out = append(out, s)
				}
			}, "", 0)
		}
	case strings.Contains(ct, "x-www-form-urlencoded") || (t != "" && !strings.ContainsAny(t, " \n<")):
		if f, err := url.ParseQuery(t); err == nil {
			for _, vs := range f {
				out = append(out, vs...)
			}
		}
	}
	return out
}

func walk(v any, f func(key, s string), key string, depth int) {
	if depth > 20 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			walk(y, f, k, depth+1)
		}
	case []any:
		for _, y := range x {
			walk(y, f, key, depth+1)
		}
	case string:
		if len(x) <= 200 {
			f(key, x)
		}
	}
}

func word(re *regexp.Regexp, s string) bool {
	for _, m := range re.FindAllStringIndex(s, -1) {
		before := m[0] == 0 || !isLetter(s[m[0]-1]) || (isUpper(s[m[0]]) && isLower(s[m[0]-1]))
		after := m[1] == len(s) || !isLetter(s[m[1]]) || (isUpper(s[m[1]]) && isLower(s[m[1]-1]))
		if before && after {
			return true
		}
	}
	return false
}

func isLetter(c byte) bool { return isLower(c) || isUpper(c) }
func isLower(c byte) bool  { return c >= 'a' && c <= 'z' }
func isUpper(c byte) bool  { return c >= 'A' && c <= 'Z' }

func decode(s string) string {
	for range 2 {
		if d, err := url.PathUnescape(s); err == nil {
			s = d
		}
	}
	return s
}

func header(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func lowerKeys(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = v
	}
	return out
}

func clip(s string) string {
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}
